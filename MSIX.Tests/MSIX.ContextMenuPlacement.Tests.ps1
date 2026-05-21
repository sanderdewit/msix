BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force

    # Minimal valid manifest used to exercise the manifest-mutation logic
    # entirely in-memory (no MakeAppx needed for these tests).
    $script:SampleXml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         IgnorableNamespaces="uap">
  <Identity Name="Test.App" Publisher="CN=Test" Version="1.0.0.0" />
  <Properties>
    <DisplayName>Test</DisplayName>
    <PublisherDisplayName>Test</PublisherDisplayName>
    <Logo>logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" />
  </Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="App" Executable="app.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Test" Description="Test" BackgroundColor="transparent" Square150x150Logo="l.png" Square44x44Logo="l.png" />
    </Application>
  </Applications>
</Package>
'@
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Shell-extension context menu placement (TMEditX-verified pattern)' -Tag 'ContextMenu' {

    # Working pattern, derived from a TMEditX-generated manifest that the
    # Windows shell actually wires up at runtime (Notepad++ NppShell case):
    #
    #   Applications/Application/Extensions
    #     <com:Extension Category="windows.comServer">          <- v10 com:
    #       <com:ComServer>
    #         <com:SurrogateServer DisplayName="...">
    #           <com:Class Id="b298d29a-..." Path="VFS\..\Shell.dll" .../>
    #         </com:SurrogateServer>
    #       </com:ComServer>
    #     </com:Extension>
    #     <desktop4:Extension Category="windows.fileExplorerContextMenus">
    #       <desktop4:FileExplorerContextMenus>
    #         <desktop5:ItemType Type="*">
    #           <desktop5:Verb Id="ContextMenuHandlers" Clsid="b298d29a-..." />
    #         </desktop5:ItemType>
    #       </desktop4:FileExplorerContextMenus>
    #     </desktop4:Extension>
    #
    # Notes:
    #   - desktop9:fileExplorerClassicContextMenuHandler turned out to be the
    #     WRONG schema for COM-based shell extensions. desktop4 + desktop5
    #     drives both legacy IContextMenu and modern IExplorerCommand via
    #     whichever interface(s) the CLSID's COM class implements.
    #   - Everything lives at Application level. Package-level placement
    #     either fails schema validation (com requires com4 at Package level
    #     and com4 disallows SurrogateServer) or installs but isn't wired up
    #     by Explorer.

    It 'Add-MsixLegacyContextMenu emits com:Extension at Application level (bare com)' {
        [xml]$xml = $script:SampleXml
        & (Get-Module MSIX) {
            param($m)
            Add-MsixManifestNamespace $m 'com'
            $app = Get-MsixManifestApplication -Manifest $m
            $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
            if (-not $appExt) {
                $appExt = $m.CreateElement('Extensions', $m.Package.NamespaceURI)
                $null = $app.AppendChild($appExt)
            }
            $comUri    = Get-MsixManifestNamespaceUri 'com'
            $comExt    = $m.CreateElement('com:Extension', $comUri)
            $comExt.SetAttribute('Category', 'windows.comServer')
            $comServer = $m.CreateElement('com:ComServer', $comUri)
            $surrogate = $m.CreateElement('com:SurrogateServer', $comUri)
            $surrogate.SetAttribute('DisplayName', 'Test')
            $null = $comServer.AppendChild($surrogate)
            $null = $comExt.AppendChild($comServer)
            $null = $appExt.AppendChild($comExt)
        } $xml

        $appComServer = $xml.SelectNodes("//*[local-name()='Application']/*[local-name()='Extensions']/*[local-name()='Extension' and @Category='windows.comServer']")
        $pkgComServer = $xml.SelectNodes("/*[local-name()='Package']/*[local-name()='Extensions']/*[local-name()='Extension' and @Category='windows.comServer']")
        $appComServer.Count | Should -Be 1
        $pkgComServer.Count | Should -Be 0
        $appComServer[0].NamespaceURI | Should -Be 'http://schemas.microsoft.com/appx/manifest/com/windows10'
    }

    It 'ContextMenu.ps1 source uses bare com: for the SurrogateServer block' {
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ContextMenu.ps1')) -Raw
        $src | Should -Match "CreateElement\('com:Extension'"
        $src | Should -Match "CreateElement\('com:ComServer'"
        $src | Should -Match "CreateElement\('com:SurrogateServer'"
        $src | Should -Match "CreateElement\('com:Class'"
        # Must NOT use com4 here — Surrogate is forbidden at Package level.
        $src | Should -Not -Match "CreateElement\('com4:Extension'"
        $src | Should -Not -Match "CreateElement\('com4:SurrogateServer'"
    }

    It 'ContextMenu.ps1 emits desktop4:Extension + desktop5:ItemType/Verb (NOT desktop9)' {
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ContextMenu.ps1')) -Raw
        # The new working pattern uses desktop4 outer, desktop5 inner verbs.
        $src | Should -Match "CreateElement\('desktop4:Extension'"
        $src | Should -Match "CreateElement\('desktop4:FileExplorerContextMenus'"
        $src | Should -Match "CreateElement\('desktop5:ItemType'"
        $src | Should -Match "CreateElement\('desktop5:Verb'"
        # No CreateElement calls should reference the old desktop9 nodes.
        # (Docstring/comments may still mention the schema for historical
        # context — we only forbid actual element construction.)
        $src | Should -Not -Match "CreateElement\('desktop9:Extension'"
        $src | Should -Not -Match "CreateElement\('desktop9:ExtensionHandler'"
        $src | Should -Not -Match "CreateElement\('desktop9:FileExplorerClassicContextMenuHandler'"
    }

    It 'CLSID is lowercased in both Add-MsixLegacyContextMenu and Add-MsixFileExplorerContextMenu' {
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ContextMenu.ps1')) -Raw
        # Both functions normalise via .ToLowerInvariant() after stripping braces.
        ($src | Select-String -Pattern '\.ToLowerInvariant\(\)' -AllMatches).Matches.Count | Should -BeGreaterOrEqual 2
    }

    It 'Add-MsixComServerExtension (InProcessServer only) still uses com4 at Package level' {
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ManifestExtensions.ps1')) -Raw
        $startIdx = $src.IndexOf('function Add-MsixComServerExtension')
        $nextIdx  = $src.IndexOf("`nfunction ", $startIdx + 1)
        if ($nextIdx -lt 0) { $nextIdx = $src.Length }
        $body = $src.Substring($startIdx, $nextIdx - $startIdx)
        $body | Should -Match "CreateElement\('com4:Extension'"
        $body | Should -Match "CreateElement\('com4:InProcessServer'"
        $body | Should -Match '_MsixGetOrCreatePackageExtensions'
        # InProc only — no Surrogate at Package level.
        $body | Should -Not -Match 'SurrogateServer'
    }
}
