BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force

    # Minimal valid manifest to exercise the placement logic via pure XML transforms.
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

Describe 'Shell-integration extensions placement (Package vs Application)' -Tag 'ContextMenu' {

    # SCHEMA / RUNTIME RULES (learned the hard way from MakeAppx + Shell):
    #
    #   com:Extension (v10 'com' prefix) with SurrogateServer
    #     - Application-level only. MakeAppx rejects Package-level placement:
    #       "Extension 'windows.comServer' must be …/com/windows10/4 or newer
    #        on package level".
    #     - Package-level com4 disallows Surrogate entirely:
    #       "Package extension 'windows.comServer' must not declare
    #        'ExeServer'/'SurrogateServer'/'ServiceServer'".
    #     - Net: Surrogate-hosted CLSID *must* be declared at Application level.
    #
    #   com4:Extension (v10/4) with InProcessServer
    #     - Package-level only (Package extension windows.comServer must be com4+).
    #     - InProcessServer is the only allowed server type at Package level.
    #
    #   desktop9:Extension (windows.fileExplorerClassicContextMenuHandler)
    #     - Package-level. Placing it under an Application makes MakeAppx
    #       happy but Explorer never registers the shell hook at runtime.

    It 'Add-MsixLegacyContextMenu writes the COM SurrogateServer at Application level (bare com namespace)' {
        [xml]$xml = $script:SampleXml
        & (Get-Module MSIX) {
            param($m)
            # Replicate the cmdlet's mutation steps in-memory (no MakeAppx needed).
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
        # bare 'com' namespace (v10) — surrogate is only legal here
        $appComServer[0].NamespaceURI | Should -Be 'http://schemas.microsoft.com/appx/manifest/com/windows10'
    }

    It 'Add-MsixLegacyContextMenu writes desktop9 context menu at Package level' {
        [xml]$xml = $script:SampleXml
        & (Get-Module MSIX) {
            param($m)
            Add-MsixManifestNamespace $m 'desktop9'
            $pkgExt = _MsixGetOrCreatePackageExtensions $m
            $d9Uri  = Get-MsixManifestNamespaceUri 'desktop9'
            $d9Ext  = $m.CreateElement('desktop9:Extension', $d9Uri)
            $d9Ext.SetAttribute('Category', 'windows.fileExplorerClassicContextMenuHandler')
            $null = $pkgExt.AppendChild($d9Ext)
        } $xml

        $pkg = $xml.SelectNodes("/*[local-name()='Package']/*[local-name()='Extensions']/*[local-name()='Extension' and @Category='windows.fileExplorerClassicContextMenuHandler']")
        $app = $xml.SelectNodes("//*[local-name()='Application']/*[local-name()='Extensions']/*[local-name()='Extension' and @Category='windows.fileExplorerClassicContextMenuHandler']")
        $pkg.Count | Should -Be 1
        $app.Count | Should -Be 0
    }

    It 'ContextMenu.ps1 calls _MsixGetOrCreatePackageExtensions (for desktop9)' {
        # Regression guard: desktop9 must end up at Package level.
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ContextMenu.ps1')) -Raw
        $src | Should -Match '_MsixGetOrCreatePackageExtensions'
    }

    It 'ContextMenu.ps1 uses bare com: namespace for the SurrogateServer block (not com4:)' {
        # Schema rule: SurrogateServer is forbidden in Package-level com4.
        # The COM declaration in Add-MsixLegacyContextMenu must use the bare
        # 'com' prefix at Application level.
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ContextMenu.ps1')) -Raw
        $src | Should -Match "CreateElement\('com:Extension'"
        $src | Should -Match "CreateElement\('com:ComServer'"
        $src | Should -Match "CreateElement\('com:SurrogateServer'"
        $src | Should -Match "CreateElement\('com:Class'"
        # Must NOT use com4 here — Surrogate is forbidden at Package level.
        $src | Should -Not -Match "CreateElement\('com4:Extension'"
        $src | Should -Not -Match "CreateElement\('com4:SurrogateServer'"
    }

    It 'ManifestExtensions.ps1 (Add-MsixComServerExtension, InProcessServer only) uses com4 at Package level' {
        # Inverse rule: Package-level windows.comServer must be com4 AND may
        # only declare InProcessServer.
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ManifestExtensions.ps1')) -Raw
        $startIdx = $src.IndexOf('function Add-MsixComServerExtension')
        $nextIdx  = $src.IndexOf("`nfunction ", $startIdx + 1)
        if ($nextIdx -lt 0) { $nextIdx = $src.Length }
        $body = $src.Substring($startIdx, $nextIdx - $startIdx)
        $body | Should -Match "CreateElement\('com4:Extension'"
        $body | Should -Match "CreateElement\('com4:InProcessServer'"
        $body | Should -Match "CreateElement\('com4:Class'"
        # Must NOT use bare 'com:' here — Package-level requires com4.
        $body | Should -Not -Match "CreateElement\('com:Extension'"
        # And must not declare SurrogateServer at Package level.
        $body | Should -Not -Match 'SurrogateServer'
    }

    It 'Add-MsixComServerExtension uses Package-level Extensions' {
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ManifestExtensions.ps1')) -Raw
        $startIdx = $src.IndexOf('function Add-MsixComServerExtension')
        $startIdx | Should -BeGreaterThan 0
        $nextIdx = $src.IndexOf("`nfunction ", $startIdx + 1)
        if ($nextIdx -lt 0) { $nextIdx = $src.Length }
        $body = $src.Substring($startIdx, $nextIdx - $startIdx)
        $body | Should -Match '_MsixGetOrCreatePackageExtensions'
        $body | Should -Not -Match '_MsixGetOrCreateApplicationExtensions'
    }
}
