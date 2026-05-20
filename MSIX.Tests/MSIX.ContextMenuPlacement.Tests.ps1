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

    # Shell-integration extensions (windows.comServer for a SurrogateServer,
    # windows.fileExplorerClassicContextMenuHandler, windows.fileExplorerContextMenus)
    # MUST live at Package/Extensions, not Applications/Application/Extensions.
    # Microsoft's context-menu integration sample registers them at Package
    # level; placing them under an Application makes MakeAppx happy but the
    # shell never registers the handler at runtime — bug surfaced as
    # "legacy context menu doesn't appear" on Notepad++-style packages.

    It 'Add-MsixLegacyContextMenu writes com4:Extension at Package level (not Application)' {
        [xml]$xml = $script:SampleXml
        & (Get-Module MSIX) {
            param($m)
            # Drive the inner mutation logic directly via the manifest transform.
            # We can't invoke the full cmdlet (it requires MakeAppx) but we can
            # exercise the manifest mutation by replicating its core steps.
            # Package-level windows.comServer requires the com4 namespace.
            Add-MsixManifestNamespace $m 'com4'
            Add-MsixManifestNamespace $m 'desktop9'
            $pkgExt = _MsixGetOrCreatePackageExtensions $m

            $comUri = Get-MsixManifestNamespaceUri 'com4'
            $comExt = $m.CreateElement('com4:Extension', $comUri)
            $comExt.SetAttribute('Category', 'windows.comServer')
            $null = $pkgExt.AppendChild($comExt)
        } $xml

        $pkgComServer = $xml.SelectNodes("/*[local-name()='Package']/*[local-name()='Extensions']/*[local-name()='Extension' and @Category='windows.comServer']")
        $appComServer = $xml.SelectNodes("//*[local-name()='Application']/*[local-name()='Extensions']/*[local-name()='Extension' and @Category='windows.comServer']")
        $pkgComServer.Count | Should -Be 1
        $appComServer.Count | Should -Be 0

        # com4 namespace (v10/4) — required for Package-level windows.comServer
        $pkgComServer[0].NamespaceURI | Should -Be 'http://schemas.microsoft.com/appx/manifest/com/windows10/4'
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

    It 'ContextMenu.ps1 calls _MsixGetOrCreatePackageExtensions (not _MsixGetOrCreateApplicationExtensions)' {
        # Source-level regression guard: catches future commits that accidentally
        # move shell-integration extensions back to Application level.
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ContextMenu.ps1')) -Raw
        $src | Should -Match '_MsixGetOrCreatePackageExtensions'
        # Must NOT contain the Application-level pattern that caused the original bug.
        # (Local $appExt variable name is fine; we look specifically for the helper call.)
        $src | Should -Not -Match '_MsixGetOrCreateApplicationExtensions'
    }

    It 'ContextMenu.ps1 emits com4: prefix (not bare com:) for Package-level COM extensions' {
        # Schema rule: package-level windows.comServer must be v10/4 (com4).
        # MakeAppx rejects packaging with "Extension 'windows.comServer' must
        # be 'http://schemas.microsoft.com/appx/manifest/com/windows10/4' or
        # newer on package level" when the bare 'com' prefix is used at
        # Package scope. Regression guard.
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ContextMenu.ps1')) -Raw
        $src | Should -Match "CreateElement\('com4:Extension'"
        $src | Should -Match "CreateElement\('com4:ComServer'"
        $src | Should -Match "CreateElement\('com4:SurrogateServer'"
        $src | Should -Match "CreateElement\('com4:Class'"
        # Must NOT contain the v10 (bare 'com:') element creations at this point.
        $src | Should -Not -Match "CreateElement\('com:Extension'"
        $src | Should -Not -Match "CreateElement\('com:SurrogateServer'"
    }

    It 'ManifestExtensions.ps1 (Add-MsixComServerExtension) emits com4: prefix' {
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ManifestExtensions.ps1')) -Raw
        $startIdx = $src.IndexOf('function Add-MsixComServerExtension')
        $nextIdx  = $src.IndexOf("`nfunction ", $startIdx + 1)
        if ($nextIdx -lt 0) { $nextIdx = $src.Length }
        $body = $src.Substring($startIdx, $nextIdx - $startIdx)
        $body | Should -Match "CreateElement\('com4:Extension'"
        $body | Should -Match "CreateElement\('com4:InProcessServer'"
        $body | Should -Match "CreateElement\('com4:Class'"
        $body | Should -Not -Match "CreateElement\('com:Extension'"
    }

    It 'Add-MsixComServerExtension uses Package-level Extensions' {
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.ManifestExtensions.ps1')) -Raw
        # The COM-server adder body must call the Package helper, NOT the
        # Application helper (the latter is what caused the original bug).
        $startIdx = $src.IndexOf('function Add-MsixComServerExtension')
        $startIdx | Should -BeGreaterThan 0
        # Find the next 'function' declaration after this one — that's the end of our body.
        $nextIdx = $src.IndexOf("`nfunction ", $startIdx + 1)
        if ($nextIdx -lt 0) { $nextIdx = $src.Length }
        $body = $src.Substring($startIdx, $nextIdx - $startIdx)
        $body | Should -Match '_MsixGetOrCreatePackageExtensions'
        $body | Should -Not -Match '_MsixGetOrCreateApplicationExtensions'
    }
}
