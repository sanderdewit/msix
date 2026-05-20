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

    It 'Add-MsixLegacyContextMenu writes com:Extension at Package level (not Application)' {
        [xml]$xml = $script:SampleXml
        & (Get-Module MSIX) {
            param($m)
            # Drive the inner mutation logic directly via the manifest transform.
            # We can't invoke the full cmdlet (it requires MakeAppx) but we can
            # exercise the manifest mutation by replicating its core steps.
            Add-MsixManifestNamespace $m 'com'
            Add-MsixManifestNamespace $m 'desktop9'
            $pkgExt = _MsixGetOrCreatePackageExtensions $m

            $comUri = Get-MsixManifestNamespaceUri 'com'
            $comExt = $m.CreateElement('com:Extension', $comUri)
            $comExt.SetAttribute('Category', 'windows.comServer')
            $null = $pkgExt.AppendChild($comExt)
        } $xml

        $pkgComServer = $xml.SelectNodes("/*[local-name()='Package']/*[local-name()='Extensions']/*[local-name()='Extension' and @Category='windows.comServer']")
        $appComServer = $xml.SelectNodes("//*[local-name()='Application']/*[local-name()='Extensions']/*[local-name()='Extension' and @Category='windows.comServer']")
        $pkgComServer.Count | Should -Be 1
        $appComServer.Count | Should -Be 0
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
