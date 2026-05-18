BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psm1')) -Force

    $script:SampleXml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         IgnorableNamespaces="uap">
  <Identity Name="Test.App" Publisher="CN=Test" Version="1.0.0.0" />
  <Properties><DisplayName>Test</DisplayName><PublisherDisplayName>Test</PublisherDisplayName><Logo>l.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" /></Dependencies>
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

Describe 'Invoke-MsixManifestTransform' -Tag 'Manifest' {

    It 'Applies transform to [xml] input and returns mutated xml' {
        [xml]$xml = $script:SampleXml
        $result = Invoke-MsixManifestTransform -Manifest $xml -Transform {
            param([xml]$m)
            $m.Package.Identity.SetAttribute('Version', '2.0.0.0')
        }
        $result.Package.Identity.Version | Should -Be '2.0.0.0'
    }

    It 'Accepts MSIX.ManifestDocument and operates on its inner Document' {
        $doc = New-MsixManifestDocument -XmlText $script:SampleXml
        $result = Invoke-MsixManifestTransform -Manifest $doc -Transform {
            param([xml]$m)
            $m.Package.Identity.SetAttribute('Name', 'Mutated.App')
        }
        $result.Package.Identity.Name | Should -Be 'Mutated.App'
    }

    It 'Returns the same xml object (in-place mutation)' {
        [xml]$xml = $script:SampleXml
        $result = Invoke-MsixManifestTransform -Manifest $xml -Transform { param([xml]$m) }
        $result | Should -BeOfType 'System.Xml.XmlDocument'
    }

    It 'Does not touch package files' {
        # No MakeAppx, no temp files — pure in-memory operation
        [xml]$xml = $script:SampleXml
        $before = (Get-ChildItem $env:TEMP -Filter 'msix-*' -ErrorAction SilentlyContinue).Count
        $null = Invoke-MsixManifestTransform -Manifest $xml -Transform { param([xml]$m) }
        $after  = (Get-ChildItem $env:TEMP -Filter 'msix-*' -ErrorAction SilentlyContinue).Count
        $after | Should -Be $before
    }
}
