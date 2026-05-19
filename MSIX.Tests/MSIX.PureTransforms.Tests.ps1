BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force

    $script:Sample = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X.Old" Publisher="CN=Old, O=X, C=NL" Version="1.0.0.0" />
  <Applications><Application Id="A" Executable="a.exe" /></Applications>
</Package>
'@
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Set-MsixManifestPublisher (pure transform)' -Tag 'Manifest' {
    It 'Updates Identity.Publisher' {
        [xml]$m = $script:Sample
        Set-MsixManifestPublisher -Manifest $m -Publisher 'CN=New, O=X, C=NL'
        $m.Package.Identity.Publisher | Should -Be 'CN=New, O=X, C=NL'
    }

    It 'Does not touch Name or Version' {
        [xml]$m = $script:Sample
        Set-MsixManifestPublisher -Manifest $m -Publisher 'CN=New'
        $m.Package.Identity.Name    | Should -Be 'X.Old'
        $m.Package.Identity.Version | Should -Be '1.0.0.0'
    }

    It 'Returns the same XmlDocument (pipeline friendly)' {
        [xml]$m = $script:Sample
        $r = Set-MsixManifestPublisher -Manifest $m -Publisher 'CN=New'
        $r | Should -BeOfType 'System.Xml.XmlDocument'
    }
}

Describe 'Set-MsixManifestIdentity (pure transform)' -Tag 'Manifest' {
    It 'Updates only the supplied attributes' {
        [xml]$m = $script:Sample
        Set-MsixManifestIdentity -Manifest $m -Version '2.0.0.0'
        $m.Package.Identity.Version   | Should -Be '2.0.0.0'
        $m.Package.Identity.Name      | Should -Be 'X.Old'
        $m.Package.Identity.Publisher | Should -Be 'CN=Old, O=X, C=NL'
    }

    It 'Updates Name + Publisher + Version together' {
        [xml]$m = $script:Sample
        Set-MsixManifestIdentity -Manifest $m -Name 'X.New' -Publisher 'CN=New' -Version '3.4.5.6'
        $m.Package.Identity.Name      | Should -Be 'X.New'
        $m.Package.Identity.Publisher | Should -Be 'CN=New'
        $m.Package.Identity.Version   | Should -Be '3.4.5.6'
    }

    It 'Rejects 3-part version' {
        [xml]$m = $script:Sample
        { Set-MsixManifestIdentity -Manifest $m -Version '1.2.3' } |
            Should -Throw '*4-part dotted-decimal*'
    }
}
