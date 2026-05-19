BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force

    $script:Sample = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         IgnorableNamespaces="uap">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Properties><DisplayName>X</DisplayName><PublisherDisplayName>X</PublisherDisplayName><Logo>l.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" /></Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications><Application Id="App" Executable="x.exe" EntryPoint="Windows.FullTrustApplication" /></Applications>
</Package>
'@
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Idempotent namespace additions' -Tag 'Idempotency' {
    It 'Add-MsixManifestNamespace twice = once' {
        [xml]$m = $script:Sample
        Add-MsixManifestNamespace -Manifest $m -Prefix 'rescap'
        Add-MsixManifestNamespace -Manifest $m -Prefix 'rescap'
        ($m.Package.Attributes | Where-Object { $_.LocalName -eq 'rescap' -and $_.Prefix -eq 'xmlns' }).Count |
            Should -Be 1
    }

    It 'IgnorableNamespaces does not gain duplicate entries' {
        [xml]$m = $script:Sample
        Add-MsixManifestNamespace -Manifest $m -Prefix 'desktop6'
        Add-MsixManifestNamespace -Manifest $m -Prefix 'desktop6'
        $tokens = $m.Package.IgnorableNamespaces -split '\s+' | Where-Object { $_ -eq 'desktop6' }
        @($tokens).Count | Should -Be 1
    }
}

Describe 'Idempotent MaxVersionTested bump' -Tag 'Idempotency' {
    It 'Two bumps to the same build = one update' {
        [xml]$m = $script:Sample
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000
        $first = $m.Package.Dependencies.TargetDeviceFamily.MaxVersionTested
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000
        $m.Package.Dependencies.TargetDeviceFamily.MaxVersionTested | Should -Be $first
    }

    It 'Lower bump leaves higher value alone' {
        [xml]$m = $script:Sample
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 19041
        $m.Package.Dependencies.TargetDeviceFamily.MaxVersionTested | Should -Be '10.0.22000.0'
    }
}

Describe 'Idempotent pure-transform mutators' -Tag 'Idempotency' {
    It 'Set-MsixManifestPublisher applied twice yields one value' {
        [xml]$m = $script:Sample
        Set-MsixManifestPublisher -Manifest $m -Publisher 'CN=New' | Out-Null
        Set-MsixManifestPublisher -Manifest $m -Publisher 'CN=New' | Out-Null
        $m.Package.Identity.Publisher | Should -Be 'CN=New'
    }
}
