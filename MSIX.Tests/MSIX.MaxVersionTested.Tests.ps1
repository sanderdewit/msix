BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    function script:New-TestManifest {
        param([string]$DependenciesXml)
        [xml]@"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  $DependenciesXml
</Package>
"@
    }

    function script:Get-Build {
        param([xml]$Manifest)
        @($Manifest.Package.Dependencies.TargetDeviceFamily) |
            ForEach-Object { ($_.GetAttribute('MaxVersionTested') -split '\.')[2] }
    }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Set-MsixManifestMaxVersionTested (#57)' -Tag 'Manifest' {

    It 'bumps every TargetDeviceFamily, not just the first' {
        $m = New-TestManifest -DependenciesXml @'
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop"   MinVersion="10.0.17763.0" MaxVersionTested="10.0.17763.0" />
    <TargetDeviceFamily Name="Windows.Universal" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" />
  </Dependencies>
'@
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000
        ((Get-Build -Manifest $m) -join ',') | Should -Be '22000,22000'
    }

    It 'bumps a version with fewer than three components instead of silently skipping' {
        $m = New-TestManifest -DependenciesXml @'
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0" MaxVersionTested="10.0" />
  </Dependencies>
'@
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000
        @($m.Package.Dependencies.TargetDeviceFamily)[0].GetAttribute('MaxVersionTested') |
            Should -Be '10.0.22000.0'
    }

    It 'is idempotent when the build floor is already met or exceeded' {
        $m = New-TestManifest -DependenciesXml @'
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.26100.0" />
  </Dependencies>
'@
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000
        @($m.Package.Dependencies.TargetDeviceFamily)[0].GetAttribute('MaxVersionTested') |
            Should -Be '10.0.26100.0'
    }

    It 'preserves the major.minor components when bumping the build' {
        $m = New-TestManifest -DependenciesXml @'
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.17763.0" />
  </Dependencies>
'@
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 19041
        @($m.Package.Dependencies.TargetDeviceFamily)[0].GetAttribute('MaxVersionTested') |
            Should -Be '10.0.19041.0'
    }

    It 'handles a single TargetDeviceFamily (backward compatibility)' {
        $m = New-TestManifest -DependenciesXml @'
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.18362.0" />
  </Dependencies>
'@
        { Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000 } | Should -Not -Throw
        ((Get-Build -Manifest $m) -join ',') | Should -Be '22000'
    }

    It 'does not throw when the manifest has no Dependencies element' {
        $m = New-TestManifest -DependenciesXml ''
        { Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000 } | Should -Not -Throw
    }
}
