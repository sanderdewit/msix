BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force

    $script:SampleManifest = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         IgnorableNamespaces="uap">
  <Identity Name="Contoso.App" Publisher="CN=Contoso, O=Contoso, C=NL" Version="1.0.0.0" />
  <Properties><DisplayName>Contoso</DisplayName><PublisherDisplayName>Contoso</PublisherDisplayName><Logo>l.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" /></Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="App" Executable="VFS\ProgramFilesX64\App\App.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="App" Description="App" BackgroundColor="transparent" Square150x150Logo="l.png" Square44x44Logo="l.png" />
    </Application>
  </Applications>
</Package>
'@

    $script:MultiAppManifest = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="Contoso.Multi" Publisher="CN=Contoso, O=Contoso, C=NL" Version="1.0.0.0" />
  <Properties><DisplayName>Contoso</DisplayName><PublisherDisplayName>Contoso</PublisherDisplayName><Logo>l.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" /></Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="AppA" Executable="A.exe" EntryPoint="Windows.FullTrustApplication" />
    <Application Id="AppB" Executable="B.exe" EntryPoint="Windows.FullTrustApplication" />
  </Applications>
</Package>
'@
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Manifest helpers' -Tag 'Manifest' {

    Context 'Add-MsixManifestNamespace' {
        It 'Adds rescap namespace if missing' {
            [xml]$x = $script:SampleManifest
            Add-MsixManifestNamespace -Manifest $x -Prefix 'rescap'
            $x.Package.Attributes['xmlns:rescap'].Value | Should -Be 'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities'
            $x.Package.IgnorableNamespaces | Should -Match '\brescap\b'
        }
        It 'Is idempotent on second call' {
            [xml]$x = $script:SampleManifest
            Add-MsixManifestNamespace -Manifest $x -Prefix 'desktop'
            Add-MsixManifestNamespace -Manifest $x -Prefix 'desktop'
            ($x.Package.Attributes | Where-Object { $_.Value -eq 'http://schemas.microsoft.com/appx/manifest/desktop/windows10' }).Count |
                Should -Be 1
        }
        It 'Throws on unknown prefix' {
            [xml]$x = $script:SampleManifest
            { Add-MsixManifestNamespace -Manifest $x -Prefix 'nopenope' } | Should -Throw
        }
    }

    Context 'Set-MsixManifestMaxVersionTested' {
        It 'Bumps when below threshold' {
            [xml]$x = $script:SampleManifest
            Set-MsixManifestMaxVersionTested -Manifest $x -MinBuild 21301
            $x.Package.Dependencies.TargetDeviceFamily.MaxVersionTested |
                Should -Be '10.0.21301.0'
        }
        It 'Leaves version alone when at/above threshold' {
            [xml]$x = $script:SampleManifest
            $x.Package.Dependencies.TargetDeviceFamily.MaxVersionTested = '10.0.26100.0'
            Set-MsixManifestMaxVersionTested -Manifest $x -MinBuild 21301
            $x.Package.Dependencies.TargetDeviceFamily.MaxVersionTested |
                Should -Be '10.0.26100.0'
        }
    }

    Context 'Get-MsixManifestApplications' {
        It 'Returns all Application elements as an array' {
            [xml]$x = $script:SampleManifest
            $apps = Get-MsixManifestApplications -Manifest $x
            ,$apps -is [array]   | Should -BeTrue
            @($apps).Count       | Should -Be 1
            @($apps)[0].Id       | Should -Be 'App'
        }

        It 'Preserves multi-application manifests' {
            $m = New-MsixManifestDocument -XmlText $script:MultiAppManifest
            $apps = @(Get-MsixManifestApplications -Manifest $m)

            $apps.Count | Should -Be 2
            ($apps | ForEach-Object { $_.GetAttribute('Id') }) | Should -Be @('AppA', 'AppB')
        }
    }

    Context 'Get-MsixManifestApplication' {
        It 'Returns one Application by Id' {
            $m = New-MsixManifestDocument -XmlText $script:MultiAppManifest
            $app = Get-MsixManifestApplication -Manifest $m -AppId 'AppB'

            $app.GetAttribute('Executable') | Should -Be 'B.exe'
        }
    }

    Context 'New-MsixManifestDocument' {
        It 'Parses XML text without package IO' {
            $m = New-MsixManifestDocument -XmlText $script:SampleManifest

            $m.PSTypeNames | Should -Contain 'MSIX.ManifestDocument'
            $m.Package.LocalName | Should -Be 'Package'
            (Select-MsixManifestNodes -Manifest $m -XPath '//f:Application').Count |
                Should -Be 1
        }

        It 'Returns an application by Id' {
            $m = New-MsixManifestDocument -XmlText $script:SampleManifest
            $app = Get-MsixManifestApplication -Manifest $m -AppId 'App'

            $app.GetAttribute('Executable') | Should -Be 'VFS\ProgramFilesX64\App\App.exe'
        }

        It 'Supports raw XmlDocument callers for compatibility' {
            [xml]$x = $script:SampleManifest

            $app = Get-MsixManifestApplication -Manifest $x

            $app.GetAttribute('Id') | Should -Be 'App'
        }
    }
}
