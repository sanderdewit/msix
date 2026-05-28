BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Empty / minimal manifests' -Tag 'EdgeCases' {
    It 'Returns empty array for a package with no Applications' {
        $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
</Package>
'@
        $doc = New-MsixManifestDocument -XmlText $xml
        $apps = @(Get-MsixManifestApplication -Manifest $doc -All)
        $apps.Count | Should -Be 0
    }

    It 'Handles 10 Applications without truncation' {
        $sb = [System.Text.StringBuilder]::new()
        [void]$sb.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
        [void]$sb.AppendLine('<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">')
        [void]$sb.AppendLine('<Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />')
        [void]$sb.AppendLine('<Applications>')
        for ($i = 1; $i -le 10; $i++) {
            [void]$sb.AppendLine("  <Application Id=`"App$i`" Executable=`"a$i.exe`" />")
        }
        [void]$sb.AppendLine('</Applications></Package>')
        $doc = New-MsixManifestDocument -XmlText $sb.ToString()
        $apps = @(Get-MsixManifestApplication -Manifest $doc -All)
        $apps.Count | Should -Be 10
    }

    It 'Preserves Unicode in DisplayName round-trip' {
        $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Properties><DisplayName>Contoso日本語</DisplayName><PublisherDisplayName>X</PublisherDisplayName><Logo>l.png</Logo></Properties>
  <Applications><Application Id="A" Executable="a.exe" /></Applications>
</Package>
'@
        $doc = New-MsixManifestDocument -XmlText $xml
        $doc.Package.Properties.DisplayName | Should -Be 'Contoso日本語'
    }
}

Describe 'Get-MsixManifestApplication parameter sets' -Tag 'EdgeCases' {
    It '-All returns all apps' {
        $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Applications>
    <Application Id="A" Executable="a.exe" />
    <Application Id="B" Executable="b.exe" />
  </Applications>
</Package>
'@
        $doc = New-MsixManifestDocument -XmlText $xml
        $apps = @(Get-MsixManifestApplication -Manifest $doc -All)
        $apps.Count | Should -Be 2
    }

    It '-AppId returns the matching one' {
        $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Applications><Application Id="Target" Executable="t.exe" /></Applications>
</Package>
'@
        $doc = New-MsixManifestDocument -XmlText $xml
        $app = Get-MsixManifestApplication -Manifest $doc -AppId 'Target'
        $app.GetAttribute('Executable') | Should -Be 't.exe'
    }

    It 'Default (no -All, no -AppId) returns first app' {
        $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Applications>
    <Application Id="First" Executable="1.exe" />
    <Application Id="Second" Executable="2.exe" />
  </Applications>
</Package>
'@
        $doc = New-MsixManifestDocument -XmlText $xml
        $app = Get-MsixManifestApplication -Manifest $doc
        $app.GetAttribute('Id') | Should -Be 'First'
    }
}

Describe 'Deprecated plural still works' -Tag 'EdgeCases' {
    It 'Get-MsixManifestApplications returns the same as -All' {
        $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Applications>
    <Application Id="A" Executable="a.exe" />
    <Application Id="B" Executable="b.exe" />
  </Applications>
</Package>
'@
        $doc = New-MsixManifestDocument -XmlText $xml
        $viaPlural = @(Get-MsixManifestApplications -Manifest $doc)
        $viaAll    = @(Get-MsixManifestApplication  -Manifest $doc -All)
        $viaPlural.Count | Should -Be $viaAll.Count
    }
}
