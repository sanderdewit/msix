BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psm1')) -Force

    $script:Tmp = Join-Path $env:TEMP "msix-validate-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item $script:Tmp -ItemType Directory -Force | Out-Null
}

AfterAll {
    Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Module MSIX -ErrorAction SilentlyContinue
}

Describe 'Validation' -Tag 'Validation' {

    Context 'Test-MsixManifest' {
        It 'Throws when file does not exist' {
            { Test-MsixManifest -Path 'C:\nope\does\not\exist.xml' } | Should -Throw
        }

        It 'Throws on malformed XML' {
            $bad = Join-Path $script:Tmp 'bad.xml'
            'not xml' | Set-Content $bad
            { Test-MsixManifest -Path $bad } | Should -Throw '*not valid XML*'
        }

        It 'Throws when Identity is missing required fields' {
            $broken = Join-Path $script:Tmp 'broken.xml'
            @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="App" />
  <Applications><Application Id="A" Executable="x.exe" /></Applications>
</Package>
'@ | Set-Content $broken
            { Test-MsixManifest -Path $broken } | Should -Throw '*Publisher*'
        }

        It 'Throws when Applications is empty' {
            $noapp = Join-Path $script:Tmp 'noapp.xml'
            @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="A" Publisher="CN=X" Version="1.0.0.0" />
</Package>
'@ | Set-Content $noapp
            { Test-MsixManifest -Path $noapp } | Should -Throw '*Application*'
        }

        It 'Returns true for a complete manifest' {
            $ok = Join-Path $script:Tmp 'ok.xml'
            @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="A" Publisher="CN=X" Version="1.0.0.0" />
  <Applications><Application Id="A" Executable="x.exe" /></Applications>
</Package>
'@ | Set-Content $ok
            Test-MsixManifest -Path $ok | Should -BeTrue
        }
    }

    Context 'Test-MsixPsfConfig' {
        It 'Throws on missing keys' {
            $bad = Join-Path $script:Tmp 'badcfg.json'
            '{}' | Set-Content $bad
            { Test-MsixPsfConfig -Path $bad } | Should -Throw '*applications*'
        }
        It 'Accepts a valid PSF config' {
            $ok = Join-Path $script:Tmp 'okcfg.json'
            @'
{
  "applications": [{ "id": "App", "executable": "x.exe" }],
  "processes":    [{ "executable": "x" }]
}
'@ | Set-Content $ok
            Test-MsixPsfConfig -Path $ok | Should -BeTrue
        }
    }

    Context 'Assert-MsixProcessSuccess' {
        It 'Throws on non-zero exit' {
            $r = [pscustomobject]@{ ExitCode = 1; StdOut = ''; StdErr = 'boom' }
            { Assert-MsixProcessSuccess -Result $r } | Should -Throw '*boom*'
        }
        It 'Stays silent on zero exit' {
            $r = [pscustomobject]@{ ExitCode = 0; StdOut = 'ok'; StdErr = '' }
            { Assert-MsixProcessSuccess -Result $r } | Should -Not -Throw
        }
    }
}
