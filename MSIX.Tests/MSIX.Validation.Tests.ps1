BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    $script:Tmp = Join-Path -Path $env:TEMP -ChildPath "msix-validate-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item $script:Tmp -ItemType Directory -Force | Out-Null
}

AfterAll {
    Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Module MSIX -ErrorAction SilentlyContinue
}

Describe 'Validation' -Tag 'Validation' {

    Context 'Test-MsixManifest' {
        It 'Throws when file does not exist' {
            { Test-MsixManifest -Path 'C:\nope\does\not\exist.xml' } | Should -Throw
        }

        It 'Throws on malformed XML' {
            $bad = Join-Path -Path $script:Tmp -ChildPath 'bad.xml'
            'not xml' | Set-Content -LiteralPath $bad
            { Test-MsixManifest -Path $bad } | Should -Throw '*not valid XML*'
        }

        It 'Throws when Identity is missing required fields' {
            $broken = Join-Path -Path $script:Tmp -ChildPath 'broken.xml'
            @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="App" />
  <Applications><Application Id="A" Executable="x.exe" /></Applications>
</Package>
'@ | Set-Content -LiteralPath $broken
            { Test-MsixManifest -Path $broken } | Should -Throw '*Publisher*'
        }

        It 'Throws when Applications is empty' {
            $noapp = Join-Path -Path $script:Tmp -ChildPath 'noapp.xml'
            @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="A" Publisher="CN=X" Version="1.0.0.0" />
</Package>
'@ | Set-Content -LiteralPath $noapp
            { Test-MsixManifest -Path $noapp } | Should -Throw '*Application*'
        }

        It 'Returns true for a complete manifest' {
            $ok = Join-Path -Path $script:Tmp -ChildPath 'ok.xml'
            @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="A" Publisher="CN=X" Version="1.0.0.0" />
  <Applications><Application Id="A" Executable="x.exe" /></Applications>
</Package>
'@ | Set-Content -LiteralPath $ok
            Test-MsixManifest -Path $ok | Should -BeTrue
        }
    }

    Context 'Test-MsixPsfConfig' {
        It 'Throws on missing keys' {
            $bad = Join-Path -Path $script:Tmp -ChildPath 'badcfg.json'
            '{}' | Set-Content -LiteralPath $bad
            { Test-MsixPsfConfig -Path $bad } | Should -Throw '*applications*'
        }
        It 'Accepts a valid PSF config' {
            $ok = Join-Path -Path $script:Tmp -ChildPath 'okcfg.json'
            @'
{
  "applications": [{ "id": "App", "executable": "x.exe" }],
  "processes":    [{ "executable": "x" }]
}
'@ | Set-Content -LiteralPath $ok
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
