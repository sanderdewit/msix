BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    $script:SignersJsonPath = (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\signers.json')).Path
    $script:SignersDoc      = Get-Content -LiteralPath $script:SignersJsonPath -Raw | ConvertFrom-Json
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Trusted-publisher allowlist (issue #19)' -Tag 'TrustedPublishers' {

    Context 'signers.json layout' {

        It 'signers.json ships at the module root' {
            Test-Path -LiteralPath $script:SignersJsonPath | Should -BeTrue
        }

        It 'declares a numeric version' {
            # ConvertFrom-Json yields [long] on PS7 and [int] on PS5.1 — both
            # are valid integer types for our purposes.
            ($script:SignersDoc.version -is [int] -or $script:SignersDoc.version -is [long]) |
                Should -BeTrue
            $script:SignersDoc.version | Should -BeGreaterOrEqual 1
        }

        It 'declares a non-empty publishers array' {
            @($script:SignersDoc.publishers).Count | Should -BeGreaterThan 0
        }

        It 'every entry has a subjectPrefix and a description' {
            foreach ($e in $script:SignersDoc.publishers) {
                $e.subjectPrefix | Should -Not -BeNullOrEmpty
                $e.description   | Should -Not -BeNullOrEmpty
            }
        }

        It 'every subjectPrefix matches the X.509 form CN=...,' {
            # Standard X.509 Subject prefix: must start with the CN= attribute
            # (case-sensitive in the leaf-cert match) and must end with the
            # ',' separator so '-like "$prefix*"' in _MsixVerifyAuthenticode
            # cannot accidentally match a longer common-name (e.g.
            # "CN=Microsoft Corp Test" against "CN=Microsoft Corp,").
            $rx = [regex]'^CN=.+,$'
            foreach ($e in $script:SignersDoc.publishers) {
                $rx.IsMatch($e.subjectPrefix) | Should -BeTrue -Because "subjectPrefix '$($e.subjectPrefix)' must match ^CN=.+,$"
            }
        }

        It 'subjectPrefix values are unique' {
            $prefixes = @($script:SignersDoc.publishers | ForEach-Object subjectPrefix)
            ($prefixes | Sort-Object -Unique).Count | Should -Be $prefixes.Count
        }
    }

    Context 'Runtime load' {

        It '$script:MsixTrustedPublishers in MSIX module matches signers.json' {
            $loaded   = (Get-Module MSIX).Invoke({ $script:MsixTrustedPublishers })
            $expected = $script:SignersDoc.publishers | ForEach-Object subjectPrefix
            $loadedJoined   = (@($loaded)   | Sort-Object) -join '|'
            $expectedJoined = (@($expected) | Sort-Object) -join '|'
            $loadedJoined | Should -Be $expectedJoined
        }

        It '_MsixLoadTrustedPublishers throws on a malformed JSON file' {
            $bad = Join-Path $env:TEMP "bad-signers-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
            '{ "publishers": ' | Out-File -LiteralPath $bad -Encoding utf8   # truncated
            try {
                { (Get-Module MSIX).Invoke({ param($p) _MsixLoadTrustedPublishers -Path $p }, $bad) } |
                    Should -Throw
            } finally {
                Remove-Item -LiteralPath $bad -Force -ErrorAction SilentlyContinue
            }
        }

        It '_MsixLoadTrustedPublishers throws on a missing file' {
            $missing = Join-Path $env:TEMP "no-such-signers-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
            { (Get-Module MSIX).Invoke({ param($p) _MsixLoadTrustedPublishers -Path $p }, $missing) } |
                Should -Throw
        }

        It '_MsixLoadTrustedPublishers throws when an entry lacks CN=...,' {
            $bad = Join-Path $env:TEMP "rogue-signers-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
            @'
{
  "version": 1,
  "publishers": [
    { "subjectPrefix": "O=Some Org", "description": "missing CN= prefix" }
  ]
}
'@ | Out-File -LiteralPath $bad -Encoding utf8
            try {
                { (Get-Module MSIX).Invoke({ param($p) _MsixLoadTrustedPublishers -Path $p }, $bad) } |
                    Should -Throw -ExpectedMessage '*X.509 form*'
            } finally {
                Remove-Item -LiteralPath $bad -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
