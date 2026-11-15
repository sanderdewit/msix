BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    $script:SignersJsonPath = (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\signers.json')).Path
    $script:SignersSchemaPath = Join-Path -Path $PSScriptRoot -ChildPath '..\signers.schema.json'
    $script:SignersDoc      = Get-Content -LiteralPath $script:SignersJsonPath -Raw | ConvertFrom-Json
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Trusted-publisher allowlist (issue #19)' -Tag 'TrustedPublishers' {

    Context 'signers.json layout' {

        It 'signers.json ships at the module root' {
            Test-Path -LiteralPath $script:SignersJsonPath | Should -BeTrue
        }

        It 'declares a local schema that ships with the module' {
            $script:SignersDoc.'$schema' | Should -Be './signers.schema.json'
            Test-Path -LiteralPath $script:SignersSchemaPath | Should -BeTrue
            { Get-Content -LiteralPath $script:SignersSchemaPath -Raw | ConvertFrom-Json } |
                Should -Not -Throw
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
            $bad = Join-Path -Path $env:TEMP -ChildPath "bad-signers-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
            '{ "publishers": ' | Out-File -LiteralPath $bad -Encoding utf8   # truncated
            try {
                { (Get-Module MSIX).Invoke({ param($p) _MsixLoadTrustedPublishers -Path $p }, $bad) } |
                    Should -Throw
            } finally {
                Remove-Item -LiteralPath $bad -Force -ErrorAction SilentlyContinue
            }
        }

        It '_MsixLoadTrustedPublishers throws on a missing file' {
            $missing = Join-Path -Path $env:TEMP -ChildPath "no-such-signers-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
            { (Get-Module MSIX).Invoke({ param($p) _MsixLoadTrustedPublishers -Path $p }, $missing) } |
                Should -Throw
        }

        It '_MsixLoadTrustedPublishers throws when an entry lacks CN=...,' {
            $bad = Join-Path -Path $env:TEMP -ChildPath "rogue-signers-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
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

    Context 'Windows SDK BuildTools signers' {
        # BuildTools 10.0.26100.9457 and 10.0.28000.2957 (2026-10-28) sign
        # appxsip.dll - x64 and x86 - with CN=Microsoft Windows Kits Publisher.
        # Observed leaf: 2C3BD48A6836D6CEBAC6FFB4A972A0A69B5D6B49, chained to
        # Microsoft Root Certificate Authority 2010 via Microsoft Windows Code
        # Signing PCA 2024 (the intermediate of the CN=Microsoft Corporation
        # certs on signtool/MakeAppx in the same package). Without the entry
        # every unpinned Install-MsixSdkTool rolled back.

        BeforeAll {
            $script:KitsProbe = Join-Path -Path $TestDrive -ChildPath 'appxsip.dll'
            Set-Content -LiteralPath $script:KitsProbe -Value 'stub' -Encoding ascii
        }

        It 'lists CN=Microsoft Windows Kits Publisher, with its audit trail' {
            $entry = @($script:SignersDoc.publishers | Where-Object { $_.subjectPrefix -eq 'CN=Microsoft Windows Kits Publisher,' })
            $entry.Count | Should -Be 1
            $entry[0].addedBy | Should -Not -BeNullOrEmpty
            $entry[0].addedAt | Should -Match '^\d{4}-\d{2}-\d{2}$'
        }

        It 'accepts the exact Subject Microsoft signs appxsip.dll with' {
            $threw = InModuleScope MSIX -Parameters @{ Probe = $script:KitsProbe } {
                param($Probe)
                $path = $Probe
                Mock Write-MsixLog {}
                Mock Get-AuthenticodeSignature {
                    [pscustomobject]@{
                        Status            = 'Valid'
                        StatusMessage     = 'Signature verified.'
                        SignerCertificate = [pscustomobject]@{
                            Subject    = 'CN=Microsoft Windows Kits Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
                            Thumbprint = '2C3BD48A6836D6CEBAC6FFB4A972A0A69B5D6B49'
                        }
                    }
                }
                try { $null = _MsixVerifyAuthenticode -Path $path -ToolName 'appxsip.dll'; $false } catch { $true }
            }
            $threw | Should -BeFalse
        }

        It 'does not trust a longer common name that merely starts with it' {
            $err = InModuleScope MSIX -Parameters @{ Probe = $script:KitsProbe } {
                param($Probe)
                $path = $Probe
                Mock Get-AuthenticodeSignature {
                    [pscustomobject]@{
                        Status            = 'Valid'
                        StatusMessage     = 'Signature verified.'
                        SignerCertificate = [pscustomobject]@{
                            Subject    = 'CN=Microsoft Windows Kits Publisher Test, O=Contoso, C=US'
                            Thumbprint = '0000000000000000000000000000000000000000'
                        }
                    }
                }
                try { $null = _MsixVerifyAuthenticode -Path $path -ToolName 'appxsip.dll'; $null } catch { $_ }
            }
            $err | Should -Not -BeNullOrEmpty
            $err.Exception.Message | Should -BeLike '*NOT in the trusted-publisher allowlist*'
            $err.Exception.Data['MsixAuthenticodeReason'] | Should -Be 'UntrustedPublisher'
        }
    }
}
