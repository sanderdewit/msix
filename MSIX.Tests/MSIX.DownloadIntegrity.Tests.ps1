BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Regression coverage for #55 — download hash-pinning and thumbprint pinning.
# Both controls are opt-in (empty by default) so the module works out of the
# box; these tests exercise the enforcement paths when they ARE configured.

Describe 'Download hash pinning (#55)' -Tag 'Security', 'PsfBinaries' {

    It '_MsixDownloadFile accepts a file whose SHA-256 matches' {
        InModuleScope MSIX -Parameters @{ Dir = $TestDrive } {
            param($Dir)
            $dest = Join-Path $Dir 'ok.bin'
            # Mock the network: write known bytes to the destination.
            Mock Invoke-WebRequest { Set-Content -LiteralPath $Destination -Value 'payload' -NoNewline -Encoding ascii }
            $expected = (Get-FileHash -InputStream ([IO.MemoryStream]::new([Text.Encoding]::ASCII.GetBytes('payload'))) -Algorithm SHA256).Hash
            { _MsixDownloadFile -Url 'https://example/x' -Destination $dest -ExpectedSha256 $expected } | Should -Not -Throw
            Test-Path -LiteralPath $dest | Should -BeTrue
        }
    }

    It '_MsixDownloadFile rejects and deletes a file whose SHA-256 mismatches' {
        InModuleScope MSIX -Parameters @{ Dir = $TestDrive } {
            param($Dir)
            $dest = Join-Path $Dir 'bad.bin'
            Mock Invoke-WebRequest { Set-Content -LiteralPath $Destination -Value 'tampered' -NoNewline -Encoding ascii }
            $wrong = ('0' * 64)
            { _MsixDownloadFile -Url 'https://example/x' -Destination $dest -ExpectedSha256 $wrong } |
                Should -Throw -ExpectedMessage '*SHA-256 mismatch*'
            # The rejected download must not be left on disk.
            Test-Path -LiteralPath $dest | Should -BeFalse
        }
    }

    It '_MsixDownloadFile skips the check when no hash is supplied (out-of-box behavior)' {
        InModuleScope MSIX -Parameters @{ Dir = $TestDrive } {
            param($Dir)
            $dest = Join-Path $Dir 'nohash.bin'
            Mock Invoke-WebRequest { Set-Content -LiteralPath $Destination -Value 'anything' -NoNewline -Encoding ascii }
            { _MsixDownloadFile -Url 'https://example/x' -Destination $dest } | Should -Not -Throw
            Test-Path -LiteralPath $dest | Should -BeTrue
        }
    }

    It 'Install-MsixMgr exposes an -ExpectedSha256 parameter defaulting to the known-hash constant' {
        (Get-Command Install-MsixMgr -Module MSIX).Parameters.ContainsKey('ExpectedSha256') | Should -BeTrue
    }

    It 'ships with the msixmgr known-hash constant empty so installs work out of the box' {
        InModuleScope MSIX { $script:MsixMgrKnownSha256 } | Should -BeNullOrEmpty
    }
}

Describe 'Trusted-publisher thumbprint pinning (#55)' -Tag 'Security', 'PsfBinaries' {

    BeforeAll {
        # _MsixLoadTrustedPublishers mutates module-level $script:MsixTrustedThumbprints
        # as a side effect; snapshot it so these tests don't leave a test thumbprint
        # pinned (which would break real Authenticode checks later in the session).
        $script:savedThumbprints = InModuleScope MSIX { $script:MsixTrustedThumbprints }
    }
    AfterAll {
        InModuleScope MSIX -Parameters @{ Saved = $script:savedThumbprints } {
            param($Saved)
            $script:MsixTrustedThumbprints = $Saved
        }
    }

    It 'loader accepts an entry with a valid 40-hex thumbprint and records it' {
        $json = @'
{ "publishers": [ { "subjectPrefix": "CN=Contoso,", "thumbprint": "AABBCCDDEEFF00112233445566778899AABBCCDD" } ] }
'@
        $p = Join-Path $TestDrive 'signers-ok.json'
        Set-Content -LiteralPath $p -Value $json -Encoding utf8
        InModuleScope MSIX -Parameters @{ P = $p } {
            param($P)
            $prefixes = _MsixLoadTrustedPublishers -Path $P
            $prefixes | Should -Contain 'CN=Contoso,'
            $script:MsixTrustedThumbprints | Should -Contain 'AABBCCDDEEFF00112233445566778899AABBCCDD'
        }
    }

    It 'loader rejects an entry with a malformed thumbprint' {
        $json = '{ "publishers": [ { "subjectPrefix": "CN=Contoso,", "thumbprint": "not-a-thumbprint" } ] }'
        $p = Join-Path $TestDrive 'signers-bad.json'
        Set-Content -LiteralPath $p -Value $json -Encoding utf8
        # Reference $P at the top level of the block (not only inside a nested
        # { } scriptblock) so PSScriptAnalyzer's PSReviewUnusedParameter sees it.
        $err = InModuleScope MSIX -Parameters @{ P = $p } {
            param($P)
            try { $null = _MsixLoadTrustedPublishers -Path $P; $null } catch { $_ }
        }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -BeLike '*thumbprint*'
    }

    It 'loader still works with no thumbprint (opt-in; prefix-only entry)' {
        $json = '{ "publishers": [ { "subjectPrefix": "CN=Contoso," } ] }'
        $p = Join-Path $TestDrive 'signers-noprefix.json'
        Set-Content -LiteralPath $p -Value $json -Encoding utf8
        $prefixes = InModuleScope MSIX -Parameters @{ P = $p } {
            param($P)
            _MsixLoadTrustedPublishers -Path $P
        }
        $prefixes | Should -Contain 'CN=Contoso,'
    }
}
