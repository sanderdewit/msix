BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    # Builds a fake tools root on disk so _MsixSetVerifiedToolsRoot enumerates
    # real files (it scans the folder rather than probing three fixed names).
    function script:New-FakeToolsRoot {
        param([string[]]$Files = @('signtool.exe', 'MakeAppx.exe', 'makepri.exe'))
        $root = Join-Path ([IO.Path]::GetTempPath()) ("toolsroot-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        $tools = Join-Path $root 'Tools'
        New-Item -ItemType Directory -Path $tools -Force | Out-Null
        foreach ($f in $Files) { Set-Content -LiteralPath (Join-Path $tools $f) -Value 'stub' -Encoding ascii }
        $root
    }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Regression coverage for #54 — Get-MsixToolsRoot must Authenticode-verify the
# resolved toolchain (fail-closed) before trusting/executing it, with an
# MSIX_SKIP_TOOL_VERIFICATION escape hatch for offline agents.
#
# Extended for #147: verification now covers EVERY .exe/.dll in the resolved
# root, not just signtool/MakeAppx/makepri. SDK signtool.exe is SxS-bound to
# load wintrust.dll / mssign32.dll / AppxSip.dll from its OWN directory, so
# checking only the three named executables let an attacker keep those genuine
# and plant a trojaned dependency DLL beside them.

Describe '_MsixSetVerifiedToolsRoot (#54, #147)' -Tag 'Toolchain', 'Security' {

    AfterEach {
        Remove-Item Env:\MSIX_SKIP_TOOL_VERIFICATION -ErrorAction SilentlyContinue
        InModuleScope MSIX { $script:ToolsRoot = $null }
    }

    It 'verifies the resolved tools and caches the root on success' {
        $root = New-FakeToolsRoot
        try {
            $result = InModuleScope MSIX -Parameters @{ Root = $root } {
                param($Root)
                $script:verified = @()
                Mock _MsixVerifyAuthenticode { $script:verified += $Path }
                $r = _MsixSetVerifiedToolsRoot -Root $Root
                [pscustomobject]@{ Returned = $r; Cached = $script:ToolsRoot; Verified = @($script:verified) }
            }
            $result.Returned | Should -Be $root
            $result.Cached   | Should -Be $root
            @($result.Verified).Count | Should -BeGreaterThan 0
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'verifies SxS dependency DLLs beside signtool, not just the named executables (#147)' {
        # The hijack: genuine signed .exe files plus a planted wintrust.dll.
        $root = New-FakeToolsRoot -Files @('signtool.exe', 'MakeAppx.exe', 'makepri.exe', 'wintrust.dll', 'mssign32.dll')
        try {
            $verified = InModuleScope MSIX -Parameters @{ Root = $root } {
                param($Root)
                $script:verified = @()
                Mock _MsixVerifyAuthenticode { $script:verified += $Path }
                $null = _MsixSetVerifiedToolsRoot -Root $Root
                @($script:verified)
            }
            ($verified | Where-Object { $_ -like '*wintrust.dll' })  | Should -Not -BeNullOrEmpty
            ($verified | Where-Object { $_ -like '*mssign32.dll' })  | Should -Not -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'is fail-closed: a verification failure propagates and the root is NOT cached' {
        $root = New-FakeToolsRoot
        try {
            InModuleScope MSIX -Parameters @{ Root = $root } {
                param($Root)
                Mock _MsixVerifyAuthenticode { throw 'Authenticode verification FAILED (planted binary)' }
                { _MsixSetVerifiedToolsRoot -Root $Root } | Should -Throw '*Authenticode verification FAILED*'
                $script:ToolsRoot | Should -BeNullOrEmpty
            }
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'refuses a tools root containing no verifiable payload (#147)' {
        $root = New-FakeToolsRoot -Files @()
        try {
            InModuleScope MSIX -Parameters @{ Root = $root } {
                param($Root)
                Mock _MsixVerifyAuthenticode {}
                { _MsixSetVerifiedToolsRoot -Root $Root } | Should -Throw '*no .exe/.dll found*'
                $script:ToolsRoot | Should -BeNullOrEmpty
            }
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'bypasses verification when MSIX_SKIP_TOOL_VERIFICATION is set (offline escape hatch)' {
        $env:MSIX_SKIP_TOOL_VERIFICATION = '1'
        $result = InModuleScope MSIX {
            $script:verifyCalled = $false
            Mock _MsixVerifyAuthenticode { $script:verifyCalled = $true }
            Mock Write-Warning {}
            $r = _MsixSetVerifiedToolsRoot -Root 'C:\offline\root'
            [pscustomobject]@{ Returned = $r; Cached = $script:ToolsRoot; VerifyCalled = $script:verifyCalled }
        }
        $result.Returned     | Should -Be 'C:\offline\root'
        $result.Cached       | Should -Be 'C:\offline\root'
        $result.VerifyCalled | Should -BeFalse
    }

    It 'announces the bypass on the real Warning stream, not only the module log (#147)' {
        # Write-MsixLog routes to Write-Information: invisible to -WarningVariable
        # and dropped entirely under Set-MsixLogLevel -Level Error. Disabling the
        # control that protects signing must not be silenceable.
        $env:MSIX_SKIP_TOOL_VERIFICATION = '1'
        $warned = InModuleScope MSIX {
            $script:warnings = @()
            Mock Write-Warning { $script:warnings += $Message }
            $null = _MsixSetVerifiedToolsRoot -Root 'C:\offline\root'
            @($script:warnings)
        }
        @($warned).Count | Should -BeGreaterThan 0
        $warned -join ' ' | Should -Match 'BYPASS'
    }
}

Describe 'Secret redaction in the exec log (#148)' -Tag 'Security' {

    It 'never writes the value following /p to the log' {
        # Invoke-MsixProcess logs the full argument vector at Debug, and
        # Write-MsixLog also appends to the file set by Set-MsixLogFile - so the
        # documented troubleshooting flow wrote the PFX password to disk.
        # Run a real, harmless process so the genuine logging path executes
        # (cmd.exe /c exit ignores the trailing arguments).
        $line = InModuleScope MSIX {
            $script:logged = @()
            Mock Write-MsixLog { $script:logged += $Message }
            $null = Invoke-MsixProcess -FilePath $env:ComSpec `
                        -ArgumentList @('/c', 'exit', '/p', 'SuperSecret123!')
            ($script:logged | Where-Object { $_ -like 'Exec:*' }) -join "`n"
        }
        $line | Should -Not -Match 'SuperSecret123'
        $line | Should -Match 'REDACTED'
    }
}
