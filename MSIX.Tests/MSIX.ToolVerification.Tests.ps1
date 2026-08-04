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
                # Bind to a local first: PSSA does not trace usage into the
                # nested scriptblock handed to Should -Throw.
                $rootPath = $Root
                Mock _MsixVerifyAuthenticode { throw 'Authenticode verification FAILED (planted binary)' }
                { _MsixSetVerifiedToolsRoot -Root $rootPath } | Should -Throw '*Authenticode verification FAILED*'
                $script:ToolsRoot | Should -BeNullOrEmpty
            }
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'tolerates the unsigned binaries Microsoft ships in real SDK layouts (#147)' {
        # Verifying EVERY file was tried first and is not viable: the real Windows
        # SDK bin\x64 ships 9 unsigned binaries (gamesaveutil.exe, SirepClient.dll,
        # WinAppDeployCmd.exe, ...) and the NuGet BuildTools layout ships 5. A
        # blanket check rejects every legitimate SDK install, so verification is
        # scoped to the tools we execute plus signtool's SxS load surface.
        $root = New-FakeToolsRoot -Files @('signtool.exe', 'MakeAppx.exe', 'gamesaveutil.exe', 'SirepClient.dll')
        try {
            $verified = InModuleScope MSIX -Parameters @{ Root = $root } {
                param($Root)
                $script:verified = @()
                Mock _MsixVerifyAuthenticode {
                    if ($ToolName -in 'gamesaveutil.exe', 'SirepClient.dll') {
                        throw "Authenticode verification FAILED for $ToolName. Status: NotSigned."
                    }
                    $script:verified += $Path
                }
                $null = _MsixSetVerifiedToolsRoot -Root $Root
                @($script:verified)
            }
            ($verified | Where-Object { $_ -like '*signtool.exe' }) | Should -Not -BeNullOrEmpty
            ($verified | Where-Object { $_ -like '*gamesaveutil*' }) | Should -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'refuses a tools root containing no verifiable payload (#147)' {
        $root = New-FakeToolsRoot -Files @()
        try {
            InModuleScope MSIX -Parameters @{ Root = $root } {
                param($Root)
                $rootPath = $Root
                Mock _MsixVerifyAuthenticode {}
                { _MsixSetVerifiedToolsRoot -Root $rootPath } | Should -Throw '*none of signtool.exe*'
                $script:ToolsRoot | Should -BeNullOrEmpty
            }
        } finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'bypasses verification for the offline escape hatch (machine-scoped)' {
        # The bypass is only honoured at MACHINE scope now (#147), which needs
        # admin rights to set - so the gate is mocked rather than setting a real
        # machine-wide variable from a test.
        $result = InModuleScope MSIX {
            $script:verifyCalled = $false
            Mock _MsixIsToolVerificationBypassed { $true }
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
        $warned = InModuleScope MSIX {
            $script:warnings = @()
            Mock _MsixIsToolVerificationBypassed { $true }
            Mock Write-Warning { $script:warnings += $Message }
            $null = _MsixSetVerifiedToolsRoot -Root 'C:\offline\root'
            @($script:warnings)
        }
        @($warned).Count | Should -BeGreaterThan 0
        $warned -join ' ' | Should -Match 'BYPASS'
    }
}

Describe 'Verification bypass requires MACHINE scope (#147)' -Tag 'Security' {

    AfterEach { Remove-Item Env:\MSIX_SKIP_TOOL_VERIFICATION -ErrorAction SilentlyContinue }

    It 'offers a session-scoped opt-out that needs no administrator rights' {
        # The module must not require admin. Set-MsixToolVerification is the
        # supported escape hatch for an air-gapped agent: in-memory, so it cannot
        # be planted for a future session the way an env var can.
        try {
            Set-MsixToolVerification -Enabled $false -WarningAction SilentlyContinue
            InModuleScope MSIX { _MsixIsToolVerificationBypassed } | Should -BeTrue
        } finally {
            Set-MsixToolVerification -Enabled $true
        }
        InModuleScope MSIX { _MsixIsToolVerificationBypassed } | Should -BeFalse
    }

    It 'does not persist the session opt-out across a module re-import' {
        Set-MsixToolVerification -Enabled $false -WarningAction SilentlyContinue
        Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
        InModuleScope MSIX { _MsixIsToolVerificationBypassed } | Should -BeFalse
    }

    It 'ignores a process/user-scoped MSIX_SKIP_TOOL_VERIFICATION' {
        # A non-admin could persist this in HKCU\Environment; combined with
        # MSIX_TOOLS_PATH that was full control of what the organisation signs.
        # The escape hatch is an administrative decision about a build machine,
        # so it must be made with administrative rights.
        $env:MSIX_SKIP_TOOL_VERIFICATION = '1'
        $bypassed = InModuleScope MSIX {
            Mock Write-Warning {}
            _MsixIsToolVerificationBypassed
        }
        $bypassed | Should -BeFalse
    }

    It 'says loudly that a process-scoped value is being ignored' {
        $env:MSIX_SKIP_TOOL_VERIFICATION = '1'
        $warned = InModuleScope MSIX {
            $script:warnings = @()
            Mock Write-Warning { $script:warnings += $Message }
            $null = _MsixIsToolVerificationBypassed
            @($script:warnings)
        }
        ($warned -join ' ') | Should -Match 'IGNORED'
    }

    It 'still verifies the toolchain when only a process-scoped value is set' {
        $env:MSIX_SKIP_TOOL_VERIFICATION = '1'
        $root = New-FakeToolsRoot
        try {
            $verified = InModuleScope MSIX -Parameters @{ Root = $root } {
                param($Root)
                $script:verified = @()
                Mock Write-Warning {}
                Mock _MsixVerifyAuthenticode { $script:verified += $Path }
                $null = _MsixSetVerifiedToolsRoot -Root $Root
                @($script:verified)
            }
            @($verified).Count | Should -BeGreaterThan 0
        } finally {
            InModuleScope MSIX { $script:ToolsRoot = $null }
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Helper executables are verified before execution (#147)' -Tag 'Security' {

    It 'refuses an untrusted binary planted via MSIX_PROCMON_PATH' {
        # ProcMon needs its kernel driver, so it runs ELEVATED. The old resolver
        # returned whatever the (user-settable) override pointed at, and also had
        # a fixed 'C:\PSF\ProcessMonitor\Procmon.exe' fallback under a directory
        # any standard user can create - a local privilege-escalation path.
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("plant-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $planted = Join-Path $dir 'Procmon.exe'
        [IO.File]::WriteAllBytes($planted, [byte[]]@(0x4D,0x5A,0x90,0x00))
        try {
            $env:MSIX_PROCMON_PATH = $planted
            $resolved = Resolve-MsixProcMonPath -WarningAction SilentlyContinue
            $resolved | Should -Not -Be $planted
        } finally {
            Remove-Item Env:\MSIX_PROCMON_PATH -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'accepts a genuinely signed executable' {
        $ok = InModuleScope MSIX {
            _MsixTestTrustedExecutable -Path "$env:WINDIR\System32\where.exe" -ToolName 'probe'
        }
        $ok | Should -BeTrue
    }

    It 'returns false (not throw) for an untrusted candidate so resolution can continue' {
        $res = InModuleScope MSIX {
            $f = Join-Path ([IO.Path]::GetTempPath()) ("unsigned-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.exe')
            [IO.File]::WriteAllBytes($f, [byte[]]@(0x4D,0x5A))
            try { _MsixTestTrustedExecutable -Path $f -ToolName 'probe' }
            finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        }
        $res | Should -BeFalse
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
