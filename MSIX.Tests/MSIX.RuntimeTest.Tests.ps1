BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')

    function script:ConvertTo-TestSecureString {
        [OutputType([SecureString])]
        param([Parameter(Mandatory)][string]$Value)
        $secure = [System.Security.SecureString]::new()
        foreach ($char in $Value.ToCharArray()) { $secure.AppendChar($char) }
        $secure.MakeReadOnly()
        return $secure
    }

    # Mock replies keyed on the phase marker in ArgumentList[0]:
    # 'install' / 'probe' / 'cleanup'.
    function script:New-RtInstall { param([bool]$Ok, [string]$Err, [int]$Mods = 0) [pscustomobject]@{ Installed = $Ok; PackageFullName = if ($Ok) { 'App_1.0.0.0_x64__abc' } else { $null }; ModificationsInstalled = $Mods; Error = $Err } }
    function script:New-RtProbe   { param([bool]$Alive, [bool]$Crash, [object]$Window, [string[]]$Events) [pscustomobject]@{ Launched = $true; ProcessAlive = $Alive; WindowAppeared = $Window; CrashDetected = $Crash; Events = @($Events); Error = $null } }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Runtime deployment test loop — orchestration unit tests (mocked VM seam).
# The real Hyper-V path is exercised manually (TEST-PLAN Scenario 14); here we
# mock _MsixInvokeInVM / _MsixCopyToVM / _MsixRestoreVMCheckpoint so the
# install/launch/probe/verdict logic is deterministically testable.
# =============================================================================

Describe 'Test-MsixDeployment verdict logic (mocked VM)' -Tag 'RuntimeTest' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-rt-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        if ($script:ToolingAvailable) {
            $script:Fixture = (New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'rt.msix')).PackagePath
        }
        $script:Cred = [pscredential]::new('vmadmin', (ConvertTo-TestSecureString 'x'))
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx (fixture) not available.' }
    }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'passes when install + launch + liveness succeed and no crash is seen' {
        Mock -ModuleName MSIX _MsixCopyToVM {}
        Mock -ModuleName MSIX _MsixInvokeInVM {
            param($ArgumentList)
            if ($ArgumentList[0] -eq 'install') { return New-RtInstall -Ok $true }
            if ($ArgumentList[0] -eq 'probe') { return New-RtProbe -Alive $true -Crash $false -Window $null -Events @() }
            return $null
        }
        $r = Test-MsixDeployment -PackagePath $script:Fixture -VMName 'vm' -Credential $script:Cred
        $r.Passed          | Should -BeTrue
        $r.Installed       | Should -BeTrue
        $r.ProcessAlive    | Should -BeTrue
        $r.PackageFullName | Should -Be 'App_1.0.0.0_x64__abc'
        $r.Reasons.Count   | Should -Be 0
    }

    It 'fails (with reason) when Add-AppxPackage fails, and does not probe' {
        Mock -ModuleName MSIX _MsixCopyToVM {}
        Mock -ModuleName MSIX _MsixInvokeInVM { New-RtInstall -Ok $false -Err '0x80073CF3 dependency missing' }
        $r = Test-MsixDeployment -PackagePath $script:Fixture -VMName 'vm' -Credential $script:Cred
        $r.Passed    | Should -BeFalse
        $r.Installed | Should -BeFalse
        ($r.Reasons -join ' ') | Should -Match '0x80073CF3'
        Should -Invoke -ModuleName MSIX _MsixInvokeInVM -Times 1
    }

    It 'fails when the process is not alive after settle' {
        Mock -ModuleName MSIX _MsixCopyToVM {}
        Mock -ModuleName MSIX _MsixInvokeInVM {
            param($ArgumentList)
            if ($ArgumentList[0] -eq 'install') { return New-RtInstall -Ok $true }
            if ($ArgumentList[0] -eq 'probe') { return New-RtProbe -Alive $false -Crash $false -Window $null -Events @() }
            return $null
        }
        $r = Test-MsixDeployment -PackagePath $script:Fixture -VMName 'vm' -Credential $script:Cred -SettleSeconds 1
        $r.Passed | Should -BeFalse
        ($r.Reasons -join ' ') | Should -Match 'process alive'
    }

    It 'fails and surfaces event artifacts when WER records a crash' {
        Mock -ModuleName MSIX _MsixCopyToVM {}
        Mock -ModuleName MSIX _MsixInvokeInVM {
            param($ArgumentList)
            if ($ArgumentList[0] -eq 'install') { return New-RtInstall -Ok $true }
            if ($ArgumentList[0] -eq 'probe') { return New-RtProbe -Alive $false -Crash $true -Window $null -Events @('2026 [WER] app.exe faulted') }
            return $null
        }
        $r = Test-MsixDeployment -PackagePath $script:Fixture -VMName 'vm' -Credential $script:Cred -SettleSeconds 1
        $r.Passed            | Should -BeFalse
        $r.CrashDetected     | Should -BeTrue
        $r.EventLogArtifacts | Should -Contain '2026 [WER] app.exe faulted'
    }

    It 'restores the checkpoint before the run when -Checkpoint is given' {
        Mock -ModuleName MSIX _MsixCopyToVM {}
        Mock -ModuleName MSIX _MsixRestoreVMCheckpoint {}
        Mock -ModuleName MSIX _MsixInvokeInVM {
            param($ArgumentList)
            if ($ArgumentList[0] -eq 'install') { return New-RtInstall -Ok $true }
            if ($ArgumentList[0] -eq 'probe') { return New-RtProbe -Alive $true -Crash $false -Window $null -Events @() }
            return $null
        }
        Test-MsixDeployment -PackagePath $script:Fixture -VMName 'vm' -Credential $script:Cred -Checkpoint 'clean' | Out-Null
        Should -Invoke -ModuleName MSIX _MsixRestoreVMCheckpoint -Times 2
    }

    It 'installs modification packages after the main package (#131)' {
        Mock -ModuleName MSIX _MsixCopyToVM {}
        Mock -ModuleName MSIX _MsixInvokeInVM {
            param($ArgumentList)
            if ($ArgumentList[0] -eq 'install') {
                # The install call must carry the staged modification paths.
                @($ArgumentList[4]).Count | Should -Be 2
                return New-RtInstall -Ok $true -Mods 2
            }
            if ($ArgumentList[0] -eq 'probe') { return New-RtProbe -Alive $true -Crash $false -Window $null -Events @() }
            return $null
        }
        $mod1 = Join-Path $script:Dir 'settings.msix';  Set-Content -LiteralPath $mod1 -Value 'stub' -Encoding ascii
        $mod2 = Join-Path $script:Dir 'plugins.msix';   Set-Content -LiteralPath $mod2 -Value 'stub' -Encoding ascii
        $r = Test-MsixDeployment -PackagePath $script:Fixture -VMName 'vm' -Credential $script:Cred `
                -ModificationPackagePaths $mod1, $mod2
        $r.Passed                 | Should -BeTrue
        $r.ModificationsInstalled | Should -Be 2
        # main pkg + 2 mods copied in
        Should -Invoke -ModuleName MSIX _MsixCopyToVM -Times 3
    }
    It 'requires a window only when -RequireWindow is set' {
        Mock -ModuleName MSIX _MsixCopyToVM {}
        Mock -ModuleName MSIX _MsixInvokeInVM {
            param($ArgumentList)
            if ($ArgumentList[0] -eq 'install') { return New-RtInstall -Ok $true }
            if ($ArgumentList[0] -eq 'probe') { return New-RtProbe -Alive $true -Crash $false -Window $false -Events @() }
            return $null
        }
        (Test-MsixDeployment -PackagePath $script:Fixture -VMName 'vm' -Credential $script:Cred).Passed | Should -BeTrue
        $r2 = Test-MsixDeployment -PackagePath $script:Fixture -VMName 'vm' -Credential $script:Cred -RequireWindow
        $r2.Passed | Should -BeFalse
        ($r2.Reasons -join ' ') | Should -Match 'window'
    }
}
