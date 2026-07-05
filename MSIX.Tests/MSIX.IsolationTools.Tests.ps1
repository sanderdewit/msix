BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Isolation tooling features (issues #103-#106) + the Invoke-MsixSelfSign rename
# =============================================================================

Describe 'Remove-MsixPsf (issue #103, real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:PsfAvailable = $false
        if ($script:ToolingAvailable) {
            $tr = & (Get-Module MSIX) { Get-MsixToolsRoot }
            $script:PsfAvailable = [bool](Test-Path -LiteralPath (Join-Path -Path $tr -ChildPath 'psf\PsfLauncher64.exe'))
        }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-rmpsf-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' }
        elseif (-not $script:PsfAvailable) { Set-ItResult -Skipped -Because 'PSF binaries not available.' }
    }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'round-trips: Add-MsixPsfV2 then Remove-MsixPsf restores the real executable' {
        $fx   = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'base.msix')
        $psf  = Join-Path $script:Dir 'psf.msix'
        $back = Join-Path $script:Dir 'stripped.msix'

        [xml]$orig = Get-MsixManifest -Path $fx.PackagePath
        $origExe = $orig.Package.Applications.Application.Executable

        $frf = New-MsixPsfFileRedirectionConfig -Base 'VFS/ProgramFilesX64/App/' -Patterns '.*\.log'
        Add-MsixPsfV2 -PackagePath $fx.PackagePath -Fixups @($frf) -OutputPath $psf -SkipSigning
        [xml]$mid = Get-MsixManifest -Path $psf
        $mid.Package.Applications.Application.Executable | Should -Match 'PsfLauncher' -Because 'precondition: PSF injected'

        Remove-MsixPsf -PackagePath $psf -OutputPath $back -SkipSigning
        [xml]$after = Get-MsixManifest -Path $back
        $after.Package.Applications.Application.Executable | Should -Be $origExe
    }

    It 'the stripped package carries no PSF payload and can then be isolated' {
        $back = Join-Path $script:Dir 'stripped.msix'
        Test-Path -LiteralPath $back | Should -BeTrue -Because 'previous test produced it'

        # No config.json / PsfLauncher left inside.
        $names = & (Get-Module MSIX) {
            param($pkg)
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $zip = [IO.Compression.ZipFile]::OpenRead($pkg)
            try { $zip.Entries.FullName } finally { $zip.Dispose() }
        } $back
        ($names | Where-Object { $_ -match 'PsfLauncher|PsfRuntime|config\.json|Fixup' }) | Should -BeNullOrEmpty

        # And Add-MsixAppIsolation now accepts it (the PSF blocker is gone).
        $iso = Join-Path $script:Dir 'stripped-iso.msix'
        { Add-MsixAppIsolation -PackagePath $back -OutputPath $iso -SkipSigning } | Should -Not -Throw
        (Test-MsixIsolation -PackagePath $iso).WouldIsolate | Should -BeTrue
    }

    It 'is a no-op (with message, no output package churn) on a PSF-free package' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'clean.msix')
        $info = Remove-MsixPsf -PackagePath $fx.PackagePath -SkipSigning 6>&1 | Out-String
        $info | Should -Match 'No PSF payload found'
    }
}

Describe 'Add-MsixAppIsolation -RemoveComServer (issue #104, real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-rmcom-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'strips the comServer + context-menu verbs and produces an isolating package' {
        $pkg = Join-Path $script:Dir 'base.msix'
        $ctx = Join-Path $script:Dir 'ctx.msix'
        $out = Join-Path $script:Dir 'iso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg
        Add-MsixLegacyContextMenu -PackagePath $fx.PackagePath `
            -ShellExtDll 'VFS\ProgramFilesX64\App\Shell.dll' `
            -Clsid '11112222-3333-4444-5555-666677778888' -DisplayName 'Ctx' -FileTypes '*' `
            -OutputPath $ctx -SkipSigning

        # Without the switch: still throws (guidance now names the switch).
        { Add-MsixAppIsolation -PackagePath $ctx -OutputPath $out -SkipSigning -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*RemoveComServer*'

        # With the switch: packs, and every COM/context-menu trace is gone.
        Add-MsixAppIsolation -PackagePath $ctx -RemoveComServer -OutputPath $out -SkipSigning
        [xml]$m = Get-MsixManifest -Path $out
        $m.SelectSingleNode("//*[local-name()='Extension' and @Category='windows.comServer']") | Should -BeNullOrEmpty
        $m.SelectSingleNode("//*[local-name()='Extension' and @Category='windows.fileExplorerContextMenus']") | Should -BeNullOrEmpty

        $status = Test-MsixIsolation -PackagePath $out
        $status.WouldIsolate | Should -BeTrue
        $status.Mode | Should -Be 'AppContainer'
    }
}

Describe 'Test-MsixIsolation (issue #105)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-tiso-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'static: a plain full-trust package would NOT isolate, with reasons' {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.'; return }
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'plain.msix')
        $s  = Test-MsixIsolation -PackagePath $fx.PackagePath
        $s.WouldIsolate | Should -BeFalse
        $s.Mode | Should -Be 'None'
        $s.HasRunFullTrust | Should -BeTrue
        @($s.Reasons).Count | Should -BeGreaterThan 0
    }

    It 'static: an Add-MsixAppIsolation output WOULD isolate' {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.'; return }
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'plain2.msix')
        $iso = Join-Path $script:Dir 'iso.msix'
        Add-MsixAppIsolation -PackagePath $fx.PackagePath -OutputPath $iso -SkipSigning
        $s = Test-MsixIsolation -PackagePath $iso
        $s.WouldIsolate | Should -BeTrue
        $s.Mode | Should -Be 'AppContainer'
        $s.EntryPoint | Should -Be 'Windows.PartialTrustApplication'
        $s.HasRunFullTrust | Should -BeFalse
    }

    It 'runtime: the current (non-packaged) process is not an AppContainer' {
        $r = Test-MsixIsolation -ProcessId $PID
        $r.IsAppContainer | Should -BeFalse
        $r.Isolated | Should -BeFalse
        $r.IntegrityLevel | Should -BeIn @('Medium', 'High')
        $r.AppContainerSid | Should -BeNullOrEmpty
    }
}

Describe 'Get-MsixIsolationAdvice (issue #106)' -Tag 'IsolationAdvice' {

    BeforeAll {
        # Synthetic ProcMon-failure rows (the shape Get-MsixProcMonFailure emits).
        $script:Rows = @(
            [pscustomobject]@{ 'Process Name' = 'app.exe'; Operation = 'CreateFile';   Path = 'C:\Users\u\Documents\report.docx'; Result = 'ACCESS DENIED' }
            [pscustomobject]@{ 'Process Name' = 'app.exe'; Operation = 'CreateFile';   Path = 'C:\Users\u\Documents\other.docx';  Result = 'ACCESS DENIED' }
            [pscustomobject]@{ 'Process Name' = 'app.exe'; Operation = 'TCP Connect';  Path = 'host:443';                          Result = 'ACCESS DENIED' }
            [pscustomobject]@{ 'Process Name' = 'app.exe'; Operation = 'RegSetValue';  Path = 'HKLM\SOFTWARE\Vendor\Key';          Result = 'ACCESS DENIED' }
            [pscustomobject]@{ 'Process Name' = 'app.exe'; Operation = 'CreateFile';   Path = 'C:\ProgramData\VendorId\cfg.json';  Result = 'ACCESS DENIED' }
            [pscustomobject]@{ 'Process Name' = 'app.exe'; Operation = 'CreateFile';   Path = 'C:\Windows\ok.txt';                 Result = 'SUCCESS' }
        )
    }

    It 'maps user-profile denials to the AppSilo prompt broker' {
        $advice = $script:Rows | Get-MsixIsolationAdvice -Mode AppSilo
        $profileAdvice = $advice | Where-Object SuggestedCapability -eq 'isolatedWin32-promptForAccess'
        $profileAdvice | Should -Not -BeNullOrEmpty
        $profileAdvice.Hits | Should -Be 2
        $profileAdvice.ExamplePaths | Should -Contain 'C:\Users\u\Documents\report.docx'
    }

    It 'maps network denials to the mode-appropriate capability' {
        ($script:Rows | Get-MsixIsolationAdvice -Mode AppSilo    | Where-Object { $_.SuggestedCapability -eq 'isolatedWin32-internetClient' }) | Should -Not -BeNullOrEmpty
        ($script:Rows | Get-MsixIsolationAdvice -Mode AppContainer | Where-Object { $_.SuggestedCapability -eq 'internetClient' }) | Should -Not -BeNullOrEmpty
    }

    It 'flags HKLM writes as unisolatable (no capability) and ProgramData as publisher-directory' {
        $advice = $script:Rows | Get-MsixIsolationAdvice
        ($advice | Where-Object { $_.SuggestedCapability -like '*HKLM*' }).Rationale | Should -Match 'code change'
        ($advice | Where-Object { $_.SuggestedCapability -eq 'isolatedWin32-accessToPublisherDirectory' }) | Should -Not -BeNullOrEmpty
    }

    It 'ignores SUCCESS rows and reports nothing when no denials exist' {
        $ok = @([pscustomobject]@{ Operation = 'CreateFile'; Path = 'C:\x'; Result = 'SUCCESS' })
        $info = $ok | Get-MsixIsolationAdvice 6>&1 | Out-String
        $info | Should -Match 'No ACCESS DENIED rows'
    }
}

Describe 'Invoke-MsixSelfSign rename' -Tag 'ModuleContract' {
    It 'exports the new name as a function and the old name as an alias' {
        (Get-Command Invoke-MsixSelfSign -Module MSIX).CommandType | Should -Be 'Function'
        $alias = Get-Command Invoke-MsixSelfSignAndDebug -ErrorAction Stop
        $alias.CommandType | Should -Be 'Alias'
        $alias.Definition  | Should -Be 'Invoke-MsixSelfSign'
    }
}
