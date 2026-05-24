BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Issue #28: registry cleanup + idempotent ManifestFix detection' -Tag 'Issue28' {

    Context 'Recursive offline-hive deletion' {

        It '_MsixOfflineDeleteKeyRecursive is defined inside the module' {
            # The helper is module-internal so Get-Command -Module won't surface
            # it from the outside; invoke via the module's session state.
            & (Get-Module MSIX) {
                Get-Command -Name '_MsixOfflineDeleteKeyRecursive' -ErrorAction SilentlyContinue
            } | Should -Not -BeNullOrEmpty
        }

        It 'Deletes a subtree with children — the case where bare ORDeleteKey fails' {
            $hivePath = Join-Path $env:TEMP "msix-issue28-recdel-$([guid]::NewGuid().ToString('N').Substring(0,8)).dat"
            try {
                & (Get-Module MSIX) {
                    # ($hivePath isn't needed inside — the test asserts in-memory
                    # state via _MsixOfflineOpenKey rather than persisting & re-loading.)
                    $h = _MsixCreateOfflineHive
                    try {
                        # Build Uninstall\App\Components\Foo and ...\Bar.
                        $a = _MsixOfflineCreateKey -Parent $h -SubKey 'Uninstall'
                        try {
                            $b = _MsixOfflineCreateKey -Parent $a -SubKey 'App'
                            try {
                                _MsixOfflineSetValueString -Key $b -Name 'DisplayName' -Value 'TheApp'
                                $c = _MsixOfflineCreateKey -Parent $b -SubKey 'Components'
                                try {
                                    $d = _MsixOfflineCreateKey -Parent $c -SubKey 'Foo'
                                    _MsixOfflineCloseKey -Key $d
                                    $e = _MsixOfflineCreateKey -Parent $c -SubKey 'Bar'
                                    _MsixOfflineCloseKey -Key $e
                                } finally { _MsixOfflineCloseKey -Key $c }
                            } finally { _MsixOfflineCloseKey -Key $b }
                        } finally { _MsixOfflineCloseKey -Key $a }

                        # Non-recursive should FAIL (key has children).
                        $bareOk = _MsixOfflineDeleteKey -Parent $h -SubKey 'Uninstall\App'
                        if ($bareOk) { throw "Setup invalid: bare ORDeleteKey unexpectedly succeeded on a key with children." }

                        # Recursive should SUCCEED and the key should be gone.
                        $recOk = _MsixOfflineDeleteKeyRecursive -Parent $h -SubKey 'Uninstall\App'
                        if (-not $recOk) { throw "_MsixOfflineDeleteKeyRecursive returned false." }
                        $stillThere = _MsixOfflineOpenKey -Parent $h -SubKey 'Uninstall\App'
                        if ($stillThere -ne [IntPtr]::Zero) {
                            _MsixOfflineCloseKey -Key $stillThere
                            throw 'Uninstall\App still exists after recursive delete.'
                        }
                    } finally {
                        _MsixCloseOfflineHive -Hive $h
                    }
                }
            } finally {
                if (Test-Path $hivePath) { Remove-Item -LiteralPath $hivePath -Force -ErrorAction SilentlyContinue }
            }
        }

        It 'Returns $true (no-op) when deleting a subkey that does not exist' {
            $hivePath = Join-Path $env:TEMP "msix-issue28-noexist-$([guid]::NewGuid().ToString('N').Substring(0,8)).dat"
            try {
                $result = & (Get-Module MSIX) {
                    $h = _MsixCreateOfflineHive
                    try {
                        return (_MsixOfflineDeleteKeyRecursive -Parent $h -SubKey 'Does\Not\Exist')
                    } finally {
                        _MsixCloseOfflineHive -Hive $h
                    }
                }
                $result | Should -BeTrue
            } finally {
                if (Test-Path $hivePath) { Remove-Item -LiteralPath $hivePath -Force -ErrorAction SilentlyContinue }
            }
        }

        It 'Remove-MsixUninstallerArtifact source calls the recursive helper' {
            # Issue #38: function moved from MSIX.Heuristics.ps1 to MSIX.PackageMutators.ps1.
            $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.PackageMutators.ps1')) -Raw
            $idx = $src.IndexOf('function Remove-MsixUninstallerArtifact')
            $nextIdx = $src.IndexOf("`nfunction ", $idx + 1)
            if ($nextIdx -lt 0) { $nextIdx = $src.Length }
            $body = $src.Substring($idx, $nextIdx - $idx)
            $body | Should -Match '_MsixOfflineDeleteKeyRecursive'
        }
    }

    Context 'Legacy shell registry cleanup (issue #28 duplicate menus)' {

        It 'Remove-MsixShellRegistryArtifact is exported' {
            $cmd = Get-Command Remove-MsixShellRegistryArtifact -Module MSIX -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
        }

        It 'Invoke-MsixAutoFixFromAnalysis adds the StripLegacyShellRegistry stage after AddLegacyContextMenu' {
            $report = [pscustomobject]@{
                PackagePath = 'C:\nope.msix'
                Findings = @(
                    [pscustomobject]@{
                        Severity = 'Error'
                        Category = 'ShellExt'
                        Symptom  = 'Legacy shellex handler in Registry.dat.'
                        Recommendation = ''
                        Evidence = ''
                        AppId    = $null
                        ShellEntries = @(
                            [pscustomobject]@{
                                Type        = 'ShellExt'
                                Target      = '*'
                                HandlerName = 'NppShell'
                                Clsid       = 'b298d29a-a6ed-11de-ba8c-a68e55d89593'
                                DllPath     = 'C:\anything'
                                VfsDllPath  = 'VFS\ProgramFilesX64\App\Shell.dll'
                            }
                        )
                    }
                )
                SuggestedFixups = @()
            }
            $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
            $addStage   = @($r.Plan | Where-Object Stage -eq 'AddLegacyContextMenu')      | Select-Object -First 1
            $stripStage = @($r.Plan | Where-Object Stage -eq 'StripLegacyShellRegistry') | Select-Object -First 1
            $addStage   | Should -Not -BeNullOrEmpty
            $stripStage | Should -Not -BeNullOrEmpty
            # Strip stage MUST come after the manifest declaration stage.
            $planNames = @($r.Plan.Stage)
            ($planNames.IndexOf('StripLegacyShellRegistry')) | Should -BeGreaterThan ($planNames.IndexOf('AddLegacyContextMenu'))
        }

        It 'StripLegacyShellRegistry stage is omitted when there are no ShellExt findings' {
            $report = [pscustomobject]@{
                PackagePath = 'C:\nope.msix'
                Findings    = @(
                    [pscustomobject]@{ Category = 'VcRuntime'; Severity = 'Warning'; Symptom = '.'; Recommendation = '.'; Evidence = '.'; AppId = $null }
                )
                SuggestedFixups = @()
            }
            $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
            ($r.Plan | Where-Object Stage -eq 'StripLegacyShellRegistry' | Measure-Object).Count | Should -Be 0
        }
    }

    Context 'Get-MsixStaticAnalysis idempotent ManifestFix detection' {

        It 'Source guards the FileSystemWriteVirtualization finding with -not $hasFsVirt' {
            $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.Investigation.ps1')) -Raw
            # The writable-file emission must be wrapped in an if (-not $hasFsVirt) block
            # so packages that already declare the desktop6 element don't get the noise.
            $src | Should -Match 'if \(-not \$hasFsVirt\)'
            $src | Should -Match "local-name\(\)='FileSystemWriteVirtualization'"
        }

        It 'Source guards the manifest-alternative entries the same way' {
            $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.Investigation.ps1')) -Raw
            # Both alternatives must be suppressed when the corresponding fix
            # is already in <Properties>. Single-quoted regex so PowerShell
            # doesn''t expand the literal $hasFsVirt / $hasRegVirt tokens.
            ($src -match '(?s)if \(-not \$hasFsVirt\).*?Set-MsixFileSystemWriteVirtualization') | Should -BeTrue
            ($src -match '(?s)if \(-not \$hasRegVirt\).*?Set-MsixRegistryWriteVirtualization') | Should -BeTrue
        }
    }
}
