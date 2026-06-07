BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Behavioural tests for the auto-fix planner (MSIX.AutoFix.ps1):
# Invoke-MsixAutoFixFromAnalysis turns an analysis report into an ordered plan
# of remediation stages. These were previously scattered across the
# issue/version-named files MSIX.v0_11 and MSIX.Issue28 (see issue #88).

Describe 'Invoke-MsixAutoFixFromAnalysis planner' -Tag 'AutoFix' {

    It 'returns an empty plan when there are no findings' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @()
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun
        $r.Plan.Count | Should -Be 0
    }

    It 'Plans RemoveUninstallers when an UninstallerArtifact finding exists' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Warning'; Category='UninstallerArtifact'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun
        $r.Plan.Stage | Should -Contain 'RemoveUninstallers'
    }

    It 'Plans manifest fixes from ManifestFix:* findings' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:FileSystemWriteVirtualization'; Symptom='x'; Recommendation='y'; Evidence='z' }
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:RegistryWriteVirtualization';   Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun
        $r.Plan.Stage | Should -Contain 'FileSystemWriteVirtualization'
        $r.Plan.Stage | Should -Contain 'RegistryWriteVirtualization'
    }

    It 'Skips PSF when -PreferManifestOverPsf and a manifest fix covers the same symptom' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:FileSystemWriteVirtualization'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' )
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun -PreferManifestOverPsf $true
        $r.Plan.Stage | Should -Not -Contain 'InjectPsf'
    }

    It 'Includes PSF when -PreferManifestOverPsf $false' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:FileSystemWriteVirtualization'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' )
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun -PreferManifestOverPsf $false
        $r.Plan.Stage | Should -Contain 'InjectPsf'
    }

    It 'Skips StartupTask when -StartupTaskAppId / -StartupTaskName missing' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:StartupTask'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun
        $r.Plan.Stage | Should -Not -Contain 'StartupTask'
    }

    It 'Plans StartupTask when params supplied' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:StartupTask'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun `
            -StartupTaskAppId 'App' -StartupTaskName 'Demo'
        $r.Plan.Stage | Should -Contain 'StartupTask'
    }
}

Describe 'Invoke-MsixAutoFixFromAnalysis: StripLegacyShellRegistry stage' -Tag 'AutoFix' {

    It 'Remove-MsixShellRegistryArtifact is exported' {
        $cmd = Get-Command Remove-MsixShellRegistryArtifact -Module MSIX -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
    }

    It 'adds the StripLegacyShellRegistry stage after AddLegacyContextMenu' {
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

    It 'omits the StripLegacyShellRegistry stage when there are no ShellExt findings' {
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
