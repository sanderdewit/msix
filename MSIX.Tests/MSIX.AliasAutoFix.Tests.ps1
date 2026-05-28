BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'AppExecutionAlias autofix stage' -Tag 'AutoFix' {

    It 'Invoke-MsixAutoFix exposes the -AddAliases switch and -AliasAppIds parameter' {
        $cmd = Get-Command Invoke-MsixAutoFix -Module MSIX
        $cmd.Parameters.Keys | Should -Contain 'AddAliases'
        $cmd.Parameters.Keys | Should -Contain 'AliasAppIds'
        $cmd.Parameters['AddAliases'].ParameterType.FullName | Should -Be 'System.Management.Automation.SwitchParameter'
        $cmd.Parameters['AliasAppIds'].ParameterType.FullName | Should -Be 'System.String[]'
    }

    It 'Invoke-MsixAutoFix -DryRun lists the AddAliases stage when -AddAliases is set' {
        # We pass a path that does not need to exist — DryRun short-circuits before any IO.
        $r = Invoke-MsixAutoFix -PackagePath 'C:\nope.msix' -AddAliases -DryRun
        $r.Stages | Should -Contain 'Recommended:AddAliases'
        $r.DryRun | Should -BeTrue
    }

    It 'Invoke-MsixAutoFix -DryRun lists AddAliases when only -AliasAppIds is supplied' {
        $r = Invoke-MsixAutoFix -PackagePath 'C:\nope.msix' -AliasAppIds 'App','Worker' -DryRun
        $r.Stages | Should -Contain 'Recommended:AddAliases'
    }

    It 'Invoke-MsixAutoFix -DryRun omits the stage when neither switch is set' {
        $r = Invoke-MsixAutoFix -PackagePath 'C:\nope.msix' -RemoveUninstallers -DryRun
        ($r.Stages -contains 'Recommended:AddAliases') | Should -BeFalse
    }

    It 'Invoke-MsixAutoFixFromAnalysis adds AddAliases stage for AppExecutionAlias findings' {
        $report = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{
                    Severity       = 'Info'
                    Category       = 'AppExecutionAlias'
                    Symptom        = 'App has no AppExecutionAlias.'
                    Recommendation = 'Add-MsixAlias …'
                    Evidence       = 'app.exe'
                    AppId          = 'App'
                }
                [pscustomobject]@{
                    Severity       = 'Info'
                    Category       = 'AppExecutionAlias'
                    Symptom        = 'Worker has no AppExecutionAlias.'
                    Recommendation = 'Add-MsixAlias …'
                    Evidence       = 'worker.exe'
                    AppId          = 'Worker'
                }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
        $aliasStage = @($r.Plan | Where-Object Stage -eq 'AddAliases') | Select-Object -First 1
        $aliasStage | Should -Not -BeNullOrEmpty
        $aliasStage.Reason | Should -Match 'App'
        $aliasStage.Reason | Should -Match 'Worker'
    }

    It 'Invoke-MsixAutoFixFromAnalysis skips AddAliases when no AppExecutionAlias findings exist' {
        $report = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Category = 'VcRuntime'; Severity = 'Warning'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'z'; AppId = $null }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
        ($r.Plan | Where-Object Stage -eq 'AddAliases' | Measure-Object).Count | Should -Be 0
    }

    It 'Invoke-MsixAutoFixFromAnalysis deduplicates AppIds across findings' {
        $report = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Category = 'AppExecutionAlias'; Severity = 'Info'; Symptom = '.'; Recommendation = '.'; Evidence = '.'; AppId = 'App' }
                [pscustomobject]@{ Category = 'AppExecutionAlias'; Severity = 'Info'; Symptom = '.'; Recommendation = '.'; Evidence = '.'; AppId = 'App' }
                [pscustomobject]@{ Category = 'AppExecutionAlias'; Severity = 'Info'; Symptom = '.'; Recommendation = '.'; Evidence = '.'; AppId = $null }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
        $stage = @($r.Plan | Where-Object Stage -eq 'AddAliases') | Select-Object -First 1
        $stage | Should -Not -BeNullOrEmpty
        # Only one AppId after dedup + null filter.
        ($stage.Reason -split ':')[-1].Trim() | Should -Be 'App'
    }
}
