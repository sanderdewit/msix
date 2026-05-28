BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    # Issue #38: heuristics split into MSIX.Scanners.ps1, MSIX.PackageMutators.ps1,
    # and MSIX.AutoFix.ps1. The source-level guards downstream operate over the
    # union of the three files; concatenate so the assertions don't have to know
    # which split a given function lives in.
    $script:HeuristicsPaths = @(
        'MSIX.Scanners.ps1','MSIX.PackageMutators.ps1','MSIX.AutoFix.ps1'
    ) | ForEach-Object { (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath "..\$_")).Path }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Updater artefact detection + removal' -Tag 'Updaters' {

    Context 'Public surface' {

        It 'Get-MsixUpdaterCandidate is exported and takes -PackagePath' {
            $cmd = Get-Command Get-MsixUpdaterCandidate -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.Parameters.ContainsKey('PackagePath') | Should -BeTrue
        }

        It 'Remove-MsixUpdaterArtifact is exported with the expected parameters' {
            $cmd = Get-Command Remove-MsixUpdaterArtifact -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            foreach ($p in 'PackagePath','PathPatterns','OutputPath','SkipSigning','Pfx','PfxPassword','UnsignedOutputPath') {
                $cmd.Parameters.ContainsKey($p) | Should -BeTrue -Because "parameter '$p' should exist"
            }
            # -NoSign alias
            $cmd.Parameters['SkipSigning'].Aliases | Should -Contain 'NoSign'
        }

        It 'Plural alias Get-MsixUpdaterCandidates resolves to the singular' {
            $a = Get-Alias Get-MsixUpdaterCandidates -ErrorAction SilentlyContinue
            $a | Should -Not -BeNullOrEmpty
            $a.Definition | Should -Be 'Get-MsixUpdaterCandidate'
        }
    }

    Context 'Invoke-MsixAutoFix wiring' {

        It 'PrePsf:RemoveUpdaters stage shows up in a DryRun plan' {
            $result = Invoke-MsixAutoFix -PackagePath 'C:\nope.msix' -RemoveUpdaters -DryRun
            $result.DryRun | Should -BeTrue
            $result.Stages | Should -Contain 'PrePsf:RemoveUpdaters'
        }

        It 'Without -RemoveUpdaters the stage does not appear' {
            $result = Invoke-MsixAutoFix -PackagePath 'C:\nope.msix' -DryRun
            $result.Stages | Should -Not -Contain 'PrePsf:RemoveUpdaters'
        }
    }

    Context 'Invoke-MsixAutoFixFromAnalysis wiring' {

        It 'Synthetic UpdaterArtifact finding produces a RemoveUpdaters stage' {
            $report = [pscustomobject]@{
                PackagePath = 'C:\nope.msix'
                Findings    = @(
                    [pscustomobject]@{
                        Severity = 'Info'
                        Category = 'UpdaterArtifact'
                        Symptom  = 'Auto-updater detected: FooUpdater.exe (Binary)'
                        Recommendation = "Remove-MsixUpdaterArtifact -PackagePath 'C:\nope.msix'"
                        Evidence = 'VFS\ProgramFilesX64\Foo\FooUpdater.exe'
                        AppId    = $null
                    }
                )
                SuggestedFixups = @()
            }
            $result = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
            $stages = @($result.Plan | Select-Object -ExpandProperty Stage)
            $stages | Should -Contain 'RemoveUpdaters'
        }

        It '-IgnoreUpdaters omits the stage even when findings are present' {
            $report = [pscustomobject]@{
                PackagePath = 'C:\nope.msix'
                Findings    = @(
                    [pscustomobject]@{
                        Severity = 'Info'
                        Category = 'UpdaterArtifact'
                        Symptom  = 'Auto-updater detected: FooUpdater.exe (Binary)'
                        Recommendation = "Remove-MsixUpdaterArtifact -PackagePath 'C:\nope.msix'"
                        Evidence = 'VFS\ProgramFilesX64\Foo\FooUpdater.exe'
                        AppId    = $null
                    }
                )
                SuggestedFixups = @()
            }
            $result = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun -IgnoreUpdaters
            $stages = @($result.Plan | Select-Object -ExpandProperty Stage)
            $stages | Should -Not -Contain 'RemoveUpdaters'
        }
    }

    Context 'Source-level regression guard' {

        BeforeAll {
            # Concatenate all three post-#38 source files so the assertions
            # below stay agnostic to which split a function landed in.
            $script:src = ($script:HeuristicsPaths | ForEach-Object {
                Get-Content -Raw -LiteralPath $_
            }) -join "`n"
        }

        It 'Get-MsixUpdaterCandidate is defined in the heuristics family' {
            $script:src | Should -Match 'function\s+Get-MsixUpdaterCandidate'
        }

        It 'Remove-MsixUpdaterArtifact is defined in the heuristics family' {
            $script:src | Should -Match 'function\s+Remove-MsixUpdaterArtifact'
        }

        It 'Invoke-MsixAutoFix has a PrePsf:RemoveUpdaters stage wired' {
            $script:src | Should -Match "PrePsf:RemoveUpdaters"
        }

        It 'Invoke-MsixAutoFixFromAnalysis has a RemoveUpdaters stage wired' {
            $script:src | Should -Match "Stage\s*=\s*'RemoveUpdaters'"
        }

        It 'IgnoreUpdaters switch is in the param block' {
            $script:src | Should -Match '\[switch\]\$IgnoreUpdaters'
        }
    }
}
