BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Unified evidence model + confidence scoring' -Tag 'Evidence' {

    Context 'Get-MsixFindingConfidence (probabilistic OR math)' {

        It 'Returns 0.0 when there are no evidence items' {
            $f = New-MsixFinding -Category 'X' -Severity 'Info' -Symptom 's' -EvidenceItems @()
            (Get-MsixFindingConfidence -Finding $f) | Should -Be 0.0
        }

        It 'A single weight=0.9 evidence item yields confidence 0.9' {
            $f = New-MsixFinding -Category 'X' -Severity 'Warning' -Symptom 's'
            Add-MsixEvidence -Finding $f -Source 'procmon' | Out-Null
            $f.Confidence | Should -BeGreaterOrEqual 0.89
            $f.Confidence | Should -BeLessOrEqual 0.91
        }

        It 'Three weight=0.5 items yield 1 - 0.5^3 = 0.875' {
            $f = New-MsixFinding -Category 'X' -Severity 'Warning' -Symptom 's'
            Add-MsixEvidence -Finding $f -Source 'pe-strings' | Out-Null
            Add-MsixEvidence -Finding $f -Source 'pe-strings' | Out-Null
            Add-MsixEvidence -Finding $f -Source 'pe-strings' | Out-Null
            $f.Confidence | Should -Be 0.875
        }

        It 'Saturates at 1.0 when one evidence item is weight=1.0' {
            $f = New-MsixFinding -Category 'X' -Severity 'Error' -Symptom 's'
            Add-MsixEvidence -Finding $f -Source 'user-supplied' | Out-Null
            $f.Confidence | Should -Be 1.0
        }

        It 'Clamps out-of-range weights to [0, 1]' {
            $f = New-MsixFinding -Category 'X' -Severity 'Info' -Symptom 's'
            Add-MsixEvidence -Finding $f -Source 'manual' -Weight 5.0 | Out-Null
            $f.Confidence | Should -Be 1.0
            $g = New-MsixFinding -Category 'Y' -Severity 'Info' -Symptom 's'
            Add-MsixEvidence -Finding $g -Source 'manual' -Weight -2 | Out-Null
            $g.Confidence | Should -Be 0.0
        }
    }

    Context 'New-MsixFinding produces the canonical shape' {
        It 'Carries every legacy field plus Confidence + EvidenceItems' {
            $f = New-MsixFinding -Category 'WorkingDirectory' -Severity 'Warning' `
                -Symptom 'Companion files outside cwd' -Recommendation 'Add-MsixPsfV2 ...' `
                -Evidence 'app.ini, settings.cfg' -AppId 'App'
            $f.PSObject.TypeNames | Should -Contain 'MsixFinding'
            $f.Category       | Should -Be 'WorkingDirectory'
            $f.Severity       | Should -Be 'Warning'
            $f.Symptom        | Should -Be 'Companion files outside cwd'
            $f.Recommendation | Should -Be 'Add-MsixPsfV2 ...'
            $f.Evidence       | Should -Be 'app.ini, settings.cfg'
            $f.AppId          | Should -Be 'App'
            $f.Confidence     | Should -Be 0.0
            # EvidenceItems is an empty array, not $null. Check the count
            # directly rather than -BeOfType because PowerShell collapses
            # an empty @() stored on a pscustomobject property to $null
            # for type-introspection purposes.
            @($f.EvidenceItems).Count | Should -Be 0
        }

        It 'Add-MsixEvidence stores per-source properties (Path, Result, ...) verbatim' {
            $f = New-MsixFinding -Category 'X' -Severity 'Error' -Symptom 's'
            Add-MsixEvidence -Finding $f -Source 'procmon' `
                -Properties @{ Path = 'C:\Program Files\App\app.ini'; Result = 'NAME NOT FOUND' } | Out-Null
            $f.EvidenceItems[0].Source | Should -Be 'procmon'
            $f.EvidenceItems[0].Path   | Should -Be 'C:\Program Files\App\app.ini'
            $f.EvidenceItems[0].Result | Should -Be 'NAME NOT FOUND'
        }
    }

    Context 'ConvertTo-MsixFinding (legacy -> evidence)' {

        It 'Wraps a legacy finding with a synthetic evidence item' {
            $legacy = [pscustomobject]@{
                Severity = 'Warning'; Category = 'X'; Symptom = 's'
                Recommendation = 'r'; Evidence = 'e'; AppId = 'App'
            }
            $f = ConvertTo-MsixFinding -Finding $legacy
            $f.PSObject.TypeNames | Should -Contain 'MsixFinding'
            $f.EvidenceItems.Count | Should -Be 1
            $f.EvidenceItems[0].Source | Should -Be 'static-analysis'
            # Warning -> 0.7 default
            $f.Confidence | Should -Be 0.7
        }

        It 'Maps Severity -> default weight (Error=0.95, Warning=0.7, Info=0.4)' {
            $err  = ConvertTo-MsixFinding ([pscustomobject]@{ Severity='Error';   Category='X'; Symptom='s' })
            $wrn  = ConvertTo-MsixFinding ([pscustomobject]@{ Severity='Warning'; Category='X'; Symptom='s' })
            $info = ConvertTo-MsixFinding ([pscustomobject]@{ Severity='Info';    Category='X'; Symptom='s' })
            $err.Confidence  | Should -Be 0.95
            $wrn.Confidence  | Should -Be 0.70
            $info.Confidence | Should -Be 0.40
        }

        It 'Is idempotent — a pre-promoted finding is returned unchanged' {
            $f = New-MsixFinding -Category 'X' -Severity 'Info' -Symptom 's'
            Add-MsixEvidence -Finding $f -Source 'procmon' | Out-Null
            $original = $f.EvidenceItems.Count
            $f2 = ConvertTo-MsixFinding -Finding $f
            $f2.EvidenceItems.Count | Should -Be $original
            $f2 | Should -Be $f
        }
    }

    Context 'Merge-MsixFinding' {

        It 'Collapses two same-Category+AppId findings into one with combined evidence' {
            $a = New-MsixFinding -Category 'InstallDirWrite' -Severity 'Warning' -Symptom 'static says' -AppId 'App'
            Add-MsixEvidence -Finding $a -Source 'static-analysis' -Properties @{ Path = 'cache.tmp' } | Out-Null

            $b = New-MsixFinding -Category 'InstallDirWrite' -Severity 'Error' -Symptom 'procmon says' -AppId 'App'
            Add-MsixEvidence -Finding $b -Source 'procmon' -Properties @{ Path = 'C:\Program Files\app\cache.tmp'; Result = 'ACCESS DENIED' } | Out-Null

            $merged = @(Merge-MsixFinding -Findings @($a, $b))
            $merged.Count | Should -Be 1
            $merged[0].EvidenceItems.Count | Should -Be 2
            # Severity is promoted to the highest (Error beats Warning).
            $merged[0].Severity | Should -Be 'Error'
            # Confidence combines: 1 - (1-0.5)(1-0.9) = 0.95
            $merged[0].Confidence | Should -BeGreaterOrEqual 0.94
        }

        It 'Keeps findings of different Categories separate' {
            $a = New-MsixFinding -Category 'A' -Severity 'Warning' -Symptom 's' -AppId 'App'
            $b = New-MsixFinding -Category 'B' -Severity 'Warning' -Symptom 's' -AppId 'App'
            $merged = @(Merge-MsixFinding -Findings @($a, $b))
            $merged.Count | Should -Be 2
        }

        It 'Keeps findings with different AppIds separate' {
            $a = New-MsixFinding -Category 'X' -Severity 'Warning' -Symptom 's' -AppId 'App1'
            $b = New-MsixFinding -Category 'X' -Severity 'Warning' -Symptom 's' -AppId 'App2'
            $merged = @(Merge-MsixFinding -Findings @($a, $b))
            $merged.Count | Should -Be 2
        }

        It 'Promotes legacy findings on the fly' {
            $legacy = [pscustomobject]@{ Severity='Warning'; Category='X'; Symptom='s'; Recommendation='r'; Evidence='e'; AppId=$null }
            $new    = New-MsixFinding -Category 'X' -Severity 'Warning' -Symptom 's'
            Add-MsixEvidence -Finding $new -Source 'procmon' | Out-Null

            $merged = @(Merge-MsixFinding -Findings @($legacy, $new))
            $merged.Count | Should -Be 1
            $merged[0].EvidenceItems.Count | Should -BeGreaterOrEqual 1
        }
    }

    Context 'ConvertTo-MsixLegacyFinding round-trip' {
        It 'Drops Confidence + EvidenceItems and keeps everything else' {
            $f = New-MsixFinding -Category 'X' -Severity 'Error' -Symptom 's' `
                -Recommendation 'r' -Evidence 'e' -AppId 'App'
            Add-MsixEvidence -Finding $f -Source 'procmon' | Out-Null
            $legacy = ConvertTo-MsixLegacyFinding -Finding $f
            $legacy.PSObject.Properties.Name | Should -Not -Contain 'Confidence'
            $legacy.PSObject.Properties.Name | Should -Not -Contain 'EvidenceItems'
            $legacy.Category | Should -Be 'X'
            $legacy.Severity | Should -Be 'Error'
            $legacy.AppId    | Should -Be 'App'
        }
    }

    Context 'Invoke-MsixAutoFixFromAnalysis -MinConfidence' {
        It 'Exposes the -MinConfidence parameter with default 0.85' {
            $cmd = Get-Command Invoke-MsixAutoFixFromAnalysis -Module MSIX
            $cmd.Parameters.Keys | Should -Contain 'MinConfidence'
            $cmd.Parameters['MinConfidence'].ParameterType.FullName | Should -Be 'System.Double'
        }

        It 'Skips an autofix stage when its finding falls below MinConfidence' {
            # Build a synthetic report with one low-confidence UninstallerArtifact finding.
            $weak = New-MsixFinding -Category 'UninstallerArtifact' -Severity 'Info' -Symptom 's'
            Add-MsixEvidence -Finding $weak -Source 'heuristic' -Weight 0.2 | Out-Null
            $report = [pscustomobject]@{
                PackagePath     = 'C:\nope.msix'
                Findings        = @($weak)
                SuggestedFixups = @()
            }
            # Default threshold (0.85) — should NOT emit the stage.
            $r1 = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
            ($r1.Plan | Where-Object Stage -eq 'RemoveUninstallers' | Measure-Object).Count | Should -Be 0

            # With threshold lowered to 0.0, the stage fires.
            $r2 = Invoke-MsixAutoFixFromAnalysis -Report $report -MinConfidence 0.0 -DryRun
            ($r2.Plan | Where-Object Stage -eq 'RemoveUninstallers' | Measure-Object).Count | Should -Be 1
        }

        It 'Pre-evidence (legacy) findings are NOT gated out' {
            # Legacy finding with no EvidenceItems must still fire (no regression).
            $legacy = [pscustomobject]@{
                Severity = 'Info'; Category = 'UninstallerArtifact'; Symptom = 's'
                Recommendation = 'r'; Evidence = 'e'; AppId = $null
            }
            $report = [pscustomobject]@{
                PackagePath     = 'C:\nope.msix'
                Findings        = @($legacy)
                SuggestedFixups = @()
            }
            $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
            ($r.Plan | Where-Object Stage -eq 'RemoveUninstallers' | Measure-Object).Count | Should -Be 1
        }
    }

    Context 'SARIF integration' {
        It 'Surfaces evidence + confidence in result.properties' {
            $f = New-MsixFinding -Category 'X' -Severity 'Warning' -Symptom 's' -AppId 'App'
            Add-MsixEvidence -Finding $f -Source 'procmon' -Properties @{ Path = '/etc/foo' } | Out-Null
            $sarif = ConvertTo-MsixSarif -Findings @($f) -PackagePath 'C:\nope.msix'
            $result = $sarif.runs[0].results[0]
            $result.properties.confidence    | Should -BeGreaterOrEqual 0.89
            $result.properties.evidenceItems | Should -Not -BeNullOrEmpty
            $result.properties.evidenceItems[0].Source | Should -Be 'procmon'
        }
    }
}
