BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Bulk / fleet analysis
# -----------------------------------------------------------------------------
# The properties that make this usable on a catalogue (or a 13k-package corpus)
# are the ones worth pinning: one bad package must not end the run, results must
# survive a kill, and a resumed run must not redo finished work.
# =============================================================================

Describe 'Invoke-MsixBulkAnalysis contract' -Tag 'Bulk' {

    It 'requires -ReportPath when -Resume is used' {
        # Resume reads the report to know what is done; without one it would
        # silently reprocess everything.
        { Invoke-MsixBulkAnalysis -Path 'C:\nope' -Resume -ErrorAction Stop } |
            Should -Throw '*-Resume needs -ReportPath*'
    }

    It 'fails loudly when no packages match' {
        $empty = Join-Path ([IO.Path]::GetTempPath()) ("bulk-empty-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $empty -Force | Out-Null
        try {
            { Invoke-MsixBulkAnalysis -Path $empty -ErrorAction Stop } | Should -Throw '*No .msix files found*'
        } finally { Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe '_MsixShortNote' -Tag 'Bulk' {

    It 'collapses a multi-line tool error to one capped line' {
        # MakeAppx failures carry its whole stdout; unchecked that makes a
        # scorecard row unreadable.
        $res = InModuleScope MSIX {
            $long = "MakeAppx unpack failed`r`nMicrosoft (R) MakeAppx Tool`r`n" + ('x' * 500)
            $n = _MsixShortNote -Text $long
            [pscustomobject]@{ Text = $n; Lines = @($n -split "`r?`n").Count }
        }
        $res.Lines | Should -Be 1
        $res.Text.Length | Should -BeLessOrEqual 240
        $res.Text | Should -Match 'MakeAppx unpack failed'
    }

    It 'returns empty for empty input' {
        InModuleScope MSIX { _MsixShortNote -Text '' } | Should -BeNullOrEmpty
    }
}

Describe 'Bulk analysis over a real package set' -Tag 'Bulk', 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:Dir = Join-Path ([IO.Path]::GetTempPath()) ("bulk-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        $script:PkgDir = Join-Path $script:Dir 'packages'
        New-Item -ItemType Directory -Path $script:PkgDir -Force | Out-Null

        if ($script:ToolingAvailable) {
            New-MsixTestFixture -OutputPath (Join-Path $script:PkgDir 'one.msix')   | Out-Null
            New-MsixTestFixture -OutputPath (Join-Path $script:PkgDir 'two.msix') -Name 'MSIX.IntegrationTest.Two' | Out-Null
            # A deliberately corrupt package: the run must survive it.
            Set-Content -LiteralPath (Join-Path $script:PkgDir 'corrupt.msix') -Value 'not a package' -Encoding ascii
        }
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'processes every package and is not aborted by a corrupt one' {
        $rows = @(Invoke-MsixBulkAnalysis -Path $script:PkgDir -WarningAction SilentlyContinue)
        $rows.Count | Should -Be 3 -Because 'a corrupt package must produce a row, not end the run'
        @($rows | Where-Object { $_.Verdict -eq 'Error' }).Count | Should -BeGreaterThan 0
        @($rows | Where-Object { $_.Verdict -ne 'Error' }).Count | Should -BeGreaterThan 0
    }

    It 'streams results to the report as it goes' {
        $report = Join-Path $script:Dir 'stream.csv'
        $null = Invoke-MsixBulkAnalysis -Path $script:PkgDir -ReportPath $report -WarningAction SilentlyContinue
        Test-Path -LiteralPath $report | Should -BeTrue
        @(Import-Csv -LiteralPath $report).Count | Should -Be 3
    }

    It 'resume skips work already recorded' {
        $report = Join-Path $script:Dir 'resume.csv'
        $first  = @(Invoke-MsixBulkAnalysis -Path $script:PkgDir -ReportPath $report -WarningAction SilentlyContinue)
        $first.Count | Should -Be 3
        $second = @(Invoke-MsixBulkAnalysis -Path $script:PkgDir -ReportPath $report -Resume -WarningAction SilentlyContinue)
        $second.Count | Should -Be 0 -Because 'a resumed corpus run must not redo finished packages'
    }

    It 'honours -First for a smoke run over a large corpus' {
        $rows = @(Invoke-MsixBulkAnalysis -Path $script:PkgDir -First 1 -WarningAction SilentlyContinue)
        $rows.Count | Should -Be 1
    }

    It 'emits a comparable row shape for every package' {
        $rows = @(Invoke-MsixBulkAnalysis -Path $script:PkgDir -First 1 -WarningAction SilentlyContinue)
        foreach ($n in 'Id','Package','SizeMB','Verdict','Findings','Errors','Warnings','Categories','PlannedFixes','DurationSec','Notes','When') {
            $rows[0].PSObject.Properties.Name | Should -Contain $n
        }
    }

    It 'never reports Clean off an incomplete scan' {
        # An unusable scanner means the report is missing a category; claiming
        # Clean from that is the honesty failure behind #140.
        $verdict = InModuleScope MSIX -Parameters @{ Pkg = (Join-Path $script:PkgDir 'one.msix') } {
            param($Pkg)
            $path = $Pkg
            Mock Invoke-MsixInvestigation {
                [pscustomobject]@{
                    PackagePath = $path
                    Findings    = @([pscustomobject]@{
                        Severity = 'Warning'; Category = 'ScannerError'
                        Symptom = 'x'; Recommendation = 'y'; Evidence = 'z'; AppId = $null
                    })
                }
            }
            (_MsixAnalyseOnePackage -PackagePath $path).Verdict
        }
        $verdict | Should -Be 'Incomplete'
    }
}
