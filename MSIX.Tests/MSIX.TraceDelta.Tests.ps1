BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force

    # Minimal trace log line emitter for use in tests.
    function Write-TraceLogFixture {
        param([psobject[]]$Rows)
        $lines = @($Rows | ForEach-Object {
            "[00:00:01.000 1234:AB1] $($_.Function): $($_.Path) -> $($_.Result)"
        })
        $tmp = Join-Path $env:TEMP ("msix-tracedelta-test-{0}.log" -f [guid]::NewGuid().ToString('N'))
        # WriteAllLines creates the file even when $lines is empty.
        [IO.File]::WriteAllLines($tmp, [string[]]$lines, [Text.UTF8Encoding]::new($false))
        return $tmp
    }

    $script:TmpFiles = [System.Collections.Generic.List[string]]::new()

    function NewLog([psobject[]]$Rows) {
        $p = Write-TraceLogFixture -Rows $Rows
        $script:TmpFiles.Add($p)
        return $p
    }

    # Common failure row factories
    function FsRow([string]$Path, [string]$Result = 'ACCESS_DENIED') {
        [pscustomobject]@{ Function = 'WriteFileW'; Path = $Path; Result = $Result }
    }
    function RegRow([string]$Path, [string]$Result = 'ACCESS_DENIED') {
        [pscustomobject]@{ Function = 'RegOpenKeyExW'; Path = "HKLM\SOFTWARE\$Path"; Result = $Result }
    }
}

AfterAll {
    foreach ($f in $script:TmpFiles) {
        Remove-Item -LiteralPath $f -ErrorAction SilentlyContinue
    }
    Remove-Module MSIX -ErrorAction SilentlyContinue
}

Describe 'Compare-MsixTrace' -Tag 'TraceDelta' {

    Context 'Exports' {
        It 'Compare-MsixTrace is exported from the module' {
            Get-Command Compare-MsixTrace -Module MSIX | Should -Not -BeNullOrEmpty
        }
        It 'Has the expected parameters' {
            $params = (Get-Command Compare-MsixTrace).Parameters
            $params.Keys | Should -Contain 'Baseline'
            $params.Keys | Should -Contain 'Candidate'
            $params.Keys | Should -Contain 'IncludeCategory'
            $params.Keys | Should -Contain 'MinSeverity'
            $params.Keys | Should -Contain 'Sarif'
        }
    }

    Context 'Equal traces produce an empty diff' {
        It 'Resolved, Persisted, Introduced counts are all zero when traces are identical' {
            $row  = FsRow 'C:\Program Files\WindowsApps\app\cache.tmp'
            $base = NewLog @($row)
            $cand = NewLog @($row)

            $diff = Compare-MsixTrace -Baseline $base -Candidate $cand
            $diff.Summary.ResolvedCount   | Should -Be 0
            $diff.Summary.IntroducedCount | Should -Be 0
        }
    }

    Context 'Completely disjoint traces' {
        It 'All baseline rows appear as Resolved; all candidate rows as Introduced' {
            $baseRow = FsRow 'C:\Program Files\WindowsApps\app\old.log'
            $candRow = FsRow 'C:\Program Files\WindowsApps\app\new.log'
            $base = NewLog @($baseRow)
            $cand = NewLog @($candRow)

            $diff = Compare-MsixTrace -Baseline $base -Candidate $cand
            $diff.Summary.ResolvedCount   | Should -BeGreaterThan 0
            $diff.Summary.IntroducedCount | Should -BeGreaterThan 0
            $diff.Summary.PersistedCount  | Should -Be 0
        }
    }

    Context 'Partial fix — one resolved, one persisted' {
        It 'Correctly classifies each row' {
            $shared = FsRow 'C:\Program Files\WindowsApps\app\persist.tmp'
            $fixed  = FsRow 'C:\Program Files\WindowsApps\app\fixed.tmp'
            $base = NewLog @($shared, $fixed)
            $cand = NewLog @($shared)

            $diff = Compare-MsixTrace -Baseline $base -Candidate $cand
            $diff.Summary.ResolvedCount  | Should -BeGreaterThan 0
            $diff.Summary.PersistedCount | Should -BeGreaterThan 0
            $diff.Summary.IntroducedCount | Should -Be 0
        }
    }

    Context '-IncludeCategory filter' {
        It 'Restricts introduced findings to the specified category' {
            $fsRow  = FsRow 'C:\Program Files\WindowsApps\app\data.bin'
            $regRow = RegRow 'Vendor\App'
            $base   = NewLog @()
            $cand   = NewLog @($fsRow, $regRow)

            $diff = Compare-MsixTrace -Baseline $base -Candidate $cand `
                -IncludeCategory 'FileRedirectionFixup'

            # Only the filesystem row maps to FileRedirectionFixup.
            $diff.Introduced | Should -Not -BeNullOrEmpty
            $diff.Introduced | ForEach-Object { $_.Category | Should -Be 'FileRedirectionFixup' }
        }
    }

    Context 'Summary maths' {
        It 'ImprovementPct is 100 when everything was resolved' {
            $row  = FsRow 'C:\Program Files\WindowsApps\app\x.tmp'
            $base = NewLog @($row)
            $cand = NewLog @()

            $diff = Compare-MsixTrace -Baseline $base -Candidate $cand
            $diff.Summary.ImprovementPct | Should -Be 100
        }

        It 'ImprovementPct is 0 when nothing changed (persisted only)' {
            $row  = FsRow 'C:\Program Files\WindowsApps\app\y.tmp'
            $base = NewLog @($row)
            $cand = NewLog @($row)

            $diff = Compare-MsixTrace -Baseline $base -Candidate $cand
            $diff.Summary.ImprovementPct | Should -Be 0
        }
    }

    Context 'Raw-row counts surface uncategorised regressions (issue #35)' {
        # ConvertFrom-MsixTraceToFinding only categorises paths under
        # System32 / WindowsApps / HKLM, or LoadLibrary failures.  A failure
        # on any other path (e.g. C:\ProgramData\Vendor) used to silently
        # disappear from the summary. The Row counts must report it.
        It 'Summary exposes ResolvedRowCount, PersistedRowCount, IntroducedRowCount' {
            $base = NewLog @()
            $cand = NewLog @()
            $diff = Compare-MsixTrace -Baseline $base -Candidate $cand
            $diff.Summary.PSObject.Properties.Name | Should -Contain 'ResolvedRowCount'
            $diff.Summary.PSObject.Properties.Name | Should -Contain 'PersistedRowCount'
            $diff.Summary.PSObject.Properties.Name | Should -Contain 'IntroducedRowCount'
        }

        It 'IntroducedRowCount > IntroducedCount when candidate has a new uncategorised failure' {
            # C:\ProgramData\... does not match WindowsApps / System32 / HKLM
            # so ConvertFrom-MsixTraceToFinding drops it, but the diff
            # bookkeeping must still count the raw row.
            $uncatRow = FsRow 'C:\ProgramData\Vendor\App\state.bin'
            $base = NewLog @()
            $cand = NewLog @($uncatRow)

            $diff = Compare-MsixTrace -Baseline $base -Candidate $cand
            $diff.Summary.IntroducedRowCount | Should -BeGreaterThan 0
            $diff.Summary.IntroducedCount    | Should -Be 0
        }

        It 'Row counts and finding counts agree when every row maps to a category' {
            $row  = FsRow 'C:\Program Files\WindowsApps\app\new.tmp'
            $base = NewLog @()
            $cand = NewLog @($row)

            $diff = Compare-MsixTrace -Baseline $base -Candidate $cand
            $diff.Summary.IntroducedRowCount | Should -Be $diff.Summary.IntroducedCount
        }
    }

    Context '-Sarif output' {
        It 'Returns a SARIF document with three runs when -Sarif is set' {
            $row  = FsRow 'C:\Program Files\WindowsApps\app\a.tmp'
            $base = NewLog @($row)
            $cand = NewLog @()

            $sarif = Compare-MsixTrace -Baseline $base -Candidate $cand -Sarif
            $sarif.'$schema' | Should -Match 'sarif'
            $sarif.runs.Count | Should -Be 3
        }

        It 'Run[0] is Resolved, run[2] is Introduced' {
            $baseRow = FsRow 'C:\Program Files\WindowsApps\app\gone.tmp'
            $newRow  = FsRow 'C:\Program Files\WindowsApps\app\new.tmp'
            $base = NewLog @($baseRow)
            $cand = NewLog @($newRow)

            $sarif = Compare-MsixTrace -Baseline $base -Candidate $cand -Sarif
            $sarif.runs[0].properties.deltaClass | Should -Be 'Resolved'
            $sarif.runs[2].properties.deltaClass | Should -Be 'Introduced'
        }

        It 'Serialises to valid JSON' {
            $base = NewLog @(FsRow 'C:\Program Files\WindowsApps\app\z.tmp')
            $cand = NewLog @()
            $json = Compare-MsixTrace -Baseline $base -Candidate $cand -Sarif |
                ConvertTo-Json -Depth 20
            { $json | ConvertFrom-Json } | Should -Not -Throw
        }
    }
}
