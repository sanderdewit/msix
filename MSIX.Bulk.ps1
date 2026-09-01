# =============================================================================
# Bulk / fleet analysis
# -----------------------------------------------------------------------------
# The module's unit of work was one package. A packaging team's unit of work is
# a CATALOGUE - "we have 200 apps to migrate, which ones break and which can you
# fix?". Answering that with a foreach around Invoke-MsixInvestigation does not
# work in practice:
#
#   * one corrupt package aborts the whole run;
#   * nothing is written until the end, so a crash at package 180 loses 180
#     results;
#   * there is no way to resume, and a 13,000-package corpus takes days;
#   * there is no aggregate a lead can act on.
#
# This provides the fleet layer: isolated per package, streamed to disk as it
# goes, resumable, and ending in a rollup. The same cmdlet serves both the
# customer case (a catalogue) and the project's own field-proofing gate (a
# winget-scale corpus with a published pass rate).
# =============================================================================

function Invoke-MsixBulkAnalysis {
    <#
    .SYNOPSIS
        Analyses many MSIX packages and produces one row per package plus a
        rollup: which are clean, which can be auto-fixed, which need a human.

    .DESCRIPTION
        Runs the standard investigate -> plan pipeline over a whole folder (or
        an explicit list) of .msix files and emits a comparable verdict for each.

        Design points that matter at scale:

          ISOLATION   Every package runs inside its own try/catch. A corrupt or
                      malicious package produces an 'Error' row; it never aborts
                      the run.
          STREAMING   Each row is appended to -ReportPath as soon as it is known,
                      so killing the run (or losing power) keeps everything
                      completed so far.
          RESUMABLE   -Resume reads the existing report and skips packages
                      already recorded, so a multi-day corpus run can be stopped
                      and restarted freely.
          NO DUPLICATED LOGIC
                      The AutoFixable verdict is decided by asking the REAL
                      planner (Invoke-MsixAutoFixFromAnalysis -DryRun) what it
                      would do, rather than re-deriving the fixable category
                      list here. A second copy of that mapping would silently
                      drift from the first.

        Deliberately SERIAL for now. The module keeps session state in script
        scope (the resolved tools root, the memoized offreg probe, the log file
        handle), so running analyses concurrently inside one process would race
        on it. Throughput comes from -Resume plus overnight runs until that
        state is made concurrency-safe; correctness first.

    .PARAMETER Path
        Folders and/or .msix files. Folders are searched recursively. Wildcards
        are supported.

    .PARAMETER ReportPath
        CSV to stream results into. Written row-by-row as the run proceeds.

    .PARAMETER Resume
        Skip packages already present in -ReportPath. Requires -ReportPath.

    .PARAMETER SkipAutoFixPlan
        Do not ask the planner what it would fix. Faster, but every package with
        findings is reported as 'NeedsReview' because fixability is unknown.

    .PARAMETER First
        Process at most this many packages. Useful for a smoke run over a corpus.

    .OUTPUTS
        [pscustomobject] per package: Id, Package, SizeMB, Verdict, Findings,
        Errors, Warnings, Categories, PlannedFixes, DurationSec, Notes, When.

    .EXAMPLE
        # A packaging team's catalogue, with a report to hand to the lead
        Invoke-MsixBulkAnalysis -Path 'D:\packages' -ReportPath .\fleet.csv

    .EXAMPLE
        # Corpus run: start it, stop it, resume it as often as you like
        Invoke-MsixBulkAnalysis -Path 'D:\corpus\out' -ReportPath .\scorecard.csv -Resume

    .EXAMPLE
        # Just the verdict spread, no report file
        Invoke-MsixBulkAnalysis -Path 'D:\packages' | Group-Object Verdict

    .LINK
        https://github.com/sanderdewit/msix
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Path,
        [string]$ReportPath,
        [switch]$Resume,
        [switch]$SkipAutoFixPlan,
        [int]$First
    )

    if ($Resume -and -not $ReportPath) {
        throw '-Resume needs -ReportPath: the existing report is what records which packages are already done.'
    }

    # ── Resolve the input set ─────────────────────────────────────────────
    $packages = New-Object System.Collections.Generic.List[string]
    foreach ($p in $Path) {
        $resolved = @(Resolve-Path -Path $p -ErrorAction SilentlyContinue)
        if (-not $resolved) {
            Write-MsixLog -Level Warning -Message "No match for input path '$p'."
            continue
        }
        foreach ($r in $resolved) {
            if (Test-Path -LiteralPath $r.Path -PathType Container) {
                foreach ($f in @(Get-ChildItem -LiteralPath $r.Path -Filter '*.msix' -File -Recurse -ErrorAction SilentlyContinue)) {
                    $packages.Add($f.FullName)
                }
            } elseif ($r.Path -like '*.msix') {
                $packages.Add($r.Path)
            }
        }
    }
    $packages = @($packages | Sort-Object -Unique)
    if (-not $packages) { throw "No .msix files found under: $($Path -join ', ')" }

    # ── Resume: which are already recorded? ───────────────────────────────
    $done = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    if ($Resume -and (Test-Path -LiteralPath $ReportPath)) {
        try {
            foreach ($row in @(Import-Csv -LiteralPath $ReportPath)) {
                if ($row.Package) { [void]$done.Add($row.Package) }
            }
            Write-MsixLog -Level Info -Message "Resuming: $($done.Count) package(s) already recorded in '$ReportPath'."
        } catch {
            Write-MsixLog -Level Warning -Message "Could not read '$ReportPath' to resume ($($_.Exception.Message)); starting from the beginning."
        }
    }

    $queue = @($packages | Where-Object { -not $done.Contains($_) })
    if ($PSBoundParameters.ContainsKey('First') -and $First -gt 0) {
        $queue = @($queue | Select-Object -First $First)
    }

    Write-MsixLog -Level Info -Message "Bulk analysis: $($queue.Count) package(s) to process ($($packages.Count) found, $($done.Count) already done)."

    $headerWritten = $ReportPath -and (Test-Path -LiteralPath $ReportPath)
    $i = 0
    $tally = [ordered]@{}

    foreach ($pkg in $queue) {
        $i++
        $sw = [Diagnostics.Stopwatch]::StartNew()
        Write-Progress -Activity 'MSIX bulk analysis' -Status "$i / $($queue.Count): $(Split-Path -Leaf $pkg)" `
                       -PercentComplete ([int](100 * $i / [Math]::Max(1, $queue.Count)))

        $row = _MsixAnalyseOnePackage -PackagePath $pkg -SkipAutoFixPlan:$SkipAutoFixPlan
        $sw.Stop()
        $row | Add-Member -NotePropertyName DurationSec -NotePropertyValue ([math]::Round($sw.Elapsed.TotalSeconds, 1)) -Force

        # Stream the row out immediately: a run killed at package 180 must keep
        # the first 179 results.
        if ($ReportPath) {
            try {
                $dir = Split-Path -Parent -Path $ReportPath
                if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                    New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false | Out-Null
                }
                if ($headerWritten) {
                    $row | Export-Csv -LiteralPath $ReportPath -NoTypeInformation -Append -Encoding UTF8
                } else {
                    $row | Export-Csv -LiteralPath $ReportPath -NoTypeInformation -Encoding UTF8
                    $headerWritten = $true
                }
            } catch {
                Write-MsixLog -Level Warning -Message "Could not append to '$ReportPath': $($_.Exception.Message)"
            }
        }

        $v = [string]$row.Verdict
        if (-not $tally.Contains($v)) { $tally[$v] = 0 }
        $tally[$v] = $tally[$v] + 1
        $row
    }
    Write-Progress -Activity 'MSIX bulk analysis' -Completed

    # ── Rollup ────────────────────────────────────────────────────────────
    Write-MsixLog -Level Info -Message '─── Bulk analysis summary ───'
    foreach ($k in $tally.Keys) {
        Write-MsixLog -Level Info -Message ("  {0,-12} {1}" -f $k, $tally[$k])
    }
    if ($ReportPath) {
        Write-MsixLog -Level Info -Message "Report: $ReportPath"
    }
}

function _MsixAnalyseOnePackage {
    <#
    .SYNOPSIS
        Analyses ONE package and returns a single comparable result row.
        Never throws - a failure becomes an 'Error' verdict, because one bad
        package must not end a fleet run.
    #>
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$PackagePath,
        [switch]$SkipAutoFixPlan
    )

    $row = [ordered]@{
        Id           = ''
        Package      = $PackagePath
        SizeMB       = ''
        Verdict      = 'Error'
        Findings     = 0
        Errors       = 0
        Warnings     = 0
        Categories   = ''
        PlannedFixes = ''
        DurationSec  = 0
        Notes        = ''
        When         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    }

    try {
        $fi = Get-Item -LiteralPath $PackagePath -ErrorAction Stop
        $row.SizeMB = [math]::Round($fi.Length / 1MB, 1)
        $row.Id     = $fi.BaseName

        # Identity is best-effort: a package whose manifest cannot be read is
        # still worth reporting as Blocked rather than silently skipped.
        try {
            [xml]$mf = Get-MsixManifest -Path $PackagePath
            if ($mf.Package.Identity.Name) { $row.Id = $mf.Package.Identity.Name }
        } catch {
            Write-MsixLog -Level Debug -Message "Identity unreadable for '$PackagePath': $($_.Exception.Message)"
        }

        $report = Invoke-MsixInvestigation -PackagePath $PackagePath -ErrorAction Stop
        $findings = @($report.Findings)

        $row.Findings   = $findings.Count
        $row.Errors     = @($findings | Where-Object { $_.Severity -eq 'Error' }).Count
        $row.Warnings   = @($findings | Where-Object { $_.Severity -eq 'Warning' }).Count
        $row.Categories = (@($findings | ForEach-Object { $_.Category } | Sort-Object -Unique) -join '; ')

        # A scanner that could not run means this report is INCOMPLETE, and an
        # incomplete report must not be presentable as a clean one (#140).
        $scannerErrors = @($findings | Where-Object { $_.Category -eq 'ScannerError' -or $_.Category -eq 'OfflineRegistryUnavailable' })

        if ($findings.Count -eq 0) {
            $row.Verdict = 'Clean'
        } elseif ($SkipAutoFixPlan) {
            $row.Verdict = 'NeedsReview'
        } else {
            # Ask the REAL planner what it would do rather than re-deriving the
            # fixable-category list here, which would drift.
            try {
                $plan = Invoke-MsixAutoFixFromAnalysis -Report $report -PackagePath $PackagePath -DryRun -ErrorAction Stop
                $stages = @($plan.Plan)
                $row.PlannedFixes = (@($stages | ForEach-Object { $_.Stage }) -join '; ')
                if ($stages.Count -gt 0) {
                    # Actionable findings remain only if something needs a human
                    # decision the planner cannot make (paths, CLSIDs, certs).
                    $row.Verdict = 'AutoFixable'
                } else {
                    $row.Verdict = 'NeedsManual'
                }
            } catch {
                $row.Verdict = 'NeedsReview'
                $row.Notes   = _MsixShortNote -Text "Planner failed: $($_.Exception.Message)"
            }
        }

        if ($scannerErrors.Count -gt 0) {
            # Downgrade: we cannot claim Clean/AutoFixable off a partial scan.
            $row.Verdict = 'Incomplete'
            $row.Notes   = (($row.Notes, "Incomplete scan: $((@($scannerErrors | ForEach-Object { $_.Category } | Sort-Object -Unique)) -join ', ')") |
                            Where-Object { $_ }) -join ' | '
        }
    } catch {
        $row.Verdict = 'Error'
        $row.Notes   = _MsixShortNote -Text $_.Exception.Message
        Write-MsixLog -Level Warning -Message "Bulk: '$PackagePath' failed - $($row.Notes)"
    }

    return [pscustomobject]$row
}

function _MsixShortNote {
    <#
    .SYNOPSIS
        Collapses a multi-line tool error into one readable CSV cell.

    .DESCRIPTION
        Tool failures carry the whole of MakeAppx's stdout, which turns a
        scorecard row into an unreadable wall. Keep the first meaningful line and
        cap the length; the full text is already in the module log.
    #>
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [int]$MaxLength = 240)

    $line = @($Text -split "`r?`n" | Where-Object { $_.Trim() }) | Select-Object -First 1
    if (-not $line) { return '' }
    $line = $line.Trim()
    if ($line.Length -gt $MaxLength) { $line = $line.Substring(0, $MaxLength - 1) + [char]0x2026 }
    return $line
}
