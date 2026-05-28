# =============================================================================
# Trace delta analysis — Compare-MsixTrace
# -----------------------------------------------------------------------------
# Given two runtime trace captures (DebugView .log / .txt or ProcMon .pml),
# classifies each observed failure row as:
#
#   Resolved   — present in the baseline, gone in the candidate.
#   Persisted  — present in both (not yet fixed).
#   Introduced — absent from the baseline, newly seen in the candidate
#                (regressions caused by a fixup).
#
# Built on top of Get-MsixTraceFailure / Get-MsixProcMonFailure so the same
# match heuristics apply for both trace sources.
# =============================================================================


# ---------------------------------------------------------------------------
# Private: normalise a row from either Get-MsixTraceFailure (TraceFixup log)
# or Get-MsixProcMonFailure (ProcMon CSV export) into a common shape used for
# keying. We only need Function/Operation, Path, and Result.
# ---------------------------------------------------------------------------
function _MsixLoadTraceFailureRows {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [string]$ProcessName
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Trace file not found: $Path"
    }

    $ext = [IO.Path]::GetExtension($Path).ToLowerInvariant()

    if ($ext -eq '.pml') {
        # ProcMon PML -> CSV -> failure rows via the existing helper.
        $rows = @(Get-MsixProcMonFailure -PmlPath $Path -ProcessName $ProcessName)
        # Normalise ProcMon row shape to the TraceFixup shape that
        # ConvertFrom-MsixTraceToFinding expects.
        return $rows | ForEach-Object {
            $r = $_
            [pscustomobject]@{
                Timestamp = $null
                ProcessId = $null
                ThreadId  = $null
                Function  = [string]$r.Operation
                Category  = switch -Regex ([string]$r.Operation) {
                    '^(CreateFile|ReadFile|WriteFile|DeleteFile|SetInfo|QueryInfo)' { 'filesystem' }
                    '^(Reg)'   { 'registry' }
                    '^(Load)'  { 'module-load' }
                    default    { 'other' }
                }
                Path      = [string]$r.Path
                Result    = [string]$r.Result
                Raw       = [string]$r.Path
            }
        }
    } else {
        # TraceFixup text log (.log / .txt)
        $pfArgs = @{ Path = $Path }
        if ($ProcessName) { $pfArgs['FunctionPattern'] = $ProcessName }
        return @(Get-MsixTraceFailure @pfArgs)
    }
}


# ---------------------------------------------------------------------------
# Private: stable match key for a normalised trace row.
# Captures (Operation, Path, Result) — same failure means same triple.
# ---------------------------------------------------------------------------
function _MsixTraceRowKey([psobject]$Row) {
    '{0}|{1}|{2}' -f $Row.Function, $Row.Path, $Row.Result
}


# ---------------------------------------------------------------------------
# Private: convert a set of raw failure rows to deduplicated findings, then
# apply category and severity filters.
# ---------------------------------------------------------------------------
function _MsixTraceRowsToFindings {
    param(
        [object[]]$Rows,
        [string[]]$IncludeCategory,
        [string]$MinSeverity
    )

    if (-not $Rows -or $Rows.Count -eq 0) { return @() }

    $findings = @($Rows | ConvertFrom-MsixTraceToFinding)

    if ($IncludeCategory) {
        $findings = @($findings | Where-Object { $_.Category -in $IncludeCategory })
    }

    if ($MinSeverity) {
        $rank = @{ 'Error' = 3; 'Warning' = 2; 'Info' = 1; 'Debug' = 0 }
        $min  = $rank[$MinSeverity]
        $findings = @($findings | Where-Object {
            $r = if ($rank.ContainsKey([string]$_.Severity)) { $rank[[string]$_.Severity] } else { 1 }
            $r -ge $min
        })
    }

    return $findings
}


# ---------------------------------------------------------------------------
# Private: SARIF emitter for a trace diff.  Three runs inside one document:
#   run[0] = Resolved findings  (level: note  — good news)
#   run[1] = Persisted findings (level: warning)
#   run[2] = Introduced findings(level: error   — regressions)
# ---------------------------------------------------------------------------
function _ConvertMsixTraceDeltaToSarif {
    param(
        [Parameter(Mandatory)] [psobject]$Diff,
        [Parameter(Mandatory)] [string]$Baseline,
        [Parameter(Mandatory)] [string]$Candidate
    )

    $modVersion = (Get-Module -Name MSIX -ErrorAction SilentlyContinue).Version
    if (-not $modVersion) { $modVersion = '0.0.0' }

    $baseUri  = try { ([uri]$Baseline).AbsoluteUri  } catch { $Baseline  }
    $candUri  = try { ([uri]$Candidate).AbsoluteUri } catch { $Candidate }

    function _Run([string]$Label, [object[]]$Findings, [string]$DefaultLevel) {
        $results = foreach ($f in $Findings) {
            if (-not $f.Category) { continue }
            @{
                ruleId   = "MSIX.$($f.Category)"
                level    = $DefaultLevel
                message  = @{ text = [string]$f.Symptom }
                locations = @(@{
                    physicalLocation = @{
                        artifactLocation = @{ uri = $candUri }
                    }
                })
                properties = @{
                    deltaClass     = $Label
                    category       = [string]$f.Category
                    recommendation = [string]$f.Recommendation
                }
            }
        }
        @{
            tool = @{
                driver = @{
                    name            = 'MSIX.TraceDelta'
                    semanticVersion = [string]$modVersion
                }
            }
            artifacts = @(
                @{ location = @{ uri = $baseUri }; roles = @('analysisTarget'); description = @{ text = 'Baseline trace' } }
                @{ location = @{ uri = $candUri  }; roles = @('analysisTarget'); description = @{ text = 'Candidate trace' } }
            )
            results    = @($results)
            properties = @{ deltaClass = $Label }
        }
    }

    return @{
        '$schema' = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/schemas/sarif-schema-2.1.0.json'
        version   = '2.1.0'
        runs      = @(
            (_Run -Label 'Resolved'   -Findings $Diff.Resolved  -DefaultLevel 'note')
            (_Run -Label 'Persisted'  -Findings $Diff.Persisted -DefaultLevel 'warning')
            (_Run -Label 'Introduced' -Findings $Diff.Introduced -DefaultLevel 'error')
        )
    }
}


function Compare-MsixTrace {
    <#
    .SYNOPSIS
        Before/after correlation of two runtime trace captures.

    .DESCRIPTION
        Given two trace files (TraceFixup .log/.txt or ProcMon .pml), classifies
        every observed failure row as Resolved, Persisted, or Introduced:

          Resolved   — in baseline, absent from candidate (fixed ✓).
          Persisted  — in both traces (still broken).
          Introduced — absent from baseline, new in candidate (regression!).

        The match key for "same failure" is (Operation × Path × Result). Two
        rows that share all three are treated as the same failure regardless of
        which PID/TID emitted them.

        Findings are produced by ConvertFrom-MsixTraceToFinding so the output
        shape is identical to what Get-MsixStaticAnalysis emits — making the
        diff consumable by Invoke-MsixAutoFixFromAnalysis and the SARIF emitter.

    .PARAMETER Baseline
        Path to the before-fix trace (.log, .txt, or .pml).

    .PARAMETER Candidate
        Path to the after-fix trace (.log, .txt, or .pml).

    .PARAMETER ProcessName
        Optional: restrict PML captures to rows from processes whose name
        matches this string (partial match, forwarded to Get-MsixProcMonFailure).
        No effect on .log/.txt traces.

    .PARAMETER IncludeCategory
        Restrict the diff to findings in these categories (e.g. 'FileRedirectionFixup',
        'RegLegacyFixups').  By default all categories are included.

    .PARAMETER MinSeverity
        Drop findings below this severity. Choices: Error, Warning, Info (default).

    .PARAMETER Sarif
        Return a SARIF 2.1.0 document instead of the diff object.
        The document has three runs: Resolved / Persisted / Introduced.
        Pipe through ConvertTo-Json -Depth 100 to serialise.

    .OUTPUTS
        [pscustomobject] with:
          Resolved      [object[]]  — findings gone in candidate
          Persisted     [object[]]  — findings still present
          Introduced    [object[]]  — new regressions in candidate
          Summary       [pscustomobject] counts + ImprovementPct

        Or [hashtable] SARIF document when -Sarif is set.

    .EXAMPLE
        $diff = Compare-MsixTrace -Baseline before.log -Candidate after.log
        $diff.Summary
        $diff.Introduced | Format-Table Category, Symptom

    .EXAMPLE
        Compare-MsixTrace -Baseline before.pml -Candidate after.pml -Sarif |
            ConvertTo-Json -Depth 100 | Out-File -FilePath delta.sarif -Encoding utf8

    .EXAMPLE
        # Only care about write-virtualisation regressions:
        Compare-MsixTrace -Baseline b.log -Candidate a.log `
            -IncludeCategory FileRedirectionFixup, RegLegacyFixups
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$Baseline,
        [Parameter(Mandatory)] [string]$Candidate,
        [string]$ProcessName,
        [string[]]$IncludeCategory,
        [ValidateSet('Error', 'Warning', 'Info')] [string]$MinSeverity = 'Info',
        [switch]$Sarif
    )

    Write-MsixLog Info "TraceDelta: loading baseline  '$Baseline'"
    $baseRows = @(_MsixLoadTraceFailureRows -Path $Baseline -ProcessName $ProcessName)

    Write-MsixLog Info "TraceDelta: loading candidate '$Candidate'"
    $candRows = @(_MsixLoadTraceFailureRows -Path $Candidate -ProcessName $ProcessName)

    Write-MsixLog Info ("TraceDelta: baseline={0} rows  candidate={1} rows" -f $baseRows.Count, $candRows.Count)

    # Build lookup sets by match key.
    $baseKeySet = [System.Collections.Generic.HashSet[string]]::new()
    $candKeySet = [System.Collections.Generic.HashSet[string]]::new()

    foreach ($r in $baseRows) { $baseKeySet.Add((_MsixTraceRowKey $r)) | Out-Null }
    foreach ($r in $candRows) { $candKeySet.Add((_MsixTraceRowKey $r)) | Out-Null }

    $resolvedRows   = @($baseRows | Where-Object { -not $candKeySet.Contains((_MsixTraceRowKey $_)) })
    $persistedRows  = @($baseRows | Where-Object {       $candKeySet.Contains((_MsixTraceRowKey $_)) })
    $introducedRows = @($candRows | Where-Object { -not $baseKeySet.Contains((_MsixTraceRowKey $_)) })

    # Convert raw rows to deduplicated findings.
    $filterArgs = @{ IncludeCategory = $IncludeCategory; MinSeverity = $MinSeverity }
    $resolvedFindings   = @(_MsixTraceRowsToFindings -Rows $resolvedRows   @filterArgs)
    $persistedFindings  = @(_MsixTraceRowsToFindings -Rows $persistedRows  @filterArgs)
    $introducedFindings = @(_MsixTraceRowsToFindings -Rows $introducedRows @filterArgs)

    $baseCount = [math]::Max($resolvedFindings.Count + $persistedFindings.Count, 1)
    $improvPct = [math]::Round($resolvedFindings.Count / $baseCount * 100, 1)

    # Raw-row counts are reported alongside the categorised-finding counts so
    # uncategorised regressions (failures on paths ConvertFrom-MsixTraceToFinding
    # doesn't map to a known fixup category — anything outside System32 /
    # WindowsApps / HKLM / LoadLibrary) don't silently disappear from the
    # summary. A user reading IntroducedCount=0 alongside IntroducedRowCount=3
    # immediately sees the asymmetry and knows to inspect the raw rows.
    $summary = [pscustomobject]@{
        BaselineRowCount    = $baseRows.Count
        CandidateRowCount   = $candRows.Count
        ResolvedCount       = $resolvedFindings.Count
        PersistedCount      = $persistedFindings.Count
        IntroducedCount     = $introducedFindings.Count
        ResolvedRowCount    = $resolvedRows.Count
        PersistedRowCount   = $persistedRows.Count
        IntroducedRowCount  = $introducedRows.Count
        ImprovementPct      = $improvPct
    }

    if ($summary.IntroducedRowCount -gt $summary.IntroducedCount) {
        $uncat = $summary.IntroducedRowCount - $summary.IntroducedCount
        Write-MsixLog Warning ("TraceDelta: {0} introduced row(s) did not map to any known fixup category and are NOT reflected in IntroducedCount. Inspect the raw trace for paths outside System32 / WindowsApps / HKLM / LoadLibrary." -f $uncat)
    }

    Write-MsixLog Info ("TraceDelta: resolved={0}  persisted={1}  introduced={2}  improvement={3}%%" `
        -f $summary.ResolvedCount, $summary.PersistedCount, $summary.IntroducedCount, $summary.ImprovementPct)

    $diff = [pscustomobject]@{
        Resolved   = [object[]]$resolvedFindings
        Persisted  = [object[]]$persistedFindings
        Introduced = [object[]]$introducedFindings
        Summary    = $summary
    }

    if ($Sarif) {
        return _ConvertMsixTraceDeltaToSarif -Diff $diff -Baseline $Baseline -Candidate $Candidate
    }

    return $diff
}
