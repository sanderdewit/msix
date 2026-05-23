# =============================================================================
# Multi-pass remediation pipeline — Invoke-MsixAutoFixLoop
# -----------------------------------------------------------------------------
# Automates the "fix → re-analyse → next fix" cycle. Many MSIX issues are
# chained: fix working dir → reveals DLL issue → fix DLL → reveals updater.
# The module already ships every building block; this stitches them into a
# controlled loop:
#
#   Pass N:
#     1. Get-MsixCompatibilityReport (static + optional trace).
#     2. Invoke-MsixAutoFixFromAnalysis -DryRun to produce a plan.
#     3. Stop if the plan is empty (NoNewFixes).
#     4. Apply the plan (no sign yet).
#     5. If -CaptureTrace: run Invoke-MsixProcMonCapture and compare via
#        Compare-MsixTrace; stop if Introduced==0 (NoRegressions).
#     6. Loop.
#
#   After all passes: sign exactly once.
#
# Per-pass artefacts (report.json, plan.json, optional trace.pml, trace-delta.json)
# are written under $env:TEMP\msix-autofix-loop-<guid>\ so operators can
# post-mortem any pass.
# =============================================================================


function Invoke-MsixAutoFixLoop {
    <#
    .SYNOPSIS
        Runs repeated static-analysis + auto-fix passes until the package is
        stable or the maximum pass count is reached.

    .DESCRIPTION
        Each pass runs Get-MsixCompatibilityReport against the current package
        state, plans the next round of fixes via Invoke-MsixAutoFixFromAnalysis,
        and applies them (unsigned). The loop continues until:

          NoNewFixes    — the planner has nothing to do (stable).
          NoRegressions — Compare-MsixTrace shows no newly-introduced failures
                          (only meaningful when -CaptureTrace is set; requires
                          Procmon to be available via Initialize-MsixToolchain).

        Both stop conditions can be combined in -StopOn. The package is signed
        exactly once at the end of the last pass (unless -SkipSigning is set).

        Per-pass artefacts (report.json, plan.json, trace.pml, delta.json) are
        kept under:
            $env:TEMP\msix-autofix-loop-<runId>\pass-N\

        so operators can post-mortem any pass without losing intermediate state.

        -WhatIf / -DryRun performs only the first pass's plan and exits without
        writing anything.

    .PARAMETER PackagePath
        .msix to act on.

    .PARAMETER MaxPasses
        Hard cap on pass count (default 5). Prevents runaway loops.

    .PARAMETER StopOn
        One or more stop conditions:
          NoNewFixes    — stop when the planner has nothing new to apply.
          NoRegressions — stop when Compare-MsixTrace detects no introduced
                          failures relative to the previous pass.
        Default: NoNewFixes.

    .PARAMETER MinConfidence
        Confidence floor forwarded to Invoke-MsixAutoFixFromAnalysis (default 0.85).

    .PARAMETER CaptureTrace
        When set, each pass installs the package in the MSIX Sandbox, captures
        a ProcMon trace, and feeds it into Compare-MsixTrace for the
        NoRegressions stop condition. Requires Hyper-V + Sandbox + ProcMon.

    .PARAMETER TraceDurationSeconds
        How long to capture the ProcMon trace per pass (default 30 seconds).

    .PARAMETER TraceLogPath
        Path to an existing TraceFixup .log/.txt to feed into each pass's
        compatibility report instead of running a live capture. Incompatible
        with -CaptureTrace.

    .PARAMETER OutputPath
        Write the final fixed package here. Defaults to overwriting PackagePath.

    .PARAMETER DryRun
        Run only the first pass planner and print the plan; do not write.

    .PARAMETER SkipSigning / NoSign / Pfx / PfxPassword
        Signing controls for the final sign-once call.

    # --- Auto-fix pass-through parameters (forwarded each pass) ---

    .PARAMETER VcRuntimeSourceFolder
        Forwarded to Invoke-MsixAutoFixFromAnalysis.

    .PARAMETER StartupTaskAppId / StartupTaskName / LoaderPaths
        Forwarded to Invoke-MsixAutoFixFromAnalysis.

    .PARAMETER IgnoreUpdaters / IgnorePluginDirectories / LegacyPluginFix
    .PARAMETER IgnoreNestedPackages / PreferManifestOverPsf
        Forwarded to Invoke-MsixAutoFixFromAnalysis.

    .OUTPUTS
        [pscustomobject] @{
            Output      [string]  path to the final (signed) package
            Passes      [object[]] per-pass summary objects
            FinalReport [pscustomobject] compatibility report from the last pass
            SignedOk    [bool]
            RunDirectory[string]  path to per-pass artefacts
        }

    .EXAMPLE
        Invoke-MsixAutoFixLoop -PackagePath app.msix -MaxPasses 5 `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # With sandbox trace capture:
        Invoke-MsixAutoFixLoop -PackagePath app.msix `
            -StopOn NoNewFixes,NoRegressions -CaptureTrace `
            -TraceDurationSeconds 30 `
            -Pfx cert.pfx -PfxPassword $pw -OutputPath app-fixed.msix

    .EXAMPLE
        # DryRun — only plan pass 1, do not write:
        Invoke-MsixAutoFixLoop -PackagePath app.msix -DryRun
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,

        [ValidateRange(1, 20)]
        [int]$MaxPasses = 5,

        [ValidateSet('NoNewFixes', 'NoRegressions')]
        [string[]]$StopOn = @('NoNewFixes'),

        [ValidateRange(0.0, 1.0)]
        [double]$MinConfidence = 0.85,

        # Trace / sandbox options
        [switch]$CaptureTrace,
        [int]$TraceDurationSeconds = 30,
        [string]$TraceLogPath,

        # Output
        [string]$OutputPath,
        [switch]$DryRun,
        [Alias('NoSign')] [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,

        # Pass-through to Invoke-MsixAutoFixFromAnalysis
        [string]$VcRuntimeSourceFolder,
        [string]$StartupTaskAppId,
        [string]$StartupTaskName,
        [string[]]$LoaderPaths,
        [switch]$IgnoreUpdaters,
        [switch]$IgnorePluginDirectories,
        [switch]$LegacyPluginFix,
        [switch]$IgnoreNestedPackages,
        [bool]$PreferManifestOverPsf = $true
    )

    if ($CaptureTrace -and $TraceLogPath) {
        throw '-CaptureTrace and -TraceLogPath are mutually exclusive.'
    }

    # Per-run working directory
    $runId  = [guid]::NewGuid().ToString('N').Substring(0, 12)
    $runDir = Join-Path $env:TEMP "msix-autofix-loop-$runId"
    $null   = New-Item -ItemType Directory -Path $runDir -Force

    # Determine the working copy path.
    $targetPath = if ($OutputPath -and $OutputPath -ne $PackagePath) {
        if (-not $DryRun) {
            Copy-Item -LiteralPath $PackagePath -Destination $OutputPath -Force
        }
        $OutputPath
    } else {
        $PackagePath
    }

    Write-MsixLog Info ("AutoFixLoop started: runId={0}  maxPasses={1}  stopOn={2}" `
        -f $runId, $MaxPasses, ($StopOn -join ','))
    Write-MsixLog Info "AutoFixLoop artefacts: $runDir"

    # --- Build the static arg hashtable for Invoke-MsixAutoFixFromAnalysis ---
    $fixArgs = @{
        MinConfidence         = $MinConfidence
        PreferManifestOverPsf = $PreferManifestOverPsf
        SkipSigning           = $true   # sign once at end
    }
    if ($VcRuntimeSourceFolder) { $fixArgs['VcRuntimeSourceFolder'] = $VcRuntimeSourceFolder }
    if ($StartupTaskAppId)      { $fixArgs['StartupTaskAppId']      = $StartupTaskAppId }
    if ($StartupTaskName)       { $fixArgs['StartupTaskName']       = $StartupTaskName }
    if ($LoaderPaths)           { $fixArgs['LoaderPaths']           = $LoaderPaths }
    if ($IgnoreUpdaters)        { $fixArgs['IgnoreUpdaters']        = $true }
    if ($IgnorePluginDirectories){ $fixArgs['IgnorePluginDirectories'] = $true }
    if ($LegacyPluginFix)       { $fixArgs['LegacyPluginFix']       = $true }
    if ($IgnoreNestedPackages)  { $fixArgs['IgnoreNestedPackages']  = $true }

    $passSummaries = [System.Collections.Generic.List[object]]::new()
    $finalReport   = $null
    $prevTracePath = $null
    $stopReason    = $null

    for ($pass = 1; $pass -le $MaxPasses; $pass++) {
        Write-MsixLog Info "AutoFixLoop pass $pass / $MaxPasses"

        $passDir = Join-Path $runDir "pass-$pass"
        $null = New-Item -ItemType Directory -Path $passDir -Force

        # ── 1. Compatibility report ──
        $reportArgs = @{ PackagePath = $targetPath }
        if ($TraceLogPath) { $reportArgs['TraceLogPath'] = $TraceLogPath }

        $report = Get-MsixCompatibilityReport @reportArgs
        $finalReport = $report

        # Persist report for post-mortem
        $report | ConvertTo-Json -Depth 10 -Compress |
            Out-File (Join-Path $passDir 'report.json') -Encoding utf8

        # ── 2. Plan ──
        $plan = Invoke-MsixAutoFixFromAnalysis -Report $report @fixArgs -DryRun

        $plan | ConvertTo-Json -Depth 10 -Compress |
            Out-File (Join-Path $passDir 'plan.json') -Encoding utf8

        $passSummary = [pscustomobject]@{
            Pass          = $pass
            FindingCount  = @($report.Findings).Count
            StageCount    = if ($plan) { @($plan).Count } else { 0 }
            TraceDelta    = $null
            StopReason    = $null
            ArtifactPath  = $passDir
        }

        # ── DryRun: only first pass plan, then stop ──
        if ($DryRun) {
            Write-MsixLog Info '[DryRun] Pass 1 plan produced - exiting without writing.'
            $passSummary.StopReason = 'DryRun'
            $passSummaries.Add($passSummary)
            break
        }

        # ── 3. Stop: NoNewFixes ──
        if ('NoNewFixes' -in $StopOn -and $passSummary.StageCount -eq 0) {
            Write-MsixLog Info "AutoFixLoop stopping: no new fixes planned (pass $pass)."
            $passSummary.StopReason = 'NoNewFixes'
            $stopReason = 'NoNewFixes'
            $passSummaries.Add($passSummary)
            break
        }

        # ── 4. Apply ──
        if ($PSCmdlet.ShouldProcess($targetPath, "AutoFix pass $pass")) {
            Invoke-MsixAutoFixFromAnalysis -Report $report -PackagePath $targetPath @fixArgs |
                Out-Null
        }

        Write-MsixLog Info "AutoFixLoop pass $pass applied."

        # ── 5. Optional trace capture + delta ──
        if ($CaptureTrace -and 'NoRegressions' -in $StopOn) {
            $tracePath = Join-Path $passDir 'trace.pml'
            Write-MsixLog Info "AutoFixLoop: capturing trace ($TraceDurationSeconds s)..."
            try {
                Invoke-MsixProcMonCapture -PackagePath $targetPath -OutputPml $tracePath `
                    -DurationSeconds $TraceDurationSeconds
            } catch {
                Write-MsixLog Warning "AutoFixLoop: trace capture failed on pass $pass - $_"
            }

            if ($prevTracePath -and (Test-Path $tracePath)) {
                $delta = Compare-MsixTrace -Baseline $prevTracePath -Candidate $tracePath
                $delta | ConvertTo-Json -Depth 10 -Compress |
                    Out-File (Join-Path $passDir 'trace-delta.json') -Encoding utf8
                $passSummary.TraceDelta = $delta.Summary

                if ('NoRegressions' -in $StopOn -and $delta.Summary.IntroducedCount -eq 0) {
                    Write-MsixLog Info "AutoFixLoop stopping: no regressions introduced (pass $pass)."
                    $passSummary.StopReason = 'NoRegressions'
                    $stopReason = 'NoRegressions'
                    $passSummaries.Add($passSummary)
                    $prevTracePath = $tracePath
                    break
                }
            }
            $prevTracePath = $tracePath
        }

        $passSummaries.Add($passSummary)

        if ($pass -eq $MaxPasses) {
            Write-MsixLog Warning "AutoFixLoop: reached MaxPasses ($MaxPasses) without a stop condition."
            $stopReason = 'MaxPasses'
        }
    }

    # ── 6. Sign once ──
    $signedOk = $false
    if (-not $DryRun) {
        if (-not $SkipSigning -and $Pfx) {
            try {
                if ($PSCmdlet.ShouldProcess($targetPath, 'Sign package')) {
                    Invoke-MsixSigning -PackagePath $targetPath -Pfx $Pfx -PfxPassword $PfxPassword
                    $signedOk = $true
                    Write-MsixLog Info "AutoFixLoop: package signed - $targetPath"
                }
            } catch {
                Write-MsixLog Warning "AutoFixLoop: signing failed - $_"
            }
        } elseif (-not $SkipSigning -and -not $Pfx) {
            Write-MsixLog Warning 'AutoFixLoop: no -Pfx supplied - package left unsigned.'
        } else {
            Write-MsixLog Info 'AutoFixLoop: skipping signing (-SkipSigning).'
        }
    }

    $stopReasonStr = if ($null -ne $stopReason) { $stopReason } else { 'MaxPasses' }
    Write-MsixLog Info ("AutoFixLoop complete: passes={0}  stopReason={1}  output={2}" `
        -f $passSummaries.Count, $stopReasonStr, $targetPath)

    return [pscustomobject]@{
        Output       = $targetPath
        Passes       = [object[]]$passSummaries
        FinalReport  = $finalReport
        SignedOk     = $signedOk
        RunDirectory = $runDir
        StopReason   = $stopReason
    }
}
