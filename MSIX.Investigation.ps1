# =============================================================================
# MSIX Investigation Engine
# -----------------------------------------------------------------------------
# Automates the manual procedure documented at:
#   - psf/package-support-framework        (overall flow)
#   - psf/psf-current-working-directory    (Name Not Found under SysWOW64)
#   - psf/psf-filesystem-writepermission   (Access Denied / Generic Write
#                                           under Program Files\WindowsApps)
# =============================================================================

# Mapping from observed failure pattern -> recommended fixup name
$script:FailurePatternMap = @(
    @{
        Name      = 'WorkingDirectory'
        Pattern   = 'Name not found.*(System32|SysWOW64)'
        Fixup     = 'WorkingDirectory'
        Reason    = 'App reads files from CWD but CWD defaults to System32/SysWOW64.'
    },
    @{
        Name      = 'WriteToPackage'
        Pattern   = 'Access denied.*WindowsApps'
        Fixup     = 'FileRedirectionFixup'
        Reason    = 'App writes inside Program Files\WindowsApps (read-only).'
    },
    @{
        Name      = 'WriteToProgramFiles'
        Pattern   = 'Access denied.*Program Files'
        Fixup     = 'FileRedirectionFixup'
        Reason    = 'App writes to Program Files (denied for non-elevated).'
    },
    @{
        Name      = 'RegistryWrite'
        Pattern   = 'Access denied.*HKLM'
        Fixup     = 'RegLegacyFixups'
        Reason    = 'App requests write/full access to HKLM keys.'
    }
)


function Add-MsixDiagnosticTrace {
    <#
    .SYNOPSIS
        Injects TraceFixup into a package with allFailures levels for diagnostics.
        Output is sent to the attached debugger / DebugView.

    .DESCRIPTION
        Equivalent to manually adding the TraceFixup snippet from the PSF docs.
        The package is repacked and re-signed; install it, run the app, and view
        output in DebugView (https://learn.microsoft.com/sysinternals/downloads/debugview).

    .PARAMETER PackagePath
        Path to the .msix to instrument.

    .PARAMETER Pfx / PfxPassword
        Signing certificate. Omit for /a (auto store).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [string]$Pfx,
        [string]$PfxPassword
    )

    $trace = New-MsixPsfTraceConfig -FilesystemLevel 'allFailures' -RegistryLevel 'allFailures'
    Add-MsixPsfV2 -PackagePath $PackagePath -Fixups @($trace) -Pfx $Pfx -PfxPassword $PfxPassword
}


function Resolve-MsixProcMonPath {
    <#
    .SYNOPSIS
        Finds procmon.exe (Sysinternals Process Monitor). Order:
        $env:MSIX_PROCMON_PATH > PATH > C:\PSF\ProcessMonitor > Sysinternals install dirs.
    #>
    [CmdletBinding()]
    param()

    if ($env:MSIX_PROCMON_PATH -and (Test-Path $env:MSIX_PROCMON_PATH)) {
        return (Resolve-Path $env:MSIX_PROCMON_PATH).Path
    }
    $cmd = Get-Command procmon.exe, procmon64.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }

    foreach ($p in @(
        'C:\PSF\ProcessMonitor\Procmon.exe',
        'C:\PSF\ProcessMonitor\Procmon64.exe',
        "${env:ProgramFiles}\SysInternals\Procmon.exe",
        "${env:ProgramFiles}\SysInternalsSuite\Procmon.exe"
    )) {
        if (Test-Path $p) { return $p }
    }
    return $null
}


function Invoke-MsixProcMonCapture {
    <#
    .SYNOPSIS
        Launches a packaged app under Process Monitor, captures filtered failure
        events into a PML file, and returns the PML path.

    .PARAMETER PackageFamilyName
        e.g. 'Contoso.App_8wekyb3d8bbwe' (from Get-AppxPackage).

    .PARAMETER AppId
        Application Id from the manifest.

    .PARAMETER OutputPml
        Path for the captured PML log (default: temp).

    .PARAMETER DurationSeconds
        How long to capture before terminating procmon.

    .PARAMETER ProcessName
        Optional process name to filter for (improves signal-to-noise).

    .NOTES
        Requires Sysinternals Process Monitor on PATH or at C:\PSF\ProcessMonitor.
        See https://learn.microsoft.com/sysinternals/downloads/procmon
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackageFamilyName,
        [Parameter(Mandatory)]
        [string]$AppId,
        [string]$OutputPml = (Join-Path $env:TEMP "msix-procmon-$([guid]::NewGuid().ToString('N').Substring(0,8)).pml"),
        [int]$DurationSeconds = 30,
        [string]$ProcessName
    )

    $procmon = Resolve-MsixProcMonPath
    if (-not $procmon) {
        throw 'Process Monitor (procmon.exe) not found. Set $env:MSIX_PROCMON_PATH or place it on PATH.'
    }

    Write-MsixLog Info "Starting Process Monitor capture: $OutputPml"

    # Procmon CLI: /AcceptEula /Quiet /Minimized /BackingFile <pml> /Runtime <sec>
    $procmonArgs = @('/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', "`"$OutputPml`"")
    Start-Process -FilePath $procmon -ArgumentList $procmonArgs -WindowStyle Minimized

    # Allow procmon to start
    Start-Sleep -Seconds 2

    Write-MsixLog Info "Launching $PackageFamilyName!$AppId"
    Invoke-CommandInDesktopPackage -PackageFamilyName $PackageFamilyName `
                                   -AppId $AppId `
                                   -Command 'cmd.exe' `
                                   -PreventBreakaway `
                                   -ErrorAction SilentlyContinue

    Start-Sleep -Seconds $DurationSeconds

    Write-MsixLog Info "Stopping Process Monitor capture"
    Start-Process -FilePath $procmon -ArgumentList @('/Terminate') -Wait

    if (-not (Test-Path $OutputPml)) {
        throw "Procmon capture failed; PML not created: $OutputPml"
    }
    return $OutputPml
}


function Get-MsixProcMonFailures {
    <#
    .SYNOPSIS
        Converts a Procmon PML log to CSV via procmon.exe and returns failure
        rows (Result != SUCCESS) parsed into objects.

    .PARAMETER PmlPath
        Path to the .pml file produced by Invoke-MsixProcMonCapture.

    .PARAMETER ProcessName
        Optional filter on Process Name column.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PmlPath,
        [string]$ProcessName
    )

    if (-not (Test-Path $PmlPath)) { throw "PML not found: $PmlPath" }

    $procmon = Resolve-MsixProcMonPath
    if (-not $procmon) { throw 'procmon.exe not found.' }

    $csv = [System.IO.Path]::ChangeExtension($PmlPath, '.csv')
    Write-MsixLog Info "Converting PML -> CSV: $csv"

    $r = Invoke-MsixProcess $procmon "/OpenLog `"$PmlPath`" /SaveAs `"$csv`" /SaveApplyFilter /Quiet /Terminate"
    if (-not (Test-Path $csv)) {
        throw "Procmon failed to export CSV from $PmlPath"
    }

    $rows = Import-Csv -Path $csv
    if ($ProcessName) {
        $rows = $rows | Where-Object { $_.'Process Name' -like "*$ProcessName*" }
    }

    return $rows | Where-Object { $_.Result -and $_.Result -ne 'SUCCESS' }
}


function Get-MsixStaticAnalysis {
    <#
    .SYNOPSIS
        Inspects an MSIX package without running it and returns a list of
        likely PSF-fixable issues.

    .DESCRIPTION
        Static heuristics:
          - Working-directory mismatch (executable in subfolder, no PSF wrap)
          - Hardcoded log/config files in same dir as exe (write-permission risk)
          - .ini files inside VFS\ProgramFilesX64 (write-permission risk)
          - Missing PSF when the manifest has multiple Applications with shared dir
          - Sniff for known problematic launchers (registered, but no fixups)
          - Detect existing PSF integration so re-runs are idempotent

    .PARAMETER PackagePath
        .msix file to analyse (read-only; not modified).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-static"
    $findings  = @()

    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"
        $apps = @($manifest.Package.Applications.Application)

        # Detect existing PSF
        $hasPsf = ($apps.Executable -match 'PsfLauncher').Count -gt 0
        if ($hasPsf) {
            $findings += [pscustomobject]@{
                Severity     = 'Info'
                Category     = 'PSF'
                Symptom      = 'Package already wraps applications with PsfLauncher.'
                Recommendation = 'Inspect existing config.json before adding more fixups.'
                AppId        = ($apps | Where-Object Executable -match 'PsfLauncher').Id -join ','
            }
        }

        foreach ($app in $apps) {
            $exe = $app.Executable
            if (-not $exe) { continue }

            # Working directory heuristic: exe lives in a subfolder
            if ($exe.Contains('\') -and -not $hasPsf) {
                $relDir = $exe.Substring(0, $exe.LastIndexOf('\'))
                $exeFs  = Join-Path $workspace $exe
                if (Test-Path $exeFs) {
                    $companions = Get-ChildItem (Split-Path $exeFs) -File -ErrorAction SilentlyContinue |
                                  Where-Object { $_.Extension -in '.ini', '.cfg', '.config', '.txt', '.dat', '.dll' }
                    if ($companions) {
                        $findings += [pscustomobject]@{
                            Severity        = 'Warning'
                            Category        = 'WorkingDirectory'
                            Symptom         = "Executable depends on companion files in $relDir but no workingDirectory set."
                            Recommendation  = "Add PSF with workingDirectory='$($relDir.Replace('\','/'))/'."
                            AppId           = $app.Id
                            Evidence        = ($companions | Select-Object -First 5 -ExpandProperty Name) -join ', '
                        }
                    }
                }
            }

            # Write-permission heuristic: log/cache/data files shipped under VFS
            $appDir = if ($exe.Contains('\')) { Join-Path $workspace ($exe.Substring(0, $exe.LastIndexOf('\'))) } else { $workspace }
            if (Test-Path $appDir) {
                $writableHints = Get-ChildItem $appDir -Recurse -File -ErrorAction SilentlyContinue |
                                 Where-Object { $_.Extension -in '.log', '.tmp', '.cache' -or
                                                $_.Name -match '^(settings|user|state)\.' }
                if ($writableHints) {
                    $base = ($exe.Substring(0, $exe.LastIndexOf('\'))).Replace('\','/') + '/'
                    $findings += [pscustomobject]@{
                        Severity        = 'Warning'
                        Category        = 'FileRedirectionFixup'
                        Symptom         = 'Writable-looking files shipped inside the VFS payload.'
                        Recommendation  = "Apply FileRedirectionFixup -Base '$base' -Patterns '.*\.log','.*\.tmp'"
                        AppId           = $app.Id
                        Evidence        = ($writableHints | Select-Object -First 5 -ExpandProperty Name) -join ', '
                    }
                }
            }
        }

        # Multi-app shared folder
        if ($apps.Count -gt 1 -and -not $hasPsf) {
            $findings += [pscustomobject]@{
                Severity        = 'Info'
                Category        = 'MultiApp'
                Symptom         = "Package contains $($apps.Count) Applications."
                Recommendation  = 'PSF will create one PsfLauncher per app; ensure all of them are listed in config.json applications[].'
                AppId           = ($apps.Id -join ',')
            }
        }

        # Merge in TMEditX-style heuristic findings (uninstaller artefacts,
        # Run keys, alias suggestions, missing VC runtimes). Defined in
        # MSIX.Heuristics.ps1 — same module scope, so just call it.
        if (Get-Command Get-MsixHeuristicFindings -ErrorAction SilentlyContinue) {
            try {
                $heuristicFindings = Get-MsixHeuristicFindings -PackagePath $PackagePath
                if ($heuristicFindings) { $findings += @($heuristicFindings) }
            } catch {
                Write-MsixLog Debug "Heuristics raised: $_"
            }
        }

        return $findings

    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


function Get-MsixCompatibilityReport {
    <#
    .SYNOPSIS
        Combines static analysis with optional procmon failures and produces a
        single report object with recommended fixup hashtables ready to feed
        into Add-MsixPsfV2 / Invoke-MsixPipeline.

    .PARAMETER PackagePath
        .msix file.

    .PARAMETER PmlPath
        Optional procmon log captured with Invoke-MsixProcMonCapture.

    .PARAMETER ProcessName
        Optional procmon process-name filter.

    .OUTPUTS
        [pscustomobject] with Findings (array) and SuggestedFixups (hashtable[]).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [string]$PmlPath,
        [string]$TraceLogPath,
        [string]$ProcessName
    )

    Write-MsixLog Info "Static analysis: $PackagePath"
    $static = Get-MsixStaticAnalysis -PackagePath $PackagePath

    # ── Dynamic: trace fixup output (DebugView log) ──
    $traceFindings = @()
    if ($TraceLogPath) {
        Write-MsixLog Info "Trace analysis: $TraceLogPath"
        $traceFindings = @(Get-MsixTraceFailures -Path $TraceLogPath | ConvertFrom-MsixTraceToFindings)
    }

    $dynamic = @()
    if ($PmlPath) {
        Write-MsixLog Info "Dynamic analysis: $PmlPath"
        $failures = Get-MsixProcMonFailures -PmlPath $PmlPath -ProcessName $ProcessName
        foreach ($f in $failures) {
            foreach ($map in $script:FailurePatternMap) {
                $combined = "$($f.Result) $($f.Path) $($f.Detail)"
                if ($combined -match $map.Pattern) {
                    $dynamic += [pscustomobject]@{
                        Severity       = 'Error'
                        Category       = $map.Fixup
                        Symptom        = "$($f.Operation) on '$($f.Path)' returned $($f.Result)"
                        Recommendation = $map.Reason
                        AppId          = $null
                        Evidence       = "$($f.'Process Name'): $($f.Operation)"
                    }
                    break
                }
            }
        }
    }

    $allFindings = @($static) + @($dynamic) + @($traceFindings)

    # Synthesise concrete fixup hashtables for the ones we have enough info for
    $suggested = @()
    foreach ($f in $allFindings) {
        switch ($f.Category) {
            'WorkingDirectory' {
                # We don't add a fixup; this is handled via -WorkingDirectory in Add-MsixPsfV2
            }
            'FileRedirectionFixup' {
                # Pull base from the recommendation text
                if ($f.Recommendation -match "-Base '([^']+)'") {
                    $base = $matches[1]
                    $suggested += New-MsixPsfFileRedirectionConfig -Base $base -Patterns '.*\.log', '.*\.tmp', '.*\.cache'
                }
            }
            'RegLegacyFixups' {
                $suggested += New-MsixPsfRegLegacyConfig -Hive HKLM -Access Full2MaxAllowed -Patterns 'SOFTWARE\*'
            }
        }
    }

    $report = [pscustomobject]@{
        PackagePath         = $PackagePath
        Findings            = $allFindings
        SuggestedFixups     = ($suggested | Select-Object -Unique)
        ProcMonLog          = $PmlPath
        RecommendedCommands = $null
    }

    # Generate copy-paste-ready PowerShell for the operator. Defined in
    # MSIX.Debug.ps1 and is dot-sourced into the same module scope.
    if (Get-Command Get-MsixDebugRecommendations -ErrorAction SilentlyContinue) {
        $report.RecommendedCommands = Get-MsixDebugRecommendations -Report $report -PackagePath $PackagePath
    }

    return $report
}


function Invoke-MsixInvestigation {
    <#
    .SYNOPSIS
        End-to-end investigation orchestrator. Runs static analysis (always) and,
        if the package is installed, optionally drives procmon + parses results.

    .PARAMETER PackagePath
        .msix file to investigate.

    .PARAMETER WithProcMon
        Also capture a runtime trace under Process Monitor. Requires the package
        to be installed and procmon.exe available.

    .PARAMETER PackageFamilyName / AppId
        Required when -WithProcMon is set.

    .PARAMETER DurationSeconds
        How long to capture for. Default 30s.

    .EXAMPLE
        Invoke-MsixInvestigation -PackagePath app.msix

    .EXAMPLE
        Invoke-MsixInvestigation -PackagePath app.msix -WithProcMon `
            -PackageFamilyName 'Contoso.App_8wekyb3d8bbwe' -AppId 'App'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [switch]$WithProcMon,
        [string]$PackageFamilyName,
        [string]$AppId,
        [int]$DurationSeconds = 30,
        [string]$ProcessName,
        # Path to a saved DebugView log (or any text file containing
        # PSF TraceFixup OutputDebugString lines).
        [string]$TraceLogPath
    )

    $pml = $null
    if ($WithProcMon) {
        if (-not $PackageFamilyName -or -not $AppId) {
            throw '-WithProcMon requires -PackageFamilyName and -AppId.'
        }
        $pml = Invoke-MsixProcMonCapture -PackageFamilyName $PackageFamilyName `
                                         -AppId $AppId `
                                         -DurationSeconds $DurationSeconds `
                                         -ProcessName $ProcessName
    }

    return Get-MsixCompatibilityReport -PackagePath $PackagePath `
                                       -PmlPath $pml `
                                       -TraceLogPath $TraceLogPath `
                                       -ProcessName $ProcessName
}
