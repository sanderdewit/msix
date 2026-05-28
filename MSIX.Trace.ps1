# =============================================================================
# Trace Fixup output parser
# -----------------------------------------------------------------------------
# Reads the OutputDebugString stream produced by PSF TraceFixup.dll, captured
# either by DebugView (saved to a .log/.txt) or via an ETW session.
#
# Each captured line typically looks like:
#
#   [hh:mm:ss.fff PID:TID] CreateFileW: \\?\C:\Program Files\WindowsApps\…\app.log -> ACCESS_DENIED
#   [00:00:01.234   8472:A1B] RegOpenKeyExW: HKLM\SOFTWARE\Vendor -> SUCCESS
#
# DebugView's "Save As" produces tab-separated lines with the timestamp,
# process id and the message:
#
#   <num>\t<elapsed>\t[PID:TID] <function>: <path> -> <result>
#
# This parser is permissive — it tries the structured form first, then falls
# back to a regex over the message text.
# =============================================================================

$script:_TraceLineRegex = [regex]'(?<func>[A-Za-z_][A-Za-z0-9_]+(?:[AW]|Ex[AW]?)?):\s*(?<path>.+?)\s*->\s*(?<result>[A-Z_][A-Z0-9_]+)'
$script:_TraceHeadRegex = [regex]'\[(?<ts>[\d:.]+)?\s*(?<pid>\d+)?:?(?<tid>[0-9A-Fa-f]+)?\]'

function ConvertFrom-MsixTraceLine {
    <#
    .SYNOPSIS
        Parses a single Trace Fixup log line into a structured object.

    .DESCRIPTION
        Accepts one line of OutputDebugString text emitted by PSF's
        TraceFixup.dll (typically captured via DebugView "Save As"). Two
        regexes run against the line:

          1. The function/path/result triplet: 'Func: <path> -> RESULT'.
          2. The leading '[hh:mm:ss.fff PID:TID]' header.

        If the first regex doesn't match, the line is silently skipped
        (returns nothing) so the parser can be used across mixed log files.
        On a match, the function name is mapped to a coarse category
        (filesystem / registry / module-load / other) which is convenient
        for downstream filtering.

    .PARAMETER Line
        A single text line from a DebugView capture. Empty strings are
        accepted (and produce no output). Pipeline input is supported so an
        entire file can be streamed via Get-Content | ConvertFrom-MsixTraceLine.

    .OUTPUTS
        [pscustomobject] with Timestamp, ProcessId, ThreadId, Function,
        Category, Path, Result, Raw. No output for lines that don't match.

    .EXAMPLE
        '[00:00:01.234 8472:A1B] CreateFileW: C:\Program Files\WindowsApps\app\log.txt -> ACCESS_DENIED' |
            ConvertFrom-MsixTraceLine

    .EXAMPLE
        Get-Content .\debugview.log | ConvertFrom-MsixTraceLine |
            Where-Object Category -eq 'filesystem'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Line
    )
    PROCESS {
        if ([string]::IsNullOrWhiteSpace($Line)) { return }

        $m = $script:_TraceLineRegex.Match($Line)
        if (-not $m.Success) { return }

        $func   = $m.Groups['func'].Value
        $path   = $m.Groups['path'].Value.Trim()
        $result = $m.Groups['result'].Value

        $head = $script:_TraceHeadRegex.Match($Line)
        $ts   = if ($head.Success) { $head.Groups['ts'].Value }  else { $null }
        $procId = if ($head.Success -and $head.Groups['pid'].Value) { [int]$head.Groups['pid'].Value } else { $null }
        $tid  = if ($head.Success) { $head.Groups['tid'].Value } else { $null }

        # Categorise by function-name prefix
        $category = switch -Regex ($func) {
            '^(CreateFile|ReadFile|WriteFile|Delete|MoveFile|CopyFile|FindFirstFile|GetFileAttributes|SetFileAttributes)' { 'filesystem' }
            '^(Reg)'   { 'registry' }
            '^(LoadLibrary|GetModuleHandle|GetProcAddress)' { 'module-load' }
            default    { 'other' }
        }

        return [pscustomobject]@{
            Timestamp = $ts
            ProcessId = $procId
            ThreadId  = $tid
            Function  = $func
            Category  = $category
            Path      = $path
            Result    = $result
            Raw       = $Line
        }
    }
}


function Get-MsixTraceOutput {
    <#
    .SYNOPSIS
        Parses an entire DebugView log file (or any text file containing PSF
        TraceFixup output) into structured objects.

    .DESCRIPTION
        Streams the file through ConvertFrom-MsixTraceLine and applies the
        optional ProcessId / FunctionPattern filters. Lines that don't look
        like TraceFixup output (banners, blank lines, other process noise)
        are dropped. Use Get-MsixTraceFailure to narrow further to
        non-success rows.

    .PARAMETER Path
        Path to the saved log (DebugView "Save As" or any text dump that
        contains TraceFixup messages).

    .PARAMETER ProcessId
        Optional filter on process id (matches the PID in [PID:TID] header).

    .PARAMETER FunctionPattern
        Optional regex matched against Function (e.g. '^Reg' to keep registry only).

    .OUTPUTS
        [pscustomobject] one per parseable line. Same shape as
        ConvertFrom-MsixTraceLine.

    .EXAMPLE
        Get-MsixTraceOutput -Path C:\debug\app.log | Format-Table

    .EXAMPLE
        # Registry activity only, for a specific process
        Get-MsixTraceOutput -Path .\app.log -ProcessId 8472 -FunctionPattern '^Reg'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [int]$ProcessId,
        [string]$FunctionPattern
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "Trace log not found: $Path" }

    Get-Content -LiteralPath $Path |
        ConvertFrom-MsixTraceLine |
        Where-Object { $_ } |
        Where-Object {
            (-not $ProcessId -or $_.ProcessId -eq $ProcessId) -and
            (-not $FunctionPattern -or $_.Function -match $FunctionPattern)
        }
}


function Get-MsixTraceFailure {
    <#
    .SYNOPSIS
        Filters Get-MsixTraceOutput to only the rows whose Result indicates a
        failure (anything other than SUCCESS / NO_ERROR / ERROR_SUCCESS).

    .DESCRIPTION
        Convenience wrapper around Get-MsixTraceOutput that drops successful
        operations, leaving the rows most useful for diagnosing fixup needs.
        Feed the output into ConvertFrom-MsixTraceToFinding to produce the
        same finding shape that Get-MsixStaticAnalysis emits.

    .PARAMETER Path
        Trace log path.

    .PARAMETER ProcessId
        Optional filter forwarded to Get-MsixTraceOutput.

    .PARAMETER FunctionPattern
        Optional regex forwarded to Get-MsixTraceOutput.

    .OUTPUTS
        [pscustomobject] one per failing trace row.

    .EXAMPLE
        Get-MsixTraceFailure -Path .\app.log | Format-Table Function, Path, Result

    .EXAMPLE
        # Identify only registry-side failures
        Get-MsixTraceFailure -Path .\app.log -FunctionPattern '^Reg'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [int]$ProcessId,
        [string]$FunctionPattern
    )

    Get-MsixTraceOutput -Path $Path -ProcessId $ProcessId -FunctionPattern $FunctionPattern |
        Where-Object {
            $_.Result -and
            $_.Result -ne 'SUCCESS' -and
            $_.Result -ne 'NO_ERROR' -and
            $_.Result -ne 'ERROR_SUCCESS'
        }
}


function ConvertFrom-MsixTraceToFinding {
    <#
    .SYNOPSIS
        Converts trace failures into the same finding shape that
        Get-MsixStaticAnalysis emits, so they can be merged into a
        compatibility report.

    .DESCRIPTION
        Maps observed paths/results to the appropriate fixup category:
          - Path under System32/SysWOW64       => WorkingDirectory
          - Path under WindowsApps + write/del => FileRedirectionFixup
          - Registry HKLM + access denied      => RegLegacyFixups
          - LoadLibrary failure                => DynamicLibraryFixup (manual)

        Findings are deduplicated by (Category + leaf path). Rows that
        don't fit any category are dropped.

    .PARAMETER Failures
        Output of Get-MsixTraceFailure. Accepts pipeline input.

    .OUTPUTS
        [pscustomobject] one per finding, with Severity, Category, Symptom,
        Recommendation, AppId, Evidence -- the same shape used elsewhere by
        Get-MsixStaticAnalysis / Invoke-MsixInvestigation.

    .EXAMPLE
        # Saved DebugView trace -> structured findings -> investigation report
        Get-MsixTraceFailure -Path .\app.log |
            ConvertFrom-MsixTraceToFinding |
            Invoke-MsixInvestigation -PackagePath .\app.msix

    .EXAMPLE
        Get-MsixTraceFailure -Path .\app.log |
            ConvertFrom-MsixTraceToFinding |
            Where-Object Category -eq 'FileRedirectionFixup'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject[]]$Failures
    )
    BEGIN {
        $seen = @{}
        $out  = [System.Collections.Generic.List[object]]::new()
    }
    PROCESS {
        foreach ($f in $Failures) {
            if (-not $f) { continue }

            $category, $reason = switch -Regex ($f.Path) {
                '\\(System32|SysWOW64)\\' {
                    'WorkingDirectory',
                    'App reads files from CWD which defaults to System32; set workingDirectory.'
                }
                'WindowsApps' {
                    'FileRedirectionFixup',
                    'App writes inside Program Files\WindowsApps (read-only).'
                }
                '^HK(LM|EY_LOCAL_MACHINE)\\' {
                    'RegLegacyFixups',
                    'App requests write/full access to HKLM keys.'
                }
                default { $null, $null }
            }
            if (-not $category -and $f.Function -match '^LoadLibrary' -and $f.Result -ne 'SUCCESS') {
                $category = 'DynamicLibraryFixup'
                $reason   = 'Library could not be loaded; consider DynamicLibraryFixup.'
            }
            if (-not $category) { continue }

            $leaf = Split-Path -Path $f.Path -Leaf -ErrorAction SilentlyContinue
            $key  = "$category|$leaf"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            $out.Add([pscustomobject]@{
                Severity       = 'Error'
                Category       = $category
                Symptom        = "$($f.Function) on '$($f.Path)' returned $($f.Result)"
                Recommendation = $reason
                AppId          = $null
                Evidence       = "$($f.Function) [$($f.ProcessId):$($f.ThreadId)]"
            })
        }
    }
    END { $out }
}


# Backward-compatible plural aliases
Set-Alias Get-MsixTraceFailures Get-MsixTraceFailure
Set-Alias ConvertFrom-MsixTraceToFindings ConvertFrom-MsixTraceToFinding
