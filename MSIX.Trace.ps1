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
        Returns $null for lines that don't match the expected shape.
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

    .PARAMETER Path
        Path to the saved log (DebugView "Save As" or any text dump that
        contains TraceFixup messages).

    .PARAMETER ProcessId
        Optional filter on process id (matches the PID in [PID:TID] header).

    .PARAMETER FunctionPattern
        Optional regex matched against Function (e.g. '^Reg' to keep registry only).

    .OUTPUTS
        [pscustomobject] one per parseable line.

    .EXAMPLE
        Get-MsixTraceOutput -Path C:\debug\app.log | Format-Table
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [int]$ProcessId,
        [string]$FunctionPattern
    )

    if (-not (Test-Path $Path)) { throw "Trace log not found: $Path" }

    Get-Content -LiteralPath $Path |
        ConvertFrom-MsixTraceLine |
        Where-Object { $_ } |
        Where-Object {
            (-not $ProcessId -or $_.ProcessId -eq $ProcessId) -and
            (-not $FunctionPattern -or $_.Function -match $FunctionPattern)
        }
}


function Get-MsixTraceFailures {
    <#
    .SYNOPSIS
        Filters Get-MsixTraceOutput to only the rows whose Result indicates a
        failure (anything other than SUCCESS / NO_ERROR / null).

    .PARAMETER Path
        Trace log path.

    .PARAMETER ProcessId / FunctionPattern
        Forwarded to Get-MsixTraceOutput.
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


function ConvertFrom-MsixTraceToFindings {
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

        Findings are deduplicated by (Category + leaf path).

    .PARAMETER Failures
        Output of Get-MsixTraceFailures.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [psobject[]]$Failures
    )
    BEGIN {
        $seen = @{}
        $out  = New-Object System.Collections.Generic.List[object]
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

            $leaf = Split-Path $f.Path -Leaf -ErrorAction SilentlyContinue
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
