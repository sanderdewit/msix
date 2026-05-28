enum LogLevel { Debug; Info; Warning; Error }

$script:LogLevel = [LogLevel]::Info
$script:LogFile  = $null

function Set-MsixLogLevel {
    <#
    .SYNOPSIS
        Sets the minimum log level emitted by Write-MsixLog.

    .DESCRIPTION
        Messages below the selected level are silently dropped. Defaults to
        Info when the module loads. Affects both the Information stream and
        the optional log file configured via Set-MsixLogFile.

    .PARAMETER Level
        Minimum level to emit: Debug, Info, Warning, or Error.

    .EXAMPLE
        # Show everything (useful for troubleshooting pipeline runs)
        Set-MsixLogLevel -Level Debug

    .EXAMPLE
        # Quiet down to warnings and errors only
        Set-MsixLogLevel -Level Warning
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param([LogLevel]$Level)
    $script:LogLevel = $Level
}

function Set-MsixLogFile {
    <#
    .SYNOPSIS
        Enables appending Write-MsixLog output to a file.

    .DESCRIPTION
        When set, every line emitted by Write-MsixLog is also appended to the
        given path. The Information stream still receives the line as usual.
        Pass an empty string or call again with `$null` to disable file logging.

    .PARAMETER Path
        Absolute path of the log file. The file is created on first write; the
        directory must already exist.

    .EXAMPLE
        Set-MsixLogFile -Path 'C:\Logs\msix-pipeline.log'
        Invoke-MsixPipeline -PackagePath app.msix -Config $cfg
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param([string]$Path)
    $script:LogFile = $Path
}

function Write-MsixLog {
    <#
    .SYNOPSIS
        Writes a timestamped diagnostic line at the given level.

    .DESCRIPTION
        Used by every cmdlet in the module for progress and diagnostic
        output. Honours the level filter set by Set-MsixLogLevel and writes
        through Write-Information (not Write-Host) so callers can capture
        the stream. When Set-MsixLogFile is configured, the same line is
        appended to that file.

    .PARAMETER Level
        Severity of the message: Debug, Info, Warning, or Error.

    .PARAMETER Message
        Text to log. Timestamp and level are added automatically.

    .EXAMPLE
        Write-MsixLog -Level Info -Message 'Starting pipeline'

    .EXAMPLE
        Write-MsixLog -Level Debug -Message "Unpacked to: $workspace"
    #>
    param(
        [LogLevel]$Level,
        [string]$Message
    )

    if ($Level -lt $script:LogLevel) { return }

    $ts     = Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'
    $line   = "[$ts][$Level] $Message"

    Write-Information -MessageData $line -InformationAction Continue

    if ($script:LogFile) {
        Add-Content -Path $script:LogFile -Value $line
    }
}
