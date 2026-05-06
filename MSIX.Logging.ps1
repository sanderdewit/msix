enum LogLevel { Debug; Info; Warning; Error }

$script:LogLevel = [LogLevel]::Info
$script:LogFile  = $null

function Set-MsixLogLevel {
    param([LogLevel]$Level)
    $script:LogLevel = $Level
}

function Set-MsixLogFile {
    param([string]$Path)
    $script:LogFile = $Path
}

function Write-MsixLog {
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
