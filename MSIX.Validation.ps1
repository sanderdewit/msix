function Test-MsixManifest {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
        throw "Manifest not found: $Path"
    }

    try {
        [xml]$xml = _MsixLoadXmlSecure -Path $Path
    } catch {
        throw "Manifest is not valid XML: $_"
    }

    foreach ($field in @('Name', 'Publisher', 'Version')) {
        if (-not $xml.Package.Identity.$field) {
            throw "Manifest missing Identity.$field"
        }
    }

    if (-not $xml.Package.Applications.Application) {
        throw "Manifest contains no Application elements"
    }

    Write-MsixLog Debug "Manifest OK: $Path"
    return $true
}

function Test-MsixPsfConfig {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
        throw "PSF config not found: $Path"
    }

    try {
        $json = Get-Content $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "PSF config is not valid JSON: $_"
    }

    if (-not $json.applications) {
        throw "PSF config missing 'applications' array"
    }
    if (-not $json.processes) {
        throw "PSF config missing 'processes' array"
    }

    Write-MsixLog Debug "PSF config OK: $Path"
    return $true
}

function Assert-MsixProcessSuccess {
    param(
        [Parameter(Mandatory)]
        [pscustomobject]$Result,
        [string]$Operation = 'Process'
    )
    if ($Result.ExitCode -eq 0) { return }

    # Include BOTH streams in the error message when present. Tools like
    # MakeAppx and SignTool sometimes split the useful diagnostic across
    # stderr (one line) and stdout (the full multi-line failure detail);
    # picking only one drops information the operator needs to act on.
    $parts = @()
    if ($Result.StdErr) { $parts += "stderr: $($Result.StdErr.Trim())" }
    if ($Result.StdOut) { $parts += "stdout: $($Result.StdOut.Trim())" }
    if ($parts.Count -eq 0) { $parts += '(no output)' }
    throw "$Operation failed (exit $($Result.ExitCode)). $([string]::Join(' | ', $parts))"
}
