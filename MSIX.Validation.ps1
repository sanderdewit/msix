function Test-MsixManifest {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "Manifest not found: $Path"
    }

    try {
        [xml]$xml = Get-Content $Path -Raw -ErrorAction Stop
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

    if (-not (Test-Path $Path)) {
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
    if ($Result.ExitCode -ne 0) {
        $detail = $Result.StdErr
        if (-not $detail) { $detail = $Result.StdOut }
        throw "$Operation failed (exit $($Result.ExitCode)): $detail"
    }
}
