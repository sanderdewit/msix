function Test-MsixManifest {
    <#
    .SYNOPSIS
        Validates that an AppxManifest.xml is well-formed and contains the
        Identity + Application elements MSIX requires.

    .DESCRIPTION
        Parses the file with secure XML settings (DTD prohibited, entities
        capped) and asserts that Identity.Name, Identity.Publisher,
        Identity.Version, and at least one Applications/Application element
        are present. Throws on the first missing field; returns $true on
        success so the call site can use it in boolean contexts.

        See Get-Help Test-MsixPsfConfig for the matching PSF config check.

    .PARAMETER Path
        Absolute path to an AppxManifest.xml file. Typically the manifest
        inside an unpacked workspace.

    .OUTPUTS
        [bool] $true when validation succeeds; otherwise throws.

    .EXAMPLE
        Test-MsixManifest -Path 'C:\workspace\AppxManifest.xml'
    #>
    [OutputType([bool])]
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

    Write-MsixLog -Level Debug -Message "Manifest OK: $Path"
    return $true
}

function Test-MsixPsfConfig {
    <#
    .SYNOPSIS
        Validates that a PSF config.json parses as JSON and contains the
        top-level applications and processes arrays PSFLauncher requires.

    .DESCRIPTION
        Add-MsixPsfV2 calls this after generating or merging config.json so
        a malformed config fails the pipeline before repack. Throws on the
        first missing structural element; returns $true on success.

    .PARAMETER Path
        Absolute path to a config.json file.

    .OUTPUTS
        [bool] $true when validation succeeds; otherwise throws.

    .EXAMPLE
        Test-MsixPsfConfig -Path 'C:\workspace\App\config.json'
    #>
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) {
        throw "PSF config not found: $Path"
    }

    try {
        $json = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "PSF config is not valid JSON: $_"
    }

    if (-not $json.applications) {
        throw "PSF config missing 'applications' array"
    }
    if (-not $json.processes) {
        throw "PSF config missing 'processes' array"
    }

    Write-MsixLog -Level Debug -Message "PSF config OK: $Path"
    return $true
}

function Assert-MsixProcessSuccess {
    <#
    .SYNOPSIS
        Throws when an Invoke-MsixProcess result indicates failure, surfacing
        both stdout and stderr in the error message.

    .DESCRIPTION
        External tools like MakeAppx and signtool routinely split diagnostic
        output across stderr (one line) and stdout (the multi-line detail).
        This helper concatenates both streams so the operator sees the full
        failure, then throws when ExitCode is non-zero. No-op on success.

    .PARAMETER Result
        The object returned by Invoke-MsixProcess: ExitCode, StdOut, StdErr.

    .PARAMETER Operation
        Short label used in the thrown error (e.g. 'MakeAppx unpack').

    .EXAMPLE
        $r = Invoke-MsixProcess -FilePath $makeAppx -ArgumentList @('unpack','/p',$pkg,'/d',$ws,'/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unpack'
    #>
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
