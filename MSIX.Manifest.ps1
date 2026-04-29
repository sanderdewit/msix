# Known namespace prefixes used across MSIX manifests
$script:KnownNamespaces = [ordered]@{
    uap      = 'http://schemas.microsoft.com/appx/manifest/uap/windows10'
    uap3     = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/3'
    uap4     = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/4'
    desktop  = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10'
    desktop4 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/4'
    desktop9 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/9'
    com      = 'http://schemas.microsoft.com/appx/manifest/com/windows10'
    rescap   = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities'
}

function Get-MsixManifest {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    [xml]$xml = Get-Content $Path -Raw
    return $xml
}

function Save-MsixManifest {
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest,
        [Parameter(Mandatory)]
        [string]$Path
    )
    $Manifest.Save($Path)
    Write-MsixLog Debug "Manifest saved: $Path"
}

function Add-MsixManifestNamespace {
    <#
    .SYNOPSIS
        Idempotently adds an xmlns prefix and URI to the Package element,
        and appends the prefix to IgnorableNamespaces if not already present.
    #>
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest,
        [Parameter(Mandatory)]
        [string]$Prefix
    )

    $uri = $script:KnownNamespaces[$Prefix]
    if (-not $uri) { throw "Unknown namespace prefix '$Prefix'. Known: $($script:KnownNamespaces.Keys -join ', ')" }

    # Already declared?
    $existing = $Manifest.Package.Attributes | Where-Object { $_.Value -eq $uri }
    if ($existing) { return }

    $Manifest.Package.SetAttribute("xmlns:$Prefix", $uri)

    $ignorable = $Manifest.Package.IgnorableNamespaces
    if ($ignorable -notmatch "\b$([regex]::Escape($Prefix))\b") {
        $Manifest.Package.IgnorableNamespaces = "$ignorable $Prefix".Trim()
    }

    Write-MsixLog Debug "Namespace added: xmlns:$Prefix"
}

function Get-MsixManifestApplications {
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest
    )
    return @($Manifest.Package.Applications.Application)
}

function Get-MsixManifestNamespaceUri {
    param([string]$Prefix)
    return $script:KnownNamespaces[$Prefix]
}

function Set-MsixManifestMaxVersionTested {
    <#
    .SYNOPSIS
        Ensures MaxVersionTested is at least the specified build number.
        Required for desktop9 context menu support (>= 10.0.21301.0).
    #>
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest,
        [int]$MinBuild = 21301
    )

    $tdf = $Manifest.Package.Dependencies.TargetDeviceFamily
    if (-not $tdf) { return }

    $parts = $tdf.MaxVersionTested -split '\.'
    if ($parts.Count -ge 3 -and [int]$parts[2] -lt $MinBuild) {
        $tdf.MaxVersionTested = "$($parts[0]).$($parts[1]).$MinBuild.0"
        Write-MsixLog Info "MaxVersionTested updated to $($tdf.MaxVersionTested)"
    }
}
