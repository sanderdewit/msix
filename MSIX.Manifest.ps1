# Known namespace prefixes used across MSIX manifests
$script:KnownNamespaces = [ordered]@{
    uap      = 'http://schemas.microsoft.com/appx/manifest/uap/windows10'
    uap3     = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/3'
    uap4     = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/4'
    uap5     = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/5'   # windows.startupTask
    uap6     = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/6'   # LoaderSearchPathOverride
    uap10    = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'  # InstalledLocationVirtualization
    desktop  = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10'
    desktop2 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/2' # FirewallRules
    desktop4 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/4'
    desktop6 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/6' # File/Registry write virtualization
    desktop9 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/9'
    com      = 'http://schemas.microsoft.com/appx/manifest/com/windows10'
    rescap         = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities'
    virtualization = 'http://schemas.microsoft.com/appx/manifest/virtualization/windows10'
}

function Get-MsixManifest {
    <#
    .SYNOPSIS
        Returns the AppxManifest.xml as an [xml] document.

    .DESCRIPTION
        Polymorphic input:
          - .msix / .appx / .msixbundle / .appxbundle  -> extracts AppxManifest.xml
            from inside the archive (no MakeAppx required, uses ZipFile)
          - any other path                              -> read as XML directly
            (typical use: the AppxManifest.xml of an already-unpacked workspace)

    .PARAMETER Path
        Path to either a packaged .msix file or an extracted AppxManifest.xml.

    .EXAMPLE
        $m = Get-MsixManifest -Path C:\drop\app.msix
        $m.Package.Identity.Name

    .EXAMPLE
        $m = Get-MsixManifest -Path C:\workspace\AppxManifest.xml
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) {
        throw "Path not found: $Path"
    }
    $item = Get-Item $Path

    if ($item.PSIsContainer) {
        # Folder — assume it's an unpacked workspace; look for AppxManifest.xml
        $candidate = Join-Path $item.FullName 'AppxManifest.xml'
        if (-not (Test-Path $candidate)) {
            throw "No AppxManifest.xml under '$($item.FullName)'."
        }
        [xml]$xml = Get-Content $candidate -Raw
        return $xml
    }

    if ($item.Extension -in '.msix', '.appx', '.msixbundle', '.appxbundle') {
        # Pull the manifest out of the archive without touching MakeAppx.
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $tmp = New-MsixWorkspace "$($item.BaseName)-mf"
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($item.FullName)
            try {
                $entry = $zip.Entries | Where-Object { $_.Name -eq 'AppxManifest.xml' } |
                         Select-Object -First 1
                if (-not $entry) {
                    throw "AppxManifest.xml not found inside $($item.Name) (is this a bundle? open the inner .msix instead)."
                }
                $out = Join-Path $tmp 'AppxManifest.xml'
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $out, $true)
                [xml]$xml = Get-Content $out -Raw
                return $xml
            } finally { $zip.Dispose() }
        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Default: assume an XML file path.
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

    # Plain 2-arg SetAttribute is correct here: .NET's XmlDocument treats
    # xmlns:* attributes as namespace declarations even without the reserved
    # http://www.w3.org/2000/xmlns/ namespace URI, and Save() serialises them
    # correctly. The 3-arg overload with that URI is rejected by the DOM.
    $Manifest.Package.SetAttribute("xmlns:$Prefix", $uri)

    $ignorable = $Manifest.Package.IgnorableNamespaces
    if ($ignorable -notmatch "\b$([regex]::Escape($Prefix))\b") {
        $Manifest.Package.IgnorableNamespaces = "$ignorable $Prefix".Trim()
    }

    Write-MsixLog Debug "Namespace added: xmlns:$Prefix"
}

function Get-MsixManifestApplications {
    <#
    .SYNOPSIS
        Returns all Application XmlElements from the manifest.
        Uses namespace-aware XPath so it is reliable even after namespace
        declarations have been modified by Add-MsixManifestNamespace.
    #>
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest
    )

    # Namespace-aware XPath (preferred path)
    $nsMgr = New-Object System.Xml.XmlNamespaceManager($Manifest.NameTable)
    $nsMgr.AddNamespace('f', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    $nodes = $Manifest.SelectNodes('//f:Application', $nsMgr)

    if ($nodes -and $nodes.Count -gt 0) {
        return @($nodes)
    }

    # Fallback: namespace-agnostic XPath (handles non-standard manifests)
    $nodes = $Manifest.SelectNodes('//*[local-name()="Application"]')
    if ($nodes -and $nodes.Count -gt 0) {
        return @($nodes)
    }

    return @()
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
