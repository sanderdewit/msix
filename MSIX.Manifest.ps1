function _MsixLoadXmlSecure {
    <#
    .SYNOPSIS
        Loads XML from a file or string with DTD processing prohibited and
        external entity resolution disabled. Use for ALL untrusted XML input
        (anything that came out of a user-supplied MSIX archive).
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [OutputType([xml])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path', Position = 0)]
        [string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'Text')]
        [string]$XmlText
    )

    $settings = New-Object System.Xml.XmlReaderSettings
    $settings.DtdProcessing                = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver                  = $null
    $settings.MaxCharactersFromEntities    = 1048576     # 1 MB — sane upper bound
    $settings.MaxCharactersInDocument      = 268435456   # 256 MB — generous but bounded

    $doc = New-Object System.Xml.XmlDocument
    $doc.PreserveWhitespace = $true
    $doc.XmlResolver        = $null

    $stringReader = $null
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "XML file not found: $Path"
        }
        $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    } else {
        $stringReader = New-Object System.IO.StringReader $XmlText
        $reader       = [System.Xml.XmlReader]::Create($stringReader, $settings)
    }

    try {
        $doc.Load($reader)
    } finally {
        $reader.Dispose()
        if ($stringReader) { $stringReader.Dispose() }
    }
    return $doc
}

# Known namespace prefixes used across MSIX manifests
$script:KnownNamespaces = [ordered]@{
    uap      = 'http://schemas.microsoft.com/appx/manifest/uap/windows10'
    uap2     = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/2'   # SupportedVerbs
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

function New-MsixManifestDocument {
    <#
    .SYNOPSIS
        Creates a test-friendly manifest document wrapper with namespace-aware
        XPath helpers.

    .DESCRIPTION
        This is the pure parser/navigator entry point. It accepts raw XML text,
        an existing XmlDocument, or a path that Get-MsixManifest can read. The
        returned object keeps the XmlDocument and XmlNamespaceManager together
        so tests and transform helpers can use consistent XPath without package
        unpack/repack IO.

    .EXAMPLE
        $m = New-MsixManifestDocument -XmlText $sampleManifest
        Get-MsixManifestApplication -Manifest $m -AppId App
    #>
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Path', Position = 0)]
        [string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'XmlText')]
        [string]$XmlText,
        [Parameter(Mandatory, ParameterSetName = 'Document')]
        [xml]$Document
    )

    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        $Document = _MsixLoadXmlSecure -Path $Path
    } elseif ($PSCmdlet.ParameterSetName -eq 'XmlText') {
        $Document = _MsixLoadXmlSecure -XmlText $XmlText
    }

    $nsMgr = New-Object System.Xml.XmlNamespaceManager($Document.NameTable)
    $nsMgr.AddNamespace('f', 'http://schemas.microsoft.com/appx/manifest/foundation/windows10')
    foreach ($prefix in $script:KnownNamespaces.Keys) {
        $nsMgr.AddNamespace($prefix, $script:KnownNamespaces[$prefix])
    }

    return [pscustomobject]@{
        PSTypeName         = 'MSIX.ManifestDocument'
        Document           = $Document
        NamespaceManager   = $nsMgr
        Package            = $Document.DocumentElement
    }
}

function Select-MsixManifestNode {
    <#
    .SYNOPSIS
        Selects the first manifest node matching a namespace-aware XPath.
    #>
    [CmdletBinding()]
    [OutputType([System.Xml.XmlNode])]
    param(
        [Parameter(Mandatory)]
        $Manifest,
        [Parameter(Mandatory)]
        [string]$XPath
    )

    $manifestDocument = if ($Manifest.PSTypeNames -contains 'MSIX.ManifestDocument') {
        $Manifest
    } else {
        New-MsixManifestDocument -Document $Manifest
    }

    return $manifestDocument.Document.SelectSingleNode($XPath, $manifestDocument.NamespaceManager)
}

function Select-MsixManifestNodes {
    <#
    .SYNOPSIS
        Selects all manifest nodes matching a namespace-aware XPath.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        $Manifest,
        [Parameter(Mandatory)]
        [string]$XPath
    )

    $manifestDocument = if ($Manifest.PSTypeNames -contains 'MSIX.ManifestDocument') {
        $Manifest
    } else {
        New-MsixManifestDocument -Document $Manifest
    }

    return @($manifestDocument.Document.SelectNodes($XPath, $manifestDocument.NamespaceManager))
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
        return (_MsixLoadXmlSecure -Path $candidate)
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
                return (_MsixLoadXmlSecure -Path $out)
            } finally { $zip.Dispose() }
        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Default: assume an XML file path.
    return (_MsixLoadXmlSecure -Path $Path)
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

function Get-MsixManifestApplication {
    <#
    .SYNOPSIS
        Returns Application elements from the manifest. Single canonical
        reader for both the "one app" and "all apps" cases — singular noun
        per Get-Verb / PSUseSingularNouns convention (cf. Get-ChildItem).

    .DESCRIPTION
        Parameter sets:
          First (default) — returns the first Application element.
          ById            — returns the single Application matching -AppId.
          All             — returns every Application as an array.
    #>
    [CmdletBinding(DefaultParameterSetName = 'First')]
    param(
        [Parameter(Mandatory)]
        $Manifest,
        [Parameter(Mandatory, ParameterSetName = 'ById')]
        [string]$AppId,
        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All
    )

    $manifestDocument = if ($Manifest.PSTypeNames -contains 'MSIX.ManifestDocument') {
        $Manifest
    } else {
        New-MsixManifestDocument -Document $Manifest
    }

    if ($All) {
        $nodes = Select-MsixManifestNodes -Manifest $manifestDocument -XPath '//f:Application'

        if ($nodes -and $nodes.Count -gt 0) {
            return @($nodes)
        }

        # Fallback: namespace-agnostic XPath (handles non-standard manifests)
        $nodes = $manifestDocument.Document.SelectNodes('//*[local-name()="Application"]')
        if ($nodes -and $nodes.Count -gt 0) {
            return @($nodes)
        }

        return @()
    }

    if ($AppId) {
        $escapedId = $AppId.Replace("'", "&apos;")
        $node = $manifestDocument.Document.SelectSingleNode("//f:Application[@Id='$escapedId']", $manifestDocument.NamespaceManager)
    } else {
        $node = $manifestDocument.Document.SelectSingleNode('//f:Application[1]', $manifestDocument.NamespaceManager)
    }

    if ($node) { return $node }

    # Fallback: namespace-agnostic search for non-standard manifests
    $applicationNodes = @($manifestDocument.Document.SelectNodes('//*[local-name()="Application"]'))
    if ($AppId) {
        return $applicationNodes | Where-Object { $_.GetAttribute('Id') -eq $AppId } | Select-Object -First 1
    }
    return $applicationNodes | Select-Object -First 1
}

function Get-MsixManifestApplications {
    <#
    .SYNOPSIS
        DEPRECATED. Use Get-MsixManifestApplication -All.
        Returns every Application XmlElement from the manifest.

    .DESCRIPTION
        Thin wrapper retained for backward compatibility. New code should call
        Get-MsixManifestApplication -All directly. The plural noun violates
        PSUseSingularNouns; the suppression is documented inline.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '',
        Justification = 'Plural retained as deprecated wrapper for backward compatibility; new code uses Get-MsixManifestApplication -All.')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Manifest
    )
    Write-MsixLog Debug 'Get-MsixManifestApplications is deprecated; use Get-MsixManifestApplication -All.'
    return Get-MsixManifestApplication -Manifest $Manifest -All
}

function Set-MsixManifestPublisher {
    <#
    .SYNOPSIS
        Pure in-memory transform: updates Identity.Publisher on the manifest.
    .DESCRIPTION
        Testable without unpacking a package — accepts an [xml] document and
        mutates it in place. Returns the same document for pipeline use.
    .EXAMPLE
        [xml]$m = $manifestXml
        Set-MsixManifestPublisher -Manifest $m -Publisher 'CN=Contoso, O=Contoso, C=NL'
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure in-memory transform on a caller-owned XmlDocument; no IO, no side effects outside the input object.')]
    [CmdletBinding()]
    [OutputType([System.Xml.XmlDocument])]
    param(
        [Parameter(Mandatory)] [xml]$Manifest,
        [Parameter(Mandatory)] [string]$Publisher
    )
    $Manifest.Package.Identity.Publisher = $Publisher
    return $Manifest
}

function Set-MsixManifestIdentity {
    <#
    .SYNOPSIS
        Pure in-memory transform: updates one or more Identity attributes
        (Name, Publisher, Version) on the manifest. Only the parameters you
        supply are changed.
    .EXAMPLE
        Set-MsixManifestIdentity -Manifest $m -Version '2.0.0.0'
    .EXAMPLE
        Set-MsixManifestIdentity -Manifest $m -Name 'Contoso.App' `
            -Publisher 'CN=Contoso, O=Contoso, C=NL' -Version '1.2.3.4'
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure in-memory transform on a caller-owned XmlDocument; no IO, no side effects outside the input object.')]
    [CmdletBinding()]
    [OutputType([System.Xml.XmlDocument])]
    param(
        [Parameter(Mandatory)] [xml]$Manifest,
        [string]$Name,
        [string]$Publisher,
        [ValidatePattern('^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$',
            ErrorMessage = 'Version must be a 4-part dotted-decimal like 1.2.3.4.')]
        [string]$Version
    )
    if ($PSBoundParameters.ContainsKey('Name'))      { $Manifest.Package.Identity.Name      = $Name }
    if ($PSBoundParameters.ContainsKey('Publisher')) { $Manifest.Package.Identity.Publisher = $Publisher }
    if ($PSBoundParameters.ContainsKey('Version'))   { $Manifest.Package.Identity.Version   = $Version }
    return $Manifest
}

function Get-MsixManifestNamespaceUri {
    param([string]$Prefix)
    return $script:KnownNamespaces[$Prefix]
}

function Set-MsixManifestMaxVersionTested {
    <#
    .SYNOPSIS
        Ensures MaxVersionTested is at least the specified build number.
        Pass -MinBuild with the feature's required build (e.g. 19041, 22000).
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest,
        [int]$MinBuild = 19041
    )

    $tdf = $Manifest.Package.Dependencies.TargetDeviceFamily
    if (-not $tdf) { return }

    $parts = $tdf.MaxVersionTested -split '\.'
    if ($parts.Count -ge 3 -and [int]$parts[2] -lt $MinBuild) {
        $tdf.MaxVersionTested = "$($parts[0]).$($parts[1]).$MinBuild.0"
        Write-MsixLog Info "MaxVersionTested updated to $($tdf.MaxVersionTested)"
    }
}
