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

    $settings = [System.Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing                = [System.Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver                  = $null
    $settings.MaxCharactersFromEntities    = 1048576     # 1 MB — sane upper bound
    $settings.MaxCharactersInDocument      = 268435456   # 256 MB — generous but bounded

    $doc = [System.Xml.XmlDocument]::new()
    $doc.PreserveWhitespace = $true
    $doc.XmlResolver        = $null

    $stringReader = $null
    if ($PSCmdlet.ParameterSetName -eq 'Path') {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "XML file not found: $Path"
        }
        $reader = [System.Xml.XmlReader]::Create($Path, $settings)
    } else {
        $stringReader = [System.IO.StringReader]::new($XmlText)
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
    uap18    = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/18'  # Win32 App Isolation (TrustLevel/RuntimeBehavior)
    desktop  = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10'
    desktop2 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/2' # FirewallRules
    desktop4 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/4'
    desktop5 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/5'
    desktop6 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/6' # File/Registry write virtualization
    desktop9 = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/9'
    com      = 'http://schemas.microsoft.com/appx/manifest/com/windows10'
    com2     = 'http://schemas.microsoft.com/appx/manifest/com/windows10/2'
    com3     = 'http://schemas.microsoft.com/appx/manifest/com/windows10/3'
    com4     = 'http://schemas.microsoft.com/appx/manifest/com/windows10/4'
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

    .PARAMETER Path
        Filesystem path to an XML file (typically an AppxManifest.xml).

    .PARAMETER XmlText
        Raw XML as a string.

    .PARAMETER Document
        Pre-parsed [xml] document. Use this when you already have a manifest
        loaded (e.g. from Get-MsixManifest).

    .OUTPUTS
        [pscustomobject] with PSTypeName MSIX.ManifestDocument, exposing
        Document, NamespaceManager, and Package properties.

    .EXAMPLE
        $m = New-MsixManifestDocument -XmlText $sampleManifest
        Get-MsixManifestApplication -Manifest $m -AppId App

    .EXAMPLE
        $m = New-MsixManifestDocument -Path 'C:\workspace\AppxManifest.xml'
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

    $nsMgr = [System.Xml.XmlNamespaceManager]::new($Document.NameTable)
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

    .DESCRIPTION
        Uses the namespace manager attached to MSIX.ManifestDocument so XPath
        like '//uap10:Folder' resolves correctly without callers having to
        wire up prefixes themselves. Returns $null if no node matches. For
        every-match queries use Select-MsixManifestNodes.

    .PARAMETER Manifest
        Either an [xml] document or an MSIX.ManifestDocument wrapper.

    .PARAMETER XPath
        Namespace-aware XPath expression. The 'f:' prefix is bound to the
        foundation namespace; uap/uap10/desktop9/com/rescap etc. are also
        pre-registered.

    .OUTPUTS
        [System.Xml.XmlNode] or $null.

    .EXAMPLE
        Select-MsixManifestNode -Manifest $m -XPath '//f:Identity'
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

    .DESCRIPTION
        Plural counterpart to Select-MsixManifestNode. Always returns an
        array (possibly empty) so callers can pipe without null checks.

    .PARAMETER Manifest
        Either an [xml] document or an MSIX.ManifestDocument wrapper.

    .PARAMETER XPath
        Namespace-aware XPath expression.

    .OUTPUTS
        [System.Xml.XmlNode[]] (array, possibly empty).

    .EXAMPLE
        Select-MsixManifestNodes -Manifest $m -XPath '//f:Capability' |
            ForEach-Object { $_.GetAttribute('Name') }
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

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path

    if ($item.PSIsContainer) {
        # Folder — assume it's an unpacked workspace; look for AppxManifest.xml
        $candidate = Join-Path -Path $item.FullName -ChildPath 'AppxManifest.xml'
        if (-not (Test-Path -LiteralPath $candidate)) {
            throw "No AppxManifest.xml under '$($item.FullName)'."
        }
        return (_MsixLoadXmlSecure -Path $candidate)
    }

    if ($item.Extension -in '.msix', '.appx', '.msixbundle', '.appxbundle') {
        # Pull the manifest out of the archive without touching MakeAppx.
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
        $tmp = New-MsixWorkspace -PackageName "$($item.BaseName)-mf"
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($item.FullName)
            try {
                $entry = $zip.Entries | Where-Object { $_.Name -eq 'AppxManifest.xml' } |
                         Select-Object -First 1
                if (-not $entry) {
                    throw "AppxManifest.xml not found inside $($item.Name) (is this a bundle? open the inner .msix instead)."
                }
                $out = Join-Path -Path $tmp -ChildPath 'AppxManifest.xml'
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $out, $true)
                return (_MsixLoadXmlSecure -Path $out)
            } finally { $zip.Dispose() }
        } finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Default: assume an XML file path.
    return (_MsixLoadXmlSecure -Path $Path)
}

function Save-MsixManifest {
    <#
    .SYNOPSIS
        Writes an [xml] manifest document back to disk.

    .DESCRIPTION
        Thin wrapper around [System.Xml.XmlDocument]::Save with a debug log
        line. Used after Set-MsixManifestPublisher / Set-MsixManifestIdentity
        / Add-MsixManifestNamespace mutations to persist the result for the
        repack stage.

    .PARAMETER Manifest
        The manifest [xml] document, normally returned by Get-MsixManifest.

    .PARAMETER Path
        Destination file. Overwrites silently.

    .EXAMPLE
        [xml]$m = Get-MsixManifest -Path "$workspace\AppxManifest.xml"
        Set-MsixManifestPublisher -Manifest $m -Publisher 'CN=Contoso, O=Contoso, C=NL'
        Save-MsixManifest -Manifest $m -Path "$workspace\AppxManifest.xml"
    #>
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest,
        [Parameter(Mandatory)]
        [string]$Path
    )
    $Manifest.Save($Path)
    Write-MsixLog -Level Debug -Message "Manifest saved: $Path"
}

function Add-MsixManifestNamespace {
    <#
    .SYNOPSIS
        Idempotently adds an xmlns prefix and URI to the Package element,
        and appends the prefix to IgnorableNamespaces if not already present.

    .DESCRIPTION
        Knows the standard MSIX prefixes (uap, uap2..uap10, desktop,
        desktop2/4/6/9, com, rescap, virtualization). Resolves the URI from
        the module's internal namespace table; throws on unknown prefixes
        with the list of supported values. Re-running with the same prefix
        is a no-op.

    .PARAMETER Manifest
        Manifest [xml] document being mutated in place.

    .PARAMETER Prefix
        One of the known short prefixes (e.g. 'desktop9', 'rescap', 'uap10').

    .EXAMPLE
        Add-MsixManifestNamespace -Manifest $m -Prefix 'desktop9'
        # Idempotent: safe to call again.
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

    Write-MsixLog -Level Debug -Message "Namespace added: xmlns:$Prefix"
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

        Accepts either an [xml] document (typical from Get-MsixManifest) or
        an MSIX.ManifestDocument wrapper (from New-MsixManifestDocument).

    .PARAMETER Manifest
        The manifest [xml] document or MSIX.ManifestDocument wrapper.

    .PARAMETER AppId
        (ById set only.) The Id attribute of the Application to return.

    .PARAMETER All
        (All set only.) Switch to return every Application as an array.

    .OUTPUTS
        [System.Xml.XmlNode] for First/ById, [System.Xml.XmlNode[]] for All.

    .EXAMPLE
        # First set (default) — get the primary entry-point application
        $app = Get-MsixManifestApplication -Manifest $m

    .EXAMPLE
        # ById set — fetch a specific Application by its Id attribute
        $tool = Get-MsixManifestApplication -Manifest $m -AppId 'ContosoTool'

    .EXAMPLE
        # All set — iterate every Application in the package
        Get-MsixManifestApplication -Manifest $m -All |
            ForEach-Object { $_.GetAttribute('Id') }
    #>
    [CmdletBinding(DefaultParameterSetName = 'First')]
    [OutputType([System.Xml.XmlNode], ParameterSetName = ('First','ById'))]
    [OutputType([System.Xml.XmlNode[]], ParameterSetName = 'All')]
    param(
        [Parameter(Mandatory, Position = 0)]
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
            return [System.Xml.XmlNode[]]@($nodes)
        }

        # Fallback: namespace-agnostic XPath (handles non-standard manifests)
        $nodes = $manifestDocument.Document.SelectNodes('//*[local-name()="Application"]')
        if ($nodes -and $nodes.Count -gt 0) {
            return [System.Xml.XmlNode[]]@($nodes)
        }

        return [System.Xml.XmlNode[]]@()
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
    Write-MsixLog -Level Debug -Message 'Get-MsixManifestApplications is deprecated; use Get-MsixManifestApplication -All.'
    return Get-MsixManifestApplication -Manifest $Manifest -All
}

function Set-MsixManifestPublisher {
    <#
    .SYNOPSIS
        Pure in-memory transform: updates Identity.Publisher on the manifest.

    .DESCRIPTION
        Testable without unpacking a package — accepts an [xml] document and
        mutates it in place. Returns the same document for pipeline use.

        Idempotent: writing the same Publisher twice is a no-op. To change
        Name and Version at the same time use Set-MsixManifestIdentity. For a
        higher-level recipe-driven transform (rename + capabilities + version
        bump in one pass) see Get-Help Invoke-MsixManifestTransform.

    .PARAMETER Manifest
        Manifest [xml] document (caller-owned; mutated in place).

    .PARAMETER Publisher
        New Distinguished Name. Must match the signing certificate's Subject
        exactly or MSIX install fails with 0x8007000B.

    .OUTPUTS
        [System.Xml.XmlDocument] — the same instance, returned for chaining.

    .EXAMPLE
        [xml]$m = Get-MsixManifest -Path "$ws\AppxManifest.xml"
        Set-MsixManifestPublisher -Manifest $m -Publisher 'CN=Contoso, O=Contoso, C=NL'
        Save-MsixManifest -Manifest $m -Path "$ws\AppxManifest.xml"
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

    .DESCRIPTION
        Companion to Set-MsixManifestPublisher when you also need to rename
        the package or bump the version in a single mutation. Idempotent
        per-attribute. For multi-step transforms (capabilities + identity +
        MaxVersionTested) wrapped in one call see Get-Help
        Invoke-MsixManifestTransform.

    .PARAMETER Manifest
        Manifest [xml] document (caller-owned; mutated in place).

    .PARAMETER Name
        Optional new Identity.Name.

    .PARAMETER Publisher
        Optional new Identity.Publisher (Distinguished Name).

    .PARAMETER Version
        Optional new Identity.Version. Validated against the
        ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ pattern.

    .OUTPUTS
        [System.Xml.XmlDocument] — the same instance, returned for chaining.

    .EXAMPLE
        # Bump the version only
        Set-MsixManifestIdentity -Manifest $m -Version '2.0.0.0'

    .EXAMPLE
        # Rename + repub + version bump in one call
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
    <#
    .SYNOPSIS
        Returns the full XML namespace URI for a known MSIX prefix.

    .DESCRIPTION
        Looks up the prefix in the module's namespace table (uap, uap2..uap10,
        desktop, desktop2/4/6/9, com, rescap, virtualization). Returns $null
        for unknown prefixes. Pair with Add-MsixManifestNamespace and
        XmlDocument.CreateElement when crafting prefixed elements.

    .PARAMETER Prefix
        Short MSIX namespace prefix (e.g. 'desktop9').

    .OUTPUTS
        [string] or $null when the prefix is unknown.

    .EXAMPLE
        $uri = Get-MsixManifestNamespaceUri -Prefix 'desktop9'
        $el  = $manifest.CreateElement('desktop9:Extension', $uri)
    #>
    [OutputType([string])]
    param([string]$Prefix)
    return $script:KnownNamespaces[$Prefix]
}

function Set-MsixManifestMaxVersionTested {
    <#
    .SYNOPSIS
        Ensures MaxVersionTested is at least the specified build number.
        Pass -MinBuild with the feature's required build (e.g. 19041, 22000).

    .DESCRIPTION
        Many manifest extensions only activate when MaxVersionTested on the
        TargetDeviceFamily element is at or above a specific build:
          17134 — desktop4 modern context menus (1803)
          19041 — desktop6 file/registry virtualization (2004)
          22000 — desktop9 legacy IContextMenu handlers (Win11 21H2)
          26100 — Win32 App Isolation rescap capabilities

        The function is idempotent: bumps only when the current value is
        lower than -MinBuild. Mutates in place.

    .PARAMETER Manifest
        Manifest [xml] document.

    .PARAMETER MinBuild
        Minimum Windows build number to advertise. Default 19041.

    .EXAMPLE
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest,
        [int]$MinBuild = 19041
    )

    $dep = $Manifest.Package.Dependencies
    if (-not $dep) { return }

    # A manifest may declare more than one TargetDeviceFamily (e.g.
    # Windows.Desktop + Windows.Universal). The XML adapter returns a single
    # node or an array depending on count, so normalise with @() and bump every
    # one whose build floor is below $MinBuild. Versions with fewer than three
    # components (e.g. '10.0') are treated as build 0 and bumped, rather than
    # silently skipped.
    foreach ($t in @($dep.TargetDeviceFamily)) {
        if (-not $t) { continue }
        $current = $t.GetAttribute('MaxVersionTested')
        $parts   = if ($current) { $current -split '\.' } else { @() }

        $nums = @(0, 0, 0, 0)
        for ($i = 0; $i -lt 4 -and $i -lt $parts.Count; $i++) {
            $parsed = 0
            if ([int]::TryParse($parts[$i], [ref]$parsed)) { $nums[$i] = $parsed }
        }

        if ($nums[2] -lt $MinBuild) {
            $major = if ($nums[0] -gt 0) { $nums[0] } else { 10 }
            $new   = "$major.$($nums[1]).$MinBuild.0"
            $t.SetAttribute('MaxVersionTested', $new)
            Write-MsixLog -Level Info -Message "MaxVersionTested updated to $new (was '$current') on TargetDeviceFamily '$($t.GetAttribute('Name'))'"
        }
    }
}
