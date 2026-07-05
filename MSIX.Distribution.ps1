# =============================================================================
# Distribution helpers (issues #117, #118)
# -----------------------------------------------------------------------------
# The step after post-processing: hand the signed .msix to users.
#   New-MsixAppInstallerFile    — .appinstaller with an auto-update policy for
#                                 HTTPS / file-share sideload distribution.
#   New-MsixModificationPackage — a customization package that layers content
#                                 onto a vendor MSIX without modifying it.
# =============================================================================

function New-MsixAppInstallerFile {
    <#
    .SYNOPSIS
        Generates a .appinstaller file (with auto-update policy) for a package,
        for HTTPS or file-share sideload distribution.

    .DESCRIPTION
        Reads Name / Publisher / Version / architecture from the package's
        manifest and emits a schema-valid .appinstaller (2018+ schema; the
        update-settings shape used from Windows 10 1903). Users install via
        Add-AppxPackage -AppInstallerFile or by opening the file; Windows then
        checks -Uri for updates per the policy.

    .PARAMETER PackagePath
        The .msix the installer file describes (identity is read from it).

    .PARAMETER PackageUri
        URL (https://...) or UNC path where the .msix will be hosted.

    .PARAMETER AppInstallerUri
        URL/UNC where THIS .appinstaller file will be hosted (used by Windows
        to re-check the file itself). Defaults to the same folder as
        -PackageUri with the .appinstaller name.

    .PARAMETER OutputPath
        Where to write the .appinstaller. Default: next to -PackagePath with
        the same base name.

    .PARAMETER HoursBetweenUpdateChecks
        Background update-check interval. Default 24. 0 = check on every
        launch.

    .PARAMETER OnLaunch
        Check for updates at app launch (adds the OnLaunch element).

    .PARAMETER ShowPrompt
        With -OnLaunch: show the user a prompt when an update is found.

    .PARAMETER UpdateBlocksActivation
        With -OnLaunch: the app cannot start until the update is applied.

    .PARAMETER ForceUpdateFromAnyVersion
        Allow downgrades / same-version reinstalls.

    .EXAMPLE
        New-MsixAppInstallerFile -PackagePath .\app.msix `
            -PackageUri 'https://dist.contoso.com/app.msix' -OnLaunch -ShowPrompt

    .EXAMPLE
        # File-share distribution, forced hourly checks
        New-MsixAppInstallerFile -PackagePath .\app.msix `
            -PackageUri '\\fs01\apps\app.msix' -HoursBetweenUpdateChecks 1

    .OUTPUTS
        [pscustomobject] with Path, PackageUri, AppInstallerUri, Version.

    .LINK
        https://learn.microsoft.com/windows/msix/app-installer/app-installer-file-overview
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [string]$PackageUri,
        [string]$AppInstallerUri,
        [string]$OutputPath,
        [ValidateRange(0, 8760)]
        [int]$HoursBetweenUpdateChecks = 24,
        [switch]$OnLaunch,
        [switch]$ShowPrompt,
        [switch]$UpdateBlocksActivation,
        [switch]$ForceUpdateFromAnyVersion
    )

    if (($ShowPrompt -or $UpdateBlocksActivation) -and -not $OnLaunch) {
        throw '-ShowPrompt / -UpdateBlocksActivation require -OnLaunch.'
    }

    [xml]$manifest = Get-MsixManifest -Path $PackagePath
    $identity  = $manifest.Package.Identity
    $name      = $identity.Name
    $publisher = $identity.Publisher
    $version   = $identity.Version
    $arch      = $identity.GetAttribute('ProcessorArchitecture')
    if (-not $arch) { $arch = 'neutral' }

    if (-not $OutputPath) {
        $OutputPath = [IO.Path]::ChangeExtension((Resolve-Path -LiteralPath $PackagePath).Path, '.appinstaller')
    }
    if (-not $AppInstallerUri) {
        $slash = if ($PackageUri -match '/') { '/' } else { '\' }
        $parent = $PackageUri.Substring(0, $PackageUri.LastIndexOf($slash))
        $AppInstallerUri = $parent + $slash + [IO.Path]::GetFileName($OutputPath)
    }

    if (-not $PSCmdlet.ShouldProcess($OutputPath, 'Write .appinstaller')) { return }

    $ns  = 'http://schemas.microsoft.com/appx/appinstaller/2018'
    $doc = New-Object System.Xml.XmlDocument
    $null = $doc.AppendChild($doc.CreateXmlDeclaration('1.0', 'utf-8', $null))

    $root = $doc.CreateElement('AppInstaller', $ns)
    $root.SetAttribute('Uri', $AppInstallerUri)
    $root.SetAttribute('Version', $version)
    $null = $doc.AppendChild($root)

    $main = $doc.CreateElement('MainPackage', $ns)
    $main.SetAttribute('Name',      $name)
    $main.SetAttribute('Publisher', $publisher)
    $main.SetAttribute('Version',   $version)
    if ($arch -ne 'neutral') { $main.SetAttribute('ProcessorArchitecture', $arch) }
    $main.SetAttribute('Uri', $PackageUri)
    $null = $root.AppendChild($main)

    $settings = $doc.CreateElement('UpdateSettings', $ns)
    if ($OnLaunch) {
        $launch = $doc.CreateElement('OnLaunch', $ns)
        $launch.SetAttribute('HoursBetweenUpdateChecks', [string]$HoursBetweenUpdateChecks)
        if ($ShowPrompt)             { $launch.SetAttribute('ShowPrompt', 'true') }
        if ($UpdateBlocksActivation) { $launch.SetAttribute('UpdateBlocksActivation', 'true') }
        $null = $settings.AppendChild($launch)
    } else {
        $auto = $doc.CreateElement('AutomaticBackgroundTask', $ns)
        $null = $settings.AppendChild($auto)
    }
    if ($ForceUpdateFromAnyVersion) {
        $force = $doc.CreateElement('ForceUpdateFromAnyVersion', $ns)
        $force.InnerText = 'true'
        $null = $settings.AppendChild($force)
    }
    $null = $root.AppendChild($settings)

    $doc.Save($OutputPath)
    Write-MsixLog -Level Info -Message ".appinstaller written: $OutputPath (package $name $version @ $PackageUri)"

    [pscustomobject]@{
        Path            = $OutputPath
        PackageUri      = $PackageUri
        AppInstallerUri = $AppInstallerUri
        Version         = $version
    }
}


function New-MsixModificationPackage {
    <#
    .SYNOPSIS
        Creates a modification package: customization content (settings,
        plugins, license files) layered onto a vendor MSIX without touching it.

    .DESCRIPTION
        Builds a package whose manifest declares
        uap4:MainPackageDependency on the target app and carries NO
        Application element - the enterprise-standard way to customize a
        vendor package. At runtime Windows merges the modification package's
        VFS content into the main app's container view.

        Identity fields for the modification package itself default to
        '<MainName>.Modification' with the MAIN package's Publisher (required:
        a modification package must be signed with a publisher the main app
        trusts - same publisher, or one allowed by policy).

    .PARAMETER MainPackagePath
        The vendor .msix being customized (Name/Publisher are read from it).

    .PARAMETER ContentPath
        Folder whose CONTENT becomes the modification package payload.
        Layout it like a package root (e.g. VFS\ProgramFilesX64\App\plugins\...).

    .PARAMETER Name
        Identity Name for the modification package.
        Default: '<MainName>.Modification'.

    .PARAMETER Version
        Version for the modification package. Default 1.0.0.0.

    .PARAMETER DisplayName
        Display name. Default: '<MainName> customization'.

    .PARAMETER OutputPath
        Where to write the modification .msix.
        Default: <ContentPath>\..\<Name>.msix.

    .PARAMETER SkipSigning
        Skip signing. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        # Layer a plugins folder onto a vendor package
        New-MsixModificationPackage -MainPackagePath .\vendor.msix `
            -ContentPath .\customization `
            -Pfx cert.pfx -PfxPassword $pw

    .OUTPUTS
        [pscustomobject] with PackagePath, Name, MainPackageName.

    .LINK
        https://learn.microsoft.com/windows/msix/modification-package-insights
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$MainPackagePath,
        [Parameter(Mandatory)] [string]$ContentPath,
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{2,49}$')]
        [string]$Name,
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$Version = '1.0.0.0',
        [string]$DisplayName,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not (Test-Path -LiteralPath $ContentPath -PathType Container)) {
        throw "ContentPath not found or not a directory: $ContentPath"
    }

    [xml]$mainManifest = Get-MsixManifest -Path $MainPackagePath
    $mainId   = $mainManifest.Package.Identity
    $mainName = $mainId.Name
    $publisher = $mainId.Publisher
    $mainPubDisplay = $mainManifest.Package.Properties.PublisherDisplayName
    if (-not $mainPubDisplay) { $mainPubDisplay = 'Unknown publisher' }

    if (-not $Name)        { $Name = "$mainName.Modification" }
    if (-not $DisplayName) { $DisplayName = "$mainName customization" }
    if (-not $OutputPath) {
        $parent = Split-Path -Path (Resolve-Path -LiteralPath $ContentPath).Path -Parent
        $OutputPath = Join-Path -Path $parent -ChildPath "$Name.msix"
    }

    if (-not $PSCmdlet.ShouldProcess($OutputPath, "Create modification package for $mainName")) { return }

    $toolsRoot = Get-MsixToolsRoot
    $staging = Join-Path -Path $env:TEMP -ChildPath ("msix-modpkg-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        Copy-Item -Path (Join-Path -Path $ContentPath -ChildPath '*') -Destination $staging -Recurse -Force

        $safeName = [Security.SecurityElement]::Escape($Name)
        $safeMainName = [Security.SecurityElement]::Escape($mainName)
        $safePublisher = [Security.SecurityElement]::Escape($publisher)
        $safeDisplayName = [Security.SecurityElement]::Escape($DisplayName)
        $safePublisherDisplayName = [Security.SecurityElement]::Escape($mainPubDisplay)

        $manifestXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap4="http://schemas.microsoft.com/appx/manifest/uap/windows10/4"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         xmlns:build="http://schemas.microsoft.com/developer/appx/2015/build"
         IgnorableNamespaces="uap uap4 rescap build">
  <Identity Name="$safeName" Publisher="$safePublisher" Version="$Version" ProcessorArchitecture="neutral"/>
  <Properties>
    <DisplayName>$safeDisplayName</DisplayName>
    <PublisherDisplayName>$safePublisherDisplayName</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Resources>
    <Resource Language="en-us"/>
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
    <uap4:MainPackageDependency Name="$safeMainName"/>
  </Dependencies>
</Package>
"@
        # Modification packages need a logo asset for the Properties/Logo.
        $assets = Join-Path -Path $staging -ChildPath 'Assets'
        if (-not (Test-Path -LiteralPath (Join-Path -Path $assets -ChildPath 'StoreLogo.png'))) {
            New-Item -ItemType Directory -Path $assets -Force | Out-Null
            # 1x1 transparent PNG.
            $png = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')
            [IO.File]::WriteAllBytes((Join-Path -Path $assets -ChildPath 'StoreLogo.png'), $png)
        }

        $manifestPath = Join-Path -Path $staging -ChildPath 'AppxManifest.xml'
        [IO.File]::WriteAllText($manifestPath, $manifestXml, [Text.UTF8Encoding]::new($false))

        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $OutputPath, '/d', $staging, '/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx pack (modification package)'

        if (-not $SkipSigning) {
            if ($Pfx) { Invoke-MsixSigning -PackagePath $OutputPath -Pfx $Pfx -PfxPassword $PfxPassword }
            else      { Invoke-MsixSigning -PackagePath $OutputPath }
        }
        Write-MsixLog -Level Info -Message "Modification package created: $OutputPath (customizes $mainName)"

        [pscustomobject]@{
            PackagePath     = $OutputPath
            Name            = $Name
            MainPackageName = $mainName
        }
    } finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

#region .msixbundle handling (issue #125) ------------------------------------

function Expand-MsixBundle {
    <#
    .SYNOPSIS
        Unbundles a .msixbundle into its inner .msix packages.

    .PARAMETER BundlePath
        The .msixbundle file.

    .PARAMETER OutputFolder
        Folder to unbundle into. Created if missing. Default: a new workspace.

    .EXAMPLE
        Expand-MsixBundle -BundlePath app.msixbundle -OutputFolder C:\work\inner

    .OUTPUTS
        [pscustomobject] with OutputFolder and Packages (FileInfo[] of the
        inner .msix files, excluding the bundle metadata).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$BundlePath,
        [string]$OutputFolder
    )

    if (-not (Test-Path -LiteralPath $BundlePath -PathType Leaf)) { throw "Bundle not found: $BundlePath" }
    if (-not $OutputFolder) {
        $OutputFolder = New-MsixWorkspace -PackageName ([IO.Path]::GetFileNameWithoutExtension($BundlePath) + '-unbundle')
    }
    if (-not $PSCmdlet.ShouldProcess($BundlePath, "Unbundle to $OutputFolder")) { return }

    $toolsRoot = Get-MsixToolsRoot
    $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unbundle', '/p', $BundlePath, '/d', $OutputFolder, '/o')
    Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unbundle'

    $inner = @(Get-ChildItem -LiteralPath $OutputFolder -File |
        Where-Object { $_.Extension -in '.msix', '.appx' })
    Write-MsixLog -Level Info -Message "Unbundled $($inner.Count) inner package(s) from $([IO.Path]::GetFileName($BundlePath))."

    [pscustomobject]@{
        OutputFolder = $OutputFolder
        Packages     = $inner
    }
}


function New-MsixBundle {
    <#
    .SYNOPSIS
        Bundles a folder of .msix packages into a signed .msixbundle.

    .PARAMETER SourceFolder
        Folder containing the .msix files to bundle (same Identity Name and
        Version across packages; architectures/languages may differ).

    .PARAMETER OutputPath
        The .msixbundle to write.

    .PARAMETER BundleVersion
        Optional explicit bundle version (defaults to MakeAppx's derivation
        from the current timestamp when omitted).

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        New-MsixBundle -SourceFolder C:\work\inner -OutputPath app.msixbundle `
            -Pfx cert.pfx -PfxPassword $pw

    .OUTPUTS
        [pscustomobject] with BundlePath and PackageCount.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$SourceFolder,
        [Parameter(Mandatory)] [string]$OutputPath,
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$BundleVersion,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not (Test-Path -LiteralPath $SourceFolder -PathType Container)) { throw "SourceFolder not found: $SourceFolder" }
    $inner = @(Get-ChildItem -LiteralPath $SourceFolder -File | Where-Object { $_.Extension -in '.msix', '.appx' })
    if (-not $inner) { throw "No .msix/.appx packages found in $SourceFolder." }
    if (-not $PSCmdlet.ShouldProcess($OutputPath, "Bundle $($inner.Count) package(s)")) { return }

    $toolsRoot = Get-MsixToolsRoot
    $bundleArgs = @('bundle', '/d', $SourceFolder, '/p', $OutputPath, '/o')
    if ($BundleVersion) { $bundleArgs += @('/bv', $BundleVersion) }
    $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList $bundleArgs
    Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx bundle'

    if (-not $SkipSigning) {
        if ($Pfx) { Invoke-MsixSigning -PackagePath $OutputPath -Pfx $Pfx -PfxPassword $PfxPassword }
        else      { Invoke-MsixSigning -PackagePath $OutputPath }
    }
    Write-MsixLog -Level Info -Message "Bundle created: $OutputPath ($($inner.Count) inner package(s))."

    [pscustomobject]@{
        BundlePath   = $OutputPath
        PackageCount = $inner.Count
    }
}


function Invoke-MsixBundleOperation {
    <#
    .SYNOPSIS
        Runs any package mutation against every inner .msix of a .msixbundle,
        then rebundles and signs once - bundle support for ALL mutators
        without per-cmdlet changes.

    .DESCRIPTION
        Unbundles, invokes -Operation once per inner package (the scriptblock
        receives the inner .msix path; call any module mutator with
        -SkipSigning inside), removes the stale bundle metadata, rebundles
        with the SAME bundle version (inner package contents changed but
        identities did not), and signs the result.

        The bundle signature and every inner package signature are
        invalidated by mutation, so the operation signs the inner packages
        and the bundle in the final pass unless -SkipSigning.

    .PARAMETER BundlePath
        The .msixbundle to operate on.

    .PARAMETER Operation
        Scriptblock receiving each inner package path. Use -SkipSigning on
        mutators inside; signing happens once at the end.

    .PARAMETER Architecture
        Restrict the operation to inner packages of this architecture
        (read from each inner manifest's Identity). Others pass through
        unchanged. Default: all.

    .PARAMETER OutputPath
        Write the rebuilt bundle here instead of overwriting -BundlePath.

    .PARAMETER SkipSigning
        Skip signing of inner packages and the bundle. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        # Add a capability to every inner package of a bundle
        Invoke-MsixBundleOperation -BundlePath app.msixbundle -Operation {
            param($pkg)
            Add-MsixCapability -PackagePath $pkg -Names runFullTrust -SkipSigning
        } -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Isolate only the x64 flavour
        Invoke-MsixBundleOperation -BundlePath app.msixbundle -Architecture x64 -Operation {
            param($pkg)
            Add-MsixAppIsolation -PackagePath $pkg -SkipSigning
        } -SkipSigning

    .OUTPUTS
        [pscustomobject] with BundlePath, PackagesMutated, PackagesTotal.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$BundlePath,
        [Parameter(Mandatory)] [scriptblock]$Operation,
        [ValidateSet('x64', 'x86', 'arm64', 'neutral')]
        [string]$Architecture,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not $PSCmdlet.ShouldProcess($BundlePath, 'Mutate bundle contents')) { return }

    $target = if ($OutputPath) { $OutputPath } else { $BundlePath }
    $work = $null
    try {
        $expanded = Expand-MsixBundle -BundlePath $BundlePath
        $work = $expanded.OutputFolder

        # Read the current bundle version so the rebuilt bundle keeps it.
        $bundleVersion = $null
        $bmPath = Join-Path -Path $work -ChildPath 'AppxMetadata\AppxBundleManifest.xml'
        if (Test-Path -LiteralPath $bmPath) {
            [xml]$bm = Get-MsixManifest -Path $bmPath
            $bundleVersion = $bm.Bundle.Identity.Version
            # MakeAppx bundle refuses a folder still carrying old metadata.
            $meta = Join-Path -Path $work -ChildPath 'AppxMetadata'
            if (Test-Path -LiteralPath $meta) { [IO.Directory]::Delete($meta, $true) }
        }

        $mutated = 0
        foreach ($pkg in $expanded.Packages) {
            $skip = $false
            if ($Architecture) {
                [xml]$inner = Get-MsixManifest -Path $pkg.FullName
                $arch = $inner.Package.Identity.GetAttribute('ProcessorArchitecture')
                if (-not $arch) { $arch = 'neutral' }
                $skip = ($arch -ne $Architecture)
            }
            if ($skip) { continue }
            Write-MsixLog -Level Info -Message "Bundle operation -> $($pkg.Name)"
            & $Operation $pkg.FullName
            if (-not $SkipSigning) {
                if ($Pfx) { Invoke-MsixSigning -PackagePath $pkg.FullName -Pfx $Pfx -PfxPassword $PfxPassword }
                else      { Invoke-MsixSigning -PackagePath $pkg.FullName }
            }
            $mutated++
        }

        $bundleArgs = @{
            SourceFolder = $work
            OutputPath   = $target
            SkipSigning  = $SkipSigning
        }
        if ($bundleVersion) { $bundleArgs['BundleVersion'] = $bundleVersion }
        if ($Pfx)           { $bundleArgs['Pfx'] = $Pfx; $bundleArgs['PfxPassword'] = $PfxPassword }
        $null = New-MsixBundle @bundleArgs

        Write-MsixLog -Level Info -Message "Bundle operation complete: $mutated/$($expanded.Packages.Count) inner package(s) mutated."
        [pscustomobject]@{
            BundlePath      = $target
            PackagesMutated = $mutated
            PackagesTotal   = $expanded.Packages.Count
        }
    } finally {
        if ($work -and (Test-Path -LiteralPath $work)) { [IO.Directory]::Delete($work, $true) }
    }
}

#endregion
