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
        # HKLM\... / HKCU\... key paths -> @{ ValueName = value } hashtables.
        # Built into Registry.dat / User.dat via the offline-registry helpers so
        # the modification package layers SETTINGS, not just files (issue #131).
        # Strings become REG_SZ, integers REG_DWORD.
        [hashtable]$RegistryContent,
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

        if ($RegistryContent -and $RegistryContent.Count -gt 0) {
            _MsixBuildRegistryContent -Staging $staging -RegistryContent $RegistryContent
        }

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


#region Shared runtime framework packages (issue #130) -----------------------

function New-MsixFrameworkPackage {
    <#
    .SYNOPSIS
        Builds a FRAMEWORK package from a runtime folder (JRE, .NET runtime,
        Python, in-house shared libraries) so many app packages can depend on
        one servicing point instead of each bundling its own copy.

    .DESCRIPTION
        Emits a package whose manifest declares <Framework>true</Framework>
        and carries NO Application element. Consumer apps reference it with
        Add-MsixRuntimeDependency (which declares the <PackageDependency> and
        optionally wires environment variables such as JAVA_HOME).

        Servicing story: patch the runtime by publishing a new framework
        version; consumer packages declare MinVersion and pick it up without
        being rebuilt. For DLL-based runtimes no wiring is needed at all -
        a packaged process's DLL search path includes its dependency
        packages' roots (the package graph).

    .PARAMETER RuntimeFolder
        Folder whose CONTENT becomes the framework payload (e.g. the root of
        an extracted JRE - bin\, lib\, ...).

    .PARAMETER Name
        Identity Name for the framework (e.g. Contoso.Java.17).

    .PARAMETER Version
        Framework version (e.g. 17.0.11.0).

    .PARAMETER Publisher
        Publisher DN the framework will be signed with (must match the
        signing certificate, and consumers must declare the same string).

    .PARAMETER DisplayName
        Display name. Default: the Name.

    .PARAMETER Architecture
        x86 | x64 | arm64 | neutral. Default x64 (runtimes are usually
        architecture-specific).

    .PARAMETER OutputPath
        The framework .msix to write. Default: <Name>.msix next to
        -RuntimeFolder.

    .PARAMETER SkipSigning
        Skip signing. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        # Package a JRE once...
        New-MsixFrameworkPackage -RuntimeFolder C:\runtimes\jre-17 `
            -Name 'Contoso.Java.17' -Version 17.0.11.0 `
            -Publisher 'CN=Contoso Ltd' -Pfx cert.pfx -PfxPassword $pw

        # ...then wire any number of apps to it:
        Add-MsixRuntimeDependency -PackagePath app.msix `
            -FrameworkName 'Contoso.Java.17' -FrameworkMinVersion 17.0.11.0 `
            -FrameworkPublisher 'CN=Contoso Ltd' -Runtime Java -SkipSigning

    .OUTPUTS
        [pscustomobject] with PackagePath, Name, Version, Architecture.

    .LINK
        https://learn.microsoft.com/windows/msix/package/create-app-package-with-makeappx-tool
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$RuntimeFolder,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{2,49}$')]
        [string]$Name,
        [Parameter(Mandatory)]
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$Version,
        [Parameter(Mandatory)] [string]$Publisher,
        [string]$DisplayName,
        [ValidateSet('x86', 'x64', 'arm64', 'neutral')]
        [string]$Architecture = 'x64',
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not (Test-Path -LiteralPath $RuntimeFolder -PathType Container)) {
        throw "RuntimeFolder not found or not a directory: $RuntimeFolder"
    }
    if (-not $DisplayName) { $DisplayName = $Name }
    if (-not $OutputPath) {
        $parent = Split-Path -Path (Resolve-Path -LiteralPath $RuntimeFolder).Path -Parent
        $OutputPath = Join-Path -Path $parent -ChildPath "$Name.msix"
    }

    if (-not $PSCmdlet.ShouldProcess($OutputPath, "Create framework package $Name $Version")) { return }

    $toolsRoot = Get-MsixToolsRoot
    $staging = Join-Path -Path $env:TEMP -ChildPath ("msix-fwpkg-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    New-Item -ItemType Directory -Path $staging -Force | Out-Null
    try {
        Copy-Item -Path (Join-Path -Path $RuntimeFolder -ChildPath '*') -Destination $staging -Recurse -Force

        $manifestXml = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         IgnorableNamespaces="uap">
  <Identity Name="$Name" Publisher="$([Security.SecurityElement]::Escape($Publisher))" Version="$Version" ProcessorArchitecture="$Architecture"/>
  <Properties>
    <Framework>true</Framework>
    <DisplayName>$([Security.SecurityElement]::Escape($DisplayName))</DisplayName>
    <PublisherDisplayName>$([Security.SecurityElement]::Escape($Publisher))</PublisherDisplayName>
    <Logo>Assets\StoreLogo.png</Logo>
  </Properties>
  <Resources>
    <Resource Language="en-us"/>
  </Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>
  </Dependencies>
</Package>
"@
        $assets = Join-Path -Path $staging -ChildPath 'Assets'
        if (-not (Test-Path -LiteralPath (Join-Path -Path $assets -ChildPath 'StoreLogo.png'))) {
            New-Item -ItemType Directory -Path $assets -Force | Out-Null
            $png = [Convert]::FromBase64String('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==')
            [IO.File]::WriteAllBytes((Join-Path -Path $assets -ChildPath 'StoreLogo.png'), $png)
        }
        $manifestPath = Join-Path -Path $staging -ChildPath 'AppxManifest.xml'
        [IO.File]::WriteAllText($manifestPath, $manifestXml, [Text.UTF8Encoding]::new($false))

        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $OutputPath, '/d', $staging, '/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx pack (framework package)'

        if (-not $SkipSigning) {
            if ($Pfx) { Invoke-MsixSigning -PackagePath $OutputPath -Pfx $Pfx -PfxPassword $PfxPassword }
            else      { Invoke-MsixSigning -PackagePath $OutputPath }
        }
        Write-MsixLog -Level Info -Message "Framework package created: $OutputPath ($Name $Version, $Architecture)"

        [pscustomobject]@{
            PackagePath  = $OutputPath
            Name         = $Name
            Version      = $Version
            Architecture = $Architecture
        }
    } finally {
        if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
    }
}


function Add-MsixRuntimeDependency {
    <#
    .SYNOPSIS
        Wires an app package to a shared runtime framework package: declares
        the PackageDependency and (optionally) environment variables like
        JAVA_HOME pointing into the framework's install location.

    .DESCRIPTION
        Two layers, per what the runtime needs:

        1. Dependency (always): <PackageDependency Name= MinVersion= Publisher=>
           via Add-MsixPackageDependency. For DLL-based runtimes this is
           usually enough - a packaged process's DLL search includes its
           dependency packages' roots (the package graph).

        2. Environment variables (optional, needs PSF): runtimes addressed by
           PATH-style discovery (java.exe via JAVA_HOME, dotnet via
           DOTNET_ROOT) get a PSF EnvVarFixup. The framework's install root is
           computed as
             C:\Program Files\WindowsApps\<Name>_<MinVersion>_<arch>__<publisherId>
           and substituted for the '{frameworkRoot}' token in values.

           WARNING: that path pins the EXACT MinVersion - when you service the
           framework to a newer version, re-run this cmdlet (or keep the
           framework version and update its content). The cmdlet warns about
           this at wiring time.

    .PARAMETER PackagePath
        The consumer app .msix to modify.

    .PARAMETER FrameworkName
        Framework Identity Name (as given to New-MsixFrameworkPackage).

    .PARAMETER FrameworkMinVersion
        Minimum framework version.

    .PARAMETER FrameworkPublisher
        Framework Publisher DN (must match the framework package identity).

    .PARAMETER FrameworkArchitecture
        Architecture used in the WindowsApps folder name. Default x64.

    .PARAMETER Runtime
        Preset for common runtimes:
          Java   -> JAVA_HOME = {frameworkRoot}
          DotNet -> DOTNET_ROOT = {frameworkRoot}
          None   -> no env wiring unless -EnvironmentVariables is given.

    .PARAMETER EnvironmentVariables
        Custom env vars. Values may contain the '{frameworkRoot}' token,
        replaced with the computed framework install path.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip signing. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        Add-MsixRuntimeDependency -PackagePath app.msix `
            -FrameworkName 'Contoso.Java.17' -FrameworkMinVersion 17.0.11.0 `
            -FrameworkPublisher 'CN=Contoso Ltd' -Runtime Java -SkipSigning

    .EXAMPLE
        # DLL-based runtime: dependency only, no env wiring, no PSF
        Add-MsixRuntimeDependency -PackagePath app.msix `
            -FrameworkName 'Contoso.SharedLibs' -FrameworkMinVersion 1.0.0.0 `
            -FrameworkPublisher 'CN=Contoso Ltd' -SkipSigning

    .OUTPUTS
        [pscustomobject] with PackagePath, FrameworkName, FrameworkRoot,
        EnvironmentWired.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{2,49}$')]
        [string]$FrameworkName,
        [Parameter(Mandatory)]
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$FrameworkMinVersion,
        [Parameter(Mandatory)] [string]$FrameworkPublisher,
        [ValidateSet('x86', 'x64', 'arm64', 'neutral')]
        [string]$FrameworkArchitecture = 'x64',
        [ValidateSet('Java', 'DotNet', 'None')]
        [string]$Runtime = 'None',
        [hashtable]$EnvironmentVariables,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not $PSCmdlet.ShouldProcess($PackagePath, "Add runtime dependency on $FrameworkName")) { return }

    # 1) The dependency itself.
    Add-MsixPackageDependency -PackagePath $PackagePath -Name $FrameworkName `
        -MinVersion $FrameworkMinVersion -Publisher $FrameworkPublisher `
        -OutputPath $OutputPath -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword

    $target = if ($OutputPath) { $OutputPath } else { $PackagePath }

    # 2) Optional env wiring via PSF.
    $envVars = @{}
    switch ($Runtime) {
        'Java'   { $envVars['JAVA_HOME']   = '{frameworkRoot}' }
        'DotNet' { $envVars['DOTNET_ROOT'] = '{frameworkRoot}' }
    }
    foreach ($k in @($EnvironmentVariables).Keys) { $envVars[$k] = $EnvironmentVariables[$k] }

    $frameworkRoot = $null
    $wired = $false
    if ($envVars.Count -gt 0) {
        $pubId = Get-MsixPublisherId -Publisher $FrameworkPublisher
        $frameworkRoot = "C:\Program Files\WindowsApps\${FrameworkName}_${FrameworkMinVersion}_${FrameworkArchitecture}__${pubId}"
        Write-MsixLog -Level Warning -Message "Environment wiring pins the framework path to version $FrameworkMinVersion ($frameworkRoot). Re-run Add-MsixRuntimeDependency after servicing the framework to a new version."

        $resolved = @{}
        foreach ($k in $envVars.Keys) {
            $resolved[$k] = ([string]$envVars[$k]).Replace('{frameworkRoot}', $frameworkRoot)
        }
        $fixup = New-MsixPsfEnvVarConfig -Variables $resolved
        Add-MsixPsfV2 -PackagePath $target -Fixups @($fixup) -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword
        $wired = $true
    } else {
        Write-MsixLog -Level Info -Message 'No environment wiring requested; the dependency alone covers DLL-based runtimes (package-graph DLL search).'
    }

    [pscustomobject]@{
        PackagePath       = $target
        FrameworkName     = $FrameworkName
        FrameworkRoot     = $frameworkRoot
        EnvironmentWired  = $wired
    }
}

#endregion


#region Modification-package registry + diff (issue #131) --------------------

function _MsixBuildRegistryContent {
    # Builds Registry.dat (HKLM keys, rooted at REGISTRY\MACHINE) and/or
    # User.dat (HKCU keys, rooted directly) in $Staging from a hashtable of
    # 'HKLM\path' / 'HKCU\path' -> @{ ValueName = value } entries.
    # String values -> REG_SZ; [int]/[uint32] -> REG_DWORD.
    param(
        [Parameter(Mandatory)] [string]$Staging,
        [Parameter(Mandatory)] [hashtable]$RegistryContent
    )

    $machine = [ordered]@{}
    $user    = [ordered]@{}
    foreach ($keyPath in $RegistryContent.Keys) {
        $values = $RegistryContent[$keyPath]
        if ($values -isnot [hashtable]) { throw "RegistryContent['$keyPath'] must be a hashtable of ValueName = value." }
        if ($keyPath -match '^(HKLM|HKEY_LOCAL_MACHINE)\\(.+)$') {
            $machine['REGISTRY\MACHINE\' + $Matches[2]] = $values
        } elseif ($keyPath -match '^(HKCU|HKEY_CURRENT_USER)\\(.+)$') {
            $user[$Matches[2]] = $values
        } else {
            throw "RegistryContent keys must start with HKLM\ or HKCU\ (got '$keyPath')."
        }
    }

    foreach ($set in @(
        @{ Map = $machine; File = 'Registry.dat' },
        @{ Map = $user;    File = 'User.dat' }
    )) {
        if ($set.Map.Count -eq 0) { continue }
        $hive = _MsixCreateOfflineHive
        try {
            foreach ($subKey in $set.Map.Keys) {
                # ORCreateKey does not create intermediate keys (error 2 on a
                # deep path) - walk the segments, closing intermediate handles.
                $segments = $subKey -split '\\'
                $parent = $hive
                $opened = @()
                foreach ($segment in $segments) {
                    $next = _MsixOfflineCreateKey -Parent $parent -SubKey $segment
                    if ($parent -ne $hive) { $opened += $parent }
                    $parent = $next
                }
                $key = $parent
                foreach ($h in $opened) { _MsixOfflineCloseKey -Key $h }
                try {
                    $values = $set.Map[$subKey]
                    foreach ($valName in $values.Keys) {
                        $val = $values[$valName]
                        if ($val -is [int] -or $val -is [uint32] -or $val -is [long]) {
                            _MsixOfflineSetValueDword -Key $key -Name $valName -Value ([uint32]$val)
                        } else {
                            _MsixOfflineSetValueString -Key $key -Name $valName -Value ([string]$val)
                        }
                    }
                } finally {
                    _MsixOfflineCloseKey -Key $key
                }
            }
            $datPath = Join-Path -Path $Staging -ChildPath $set.File
            _MsixOfflineSaveHive -Hive $hive -Path $datPath
            Write-MsixLog -Level Info -Message "$($set.File) built with $($set.Map.Count) key(s)."
        } finally {
            _MsixCloseOfflineHive -Hive $hive
        }
    }
}


function ConvertTo-MsixModificationPackage {
    <#
    .SYNOPSIS
        Generates a modification package from the DIFF between a vendor
        package and a customized copy - "productize the golden-image delta".

    .DESCRIPTION
        Unpacks both packages, computes the payload delta (files added or
        changed in the customized copy, compared by SHA-256), stages the delta
        as modification-package content, and calls New-MsixModificationPackage
        against the vendor package's identity.

        Registry: when the customized package's Registry.dat / User.dat differ
        from the vendor's, the customized hive files are carried into the
        modification package wholesale (a warning notes they may re-state
        vendor defaults - harmless on overlay, but review for secrets).

        Footprint files (AppxManifest.xml, signature, blockmap, metadata,
        resources.pri) are never part of the delta.

    .PARAMETER MainPackagePath
        The unmodified vendor .msix.

    .PARAMETER CustomizedPackagePath
        The customized copy of the same package (same identity family).

    .PARAMETER Name
        Identity Name for the modification package.
        Default: '<MainName>.Modification'.

    .PARAMETER Version
        Modification package version. Default 1.0.0.0.

    .PARAMETER OutputPath
        Where to write the modification .msix.

    .PARAMETER SkipSigning
        Skip signing. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        ConvertTo-MsixModificationPackage `
            -MainPackagePath .\vendor.msix `
            -CustomizedPackagePath .\vendor-customized.msix `
            -OutputPath .\vendor-settings.msix -SkipSigning

    .OUTPUTS
        [pscustomobject] with PackagePath, FilesAdded, FilesChanged,
        RegistryCarried.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$MainPackagePath,
        [Parameter(Mandatory)] [string]$CustomizedPackagePath,
        [string]$Name,
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$Version = '1.0.0.0',
        [Parameter(Mandatory)] [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not $PSCmdlet.ShouldProcess($OutputPath, 'Create modification package from diff')) { return }

    $toolsRoot = Get-MsixToolsRoot
    $wsMain = Join-Path -Path $env:TEMP -ChildPath ("msix-diff-a-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $wsCust = Join-Path -Path $env:TEMP -ChildPath ("msix-diff-b-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $content = Join-Path -Path $env:TEMP -ChildPath ("msix-diff-c-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    try {
        foreach ($pair in @(@($MainPackagePath, $wsMain), @($CustomizedPackagePath, $wsCust))) {
            $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', (Resolve-Path -LiteralPath $pair[0]).Path, '/d', $pair[1], '/o')
            Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unpack (diff)'
        }
        New-Item -ItemType Directory -Path $content -Force | Out-Null

        # Normalize long paths (8.3 segments corrupt relative offsets).
        $mainRoot = (Get-Item -LiteralPath $wsMain).FullName
        $custRoot = (Get-Item -LiteralPath $wsCust).FullName

        $footprint = @('AppxManifest.xml', 'AppxBlockMap.xml', 'AppxSignature.p7x', '[Content_Types].xml', 'resources.pri')
        $registryFiles = @('Registry.dat', 'User.dat', 'UserClasses.dat')

        $added = 0; $changed = 0; $registryCarried = @()
        foreach ($file in (Get-ChildItem -LiteralPath $custRoot -Recurse -File)) {
            $rel = $file.FullName.Substring($custRoot.Length + 1)
            $leaf = [IO.Path]::GetFileName($rel)
            if ($rel -like 'AppxMetadata*') { continue }
            if ($leaf -in $footprint -and $rel -eq $leaf) { continue }

            $mainFile = Join-Path -Path $mainRoot -ChildPath $rel
            $isRegistry = ($leaf -in $registryFiles -and $rel -eq $leaf)
            $differs = $true
            if (Test-Path -LiteralPath $mainFile) {
                $hA = (Get-FileHash -LiteralPath $mainFile   -Algorithm SHA256).Hash
                $hB = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
                $differs = ($hA -ne $hB)
                if ($differs -and -not $isRegistry) { $changed++ }
            } elseif (-not $isRegistry) {
                $added++
            }
            if (-not $differs) { continue }

            if ($isRegistry) { $registryCarried += $leaf }
            $destination = Join-Path -Path $content -ChildPath $rel
            $destDir = [IO.Path]::GetDirectoryName($destination)
            if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
            Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
        }

        if ($registryCarried) {
            Write-MsixLog -Level Warning -Message ("Customized registry hive(s) carried wholesale into the modification package: {0}. They may re-state vendor defaults (harmless on overlay) - review for machine-specific or sensitive values." -f ($registryCarried -join ', '))
        }
        if ($added -eq 0 -and $changed -eq 0 -and -not $registryCarried) {
            Write-MsixLog -Level Warning -Message 'No differences found between the packages; nothing to productize.'
            return $null
        }
        Write-MsixLog -Level Info -Message "Delta: $added added, $changed changed, registry: $($registryCarried.Count) hive file(s)."

        $modArgs = @{
            MainPackagePath = $MainPackagePath
            ContentPath     = $content
            Version         = $Version
            OutputPath      = $OutputPath
            SkipSigning     = [bool]$SkipSigning
        }
        if ($Name) { $modArgs['Name'] = $Name }
        if ($Pfx)  { $modArgs['Pfx'] = $Pfx; $modArgs['PfxPassword'] = $PfxPassword }
        $result = New-MsixModificationPackage @modArgs

        [pscustomobject]@{
            PackagePath     = $result.PackagePath
            FilesAdded      = $added
            FilesChanged    = $changed
            RegistryCarried = @($registryCarried)
        }
    } finally {
        foreach ($d in @($wsMain, $wsCust, $content)) {
            if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }
}

#endregion
