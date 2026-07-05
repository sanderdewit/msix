# =============================================================================
# .msixbundle handling (issue #125)
# -----------------------------------------------------------------------------
# Real estates ship multi-arch bundles. These helpers make bundles first-class:
#   Get-MsixBundleInfo         — inner-package inventory
#   Expand-MsixBundle          — unbundle to a folder
#   New-MsixBundle             — bundle a folder of .msix files (+ sign)
#   Invoke-MsixBundleOperation — unbundle -> run any mutator per inner package
#                                -> rebundle -> sign, atomically. This gives
#                                every existing mutator bundle support without
#                                per-cmdlet changes.
# =============================================================================

function Get-MsixBundleInfo {
    <#
    .SYNOPSIS
        Lists the packages inside a .msixbundle (name, version, architecture,
        resource language) without extracting it to disk permanently.

    .PARAMETER BundlePath
        The .msixbundle file to inspect.

    .EXAMPLE
        Get-MsixBundleInfo -BundlePath .\app.msixbundle | Format-Table

    .OUTPUTS
        [pscustomobject] per inner package: FileName, Name, Version,
        Architecture, ResourceLanguage, IsResourcePackage, SizeBytes.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string]$BundlePath
    )

    $ws = Join-Path -Path $env:TEMP -ChildPath ("msix-binfo-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    try {
        Expand-MsixBundle -BundlePath $BundlePath -Destination $ws | Out-Null
        foreach ($pkg in (Get-ChildItem -LiteralPath $ws -File | Where-Object { $_.Extension -in '.msix', '.appx' })) {
            [xml]$m = Get-MsixManifest -Path $pkg.FullName
            $identity = $m.Package.Identity
            $lang = $null
            $resources = @($m.Package.Resources.Resource)
            if ($resources) { $lang = ($resources | ForEach-Object { $_.GetAttribute('Language') } | Where-Object { $_ }) -join ',' }
            $arch = $identity.GetAttribute('ProcessorArchitecture')
            if (-not $arch) { $arch = 'neutral' }
            [pscustomobject]@{
                FileName          = $pkg.Name
                Name              = $identity.Name
                Version           = $identity.Version
                Architecture      = $arch
                ResourceLanguage  = $lang
                IsResourcePackage = ($null -ne $identity.GetAttribute('ResourceId') -and '' -ne $identity.GetAttribute('ResourceId'))
                SizeBytes         = $pkg.Length
            }
        }
    } finally {
        if (Test-Path -LiteralPath $ws) { Remove-Item -LiteralPath $ws -Recurse -Force -ErrorAction SilentlyContinue }
    }
}


function Expand-MsixBundle {
    <#
    .SYNOPSIS
        Extracts a .msixbundle's inner packages (MakeAppx unbundle).

    .PARAMETER BundlePath
        The .msixbundle file.

    .PARAMETER Destination
        Folder to extract into (created if absent).

    .EXAMPLE
        Expand-MsixBundle -BundlePath .\app.msixbundle -Destination C:\work\inner

    .OUTPUTS
        [pscustomobject] with Destination and Packages (inner .msix file paths).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$BundlePath,
        [Parameter(Mandatory)] [string]$Destination
    )

    $toolsRoot = Get-MsixToolsRoot
    if (-not (Test-Path -LiteralPath $Destination)) {
        New-Item -ItemType Directory -Path $Destination -Force | Out-Null
    }
    $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unbundle', '/p', (Resolve-Path -LiteralPath $BundlePath).Path, '/d', $Destination, '/o')
    Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unbundle'

    [pscustomobject]@{
        Destination = $Destination
        Packages    = @(Get-ChildItem -LiteralPath $Destination -File |
            Where-Object { $_.Extension -in '.msix', '.appx' } |
            Select-Object -ExpandProperty FullName)
    }
}


function New-MsixBundle {
    <#
    .SYNOPSIS
        Bundles .msix packages into a .msixbundle (MakeAppx bundle) and signs it.

    .DESCRIPTION
        All inner packages must share Identity Name + Publisher + Version and
        differ by architecture / resources (MakeAppx enforces this). Pass a
        folder containing only the .msix files to bundle, or an explicit list
        (staged into a temp folder automatically).

    .PARAMETER SourceFolder
        Folder whose *.msix/*.appx files become the bundle.

    .PARAMETER PackagePaths
        Alternative to -SourceFolder: explicit .msix files to bundle.

    .PARAMETER OutputPath
        The .msixbundle to write.

    .PARAMETER BundleVersion
        Optional bundle version (defaults to the inner packages' version).

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        New-MsixBundle -SourceFolder C:\work\inner -OutputPath .\app.msixbundle -SkipSigning

    .EXAMPLE
        New-MsixBundle -PackagePaths .\app-x64.msix, .\app-arm64.msix `
            -OutputPath .\app.msixbundle -Pfx cert.pfx -PfxPassword $pw

    .OUTPUTS
        [pscustomobject] with BundlePath and PackageCount.
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'Folder')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Folder')]
        [string]$SourceFolder,
        [Parameter(Mandatory, ParameterSetName = 'Files')]
        [string[]]$PackagePaths,
        [Parameter(Mandatory)] [string]$OutputPath,
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$BundleVersion,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not $PSCmdlet.ShouldProcess($OutputPath, 'Create bundle')) { return }

    $toolsRoot = Get-MsixToolsRoot
    $staging = $null
    try {
        if ($PSCmdlet.ParameterSetName -eq 'Files') {
            $staging = Join-Path -Path $env:TEMP -ChildPath ("msix-bundle-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
            New-Item -ItemType Directory -Path $staging -Force | Out-Null
            foreach ($p in $PackagePaths) {
                Copy-Item -LiteralPath $p -Destination $staging -Force
            }
            $dir = $staging
        } else {
            $dir = (Resolve-Path -LiteralPath $SourceFolder).Path
        }

        $bundleArgs = @('bundle', '/d', $dir, '/p', $OutputPath, '/o')
        if ($BundleVersion) { $bundleArgs += @('/bv', $BundleVersion) }
        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList $bundleArgs
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx bundle'

        if (-not $SkipSigning) {
            if ($Pfx) { Invoke-MsixSigning -PackagePath $OutputPath -Pfx $Pfx -PfxPassword $PfxPassword }
            else      { Invoke-MsixSigning -PackagePath $OutputPath }
        }

        $count = @(Get-ChildItem -LiteralPath $dir -File | Where-Object { $_.Extension -in '.msix', '.appx' }).Count
        Write-MsixLog -Level Info -Message "Bundle created: $OutputPath ($count package(s))."
        [pscustomobject]@{
            BundlePath   = $OutputPath
            PackageCount = $count
        }
    } finally {
        if ($staging -and (Test-Path -LiteralPath $staging)) {
            Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}


function Invoke-MsixBundleOperation {
    <#
    .SYNOPSIS
        Applies any package mutator to the packages inside a .msixbundle:
        unbundle -> operate per inner package -> rebundle -> sign, atomically.

    .DESCRIPTION
        This is the bridge that gives every existing mutator bundle support
        without per-cmdlet changes. The -Operation scriptblock receives one
        inner .msix path at a time and mutates it IN PLACE (use -SkipSigning
        inside the block - the rebundled .msixbundle is signed once at the end).

        Resource packages (language .appx) are passed through untouched unless
        -IncludeResourcePackages is set. Use -Architecture to restrict the
        operation to specific inner architectures (others pass through).

        The original bundle is only replaced after the rebundle (and signing,
        unless -SkipSigning) succeeded.

    .PARAMETER BundlePath
        The .msixbundle to operate on.

    .PARAMETER Operation
        Scriptblock invoked per selected inner package with the .msix path as
        its first argument, e.g.:
        { param($pkg) Add-MsixCapability -PackagePath $pkg -Names runFullTrust -SkipSigning }

    .PARAMETER Architecture
        Restrict the operation to these architectures (x86, x64, arm64,
        neutral). Default: all application packages.

    .PARAMETER IncludeResourcePackages
        Also run the operation against resource (.appx language) packages.

    .PARAMETER OutputPath
        Write the resulting bundle here instead of overwriting -BundlePath.

    .PARAMETER SkipSigning
        Skip the final signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        # Add a capability to every architecture in the bundle
        Invoke-MsixBundleOperation -BundlePath .\app.msixbundle -Operation {
            param($pkg)
            Add-MsixCapability -PackagePath $pkg -Names runFullTrust -SkipSigning
        } -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Isolate only the x64 package
        Invoke-MsixBundleOperation -BundlePath .\app.msixbundle -Architecture x64 -Operation {
            param($pkg)
            Add-MsixAppIsolation -PackagePath $pkg -SkipSigning
        } -SkipSigning

    .OUTPUTS
        [pscustomobject] with BundlePath, PackagesProcessed, PackagesPassedThrough.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$BundlePath,
        [Parameter(Mandatory)] [scriptblock]$Operation,
        [ValidateSet('x86', 'x64', 'arm', 'arm64', 'neutral')]
        [string[]]$Architecture,
        [switch]$IncludeResourcePackages,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not $PSCmdlet.ShouldProcess($BundlePath, 'Bundle operation')) { return }

    $target = if ($OutputPath) { $OutputPath } else { $BundlePath }
    $ws = Join-Path -Path $env:TEMP -ChildPath ("msix-bop-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    $scratch = Join-Path -Path $env:TEMP -ChildPath ("msix-bop-out-{0}.msixbundle" -f ([guid]::NewGuid().ToString('N').Substring(0, 8)))
    try {
        $inner = Expand-MsixBundle -BundlePath $BundlePath -Destination $ws

        # The unbundle folder carries footprint files (AppxMetadata etc.);
        # rebundle needs a clean staging dir with only the packages.
        $stage = Join-Path -Path $ws -ChildPath 'rebundle'
        New-Item -ItemType Directory -Path $stage -Force | Out-Null

        $processed = 0
        $passed = 0
        # Bind the operation to this module's session state so module-private
        # helpers resolve (same pattern as _MsixMutatePackage).
        $boundOp = $Operation
        if ($ExecutionContext.SessionState.Module) {
            try { $boundOp = $ExecutionContext.SessionState.Module.NewBoundScriptBlock($Operation) } catch { $boundOp = $Operation }
        }

        foreach ($pkg in $inner.Packages) {
            [xml]$m = Get-MsixManifest -Path $pkg
            $identity = $m.Package.Identity
            $arch = $identity.GetAttribute('ProcessorArchitecture')
            if (-not $arch) { $arch = 'neutral' }
            $isResource = ($null -ne $identity.GetAttribute('ResourceId') -and '' -ne $identity.GetAttribute('ResourceId'))

            $select = $true
            if ($isResource -and -not $IncludeResourcePackages) { $select = $false }
            if ($Architecture -and $arch -notin $Architecture)  { $select = $false }

            if ($select) {
                Write-MsixLog -Level Info -Message "Bundle operation: $([IO.Path]::GetFileName($pkg)) ($arch)"
                & $boundOp $pkg
                $processed++
            } else {
                $passed++
            }
            Copy-Item -LiteralPath $pkg -Destination $stage -Force
        }

        if ($processed -eq 0) {
            Write-MsixLog -Level Warning -Message 'Bundle operation matched no inner packages; bundle left unchanged.'
            return [pscustomobject]@{
                BundlePath            = $BundlePath
                PackagesProcessed     = 0
                PackagesPassedThrough = $passed
            }
        }

        # Rebundle to scratch, sign, then atomically replace the target.
        $toolsRoot = Get-MsixToolsRoot
        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('bundle', '/d', $stage, '/p', $scratch, '/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx bundle (rebundle)'

        if (-not $SkipSigning) {
            if ($Pfx) { Invoke-MsixSigning -PackagePath $scratch -Pfx $Pfx -PfxPassword $PfxPassword }
            else      { Invoke-MsixSigning -PackagePath $scratch }
        }

        Move-Item -LiteralPath $scratch -Destination $target -Force
        Write-MsixLog -Level Info -Message "Bundle operation complete: $target ($processed processed, $passed passed through)."
        [pscustomobject]@{
            BundlePath            = $target
            PackagesProcessed     = $processed
            PackagesPassedThrough = $passed
        }
    } finally {
        if (Test-Path -LiteralPath $ws)      { Remove-Item -LiteralPath $ws -Recurse -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue }
    }
}
