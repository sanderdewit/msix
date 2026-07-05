# =============================================================================
# MSIX App Attach
# -----------------------------------------------------------------------------
# Generates VHDX or CIM images from an .msix using msixmgr.exe so the package
# can be attached as a layered image in Azure Virtual Desktop / Windows 365 /
# any App Attach scenario.
#
# Reference:
#   https://learn.microsoft.com/azure/virtual-desktop/app-attach-msixmgr
#   https://learn.microsoft.com/azure/virtual-desktop/app-attach-overview
# =============================================================================

# Microsoft hosts the latest msixmgrSetup.zip behind an aka.ms redirect.
# Drop a marker file alongside the binary so Update-MsixMgr can age it out.
$script:MsixMgrZipUrl = 'https://aka.ms/msixmgr'

# Optional known-good SHA-256 of the msixmgrSetup.zip served by aka.ms/msixmgr.
# msixmgr's upstream is unsigned (microsoft/msix-packaging#710), so Authenticode
# verification is off by default; a hash is the only integrity control available.
#
# Left EMPTY intentionally so the module works out of the box (a wrong/guessed
# hash would reject the legitimate download). To turn on integrity pinning by
# default for every Install-MsixMgr call, paste the SHA-256 of a trusted copy
# here — capture it from the "SHA-256 verified/observed" log line emitted on a
# normal download, or run:
#   (Get-FileHash .\msixmgrSetup.zip -Algorithm SHA256).Hash
# Callers can always override per-call with -ExpectedSha256 regardless of this.
$script:MsixMgrKnownSha256 = ''

function Install-MsixMgr {
    <#
    .SYNOPSIS
        Downloads and extracts the latest msixmgr.exe from Microsoft, ready for
        New-MsixAppAttachImage.

    .DESCRIPTION
        Pulls https://aka.ms/msixmgr (Microsoft's stable redirect to the latest
        msixmgrSetup.zip), unpacks under "$ToolsRoot\msixmgr", and exports
        $env:MSIX_MSIXMGR_PATH so subsequent calls find it.

        SECURITY / msixmgr signature status: the upstream archive ships
        with binaries that fail Authenticode verification against any
        production-Microsoft allowlist — msixmgr.exe and msix.dll are
        unsigned, and ApplyACLs.dll / CreateCIM.dll / WVDUtilities.dll are
        signed by 'CN=Microsoft Testing PCA 2010' (test CA, not in the
        Windows trusted-root store). Filed upstream:
        https://github.com/microsoft/msix-packaging/issues/710 — at time of
        writing the issue is open and the repo appears inactive.

        Because the verification check fails on every install today, this
        cmdlet defaults to SKIPPING Authenticode verification for msixmgr
        specifically. Pass -VerifyAuthenticode to opt back in (e.g. once
        Microsoft ships production-signed binaries upstream). The skip
        applies ONLY to msixmgr — every other downloaded toolchain binary
        (PSF, Procmon, DebugView, SDK BuildTools) is still verified.

    .PARAMETER Destination
        Where to extract. Defaults to "(Get-MsixToolsRoot)\msixmgr".

    .PARAMETER Force
        Re-download even if msixmgr is already installed.

    .PARAMETER VerifyAuthenticode
        Opt in to Authenticode verification of the msixmgr archive contents.
        Default: $false (skip). Currently failing upstream — see DESCRIPTION
        / microsoft/msix-packaging#710. Other toolchain downloaders verify
        unconditionally.

    .OUTPUTS
        [pscustomobject] with Path, Updated, and (on fresh install) Source URL.

    .EXAMPLE
        # Install msixmgr so New-MsixAppAttachImage can produce VHDX / CIM images.
        # Authenticode verification is skipped by default — see DESCRIPTION
        # for why (upstream signing is broken).
        Install-MsixMgr

    .EXAMPLE
        # Opt back in to verification (will throw today until upstream
        # microsoft/msix-packaging#710 ships production-signed binaries).
        Install-MsixMgr -VerifyAuthenticode

    .EXAMPLE
        # Force a re-download (msixmgr updates infrequently).
        Install-MsixMgr -Force
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '',
        Justification = 'ShouldProcess is invoked inside _MsixInstallArchiveTool which receives -WhatIf through CmdletBinding inheritance. PSSA cannot trace the call across the helper boundary.')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [switch]$Force,
        [switch]$VerifyAuthenticode,
        # Optional SHA-256 of msixmgrSetup.zip. Defaults to the module's
        # known-good constant ($script:MsixMgrKnownSha256), which ships empty so
        # the install works out of the box. Supply this (or populate the
        # constant) to integrity-pin the download since msixmgr is unsigned.
        [string]$ExpectedSha256 = $script:MsixMgrKnownSha256
    )
    if (-not $Destination) { $Destination = Join-Path -Path (Get-MsixToolsRoot) 'msixmgr' }

    _MsixInstallArchiveTool `
        -ToolName 'msixmgr' `
        -Destination $Destination `
        -MarkerFile (Join-Path -Path $Destination 'msixmgr.installed') `
        -Url $script:MsixMgrZipUrl `
        -ArchiveFileName 'msixmgrSetup.zip' `
        -VerifyAuthenticode ([bool]$VerifyAuthenticode) `
        -ExpectedSha256 $ExpectedSha256 `
        -SkipVerificationWarning 'Skipping Authenticode verification for msixmgr (upstream signing is broken: microsoft/msix-packaging#710). Pass -VerifyAuthenticode to re-enable. This skip applies ONLY to msixmgr — every other downloaded toolchain binary is still verified.' `
        -Force:$Force `
        -PostInstall {
            param($dest)
            $exe = Get-ChildItem -LiteralPath $dest -Recurse -Filter 'msixmgr.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($exe) {
                $env:MSIX_MSIXMGR_PATH = $exe.FullName
                Write-MsixLog -Level Info -Message "msixmgr installed: $($exe.FullName)"
            } else {
                Write-MsixLog -Level Warning -Message "msixmgr.exe not found after extraction; check $dest"
            }
        }
}


function Update-MsixMgr {
    <#
    .SYNOPSIS
        Refreshes msixmgr if the local copy is older than -MaxAgeDays
        (default 60). Microsoft updates msixmgr infrequently.

    .DESCRIPTION
        Age-based updater. Re-runs Install-MsixMgr -Force only when the cached
        marker is older than -MaxAgeDays; otherwise reports the existing
        install. Falls back to a fresh install if nothing is cached.

    .PARAMETER Destination
        Cache folder. Defaults to "(Get-MsixToolsRoot)\msixmgr".

    .PARAMETER MaxAgeDays
        Refresh threshold in days. Default 60.

    .OUTPUTS
        [pscustomobject] from Install-MsixMgr or a no-op summary.

    .EXAMPLE
        # Keep msixmgr fresh on a CI agent.
        Update-MsixMgr
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '',
        Justification = 'ShouldProcess is invoked inside _MsixUpdateToolByAge which receives -WhatIf through CmdletBinding inheritance.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'VerifyAuthenticode',
        Justification = 'Captured by the -InstallFresh / -InstallForce script blocks via lexical closure; PSSA cannot trace scriptblock captures.')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [int]$MaxAgeDays = 60,
        # Pass-through to Install-MsixMgr; see that cmdlet's help for why
        # Authenticode verification is opt-in for msixmgr specifically
        # (upstream signing is broken — microsoft/msix-packaging#710).
        [switch]$VerifyAuthenticode
    )
    if (-not $Destination) { $Destination = Join-Path -Path (Get-MsixToolsRoot) 'msixmgr' }
    _MsixUpdateToolByAge `
        -ToolName 'msixmgr' `
        -Destination $Destination `
        -MarkerFile (Join-Path -Path $Destination 'msixmgr.installed') `
        -MaxAgeDays $MaxAgeDays `
        -InstallFresh { Install-MsixMgr -Destination $Destination -VerifyAuthenticode:$VerifyAuthenticode } `
        -InstallForce { Install-MsixMgr -Destination $Destination -Force -VerifyAuthenticode:$VerifyAuthenticode }
}


function Get-MsixMgrVersion {
    <#
    .SYNOPSIS
        Reports the version of msixmgr.exe currently resolved.

    .DESCRIPTION
        Reads file-version metadata of the resolved msixmgr.exe. Falls back to
        Resolve-MsixMgrPath when -Path is omitted.

    .PARAMETER Path
        Explicit path to msixmgr.exe. Defaults to Resolve-MsixMgrPath.

    .OUTPUTS
        [pscustomobject] with Path, Installed, Version (FileVersion).

    .EXAMPLE
        # Quickly verify the installed msixmgr build.
        Get-MsixMgrVersion
    #>
    [CmdletBinding()]
    param([string]$Path)

    if (-not $Path) { $Path = Resolve-MsixMgrPath }
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]@{ Path = $Path; Installed = $false; Version = $null }
    }
    $info = Get-Item -LiteralPath $Path
    return [pscustomobject]@{
        Path      = $info.FullName
        Installed = $true
        Version   = $info.VersionInfo.FileVersion
    }
}


function Resolve-MsixMgrPath {
    <#
    .SYNOPSIS
        Locates msixmgr.exe.

    .DESCRIPTION
        Resolution order:
          1. $env:MSIX_MSIXMGR_PATH (set by Install-MsixMgr).
          2. "(Get-MsixToolsRoot)\msixmgr\x64\msixmgr.exe" or its x86 sibling.
          3. "(Get-MsixToolsRoot)\Tools\msixmgr.exe" (legacy layout).

        Returns $null when nothing is found. Callers can then choose to invoke
        Install-MsixMgr.

    .OUTPUTS
        [string] full path to msixmgr.exe, or $null.

    .EXAMPLE
        # Resolve msixmgr before invoking it directly.
        $exe = Resolve-MsixMgrPath
        if (-not $exe) { Install-MsixMgr | Out-Null; $exe = Resolve-MsixMgrPath }
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    if ($env:MSIX_MSIXMGR_PATH -and (Test-Path -LiteralPath $env:MSIX_MSIXMGR_PATH)) {
        return (Resolve-Path -LiteralPath $env:MSIX_MSIXMGR_PATH).Path
    }
    $toolsRoot = Get-MsixToolsRoot
    foreach ($p in @(
        (Join-Path -Path $toolsRoot -ChildPath 'msixmgr\x64\msixmgr.exe'),
        (Join-Path -Path $toolsRoot -ChildPath 'msixmgr\x86\msixmgr.exe'),
        (Join-Path -Path $toolsRoot -ChildPath 'Tools\msixmgr.exe')
    )) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}


function _MsixGetPackageInfo {
    param([string]$PackagePath)
    $m = Get-MsixManifest -Path $PackagePath
    return [pscustomobject]@{
        Name        = $m.Package.Identity.Name
        Publisher   = $m.Package.Identity.Publisher
        Version     = $m.Package.Identity.Version
        DisplayName = $m.Package.Properties.DisplayName
    }
}


function New-MsixAppAttachImage {
    <#
    .SYNOPSIS
        Builds an App Attach image (VHDX or CIM) from one or more .msix files
        using msixmgr.exe.

    .DESCRIPTION
        For VHDX:
          1. Creates a fixed-size VHDX (PowerShell New-VHD or fallback diskpart).
          2. Mounts and formats it NTFS.
          3. Calls `msixmgr.exe -Unpack -applyacls` to expand each .msix onto
             the mounted volume.
          4. Dismounts. The VHDX is ready to be staged on an SMB share.

        For CIM:
          msixmgr can create a Composite Image directly without VHD plumbing.

    .PARAMETER PackagePath
        One or more .msix files to include.

    .PARAMETER OutputPath
        The .vhdx or .cim path to create.

    .PARAMETER FileType
        'vhdx' or 'cim'. Default: vhdx.

    .PARAMETER SizeGB
        Size of the VHDX. Auto-sized to the unpacked footprint + 20% if omitted.
        Ignored for CIM.

    .PARAMETER VolumeLabel
        Label for the formatted volume. Default: 'AppAttach'.

    .PARAMETER ApplyAcls
        Apply the necessary ACLs for App Attach. Default: $true.

    .OUTPUTS
        [System.IO.FileInfo] for the produced .vhdx or .cim file.

    .NOTES
        Requires elevation (Administrator) AND the Hyper-V PowerShell module
        (New-VHD, Mount-DiskImage, Initialize-Disk, Format-Volume). Install
        with:
            Enable-WindowsOptionalFeature -Online ``
                -FeatureName Microsoft-Hyper-V-Management-PowerShell

        -WhatIf semantics: every state-changing step (VHDX creation and each
        msixmgr unpack call) honors -WhatIf, so you can dry-run the
        per-package plan against an existing OutputPath without modifying
        anything.

    .EXAMPLE
        # Single-package VHDX (auto-sized) — typical App Attach scenario.
        New-MsixAppAttachImage -PackagePath app.msix `
                               -OutputPath C:\images\app.vhdx

    .EXAMPLE
        # Multi-package CIM — one image with several apps.
        New-MsixAppAttachImage -PackagePath app1.msix,app2.msix `
                               -OutputPath C:\images\bundle.cim -FileType cim

    .EXAMPLE
        # Dry-run a 5GB build to see the planned operations without creating the VHDX.
        New-MsixAppAttachImage -PackagePath app.msix `
                               -OutputPath C:\images\app.vhdx `
                               -SizeGB 5 -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string[]]$PackagePath,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [ValidateSet('vhdx','cim')]
        [string]$FileType = 'vhdx',
        [int]$SizeGB,
        [string]$VolumeLabel = 'AppAttach',
        [bool]$ApplyAcls = $true
    )

    $msixmgr = Resolve-MsixMgrPath
    if (-not $msixmgr) {
        throw "msixmgr.exe not found. Set `$env:MSIX_MSIXMGR_PATH or place it under the tools root\msixmgr\."
    }

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'New-MsixAppAttachImage requires elevation. Run PowerShell as Administrator.'
    }

    foreach ($p in $PackagePath) {
        if (-not (Test-Path -LiteralPath $p)) { throw "Package not found: $p" }
    }

    if ($FileType -eq 'cim') {
        # msixmgr CIM mode handles everything in one call per package.
        # For multiple packages, we expand the first one with -create and add the rest.
        $first = $true
        foreach ($p in $PackagePath) {
            $msixMgrArgs = @('-Unpack', '-packagePath', $p, '-destination', $OutputPath, '-fileType', 'cim')
            if ($first)     { $msixMgrArgs += '-create' }
            if ($ApplyAcls) { $msixMgrArgs += '-applyacls' }
            if ($PSCmdlet.ShouldProcess($OutputPath, "Add $p to CIM")) {
                $r = Invoke-MsixProcess -FilePath $msixmgr -ArgumentList $msixMgrArgs
                Assert-MsixProcessSuccess -Result $r -Operation 'msixmgr CIM'
            }
            $first = $false
        }
        Write-MsixLog -Level Info -Message "App Attach CIM created: $OutputPath"
        return Get-Item -LiteralPath $OutputPath
    }

    # ──────────── VHDX path ────────────
    if (-not (Get-Command New-VHD -ErrorAction SilentlyContinue)) {
        throw 'New-VHD not available. Install the Hyper-V PowerShell module: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell'
    }

    if (-not $SizeGB) {
        $totalBytes = ($PackagePath | ForEach-Object { (Get-Item -LiteralPath $_).Length } | Measure-Object -Sum).Sum
        # Unpacked is roughly 2-3x compressed; pad another 20% headroom; minimum 1 GB
        $SizeGB = [math]::Max(1, [math]::Ceiling(($totalBytes * 3 * 1.2) / 1GB))
        Write-MsixLog -Level Info -Message "Auto-sized VHDX: ${SizeGB} GB"
    }

    if (-not $PSCmdlet.ShouldProcess($OutputPath, "Create VHDX (${SizeGB} GB) and unpack packages")) {
        Write-MsixLog -Level Info -Message "[WhatIf] Would create ${SizeGB} GB VHDX at '$OutputPath' and unpack $($PackagePath.Count) package(s). No changes made."
        return $null
    }

    New-VHD -Path $OutputPath -SizeBytes ([int64]$SizeGB * 1GB) -Dynamic | Out-Null

    $disk = Mount-DiskImage -ImagePath $OutputPath -PassThru | Get-DiskImage
    $diskNum = (Get-Disk -Number $disk.Number).Number
    try {
        Initialize-Disk -Number $diskNum -PartitionStyle GPT -ErrorAction SilentlyContinue | Out-Null
        $part = New-Partition -DiskNumber $diskNum -UseMaximumSize -AssignDriveLetter
        Format-Volume -DriveLetter $part.DriveLetter -FileSystem NTFS -NewFileSystemLabel $VolumeLabel -Confirm:$false | Out-Null
        $drive = "$($part.DriveLetter):"

        foreach ($p in $PackagePath) {
            $info  = _MsixGetPackageInfo -PackagePath $p
            $folder = "${drive}\$($info.Name)_$($info.Version)"
            Write-MsixLog -Level Info -Message "Expanding $p -> $folder"
            $msixMgrArgs = @('-Unpack', '-packagePath', $p, '-destination', $folder)
            if ($ApplyAcls) { $msixMgrArgs += '-applyacls' }
            $r = Invoke-MsixProcess -FilePath $msixmgr -ArgumentList $msixMgrArgs
            Assert-MsixProcessSuccess -Result $r -Operation 'msixmgr unpack-to-vhd'
        }

    } finally {
        Dismount-DiskImage -ImagePath $OutputPath | Out-Null
    }

    Write-MsixLog -Level Info -Message "App Attach VHDX created: $OutputPath"
    return Get-Item -LiteralPath $OutputPath
}


function Mount-MsixAppAttachImage {
    <#
    .SYNOPSIS
        Mounts a VHDX/CIM created by New-MsixAppAttachImage so its contents can
        be inspected.

    .DESCRIPTION
        Wraps Mount-DiskImage + Get-Partition + Get-Volume to surface the
        sandbox-friendly mount info (drive letter, disk number) in a single
        object. Use Dismount-MsixAppAttachImage to release it.

    .PARAMETER ImagePath
        Path to the .vhdx or .cim file produced by New-MsixAppAttachImage.

    .OUTPUTS
        [pscustomobject] with ImagePath, DiskNumber, DriveLetter.

    .EXAMPLE
        # Inspect an image's contents from PowerShell.
        $mnt = Mount-MsixAppAttachImage -ImagePath C:\images\app.vhdx
        Get-ChildItem -LiteralPath $mnt.DriveLetter
        Dismount-MsixAppAttachImage -ImagePath C:\images\app.vhdx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ImagePath
    )

    if (-not (Test-Path -LiteralPath $ImagePath)) { throw "Image not found: $ImagePath" }

    Mount-DiskImage -ImagePath $ImagePath -PassThru | Out-Null
    Start-Sleep -Milliseconds 500
    $disk = Get-DiskImage -ImagePath $ImagePath
    $vol  = Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue |
            Get-Volume -ErrorAction SilentlyContinue |
            Where-Object DriveLetter | Select-Object -First 1

    return [pscustomobject]@{
        ImagePath   = $ImagePath
        DiskNumber  = $disk.Number
        DriveLetter = if ($vol) { "$($vol.DriveLetter):" } else { $null }
    }
}


function Dismount-MsixAppAttachImage {
    <#
    .SYNOPSIS
        Dismounts a VHDX/CIM previously mounted with Mount-MsixAppAttachImage.

    .DESCRIPTION
        Thin wrapper around Dismount-DiskImage that logs the result via
        Write-MsixLog.

    .PARAMETER ImagePath
        Path to the .vhdx or .cim file to dismount.

    .EXAMPLE
        # Release an image after inspection.
        Dismount-MsixAppAttachImage -ImagePath C:\images\app.vhdx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ImagePath
    )
    Dismount-DiskImage -ImagePath $ImagePath -ErrorAction Stop | Out-Null
    Write-MsixLog -Level Info -Message "Dismounted: $ImagePath"
}


function Test-MsixAppAttachImage {
    <#
    .SYNOPSIS
        Validates an existing image: mounts it, lists the package folder(s) it
        contains, dismounts. Use as a smoke-test before publishing to a share.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ImagePath
    )
    $m = Mount-MsixAppAttachImage -ImagePath $ImagePath
    try {
        if (-not $m.DriveLetter) { throw "Image mounted without an accessible volume." }
        $packages = Get-ChildItem -LiteralPath $m.DriveLetter -Directory -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $manifest = Join-Path -Path $_.FullName -ChildPath 'AppxManifest.xml'
                        if (Test-Path -LiteralPath $manifest) {
                            [xml]$x = _MsixLoadXmlSecure -Path $manifest
                            [pscustomobject]@{
                                Folder      = $_.Name
                                Name        = $x.Package.Identity.Name
                                Version     = $x.Package.Identity.Version
                                Publisher   = $x.Package.Identity.Publisher
                            }
                        }
                    }
        return [pscustomobject]@{
            ImagePath   = $ImagePath
            DriveLetter = $m.DriveLetter
            Packages    = $packages
        }
    } finally {
        Dismount-MsixAppAttachImage -ImagePath $ImagePath
    }
}
