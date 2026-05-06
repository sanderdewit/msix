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

function Install-MsixMgr {
    <#
    .SYNOPSIS
        Downloads and extracts the latest msixmgr.exe from Microsoft, ready for
        New-MsixAppAttachImage.

    .DESCRIPTION
        Pulls https://aka.ms/msixmgr (Microsoft's stable redirect to the latest
        msixmgrSetup.zip), unpacks under "$ToolsRoot\msixmgr", and exports
        $env:MSIX_MSIXMGR_PATH so subsequent calls find it.

    .PARAMETER Destination
        Where to extract. Defaults to "$Get-MsixToolsRoot\msixmgr".

    .PARAMETER Force
        Re-download even if msixmgr is already installed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [switch]$Force
    )

    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'msixmgr' }

    $marker = Join-Path $Destination 'msixmgr.installed'
    if ((Test-Path $marker) -and -not $Force) {
        Write-MsixLog Info "msixmgr already installed at $Destination. Use -Force to reinstall."
        return [pscustomobject]@{ Path = $Destination; Updated = $false }
    }

    $tmp = Join-Path $env:TEMP "msixmgr-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item $tmp -ItemType Directory -Force | Out-Null
    $zip = Join-Path $tmp 'msixmgrSetup.zip'

    if ($PSCmdlet.ShouldProcess($Destination, 'Install msixmgr')) {
        try {
            Write-MsixLog Info "Downloading $script:MsixMgrZipUrl"
            $oldPref = $ProgressPreference
            $ProgressPreference = 'SilentlyContinue'
            try {
                Invoke-WebRequest -Uri $script:MsixMgrZipUrl -OutFile $zip -UseBasicParsing -ErrorAction Stop
            } finally {
                $ProgressPreference = $oldPref
            }

            New-Item $Destination -ItemType Directory -Force | Out-Null
            Expand-Archive -LiteralPath $zip -DestinationPath $Destination -Force
            (Get-Date -Format o) | Set-Content $marker -Encoding ascii

            $exe = Get-ChildItem $Destination -Recurse -Filter 'msixmgr.exe' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($exe) {
                $env:MSIX_MSIXMGR_PATH = $exe.FullName
                Write-MsixLog Info "msixmgr installed: $($exe.FullName)"
            } else {
                Write-MsixLog Warning "msixmgr.exe not found after extraction; check $Destination"
            }
        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{
        Path    = $Destination
        Updated = $true
        Source  = $script:MsixMgrZipUrl
    }
}


function Update-MsixMgr {
    <#
    .SYNOPSIS
        Refreshes msixmgr if the local copy is older than -MaxAgeDays
        (default 60). Microsoft updates msixmgr infrequently.
    #>
    [CmdletBinding()]
    param(
        [string]$Destination,
        [int]$MaxAgeDays = 60
    )
    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'msixmgr' }
    $marker = Join-Path $Destination 'msixmgr.installed'

    if (-not (Test-Path $marker)) {
        return Install-MsixMgr -Destination $Destination
    }
    $stamp = [datetime](Get-Content $marker -Raw).Trim()
    $age   = (Get-Date) - $stamp
    if ($age.TotalDays -gt $MaxAgeDays) {
        Write-MsixLog Info "msixmgr is $([int]$age.TotalDays) days old; refreshing."
        return Install-MsixMgr -Destination $Destination -Force
    }
    Write-MsixLog Info "msixmgr is fresh ($([int]$age.TotalDays) days old; threshold $MaxAgeDays)."
    return [pscustomobject]@{ Path = $Destination; Updated = $false }
}


function Get-MsixMgrVersion {
    <#
    .SYNOPSIS
        Reports the version of msixmgr.exe currently resolved.
    #>
    [CmdletBinding()]
    param([string]$Path)

    if (-not $Path) { $Path = Resolve-MsixMgrPath }
    if (-not $Path -or -not (Test-Path $Path)) {
        return [pscustomobject]@{ Path = $Path; Installed = $false; Version = $null }
    }
    $info = Get-Item $Path
    return [pscustomobject]@{
        Path      = $info.FullName
        Installed = $true
        Version   = $info.VersionInfo.FileVersion
    }
}


function Resolve-MsixMgrPath {
    if ($env:MSIX_MSIXMGR_PATH -and (Test-Path $env:MSIX_MSIXMGR_PATH)) {
        return (Resolve-Path $env:MSIX_MSIXMGR_PATH).Path
    }
    $toolsRoot = Get-MsixToolsRoot
    foreach ($p in @(
        (Join-Path $toolsRoot 'msixmgr\x64\msixmgr.exe'),
        (Join-Path $toolsRoot 'msixmgr\x86\msixmgr.exe'),
        (Join-Path $toolsRoot 'Tools\msixmgr.exe')
    )) {
        if (Test-Path $p) { return $p }
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
        .vhdx or .cim path to create.

    .PARAMETER FileType
        'vhdx' or 'cim'. Default: vhdx.

    .PARAMETER SizeGB
        Size of the VHDX. Auto-sized to the unpacked footprint + 20% if omitted.
        Ignored for CIM.

    .PARAMETER VolumeLabel
        Label for the formatted volume. Default: 'AppAttach'.

    .PARAMETER ApplyAcls
        Apply the necessary ACLs for App Attach. Default: $true.

    .NOTES
        Requires administrator rights (New-VHD, Mount-DiskImage, Initialize-Disk, Format-Volume).

    .EXAMPLE
        New-MsixAppAttachImage -PackagePath app.msix -OutputPath C:\images\app.vhdx
    .EXAMPLE
        New-MsixAppAttachImage -PackagePath app.msix -OutputPath C:\images\app.cim -FileType cim
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
        if (-not (Test-Path $p)) { throw "Package not found: $p" }
    }

    $aclFlag = if ($ApplyAcls) { '-applyacls' } else { '' }

    if ($FileType -eq 'cim') {
        # msixmgr CIM mode handles everything in one call per package.
        # For multiple packages, we expand the first one with -create and add the rest.
        $first = $true
        foreach ($p in $PackagePath) {
            $createFlag = if ($first) { '-create' } else { '' }
            $args = "-Unpack -packagePath `"$p`" -destination `"$OutputPath`" -fileType cim $createFlag $aclFlag"
            if ($PSCmdlet.ShouldProcess($OutputPath, "Add $p to CIM")) {
                $r = Invoke-MsixProcess $msixmgr $args
                Assert-MsixProcessSuccess $r 'msixmgr CIM'
            }
            $first = $false
        }
        Write-MsixLog Info "App Attach CIM created: $OutputPath"
        return Get-Item $OutputPath
    }

    # ──────────── VHDX path ────────────
    if (-not (Get-Command New-VHD -ErrorAction SilentlyContinue)) {
        throw 'New-VHD not available. Install the Hyper-V PowerShell module: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-Management-PowerShell'
    }

    if (-not $SizeGB) {
        $totalBytes = ($PackagePath | ForEach-Object { (Get-Item $_).Length } | Measure-Object -Sum).Sum
        # Unpacked is roughly 2-3x compressed; pad another 20% headroom; minimum 1 GB
        $SizeGB = [math]::Max(1, [math]::Ceiling(($totalBytes * 3 * 1.2) / 1GB))
        Write-MsixLog Info "Auto-sized VHDX: ${SizeGB} GB"
    }

    if ($PSCmdlet.ShouldProcess($OutputPath, "Create VHDX (${SizeGB} GB)")) {
        New-VHD -Path $OutputPath -SizeBytes ([int64]$SizeGB * 1GB) -Dynamic | Out-Null
    }

    $disk = Mount-DiskImage -ImagePath $OutputPath -PassThru | Get-DiskImage
    $diskNum = (Get-Disk -Number $disk.Number).Number
    try {
        Initialize-Disk -Number $diskNum -PartitionStyle GPT -ErrorAction SilentlyContinue | Out-Null
        $part = New-Partition -DiskNumber $diskNum -UseMaximumSize -AssignDriveLetter
        Format-Volume -DriveLetter $part.DriveLetter -FileSystem NTFS -NewFileSystemLabel $VolumeLabel -Confirm:$false | Out-Null
        $drive = "$($part.DriveLetter):"

        foreach ($p in $PackagePath) {
            $info  = _MsixGetPackageInfo $p
            $folder = "${drive}\$($info.Name)_$($info.Version)"
            Write-MsixLog Info "Expanding $p -> $folder"
            $args = "-Unpack -packagePath `"$p`" -destination `"$folder`" $aclFlag"
            $r = Invoke-MsixProcess $msixmgr $args
            Assert-MsixProcessSuccess $r 'msixmgr unpack-to-vhd'
        }

    } finally {
        Dismount-DiskImage -ImagePath $OutputPath | Out-Null
    }

    Write-MsixLog Info "App Attach VHDX created: $OutputPath"
    return Get-Item $OutputPath
}


function Mount-MsixAppAttachImage {
    <#
    .SYNOPSIS
        Mounts a VHDX/CIM created by New-MsixAppAttachImage so its contents can
        be inspected.

    .EXAMPLE
        Mount-MsixAppAttachImage -ImagePath C:\images\app.vhdx
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ImagePath
    )

    if (-not (Test-Path $ImagePath)) { throw "Image not found: $ImagePath" }

    $img = Mount-DiskImage -ImagePath $ImagePath -PassThru
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
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ImagePath
    )
    Dismount-DiskImage -ImagePath $ImagePath -ErrorAction Stop | Out-Null
    Write-MsixLog Info "Dismounted: $ImagePath"
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
        $packages = Get-ChildItem $m.DriveLetter -Directory -ErrorAction SilentlyContinue |
                    ForEach-Object {
                        $manifest = Join-Path $_.FullName 'AppxManifest.xml'
                        if (Test-Path $manifest) {
                            [xml]$x = Get-Content $manifest -Raw
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
