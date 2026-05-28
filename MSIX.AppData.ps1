# =============================================================================
# MSIX AppData / out-of-package helpers
# -----------------------------------------------------------------------------
# Bridge between the host filesystem and packaged-app virtualised storage.
# Useful when:
#   - A legacy installer dropped data in %AppData%\Roaming during conversion
#     (and the packaged app can't see it).
#   - You need to inspect / copy data into the package container's redirected
#     AppData (LocalCache\Roaming).
#   - A package was uninstalled but left orphaned data behind.
#
# References:
#   - manage/troubleshoot-msix-container          (Invoke-CommandInDesktopPackage)
#   - desktop/desktop-to-uwp-known-issues
#   - PSF FileRedirectionFixup behaviour
# =============================================================================

function Get-MsixContainerAppData {
    <#
    .SYNOPSIS
        Returns the per-package redirected AppData paths for an installed MSIX.

    .DESCRIPTION
        Packaged Win32 apps don't see the real %AppData%\Roaming. Their writes
        get redirected to %LocalAppData%\Packages\<PackageFamilyName>\LocalCache\
        which is laid out as:

            LocalCache\Local       <- maps to %LocalAppData%
            LocalCache\Roaming     <- maps to %AppData% (Roaming)
            LocalCache\Temp        <- maps to %Temp%

        This function returns those four paths for the named package.

    .PARAMETER PackageName
        Full or partial package name (wildcards accepted).

    .EXAMPLE
        Get-MsixContainerAppData -PackageName 'Contoso.App'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$PackageName
    )

    PROCESS {
        $appx = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
        if (-not $appx) {
            $appx = Get-AppxPackage | Where-Object { $_.Name -like "*$PackageName*" }
        }
        if (-not $appx) { throw "No installed package matches '$PackageName'." }
        if (@($appx).Count -gt 1) {
            throw "Multiple matches for '$PackageName'. Be more specific. Found: $(($appx.Name) -join ', ')"
        }

        $base = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Packages\$($appx.PackageFamilyName)"
        $cache = Join-Path -Path $base -ChildPath 'LocalCache'

        return [pscustomobject]@{
            Name              = $appx.Name
            PackageFamilyName = $appx.PackageFamilyName
            PackageRoot       = $base
            VirtualLocal      = Join-Path -Path $cache -ChildPath 'Local'
            VirtualRoaming    = Join-Path -Path $cache -ChildPath 'Roaming'
            VirtualTemp       = Join-Path -Path $cache -ChildPath 'Temp'
            AcExists          = Test-Path -LiteralPath (Join-Path -Path $base -ChildPath 'AC')
            CacheExists       = Test-Path -LiteralPath $cache
        }
    }
}


function Get-MsixOrphanedAppData {
    <#
    .SYNOPSIS
        Lists %AppData%\Roaming subfolders that belong to no installed MSIX
        package family — i.e. probable leftovers from legacy installers run
        before/during MSIX conversion.

    .DESCRIPTION
        For every subfolder of %AppData%\Roaming this checks whether the folder
        name appears in any installed AppxPackage display/full name. Anything
        with no match is returned as a candidate orphan. False positives are
        expected — this is a triage list, not a delete list.

        Background: legacy installers run during MSIX conversion (Capture
        phase) sometimes write to %AppData%\Roaming. Those writes land on the
        host AppData, not inside the package. The packaged app can't see them
        on first launch and either re-creates state or fails. See
        https://learn.microsoft.com/windows/msix/desktop/desktop-to-uwp-known-issues

    .PARAMETER PackageHints
        Optional list of additional substrings that should be considered as
        "owned" (e.g. vendor names that don't appear in the package identity).

    .OUTPUTS
        Folder objects with .Path, .SizeMB, .LastWriteTime
    #>
    [CmdletBinding()]
    param(
        [string[]]$PackageHints
    )

    $roaming = $env:APPDATA
    if (-not (Test-Path -LiteralPath $roaming)) { throw "Roaming AppData not found: $roaming" }

    $installed = Get-AppxPackage |
                 ForEach-Object { @($_.Name, $_.PackageFamilyName, $_.PublisherId, $_.Publisher) } |
                 Where-Object { $_ } |
                 Sort-Object -Unique

    $hints = @($PackageHints) + $installed | Where-Object { $_ }

    Get-ChildItem -LiteralPath $roaming -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $folder = $_
        $matched = $false
        foreach ($h in $hints) {
            if ($folder.Name -like "*$h*" -or $h -like "*$($folder.Name)*") { $matched = $true; break }
        }
        if (-not $matched) {
            $size = 0
            try {
                $size = (Get-ChildItem -LiteralPath $folder.FullName -Recurse -File -ErrorAction SilentlyContinue |
                         Measure-Object -Property Length -Sum).Sum
            } catch {
                Write-MsixLog -Level Debug -Message "Could not measure orphaned AppData folder '$($folder.FullName)': $_"
            }
            [pscustomobject]@{
                Path          = $folder.FullName
                Name          = $folder.Name
                SizeMB        = if ($size) { [math]::Round($size / 1MB, 2) } else { 0 }
                LastWriteTime = $folder.LastWriteTime
            }
        }
    } | Sort-Object SizeMB -Descending
}


function Copy-MsixHostAppDataIntoPackage {
    <#
    .SYNOPSIS
        Copies a host filesystem folder into the redirected Roaming directory
        of an installed MSIX package, so the packaged app sees the data on
        next launch.

    .DESCRIPTION
        Solves the common scenario where a legacy installer wrote per-user data
        to %AppData%\Roaming\<Vendor> before the package was converted, and the
        packaged app now starts with empty state. After running this, the data
        appears under LocalCache\Roaming (which the app sees as %AppData%).

    .PARAMETER SourcePath
        Folder on the host (typically under %AppData%\Roaming) to copy from.

    .PARAMETER PackageName
        Installed MSIX package name (or partial; wildcards allowed).

    .PARAMETER DestinationSubfolder
        Subfolder name inside LocalCache\Roaming. Defaults to source folder name.

    .PARAMETER WhatIf
        Show what would happen without copying.

    .EXAMPLE
        Copy-MsixHostAppDataIntoPackage -SourcePath "$env:APPDATA\ContosoLegacy" -PackageName 'Contoso.App'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,
        [Parameter(Mandatory)]
        [string]$PackageName,
        [string]$DestinationSubfolder
    )

    if (-not (Test-Path -LiteralPath $SourcePath)) { throw "Source not found: $SourcePath" }

    $info = Get-MsixContainerAppData -PackageName $PackageName
    if (-not $DestinationSubfolder) {
        $DestinationSubfolder = (Get-Item -LiteralPath $SourcePath).Name
    }
    $dest = Join-Path -Path $info.VirtualRoaming -ChildPath $DestinationSubfolder

    if ($PSCmdlet.ShouldProcess($dest, "Copy from $SourcePath")) {
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        Copy-Item -Path "$SourcePath\*" -Destination $dest -Recurse -Force
        Write-MsixLog -Level Info -Message "Copied $SourcePath -> $dest"
    }
    return $dest
}


function Invoke-MsixContainerCommand {
    <#
    .SYNOPSIS
        Convenience wrapper around Invoke-CommandInDesktopPackage.

    .DESCRIPTION
        Launches a command inside the package container so you can inspect the
        merged file system and registry as the app sees them. Common uses:
        cmd.exe, regedit.exe, powershell.exe.

        See https://learn.microsoft.com/windows/msix/manage/troubleshoot-msix-container

    .PARAMETER PackageName
        Package name (wildcards allowed).

    .PARAMETER Command
        Command to run. Default: cmd.exe.

    .PARAMETER AppId
        Override Application Id. Defaults to the first one in the manifest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$PackageName,
        [string]$Command = 'cmd.exe',
        [string]$AppId
    )

    PROCESS {
        $appx = Get-AppxPackage -Name $PackageName -ErrorAction SilentlyContinue
        if (-not $appx) { $appx = Get-AppxPackage | Where-Object { $_.Name -like "*$PackageName*" } }
        if (-not $appx) { throw "No installed package matches '$PackageName'." }
        if (@($appx).Count -gt 1) { throw "Multiple packages match '$PackageName'. Be specific." }

        if (-not $AppId) {
            $manifest = Get-AppPackageManifest -Package $appx.PackageFullName
            $AppId = (@($manifest.Package.Applications.Application))[0].Id
        }

        Write-MsixLog -Level Info -Message "Container exec: $($appx.PackageFamilyName)!$AppId -> $Command"
        Invoke-CommandInDesktopPackage -PackageFamilyName $appx.PackageFamilyName `
                                       -AppId $AppId `
                                       -Command $Command `
                                       -PreventBreakaway
    }
}


function Get-MsixPackageStorageSummary {
    <#
    .SYNOPSIS
        Summarises disk usage of an installed package: install root, virtualised
        AppData (Local/Roaming/Temp), and AppContainer state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$PackageName
    )

    PROCESS {
        $info = Get-MsixContainerAppData -PackageName $PackageName
        $appx = Get-AppxPackage -Name $info.Name | Select-Object -First 1

        function _size($p) {
            if (-not (Test-Path -LiteralPath $p)) { return 0 }
            $s = (Get-ChildItem -LiteralPath $p -Recurse -File -ErrorAction SilentlyContinue |
                  Measure-Object -Property Length -Sum).Sum
            [math]::Round(([double]$s) / 1MB, 2)
        }

        [pscustomobject]@{
            Name              = $info.Name
            PackageFamilyName = $info.PackageFamilyName
            InstallLocation   = $appx.InstallLocation
            InstallSizeMB     = _size $appx.InstallLocation
            RoamingMB         = _size $info.VirtualRoaming
            LocalMB           = _size $info.VirtualLocal
            TempMB            = _size $info.VirtualTemp
            PackageRoot       = $info.PackageRoot
        }
    }
}
