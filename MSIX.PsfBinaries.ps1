# =============================================================================
# PSF binary management
# -----------------------------------------------------------------------------
# Downloads, caches, and updates the binaries the module needs at runtime:
#
#   - PSF (Tim Mangan's fork — TMurgent, more actively maintained than upstream)
#         https://github.com/TimMangan/MSIX-PackageSupportFramework/releases
#   - Sysinternals Process Monitor
#         https://download.sysinternals.com/files/ProcessMonitor.zip
#
# Default install root is "$ToolsRoot\psf" / "$ToolsRoot\procmon" so existing
# Get-MsixToolsRoot logic continues to find them.
# =============================================================================

$script:TMurgentRepo  = 'TimMangan/MSIX-PackageSupportFramework'
$script:ProcmonZipUrl = 'https://download.sysinternals.com/files/ProcessMonitor.zip'

function _MsixDownloadFile {
    param(
        [string]$Url,
        [string]$Destination
    )
    Write-MsixLog Info "Downloading $Url"
    $oldPref = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'   # MUCH faster on Windows PowerShell 5.1
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
    } finally {
        $ProgressPreference = $oldPref
    }
}

function _MsixGitHubLatest {
    param([string]$Repo)
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $hdr = @{ 'User-Agent' = 'MSIX-PowerShell-Module' }
    if ($env:GITHUB_TOKEN) { $hdr['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
    return Invoke-RestMethod -Uri $api -Headers $hdr -UseBasicParsing -ErrorAction Stop
}


function Install-MsixPsfBinaries {
    <#
    .SYNOPSIS
        Downloads the latest TMurgent PSF release and installs it under the
        module's tools root (or a path you specify), ready for Add-MsixPsfV2.

    .DESCRIPTION
        Tim Mangan's fork of the Package Support Framework
        (https://github.com/TimMangan/MSIX-PackageSupportFramework) ships
        pre-built binaries — including PsfLauncher*.exe, PsfRuntime*.dll,
        StartingScriptWrapper.ps1 and the modern MFRFixup — that the upstream
        Microsoft repo does not always include in releases.

        This function uses the GitHub API to find the latest release, downloads
        the asset that contains the binaries (.zip), extracts everything into
        $ToolsRoot\psf, and writes a `psf.version` marker so subsequent calls
        know what's installed.

    .PARAMETER Destination
        Where to extract. Defaults to "$Get-MsixToolsRoot\psf".

    .PARAMETER Force
        Reinstall even if the latest version is already present.

    .PARAMETER AssetPattern
        Regex matched against asset names. Defaults to '\.zip$' so any zip works.

    .EXAMPLE
        Install-MsixPsfBinaries
    .EXAMPLE
        Install-MsixPsfBinaries -Force
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [switch]$Force,
        [string]$AssetPattern = '\.zip$'
    )

    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'psf' }

    $release = _MsixGitHubLatest $script:TMurgentRepo
    $tag     = $release.tag_name
    Write-MsixLog Info "Latest TMurgent PSF release: $tag"

    $marker = Join-Path $Destination 'psf.version'
    if ((Test-Path $marker) -and -not $Force) {
        $current = (Get-Content $marker -Raw -ErrorAction SilentlyContinue).Trim()
        if ($current -eq $tag) {
            Write-MsixLog Info "PSF $tag already installed at $Destination. Use -Force to reinstall."
            return [pscustomobject]@{ Path = $Destination; Version = $tag; Updated = $false }
        }
    }

    $asset = $release.assets | Where-Object { $_.name -match $AssetPattern } | Select-Object -First 1
    if (-not $asset) {
        throw "No release asset matching '$AssetPattern' in $tag. Assets: $($release.assets.name -join ', ')"
    }

    $tmp = Join-Path $env:TEMP "tmurgent-psf-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item $tmp -ItemType Directory -Force | Out-Null
    $zip = Join-Path $tmp $asset.name

    if ($PSCmdlet.ShouldProcess($Destination, "Install PSF $tag")) {
        try {
            _MsixDownloadFile -Url $asset.browser_download_url -Destination $zip
            Expand-Archive -LiteralPath $zip -DestinationPath $tmp -Force

            New-Item $Destination -ItemType Directory -Force | Out-Null
            # Copy every file from extracted layout into Destination flatly
            Get-ChildItem $tmp -Recurse -File | Where-Object { $_.FullName -ne $zip } |
                ForEach-Object { Copy-Item $_.FullName $Destination -Force }

            Set-Content -Path $marker -Value $tag -Encoding ascii
            Write-MsixLog Info "PSF $tag installed to $Destination"

        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{
        Path    = $Destination
        Version = $tag
        Updated = $true
        Source  = $asset.browser_download_url
    }
}


function Get-MsixPsfBinariesVersion {
    <#
    .SYNOPSIS
        Reports the version of PSF binaries currently installed under the
        tools root (or the path you provide).
    #>
    [CmdletBinding()]
    param(
        [string]$Path
    )
    if (-not $Path) { $Path = Join-Path (Get-MsixToolsRoot) 'psf' }
    $marker = Join-Path $Path 'psf.version'
    return [pscustomobject]@{
        Path        = $Path
        Installed   = Test-Path $marker
        Version     = if (Test-Path $marker) { (Get-Content $marker -Raw).Trim() } else { $null }
        HasLauncher = Test-Path (Join-Path $Path 'PsfLauncher32.exe')
    }
}


function Update-MsixPsfBinaries {
    <#
    .SYNOPSIS
        Convenience wrapper: re-runs Install-MsixPsfBinaries only when the GitHub
        latest tag differs from what's installed.
    #>
    [CmdletBinding()]
    param([string]$Destination)

    $current = Get-MsixPsfBinariesVersion -Path $Destination
    if (-not $current.Installed) {
        Write-MsixLog Info "No PSF found locally; installing."
        return Install-MsixPsfBinaries -Destination $Destination
    }

    $latest = (_MsixGitHubLatest $script:TMurgentRepo).tag_name
    if ($current.Version -eq $latest) {
        Write-MsixLog Info "PSF up to date ($latest)"
        return $current
    }
    Write-MsixLog Info "Update available: $($current.Version) -> $latest"
    return Install-MsixPsfBinaries -Destination $Destination -Force
}


function Install-MsixProcMon {
    <#
    .SYNOPSIS
        Downloads and extracts Sysinternals Process Monitor under the tools root
        (or to a path you specify), ready for Invoke-MsixProcMonCapture.

    .PARAMETER Destination
        Where to extract. Defaults to "$Get-MsixToolsRoot\procmon".

    .PARAMETER Force
        Re-download even if procmon is already present.

    .NOTES
        Sysinternals doesn't expose a versioned download URL — the zip is always
        the latest. This function therefore stamps the install date as the
        "version" so Update-MsixProcMon knows when to refresh.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [switch]$Force
    )

    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'procmon' }

    $marker = Join-Path $Destination 'procmon.installed'
    if ((Test-Path $marker) -and -not $Force) {
        Write-MsixLog Info "Process Monitor already installed at $Destination. Use -Force to reinstall."
        return [pscustomobject]@{ Path = $Destination; Updated = $false }
    }

    $tmp = Join-Path $env:TEMP "procmon-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item $tmp -ItemType Directory -Force | Out-Null
    $zip = Join-Path $tmp 'ProcessMonitor.zip'

    if ($PSCmdlet.ShouldProcess($Destination, 'Install Process Monitor')) {
        try {
            _MsixDownloadFile -Url $script:ProcmonZipUrl -Destination $zip
            New-Item $Destination -ItemType Directory -Force | Out-Null
            Expand-Archive -LiteralPath $zip -DestinationPath $Destination -Force
            (Get-Date -Format o) | Set-Content $marker -Encoding ascii

            # Make Resolve-MsixProcMonPath find it via env-var hint
            $exe = Join-Path $Destination 'Procmon.exe'
            if (Test-Path $exe) {
                $env:MSIX_PROCMON_PATH = $exe
                Write-MsixLog Info "Process Monitor installed at $exe"
            } else {
                Write-MsixLog Warning "Procmon.exe not found after extraction; check $Destination"
            }
        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{
        Path    = $Destination
        Updated = $true
        Source  = $script:ProcmonZipUrl
    }
}


function Update-MsixProcMon {
    <#
    .SYNOPSIS
        Refreshes Process Monitor if the local copy is older than -MaxAgeDays
        (default 30). Sysinternals updates infrequently so a slow cadence is fine.
    #>
    [CmdletBinding()]
    param(
        [string]$Destination,
        [int]$MaxAgeDays = 30
    )

    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'procmon' }
    $marker = Join-Path $Destination 'procmon.installed'

    if (-not (Test-Path $marker)) {
        return Install-MsixProcMon -Destination $Destination
    }
    $stamp = [datetime](Get-Content $marker -Raw).Trim()
    $age   = (Get-Date) - $stamp
    if ($age.TotalDays -gt $MaxAgeDays) {
        Write-MsixLog Info "Procmon is $([int]$age.TotalDays) days old; refreshing."
        return Install-MsixProcMon -Destination $Destination -Force
    }
    Write-MsixLog Info "Procmon is fresh ($([int]$age.TotalDays) days old; threshold $MaxAgeDays)."
    return [pscustomobject]@{ Path = $Destination; Updated = $false }
}


function Initialize-MsixToolchain {
    <#
    .SYNOPSIS
        One-call setup: ensures PSF binaries (TMurgent), Process Monitor, and
        msixmgr are present and up to date under the tools root. Run once
        before doing any investigation/PSF injection/App Attach work.

    .EXAMPLE
        Initialize-MsixToolchain                  # install/update everything
        Initialize-MsixToolchain -Skip Procmon    # skip Procmon
        Initialize-MsixToolchain -Skip Procmon,MsixMgr   # PSF only
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Psf','Procmon','MsixMgr')]
        [string[]]$Skip
    )

    $result = [ordered]@{ Psf = $null; Procmon = $null; MsixMgr = $null }
    if ($Skip -notcontains 'Psf')     { $result.Psf     = Update-MsixPsfBinaries }
    if ($Skip -notcontains 'Procmon') { $result.Procmon = Update-MsixProcMon }
    if ($Skip -notcontains 'MsixMgr') { $result.MsixMgr = Update-MsixMgr }
    return [pscustomobject]$result
}
