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
$script:SdkToolsNuGet = 'Microsoft.Windows.SDK.BuildTools'   # publishes MakeAppx + signtool

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

function _MsixExpandZip {
    <#
    Extracts any zip-format archive into a folder. Unlike Expand-Archive,
    this works regardless of the file's extension (.nupkg, .vsix, etc.).
    #>
    param(
        [string]$ArchivePath,
        [string]$DestinationPath
    )
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    if (-not (Test-Path $DestinationPath)) {
        New-Item $DestinationPath -ItemType Directory -Force | Out-Null
    }
    [System.IO.Compression.ZipFile]::ExtractToDirectory($ArchivePath, $DestinationPath)
}

function _MsixGitHubLatest {
    param([string]$Repo)
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $hdr = @{ 'User-Agent' = 'MSIX-PowerShell-Module' }
    if ($env:GITHUB_TOKEN) { $hdr['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
    return Invoke-RestMethod -Uri $api -Headers $hdr -UseBasicParsing -ErrorAction Stop
}


function Install-MsixPsfBinary {
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
        Install-MsixPsfBinary
    .EXAMPLE
        Install-MsixPsfBinary -Force
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
            _MsixExpandZip -ArchivePath $zip -DestinationPath $tmp

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


function Update-MsixPsfBinary {
    <#
    .SYNOPSIS
        Convenience wrapper: re-runs Install-MsixPsfBinary only when the GitHub
        latest tag differs from what's installed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([string]$Destination)

    if (-not $PSCmdlet.ShouldProcess($Destination, 'Update PSF Binaries')) { return }
    $current = Get-MsixPsfBinariesVersion -Path $Destination
    if (-not $current.Installed) {
        Write-MsixLog Info "No PSF found locally; installing."
        return Install-MsixPsfBinary -Destination $Destination
    }

    $latest = (_MsixGitHubLatest $script:TMurgentRepo).tag_name
    if ($current.Version -eq $latest) {
        Write-MsixLog Info "PSF up to date ($latest)"
        return $current
    }
    Write-MsixLog Info "Update available: $($current.Version) -> $latest"
    return Install-MsixPsfBinary -Destination $Destination -Force
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
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [int]$MaxAgeDays = 30
    )

    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'procmon' }
    if (-not $PSCmdlet.ShouldProcess($Destination, 'Update Process Monitor')) { return }
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


function Install-MsixSdkTool {
    <#
    .SYNOPSIS
        Downloads MakeAppx.exe + signtool.exe from the official Microsoft
        Windows SDK BuildTools NuGet package and lays them out under the
        module's tools root so Get-MsixToolsRoot finds them.

    .DESCRIPTION
        The package id is `Microsoft.Windows.SDK.BuildTools` — Microsoft
        publishes signed CLI tools there for use in CI / build pipelines
        without requiring the full SDK installer. The NuGet package
        contains:

          bin\<sdk-version>\<arch>\MakeAppx.exe
          bin\<sdk-version>\<arch>\signtool.exe
          bin\<sdk-version>\<arch>\makepri.exe
          ... + the AppxPackaging COM stack DLLs

        This function pulls the latest stable version (or the version you
        pin via -Version), extracts the matching architecture into
        "$ToolsRoot\Tools\", and writes a `sdk.version` marker so
        Update-MsixSdkTool knows what's installed.

    .PARAMETER Destination
        Where to land the binaries. Default: the module folder. After install,
        Get-MsixToolsRoot returns this path automatically.

    .PARAMETER Architecture
        x64 (default) or x86. Use whatever matches the architecture you'll be
        signing/packaging from (the host architecture, not the package's).

    .PARAMETER Version
        Pin to a specific NuGet version. Default: latest stable.

    .PARAMETER Force
        Reinstall even if the version is already present.

    .EXAMPLE
        Install-MsixSdkTool

    .EXAMPLE
        Install-MsixSdkTool -Architecture x86 -Force

    .EXAMPLE
        Install-MsixSdkTool -Version '10.0.26100.1742'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [ValidateSet('x86','x64')]
        [string]$Architecture = 'x64',
        [string]$Version,
        [switch]$Force
    )

    if (-not $Destination) { $Destination = $PSScriptRoot }

    # ── Find latest version if not pinned ─────────────────────────────────
    if (-not $Version) {
        $idxUrl = "https://api.nuget.org/v3-flatcontainer/$($script:SdkToolsNuGet.ToLower())/index.json"
        try {
            $idx = Invoke-RestMethod -Uri $idxUrl -UseBasicParsing -ErrorAction Stop
        } catch {
            throw "Could not query NuGet for $($script:SdkToolsNuGet) versions: $_"
        }
        # The index lists every version. Take the highest non-prerelease one.
        $stable = $idx.versions |
                  Where-Object { $_ -notmatch '-' } |
                  ForEach-Object { [pscustomobject]@{ Raw = $_; Ver = [version]($_ -replace '[^0-9.]','') } } |
                  Sort-Object -Property Ver -Descending |
                  Select-Object -First 1
        if (-not $stable) {
            throw "No stable versions found for $($script:SdkToolsNuGet)."
        }
        $Version = $stable.Raw
    }
    Write-MsixLog Info "Microsoft.Windows.SDK.BuildTools version: $Version"

    # ── Idempotency check ─────────────────────────────────────────────────
    $marker = Join-Path $Destination 'Tools\sdk.version'
    if ((Test-Path $marker) -and -not $Force) {
        $current = (Get-Content $marker -Raw -ErrorAction SilentlyContinue).Trim()
        if ($current -eq "$Version|$Architecture") {
            Write-MsixLog Info "SDK tools $Version ($Architecture) already installed at $Destination\Tools."
            return [pscustomobject]@{ Path = "$Destination\Tools"; Version = $Version; Architecture = $Architecture; Updated = $false }
        }
    }

    # ── Download + extract ────────────────────────────────────────────────
    $tmp = Join-Path $env:TEMP "sdk-buildtools-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item $tmp -ItemType Directory -Force | Out-Null
    $nupkg = Join-Path $tmp "$($script:SdkToolsNuGet).$Version.nupkg"
    $url   = "https://api.nuget.org/v3-flatcontainer/$($script:SdkToolsNuGet.ToLower())/$Version/$($script:SdkToolsNuGet.ToLower()).$Version.nupkg"

    if ($PSCmdlet.ShouldProcess("$Destination\Tools", "Install Microsoft.Windows.SDK.BuildTools $Version ($Architecture)")) {
        try {
            _MsixDownloadFile -Url $url -Destination $nupkg

            $extracted = Join-Path $tmp 'extracted'
            _MsixExpandZip -ArchivePath $nupkg -DestinationPath $extracted

            # Locate the bin\<sdk-ver>\<arch> folder. NuGet packages may have a
            # versioned subdirectory we need to discover.
            $archDir = Get-ChildItem (Join-Path $extracted 'bin') -Directory -ErrorAction SilentlyContinue |
                       ForEach-Object { Join-Path $_.FullName $Architecture } |
                       Where-Object { Test-Path (Join-Path $_ 'MakeAppx.exe') } |
                       Sort-Object -Descending |
                       Select-Object -First 1
            if (-not $archDir) {
                throw "MakeAppx.exe not found inside the NuGet package for architecture '$Architecture'."
            }

            $toolsDir = Join-Path $Destination 'Tools'
            New-Item $toolsDir -ItemType Directory -Force | Out-Null

            # Copy the whole arch folder (MakeAppx, signtool, makepri, plus
            # the AppxPackaging dependency DLLs that signtool needs at runtime).
            Copy-Item "$archDir\*" $toolsDir -Recurse -Force

            "$Version|$Architecture" | Set-Content $marker -Encoding ascii
            Write-MsixLog Info "MakeAppx.exe + signtool.exe installed at $toolsDir"

            # Reset the cached tools root so the next Get-MsixToolsRoot picks this up
            Set-MsixToolsRoot -Path $Destination

        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{
        Path         = "$Destination\Tools"
        Version      = $Version
        Architecture = $Architecture
        Updated      = $true
        Source       = $url
    }
}


function Update-MsixSdkTool {
    <#
    .SYNOPSIS
        Refreshes the bundled SDK tools to the latest NuGet version, but only
        when a new one exists.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [ValidateSet('x86','x64')]
        [string]$Architecture = 'x64'
    )
    if (-not $Destination) { $Destination = $PSScriptRoot }
    if (-not $PSCmdlet.ShouldProcess($Destination, 'Update SDK Tools')) { return }
    $marker = Join-Path $Destination 'Tools\sdk.version'
    if (-not (Test-Path $marker)) {
        return Install-MsixSdkTool -Destination $Destination -Architecture $Architecture
    }

    # Find latest published version
    $idxUrl = "https://api.nuget.org/v3-flatcontainer/$($script:SdkToolsNuGet.ToLower())/index.json"
    $idx    = Invoke-RestMethod -Uri $idxUrl -UseBasicParsing -ErrorAction Stop
    $latest = ($idx.versions | Where-Object { $_ -notmatch '-' } |
               ForEach-Object { [pscustomobject]@{ Raw=$_; Ver=[version]($_ -replace '[^0-9.]','') } } |
               Sort-Object Ver -Descending | Select-Object -First 1).Raw

    $current = (Get-Content $marker -Raw).Trim()
    if ($current -eq "$latest|$Architecture") {
        Write-MsixLog Info "SDK tools up to date ($latest, $Architecture)."
        return [pscustomobject]@{ Path = "$Destination\Tools"; Version = $latest; Architecture = $Architecture; Updated = $false }
    }
    Write-MsixLog Info "SDK tools update available: $current -> $latest|$Architecture"
    return Install-MsixSdkTool -Destination $Destination -Architecture $Architecture -Version $latest -Force
}


function Get-MsixSdkToolsVersion {
    <#
    .SYNOPSIS
        Reports the version + architecture of MakeAppx.exe / signtool.exe
        currently installed under the module's tools root.
    #>
    [CmdletBinding()]
    param([string]$Destination)
    if (-not $Destination) { $Destination = $PSScriptRoot }
    $marker = Join-Path $Destination 'Tools\sdk.version'
    if (-not (Test-Path $marker)) {
        return [pscustomobject]@{ Path = "$Destination\Tools"; Installed = $false; Version = $null; Architecture = $null }
    }
    $current = (Get-Content $marker -Raw).Trim()
    $parts   = $current -split '\|'
    return [pscustomobject]@{
        Path         = "$Destination\Tools"
        Installed    = $true
        Version      = $parts[0]
        Architecture = if ($parts.Count -gt 1) { $parts[1] } else { 'x64' }
    }
}


# ===========================================================================
# Windows App Runtime + DesktopAppInstaller (for sandbox / fresh hosts)
# ===========================================================================
# Default Win11 Sandbox cannot install MSIX packages out of the box — it
# lacks the AppInstaller MSIX shell handler and (depending on the package's
# uap10:HostRuntimeDependency / Windows App SDK target) the Windows App
# Runtime. These two installers fix both:
#
#   - DesktopAppInstaller    (Microsoft.DesktopAppInstaller msixbundle)
#                            Adds the Add-AppPackage UI handler and winget.
#                            Served by Microsoft at https://aka.ms/getwinget
#                            (redirects to the latest stable msixbundle).
#
#   - WindowsAppRuntime      (WindowsAppRuntimeInstall-x64.exe)
#                            The Windows App SDK runtime that many modern
#                            MSIX packages depend on. Pinned to a known good
#                            channel via Microsoft's aka.ms redirect.
# ===========================================================================

# aka.ms redirects — Microsoft keeps these stable across releases.
$script:DesktopAppInstallerUrl = 'https://aka.ms/getwinget'
$script:WindowsAppRuntimeUrl   = 'https://aka.ms/windowsappsdk/1.6/latest/windowsappruntimeinstall-x64.exe'


function Install-MsixAppRuntime {
    <#
    .SYNOPSIS
        Downloads the DesktopAppInstaller bundle and the Windows App Runtime
        installer so a sandbox (or a freshly imaged host) can install MSIX
        packages reliably.

    .DESCRIPTION
        Default Windows Sandbox lacks both components; double-clicking a
        .msix file silently fails. This function caches them under
        $ToolsRoot\runtime\ so:

          - Start-MsixSandbox can map them into the sandbox and run them
            from its bootstrap script.
          - Operators on bare hosts can just `Add-AppPackage` and execute
            the .exe to provision the platform.

        DesktopAppInstaller is an msixbundle (Microsoft.DesktopAppInstaller).
        WindowsAppRuntime is an .exe installer; pass /silent in unattended
        scenarios.

    .PARAMETER Destination
        Cache folder. Defaults to "$Get-MsixToolsRoot\runtime".

    .PARAMETER Force
        Re-download even if both files are already present.

    .EXAMPLE
        Install-MsixAppRuntime
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [switch]$Force
    )
    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'runtime' }

    $marker = Join-Path $Destination 'runtime.installed'
    if ((Test-Path $marker) -and -not $Force) {
        Write-MsixLog Info "Windows App Runtime + DesktopAppInstaller cached at $Destination. Use -Force to refresh."
        return [pscustomobject]@{ Path = $Destination; Updated = $false }
    }

    if ($PSCmdlet.ShouldProcess($Destination, 'Install Windows App Runtime + DesktopAppInstaller')) {
        New-Item $Destination -ItemType Directory -Force | Out-Null

        $bundlePath  = Join-Path $Destination 'Microsoft.DesktopAppInstaller.msixbundle'
        $runtimePath = Join-Path $Destination 'WindowsAppRuntimeInstall-x64.exe'

        _MsixDownloadFile -Url $script:DesktopAppInstallerUrl -Destination $bundlePath
        _MsixDownloadFile -Url $script:WindowsAppRuntimeUrl   -Destination $runtimePath

        (Get-Date -Format o) | Set-Content $marker -Encoding ascii
        Write-MsixLog Info "AppRuntime cached: $Destination"
    }

    return [pscustomobject]@{
        Path                  = $Destination
        Updated               = $true
        DesktopAppInstaller   = Join-Path $Destination 'Microsoft.DesktopAppInstaller.msixbundle'
        WindowsAppRuntimeExe  = Join-Path $Destination 'WindowsAppRuntimeInstall-x64.exe'
    }
}


function Update-MsixAppRuntime {
    <#
    .SYNOPSIS
        Refreshes the cached Windows App Runtime + DesktopAppInstaller if the
        local copy is older than -MaxAgeDays (default 45).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [int]$MaxAgeDays = 45
    )
    if (-not $PSCmdlet.ShouldProcess($Destination, 'Update Windows App Runtime cache')) { return }
    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'runtime' }
    $marker = Join-Path $Destination 'runtime.installed'

    if (-not (Test-Path $marker)) {
        return Install-MsixAppRuntime -Destination $Destination
    }
    $stamp = [datetime](Get-Content $marker -Raw).Trim()
    $age   = (Get-Date) - $stamp
    if ($age.TotalDays -gt $MaxAgeDays) {
        Write-MsixLog Info "AppRuntime cache is $([int]$age.TotalDays) days old; refreshing."
        return Install-MsixAppRuntime -Destination $Destination -Force
    }
    Write-MsixLog Info "AppRuntime cache is fresh ($([int]$age.TotalDays) days; threshold $MaxAgeDays)."
    return [pscustomobject]@{ Path = $Destination; Updated = $false }
}


function Get-MsixAppRuntimeVersion {
    <#
    .SYNOPSIS
        Reports the cached AppRuntime install timestamp and resolved paths.
    #>
    [CmdletBinding()]
    param([string]$Path)

    if (-not $Path) { $Path = Join-Path (Get-MsixToolsRoot) 'runtime' }
    $marker = Join-Path $Path 'runtime.installed'

    $bundle  = Join-Path $Path 'Microsoft.DesktopAppInstaller.msixbundle'
    $runtime = Join-Path $Path 'WindowsAppRuntimeInstall-x64.exe'

    return [pscustomobject]@{
        Path                  = $Path
        Installed             = Test-Path $marker
        InstalledOn           = if (Test-Path $marker) { [datetime](Get-Content $marker -Raw).Trim() } else { $null }
        DesktopAppInstaller   = if (Test-Path $bundle)  { $bundle  } else { $null }
        WindowsAppRuntimeExe  = if (Test-Path $runtime) { $runtime } else { $null }
    }
}


function Initialize-MsixToolchain {
    <#
    .SYNOPSIS
        One-call setup: ensures the SDK tools, PSF binaries (TMurgent),
        Process Monitor, msixmgr, AND the Windows App Runtime +
        DesktopAppInstaller (for sandbox/MSIX install support) are present
        and up to date under the tools root.

    .EXAMPLE
        Initialize-MsixToolchain                              # everything
        Initialize-MsixToolchain -Skip Procmon                # skip Procmon
        Initialize-MsixToolchain -Skip Procmon,MsixMgr,Runtime # PSF + SDK only
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Sdk','Psf','Procmon','MsixMgr','Runtime')]
        [string[]]$Skip
    )

    $result = [ordered]@{
        Sdk = $null; Psf = $null; Procmon = $null
        MsixMgr = $null; Runtime = $null
    }
    # SDK tools first — everything else needs MakeAppx.exe to do anything useful.
    if ($Skip -notcontains 'Sdk')     { $result.Sdk     = Update-MsixSdkTool }
    if ($Skip -notcontains 'Psf')     { $result.Psf     = Update-MsixPsfBinary }
    if ($Skip -notcontains 'Procmon') { $result.Procmon = Update-MsixProcMon }
    if ($Skip -notcontains 'MsixMgr') { $result.MsixMgr = Update-MsixMgr }
    if ($Skip -notcontains 'Runtime') { $result.Runtime = Update-MsixAppRuntime }
    return [pscustomobject]$result
}


# Backward-compatible plural aliases
Set-Alias Install-MsixPsfBinaries Install-MsixPsfBinary
Set-Alias Update-MsixPsfBinaries Update-MsixPsfBinary
Set-Alias Install-MsixSdkTools Install-MsixSdkTool
Set-Alias Update-MsixSdkTools Update-MsixSdkTool
