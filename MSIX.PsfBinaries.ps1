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
$script:ProcmonZipUrl    = 'https://download.sysinternals.com/files/ProcessMonitor.zip'
$script:DebugViewZipUrl  = 'https://download.sysinternals.com/files/DebugView.zip'
$script:SdkToolsNuGet = 'Microsoft.Windows.SDK.BuildTools'   # publishes MakeAppx + signtool

# =============================================================================
# Authenticode verification of downloaded tool binaries (Wave 2a / H1)
# -----------------------------------------------------------------------------
# Trusted publisher Subject prefixes. Match against the leaf cert's Subject
# (case-insensitive, StartsWith). New entries added here become trusted across
# the entire toolchain.
# =============================================================================
$script:MsixTrustedPublishers = @(
    'CN=Microsoft Corporation,',                    # Microsoft (incl. Windows SDK, signtool, MakeAppx, DesktopAppInstaller, Windows App Runtime)
    'CN=Microsoft Windows,',                        # Some Microsoft signing certs
    'CN=Windows Phone,',                        # deployutil.exe etc
    'CN=Microsoft Windows Publisher,',              # Microsoft publisher (Procmon, DebugView via Sysinternals signing)
    'CN=Microsoft 3rd Party Application Component,', # Sysinternals tools sometimes use this
    'CN=Tim Mangan,',                               # PSF maintainer (TMurgent fork)
    'CN=TMurgent Technologies LLP,'                # PSF maintainer corporate
)

function _MsixVerifyAuthenticode {
    <#
    .SYNOPSIS
        Verifies a file is Authenticode-signed by a trusted publisher.
    .DESCRIPTION
        Reject the file unless:
          - signature Status is 'Valid'
          - signer cert is in $script:MsixTrustedPublishers
        Throws on rejection; returns the signature object on success.
    .PARAMETER Path
        File to verify.
    .PARAMETER ToolName
        Logical tool name for error messages.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$ToolName
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Cannot verify Authenticode: file not found at $Path"
    }
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid') {
        throw "Authenticode verification FAILED for $ToolName at $Path. Status: $($sig.Status). $($sig.StatusMessage)"
    }
    $subject = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }
    if (-not $subject) {
        throw "Authenticode verification FAILED for $ToolName at $Path`: no signer cert."
    }
    $isTrusted = $false
    foreach ($prefix in $script:MsixTrustedPublishers) {
        if ($subject -like "$prefix*") { $isTrusted = $true; break }
    }
    if (-not $isTrusted) {
        throw @"
Authenticode verification FAILED for $ToolName at $Path.
Signer is NOT in the trusted-publisher allowlist:
  Subject:    $subject
  Thumbprint: $($sig.SignerCertificate.Thumbprint)
If you trust this publisher, add the CN prefix to `$script:MsixTrustedPublishers in MSIX.PsfBinaries.ps1.
"@
    }
    Write-MsixLog Info "Authenticode verified: $ToolName ($subject)"
    return $sig
}

function _MsixVerifyAuthenticodeFolder {
    <#
    .SYNOPSIS
        Verifies every .exe and .dll under a folder.
    .DESCRIPTION
        Calls _MsixVerifyAuthenticode against every .exe / .dll under the given
        folder (recursively). Throws on the first untrusted / unsigned binary.
        Logs a warning if no .exe/.dll were found at all (caller decides whether
        that's acceptable - e.g. for archives that bundle only data).

        NOTE on the filter: we use the file's .Extension property (exact match)
        rather than -Include '*.exe','*.dll'. The wildcard form can spuriously
        match side-by-side assembly manifests like 'app.exe.manifest' in some
        PowerShell versions because the FileSystem provider's wildcard engine
        treats '*.exe' more loosely than the .Extension equality check.
        .manifest files are XML — not Authenticode-signable — so accidentally
        feeding them to Get-AuthenticodeSignature produced bogus "not signed"
        failures and aborted toolchain installs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Folder,
        [Parameter(Mandatory)] [string]$ToolName
    )
    $files = @(Get-ChildItem -LiteralPath $Folder -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.exe', '.dll' })
    if ($files.Count -eq 0) {
        Write-MsixLog Warning "No .exe/.dll under $Folder to verify ($ToolName)"
        return
    }
    foreach ($file in $files) {
        _MsixVerifyAuthenticode -Path $file.FullName -ToolName "$ToolName/$($file.Name)" | Out-Null
    }
}

function _MsixVerifyAuthenticodeMsixBundle {
    <#
    .SYNOPSIS
        Verifies a .msix / .msixbundle / .appxbundle is Authenticode-signed by a
        trusted publisher. Unlike _MsixVerifyAuthenticodeFolder this expects a
        single signed file (the bundle itself).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$ToolName
    )
    _MsixVerifyAuthenticode -Path $Path -ToolName $ToolName | Out-Null
}

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
        know what's installed. The install is idempotent: re-running with the
        same latest tag is a no-op unless -Force is supplied.

        SECURITY: every .exe / .dll in the extracted archive is verified to
        have a valid Authenticode signature from a trusted publisher BEFORE
        anything is copied into the toolchain folder. A failed verification
        rolls back the install (the destination folder is removed if this
        cmdlet created it). See $script:MsixTrustedPublishers for the
        allowlist.

        Related: Update-MsixPsfBinary (re-installs only when GitHub publishes a
        newer tag), Get-MsixPsfBinariesVersion (queries what's currently
        installed), Add-MsixPsfV2 (the consumer that uses the binaries).

    .PARAMETER Destination
        Where to extract. Defaults to "(Get-MsixToolsRoot)\psf".

    .PARAMETER Force
        Reinstall even if the latest version is already present.

    .PARAMETER AssetPattern
        Regex matched against asset names. Defaults to '\.zip$' so any zip works.

    .OUTPUTS
        [pscustomobject] with Path, Version, Updated, and Source (download URL).

    .EXAMPLE
        # Install the latest PSF binaries into the default tools root.
        Install-MsixPsfBinary

    .EXAMPLE
        # Force reinstall (useful after deleting binaries by hand).
        Install-MsixPsfBinary -Force

    .EXAMPLE
        # Install into a custom location.
        Install-MsixPsfBinary -Destination 'D:\msix-tools\psf'
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
        $destinationCreated = $false
        try {
            _MsixDownloadFile -Url $asset.browser_download_url -Destination $zip
            _MsixExpandZip -ArchivePath $zip -DestinationPath $tmp

            # H1: verify Authenticode signer on every .exe/.dll before we copy
            # any of them into the toolchain root.
            _MsixVerifyAuthenticodeFolder -Folder $tmp -ToolName 'PSF'

            if (-not (Test-Path $Destination)) {
                New-Item $Destination -ItemType Directory -Force | Out-Null
                $destinationCreated = $true
            }
            # Copy every file from extracted layout into Destination flatly
            Get-ChildItem $tmp -Recurse -File | Where-Object { $_.FullName -ne $zip } |
                ForEach-Object { Copy-Item $_.FullName $Destination -Force }

            Set-Content -Path $marker -Value $tag -Encoding ascii
            Write-MsixLog Info "PSF $tag installed to $Destination"

        } catch {
            Write-MsixLog Error "PSF install rolled back: $_"
            if ($destinationCreated) {
                Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
            }
            throw
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

    .DESCRIPTION
        Reads the `psf.version` marker that Install-MsixPsfBinary writes into
        the destination folder and reports whether PsfLauncher32.exe is also
        present (sanity check that the install wasn't partially deleted).

    .PARAMETER Path
        Folder to inspect. Defaults to "(Get-MsixToolsRoot)\psf".

    .OUTPUTS
        [pscustomobject] with Path, Installed (bool), Version (GitHub tag),
        and HasLauncher (bool).

    .EXAMPLE
        # Print the cached PSF version on the current machine.
        Get-MsixPsfBinariesVersion
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

    .DESCRIPTION
        Idempotent updater suitable for scheduled / CI use. If no PSF is cached
        locally, runs a fresh install. Otherwise queries the TMurgent GitHub
        releases API and compares against the local `psf.version` marker;
        re-downloads (with Authenticode verification) only when the tag has
        changed.

    .PARAMETER Destination
        Folder containing PSF. Defaults to "(Get-MsixToolsRoot)\psf".

    .OUTPUTS
        [pscustomobject] from Install-MsixPsfBinary or Get-MsixPsfBinariesVersion.

    .EXAMPLE
        # Refresh PSF if a newer release has appeared upstream.
        Update-MsixPsfBinary
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

    .DESCRIPTION
        Downloads https://download.sysinternals.com/files/ProcessMonitor.zip,
        Authenticode-verifies every .exe/.dll against the Microsoft / Microsoft
        Windows Publisher trusted-publisher allowlist BEFORE copying anything
        into $Destination, and sets $env:MSIX_PROCMON_PATH so
        Resolve-MsixProcMonPath / Invoke-MsixProcMonCapture pick it up
        immediately. Idempotent: existing installs are skipped unless -Force.

    .PARAMETER Destination
        Where to extract. Defaults to "(Get-MsixToolsRoot)\procmon".

    .PARAMETER Force
        Re-download even if procmon is already present.

    .OUTPUTS
        [pscustomobject] with Path, Updated, and (on fresh install) Source URL.

    .NOTES
        Sysinternals doesn't expose a versioned download URL — the zip is always
        the latest. This function therefore stamps the install date as the
        "version" so Update-MsixProcMon knows when to refresh.

    .EXAMPLE
        # Install Process Monitor into the default location.
        Install-MsixProcMon

    .EXAMPLE
        # Force re-download (e.g. after an accidental delete).
        Install-MsixProcMon -Force
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
        $destinationExisted = Test-Path $Destination
        # Stage extraction into a temp folder so a bad signature doesn't pollute Destination.
        $stage = Join-Path $tmp 'extracted'
        try {
            _MsixDownloadFile -Url $script:ProcmonZipUrl -Destination $zip
            New-Item $stage -ItemType Directory -Force | Out-Null
            Expand-Archive -LiteralPath $zip -DestinationPath $stage -Force

            # H1: verify Authenticode signer before installing into $Destination.
            _MsixVerifyAuthenticodeFolder -Folder $stage -ToolName 'Procmon'

            New-Item $Destination -ItemType Directory -Force | Out-Null
            Copy-Item (Join-Path $stage '*') $Destination -Recurse -Force
            (Get-Date -Format o) | Set-Content $marker -Encoding ascii

            # Make Resolve-MsixProcMonPath find it via env-var hint
            $exe = Join-Path $Destination 'Procmon.exe'
            if (Test-Path $exe) {
                $env:MSIX_PROCMON_PATH = $exe
                Write-MsixLog Info "Process Monitor installed at $exe"
            } else {
                Write-MsixLog Warning "Procmon.exe not found after extraction; check $Destination"
            }
        } catch {
            Write-MsixLog Error "Procmon install rolled back: $_"
            if (-not $destinationExisted) {
                Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
            }
            throw
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

    .DESCRIPTION
        Age-based updater. Re-runs Install-MsixProcMon -Force only when the
        install marker is older than -MaxAgeDays. If nothing is installed yet,
        falls back to a fresh Install-MsixProcMon.

    .PARAMETER Destination
        Folder containing Procmon. Defaults to "(Get-MsixToolsRoot)\procmon".

    .PARAMETER MaxAgeDays
        Refresh threshold in days. Default 30.

    .OUTPUTS
        [pscustomobject] from Install-MsixProcMon or a no-op summary.

    .EXAMPLE
        # Refresh Procmon if its cached copy is over a month old.
        Update-MsixProcMon

    .EXAMPLE
        # Tighter cadence for kiosk-style refresh.
        Update-MsixProcMon -MaxAgeDays 7
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


function Install-MsixDebugView {
    <#
    .SYNOPSIS
        Downloads and extracts Sysinternals DebugView under the tools root,
        ready for Resolve-MsixDebugViewPath / Start-MsixDebugSession.

    .DESCRIPTION
        DebugView ships separately from Process Monitor (different zip on
        the Sysinternals download server). Start-MsixDebugSession was
        printing "DebugView not found" if the operator had only run
        Initialize-MsixToolchain; this cmdlet closes that gap.

        Every .exe / .dll in the extracted archive is Authenticode-verified
        against the trusted-publisher allowlist BEFORE anything is copied into
        $Destination. A failed verification rolls the install back. The
        environment variable $env:MSIX_DEBUGVIEW_PATH is set to the resolved
        Dbgview64.exe so subsequent calls find it without further setup.

    .PARAMETER Destination
        Where to extract. Defaults to "(Get-MsixToolsRoot)\debugview".

    .PARAMETER Force
        Re-download even if already present.

    .OUTPUTS
        [pscustomobject] with Path, Updated, and (on fresh install) Source URL.

    .EXAMPLE
        # Cache DebugView so PSF TraceFixup output can be captured.
        Install-MsixDebugView
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [switch]$Force
    )

    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'debugview' }

    $marker = Join-Path $Destination 'debugview.installed'
    if ((Test-Path $marker) -and -not $Force) {
        Write-MsixLog Info "DebugView already installed at $Destination. Use -Force to reinstall."
        return [pscustomobject]@{ Path = $Destination; Updated = $false }
    }

    $tmp = Join-Path $env:TEMP "debugview-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item $tmp -ItemType Directory -Force | Out-Null
    $zip = Join-Path $tmp 'DebugView.zip'

    if ($PSCmdlet.ShouldProcess($Destination, 'Install DebugView')) {
        $destinationExisted = Test-Path $Destination
        $stage = Join-Path $tmp 'extracted'
        try {
            _MsixDownloadFile -Url $script:DebugViewZipUrl -Destination $zip
            New-Item $stage -ItemType Directory -Force | Out-Null
            Expand-Archive -LiteralPath $zip -DestinationPath $stage -Force

            # H1: verify Authenticode signer before installing into $Destination.
            _MsixVerifyAuthenticodeFolder -Folder $stage -ToolName 'DebugView'

            New-Item $Destination -ItemType Directory -Force | Out-Null
            Copy-Item (Join-Path $stage '*') $Destination -Recurse -Force
            (Get-Date -Format o) | Set-Content $marker -Encoding ascii

            # Make Resolve-MsixDebugViewPath find it via env-var hint
            $exe = Join-Path $Destination 'Dbgview64.exe'
            if (-not (Test-Path $exe)) { $exe = Join-Path $Destination 'Dbgview.exe' }
            if (Test-Path $exe) {
                $env:MSIX_DEBUGVIEW_PATH = $exe
                Write-MsixLog Info "DebugView installed at $exe"
            } else {
                Write-MsixLog Warning "Dbgview.exe / Dbgview64.exe not found after extraction; check $Destination"
            }
        } catch {
            Write-MsixLog Error "DebugView install rolled back: $_"
            if (-not $destinationExisted) {
                Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
            }
            throw
        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    return [pscustomobject]@{
        Path    = $Destination
        Updated = $true
        Source  = $script:DebugViewZipUrl
    }
}


function Update-MsixDebugView {
    <#
    .SYNOPSIS
        Refreshes DebugView if older than -MaxAgeDays (default 30).

    .DESCRIPTION
        Age-based updater. Re-runs Install-MsixDebugView -Force only when the
        cached install marker is older than -MaxAgeDays. Mirrors
        Update-MsixProcMon semantics.

    .PARAMETER Destination
        Folder containing DebugView. Defaults to "(Get-MsixToolsRoot)\debugview".

    .PARAMETER MaxAgeDays
        Refresh threshold in days. Default 30.

    .OUTPUTS
        [pscustomobject] from Install-MsixDebugView or a no-op summary.

    .EXAMPLE
        # Keep DebugView fresh-ish on a CI agent.
        Update-MsixDebugView
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [int]$MaxAgeDays = 30
    )
    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'debugview' }
    if (-not $PSCmdlet.ShouldProcess($Destination, 'Update DebugView')) { return }
    $marker = Join-Path $Destination 'debugview.installed'

    if (-not (Test-Path $marker)) {
        return Install-MsixDebugView -Destination $Destination
    }
    $stamp = [datetime](Get-Content $marker -Raw).Trim()
    $age   = (Get-Date) - $stamp
    if ($age.TotalDays -gt $MaxAgeDays) {
        Write-MsixLog Info "DebugView is $([int]$age.TotalDays) days old; refreshing."
        return Install-MsixDebugView -Destination $Destination -Force
    }
    Write-MsixLog Info "DebugView is fresh ($([int]$age.TotalDays) days old; threshold $MaxAgeDays)."
    return [pscustomobject]@{ Path = $Destination; Updated = $false }
}


function Get-MsixDebugViewVersion {
    <#
    .SYNOPSIS
        Reports the cached DebugView install timestamp and resolved Dbgview path.

    .DESCRIPTION
        Reads the `debugview.installed` marker that Install-MsixDebugView wrote
        and resolves Dbgview64.exe / Dbgview.exe under the folder.

    .PARAMETER Path
        Folder to inspect. Defaults to "(Get-MsixToolsRoot)\debugview".

    .OUTPUTS
        [pscustomobject] with Path, Installed, InstalledOn ([datetime]), and
        Executable (resolved Dbgview path).

    .EXAMPLE
        # See how stale the cached DebugView is.
        Get-MsixDebugViewVersion
    #>
    [CmdletBinding()]
    param([string]$Path)
    if (-not $Path) { $Path = Join-Path (Get-MsixToolsRoot) 'debugview' }
    $marker = Join-Path $Path 'debugview.installed'
    $exe    = Join-Path $Path 'Dbgview64.exe'
    if (-not (Test-Path $exe)) { $exe = Join-Path $Path 'Dbgview.exe' }

    return [pscustomobject]@{
        Path        = $Path
        Installed   = Test-Path $marker
        InstalledOn = if (Test-Path $marker) { [datetime](Get-Content $marker -Raw).Trim() } else { $null }
        Executable  = if (Test-Path $exe) { $exe } else { $null }
    }
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

        SECURITY: every .exe / .dll inside the chosen arch folder is
        Authenticode-verified against the Microsoft trusted-publisher
        allowlist BEFORE anything is copied to "$Destination\Tools".

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

    .OUTPUTS
        [pscustomobject] with Path, Version, Architecture, Updated, and (on
        fresh install) Source URL.

    .EXAMPLE
        # Install latest x64 SDK tools into the module folder.
        Install-MsixSdkTool

    .EXAMPLE
        # 32-bit signtool, forced reinstall.
        Install-MsixSdkTool -Architecture x86 -Force

    .EXAMPLE
        # Pin a specific NuGet version for reproducible CI builds.
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
        $toolsDir = Join-Path $Destination 'Tools'
        $toolsDirExisted = Test-Path $toolsDir
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

            # H1: verify every .exe/.dll in the SDK arch folder before we copy
            # them into Tools\ where Get-MsixToolsRoot will surface them.
            _MsixVerifyAuthenticodeFolder -Folder $archDir -ToolName "SDK BuildTools $Version/$Architecture"

            New-Item $toolsDir -ItemType Directory -Force | Out-Null

            # Copy the whole arch folder (MakeAppx, signtool, makepri, plus
            # the AppxPackaging dependency DLLs that signtool needs at runtime).
            Copy-Item "$archDir\*" $toolsDir -Recurse -Force

            "$Version|$Architecture" | Set-Content $marker -Encoding ascii
            Write-MsixLog Info "MakeAppx.exe + signtool.exe installed at $toolsDir"

            # Reset the cached tools root so the next Get-MsixToolsRoot picks this up
            Set-MsixToolsRoot -Path $Destination

        } catch {
            Write-MsixLog Error "SDK tools install rolled back: $_"
            if (-not $toolsDirExisted) {
                Remove-Item -LiteralPath $toolsDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            throw
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

    .DESCRIPTION
        Idempotent updater. Queries the NuGet flat-container index for the
        highest non-prerelease version of Microsoft.Windows.SDK.BuildTools and
        re-runs Install-MsixSdkTool only if the local `sdk.version` marker
        doesn't already match "<version>|<architecture>".

    .PARAMETER Destination
        Where SDK tools are installed. Defaults to the module folder
        ($PSScriptRoot).

    .PARAMETER Architecture
        x64 (default) or x86.

    .OUTPUTS
        [pscustomobject] from Install-MsixSdkTool or a no-op summary.

    .EXAMPLE
        # Refresh the SDK tools (no-op if already on the latest tag).
        Update-MsixSdkTool
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

    .DESCRIPTION
        Parses the `sdk.version` marker that Install-MsixSdkTool writes
        ("<version>|<architecture>"). Returns Installed=$false when the marker
        is missing.

    .PARAMETER Destination
        Module / install folder. Defaults to $PSScriptRoot.

    .OUTPUTS
        [pscustomobject] with Path, Installed, Version, Architecture.

    .EXAMPLE
        # Verify which signtool / MakeAppx version is bundled.
        Get-MsixSdkToolsVersion
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

# aka.ms redirects -- Microsoft keeps these stable across releases.
$script:DesktopAppInstallerUrl = 'https://aka.ms/getwinget'

# Channels we cache by default. Real-world packages still pin specific
# channels (Notepad 8.9.x pins 1.4, etc.) so we keep a broad floor here.
# The sandbox bootstrap also reads the actual manifest dependencies and
# downloads any missing channel on demand.
$script:WindowsAppRuntimeDefaultChannels = @('1.4','1.5','1.6','1.7','1.8')

function _MsixAppRuntimeUrl {
    param([string]$Channel)
    "https://aka.ms/windowsappsdk/$Channel/latest/windowsappruntimeinstall-x64.exe"
}

function _MsixAppRuntimeFileName {
    param([string]$Channel)
    "WindowsAppRuntimeInstall-x64-$Channel.exe"
}


function Install-MsixAppRuntime {
    <#
    .SYNOPSIS
        Downloads the DesktopAppInstaller bundle + one or more Windows App
        Runtime channel installers so a sandbox (or a freshly imaged host)
        can install ANY MSIX package, including ones that pin a specific
        WindowsAppRuntime version.

    .DESCRIPTION
        Default Windows Sandbox lacks both components; .msix install fails
        with HRESULT 0x80073CF3 when the required WindowsAppRuntime channel
        is missing.

        Packages declare their WindowsAppRuntime dependency in the manifest:
            <PackageDependency Name="Microsoft.WindowsAppRuntime.1.4" .../>
        So one fixed installer is not enough. This function caches ALL
        requested channels under $ToolsRoot\runtime\ as
        WindowsAppRuntimeInstall-x64-<channel>.exe.

        Use Get-MsixRequiredAppRuntimeChannel against a specific .msix to
        find out which channels it pins, then pass that list to -Channels.

    .PARAMETER Destination
        Cache folder. Defaults to "$Get-MsixToolsRoot\runtime".

    .PARAMETER Channels
        WindowsAppRuntime channels (major.minor strings, e.g. '1.4').
        Defaults to 1.4 / 1.5 / 1.6 so the cache covers the long tail.

    .PARAMETER Force
        Re-download even if cached.

    .OUTPUTS
        [pscustomobject] with Path, Updated, Channels (string[]),
        DesktopAppInstaller (path), and WindowsAppRuntimeExes (string[]).

    .EXAMPLE
        # Cache the default 1.4 / 1.5 / 1.6 / 1.7 / 1.8 channels + DesktopAppInstaller.
        Install-MsixAppRuntime

    .EXAMPLE
        # Cache only what one specific package actually needs.
        $req = Get-MsixRequiredAppRuntimeChannel -PackagePath app.msix
        Install-MsixAppRuntime -Channels $req
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Destination,
        [string[]]$Channels = $script:WindowsAppRuntimeDefaultChannels,
        [switch]$Force
    )
    if (-not $Destination) { $Destination = Join-Path (Get-MsixToolsRoot) 'runtime' }

    $marker = Join-Path $Destination 'runtime.installed'
    if ((Test-Path $marker) -and -not $Force) {
        # Check whether all requested channels are cached; if any is missing
        # we still need to download just that one (don't bail out).
        $missing = $Channels | Where-Object {
            -not (Test-Path (Join-Path $Destination (_MsixAppRuntimeFileName $_)))
        }
        if (-not $missing) {
            Write-MsixLog Info "Windows App Runtime ($($Channels -join ', ')) + DesktopAppInstaller cached at $Destination."
            return [pscustomobject]@{
                Path = $Destination; Updated = $false; Channels = $Channels
            }
        }
        $Channels = $missing
        Write-MsixLog Info "Caching additional WindowsAppRuntime channels: $($missing -join ', ')"
    }

    if (-not $PSCmdlet.ShouldProcess($Destination, "Install Windows App Runtime ($($Channels -join ', ')) + DesktopAppInstaller")) { return }

    New-Item $Destination -ItemType Directory -Force | Out-Null

    # DesktopAppInstaller msixbundle (only download if missing or -Force)
    $bundlePath = Join-Path $Destination 'Microsoft.DesktopAppInstaller.msixbundle'
    if ($Force -or -not (Test-Path $bundlePath)) {
        _MsixDownloadFile -Url $script:DesktopAppInstallerUrl -Destination $bundlePath
    }

    # Each WindowsAppRuntime channel installer
    $runtimePaths = foreach ($ch in $Channels) {
        $rt = Join-Path $Destination (_MsixAppRuntimeFileName $ch)
        try {
            _MsixDownloadFile -Url (_MsixAppRuntimeUrl $ch) -Destination $rt
            $rt
        } catch {
            Write-MsixLog Warning "Channel $ch download failed: $($_.Exception.Message)"
        }
    }

    (Get-Date -Format o) | Set-Content $marker -Encoding ascii
    Write-MsixLog Info "AppRuntime cached: $Destination"

    return [pscustomobject]@{
        Path                  = $Destination
        Updated               = $true
        Channels              = $Channels
        DesktopAppInstaller   = $bundlePath
        WindowsAppRuntimeExes = @($runtimePaths)
    }
}


function Get-MsixRequiredAppRuntimeChannel {
    <#
    .SYNOPSIS
        Parses the AppxManifest of an MSIX package and returns the list of
        Microsoft.WindowsAppRuntime.<channel> dependencies it declares.

    .DESCRIPTION
        Returns an array of channel strings ('1.4', '1.5', etc.) that can be
        passed directly to Install-MsixAppRuntime -Channels.

        Returns an empty array if the manifest declares no WindowsAppRuntime
        dependency (typical for older unpackaged-bridged Win32 apps).

    .PARAMETER PackagePath
        Path to the .msix / .appx / folder containing AppxManifest.xml.

    .OUTPUTS
        [string[]] — sorted, unique list of channel strings, or an empty array.

    .EXAMPLE
        # Inspect what runtime a single package needs.
        Get-MsixRequiredAppRuntimeChannel -PackagePath app.msix
        # => @('1.4')
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath
    )

    [xml]$m = Get-MsixManifest -Path $PackagePath
    $deps   = @($m.Package.Dependencies.PackageDependency) | Where-Object { $_.Name }

    $channels = foreach ($d in $deps) {
        if ($d.Name -match '^Microsoft\.WindowsAppRuntime\.(\d+\.\d+)$') {
            $matches[1]
        }
    }
    return [string[]]@($channels | Sort-Object -Unique)
}


function Update-MsixAppRuntime {
    <#
    .SYNOPSIS
        Refreshes the cached Windows App Runtime + DesktopAppInstaller if the
        local copy is older than -MaxAgeDays (default 45).

    .DESCRIPTION
        Age-based updater. Re-runs Install-MsixAppRuntime -Force only when the
        cached marker is older than -MaxAgeDays; otherwise reports the existing
        cache. If nothing is cached yet, performs a fresh install.

    .PARAMETER Destination
        Cache folder. Defaults to "(Get-MsixToolsRoot)\runtime".

    .PARAMETER MaxAgeDays
        Refresh threshold. Default 45.

    .OUTPUTS
        [pscustomobject] from Install-MsixAppRuntime or a no-op summary.

    .EXAMPLE
        # Refresh AppRuntime cache if older than ~6 weeks.
        Update-MsixAppRuntime
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

    .DESCRIPTION
        Inspects the `runtime.installed` marker plus the bundle and runtime exe
        on disk and returns a summary object that Update-MsixAppRuntime /
        Initialize-MsixToolchain consume.

    .PARAMETER Path
        Cache folder. Defaults to "(Get-MsixToolsRoot)\runtime".

    .OUTPUTS
        [pscustomobject] with Path, Installed, InstalledOn,
        DesktopAppInstaller (bundle path or $null), WindowsAppRuntimeExe.

    .EXAMPLE
        # Check whether the sandbox runtime cache is ready.
        Get-MsixAppRuntimeVersion
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
        One-call setup: ensures SDK tools, PSF binaries (TMurgent),
        Process Monitor, DebugView, msixmgr, AND the Windows App Runtime +
        DesktopAppInstaller (for sandbox/MSIX install support) are present
        and up to date under the tools root.

    .DESCRIPTION
        Runs the Update-* cmdlet for each toolchain component in dependency
        order (SDK first, since MakeAppx is needed by almost every other
        operation), respecting -Skip. Every component is downloaded only if
        missing or stale; all downloaded binaries are Authenticode-verified
        against the trusted-publisher allowlist before they land in the
        toolchain root. Safe to run repeatedly — idempotent across components.

        This is what you should call from a fresh CI agent / VM / sandbox
        before doing anything else with this module.

    .PARAMETER Skip
        One or more component names to skip:
          Sdk, Psf, Procmon, DebugView, MsixMgr, Runtime.

    .OUTPUTS
        [pscustomobject] with one property per component (Sdk, Psf, Procmon,
        DebugView, MsixMgr, Runtime). Each holds the return value of its
        corresponding Update-* call or $null when skipped.

    .EXAMPLE
        # Default: install / refresh everything the module needs.
        Initialize-MsixToolchain

    .EXAMPLE
        # Skip Procmon (e.g. on a server you don't want UI tools on).
        Initialize-MsixToolchain -Skip Procmon

    .EXAMPLE
        # Minimal: only the SDK tools (signtool, MakeAppx) and PSF.
        Initialize-MsixToolchain -Skip Procmon,DebugView,MsixMgr,Runtime
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('Sdk','Psf','Procmon','DebugView','MsixMgr','Runtime')]
        [string[]]$Skip
    )

    $result = [ordered]@{
        Sdk = $null; Psf = $null; Procmon = $null; DebugView = $null
        MsixMgr = $null; Runtime = $null
    }
    # SDK tools first -- everything else needs MakeAppx.exe to do anything useful.
    if ($Skip -notcontains 'Sdk')       { $result.Sdk       = Update-MsixSdkTool }
    if ($Skip -notcontains 'Psf')       { $result.Psf       = Update-MsixPsfBinary }
    if ($Skip -notcontains 'Procmon')   { $result.Procmon   = Update-MsixProcMon }
    if ($Skip -notcontains 'DebugView') { $result.DebugView = Update-MsixDebugView }
    if ($Skip -notcontains 'MsixMgr')   { $result.MsixMgr   = Update-MsixMgr }
    if ($Skip -notcontains 'Runtime')   { $result.Runtime   = Update-MsixAppRuntime }
    return [pscustomobject]$result
}


# Backward-compatible plural aliases
Set-Alias Install-MsixPsfBinaries Install-MsixPsfBinary
Set-Alias Update-MsixPsfBinaries Update-MsixPsfBinary
Set-Alias Install-MsixSdkTools Install-MsixSdkTool
Set-Alias Update-MsixSdkTools Update-MsixSdkTool
