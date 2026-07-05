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
# (case-insensitive, StartsWith). New entries become trusted across the entire
# toolchain.
#
# Source of truth: signers.json at the module root (loaded at import time by
# _MsixLoadTrustedPublishers below). Issue #19 moved the list out of code so
# security teams can add publishers without re-shipping the module. The file
# is intentionally unsigned today; a future change will Authenticode-sign it
# and require Get-AuthenticodeSignature -Status -eq 'Valid' before load.
# =============================================================================

function _MsixLoadTrustedPublishers {
    <#
    .SYNOPSIS
        Loads the trusted-publisher allowlist from signers.json. Internal.
    .DESCRIPTION
        Reads $PSScriptRoot\signers.json, validates each entry's
        subjectPrefix matches the standard X.509 form (starts with 'CN=',
        ends with ','), returns the deduplicated prefix list as [string[]]
        for the existing module contract, and records structured entries in
        $script:MsixTrustedPublisherEntries for verification.

        An entry MAY also carry an optional 'thumbprint' (SHA-1, the standard
        certificate thumbprint format, hex, case/space-insensitive). When
        present it is scoped to that allowlist entry: only files whose signer
        Subject matches the entry's subjectPrefix must match that entry's pin.
        Prefix-only entries keep their existing behaviour even when another
        publisher entry is pinned.

        Throws on:
          - missing signers.json (loud failure; toolchain installs cannot
            verify downloads, so we refuse to run rather than silently
            degrade to "no allowlist").
          - malformed JSON.
          - any entry whose subjectPrefix doesn't match ^CN=.+,$.
          - zero valid entries (same reasoning as missing file).
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([string]$Path)

    if (-not $Path) { $Path = Join-Path -Path $PSScriptRoot -ChildPath 'signers.json' }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "MSIX trusted-publisher allowlist not found at '$Path'. The module cannot Authenticode-verify downloaded toolchain binaries without it. Re-install the module or restore signers.json from source."
    }

    try {
        $doc = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Failed to parse trusted-publisher allowlist at '$Path': $($_.Exception.Message)"
    }

    if (-not $doc.publishers) {
        throw "Trusted-publisher allowlist at '$Path' has no 'publishers' array."
    }

    $rx          = [regex]'^CN=.+,$'
    $prefixes    = [System.Collections.Generic.List[string]]::new()
    $thumbprints       = [System.Collections.Generic.List[string]]::new()
    $publisherEntries  = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $doc.publishers) {
        $p = [string]$entry.subjectPrefix
        if (-not $p) {
            throw "Trusted-publisher allowlist at '$Path' has an entry missing 'subjectPrefix'."
        }
        if (-not $rx.IsMatch($p)) {
            throw "Trusted-publisher allowlist at '$Path' has an entry whose subjectPrefix does not match the X.509 form 'CN=...,': '$p'."
        }
        if (-not $prefixes.Contains($p)) { $prefixes.Add($p) }

        # Optional thumbprint pin (normalised: strip spaces, upper-case hex).
        $entryThumbprints = [System.Collections.Generic.List[string]]::new()
        $tp = [string]$entry.thumbprint
        if ($tp) {
            $tpNorm = ($tp -replace '\s', '').ToUpperInvariant()
            if ($tpNorm -notmatch '^[0-9A-F]{40}$') {
                throw "Trusted-publisher allowlist at '$Path' has an entry with an invalid 'thumbprint' (expected 40 hex chars, SHA-1): '$tp'."
            }
            if (-not $thumbprints.Contains($tpNorm)) { $thumbprints.Add($tpNorm) }
            if (-not $entryThumbprints.Contains($tpNorm)) { $entryThumbprints.Add($tpNorm) }
        }
        $publisherEntries.Add([pscustomobject]@{
            SubjectPrefix = $p
            Thumbprints   = [string[]]$entryThumbprints
        })
    }

    if ($prefixes.Count -eq 0) {
        throw "Trusted-publisher allowlist at '$Path' contains zero valid entries."
    }

    # Side-channel structured entries for verification while preserving the
    # original string[] prefix contract expected by existing tests/callers.
    $script:MsixTrustedPublisherEntries = [object[]]$publisherEntries
    $script:MsixTrustedThumbprints = [string[]]$thumbprints
    return [string[]]$prefixes
}

$script:MsixTrustedThumbprints = @()
$script:MsixTrustedPublisherEntries = @()
$script:MsixTrustedPublishers = _MsixLoadTrustedPublishers
$script:MsixTrustedPublishersPath = Join-Path -Path $PSScriptRoot -ChildPath 'signers.json'

function _MsixVerifyAuthenticode {
    <#
    .SYNOPSIS
        Verifies a file is Authenticode-signed by a trusted publisher.
    .DESCRIPTION
        Reject the file unless:
          - signature Status is 'Valid'
          - signer cert is in signers.json's trusted-publisher allowlist
          - when the matching entry has a thumbprint pin, the signer cert
            thumbprint matches that entry's pin
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
    $matchedEntries = @()
    if ($script:MsixTrustedPublisherEntries -and $script:MsixTrustedPublisherEntries.Count -gt 0) {
        foreach ($entry in $script:MsixTrustedPublisherEntries) {
            if ($subject -like "$($entry.SubjectPrefix)*") { $matchedEntries += $entry }
        }
    } else {
        foreach ($prefix in $script:MsixTrustedPublishers) {
            if ($subject -like "$prefix*") {
                $matchedEntries += [pscustomobject]@{
                    SubjectPrefix = $prefix
                    Thumbprints   = @()
                }
            }
        }
    }
    if (-not $matchedEntries) {
        throw @"
Authenticode verification FAILED for $ToolName at $Path.
Signer is NOT in the trusted-publisher allowlist:
  Subject:    $subject
  Thumbprint: $($sig.SignerCertificate.Thumbprint)
If you trust this publisher, add its CN prefix to signers.json and follow the trusted-publisher governance notes in CONTRIBUTING.md.
"@
    }
    # When the matching signers.json entry pins one or more thumbprints,
    # require an exact match. Pinning is opt-in per entry: unrelated prefix-only
    # entries keep their existing behaviour even if another publisher is pinned.
    $pinnedEntries = @($matchedEntries | Where-Object { $_.Thumbprints -and @($_.Thumbprints).Count -gt 0 })
    if ($pinnedEntries) {
        $actualTp = if ($sig.SignerCertificate) { ($sig.SignerCertificate.Thumbprint -replace '\s', '').ToUpperInvariant() } else { '' }
        $allowedThumbprints = @($pinnedEntries | ForEach-Object { $_.Thumbprints })
        if ($actualTp -notin $allowedThumbprints) {
            throw @"
Authenticode verification FAILED for $ToolName at $Path.
Signer cert passed the publisher-prefix check but its thumbprint is NOT pinned
on the matching signers.json entry:
  Subject:    $subject
  Thumbprint: $actualTp
If you trust this certificate, add its thumbprint to the matching signers.json entry.
"@
        }
    }
    Write-MsixLog -Level Info -Message "Authenticode verified: $ToolName ($subject)"
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
        The .manifest files are XML — not Authenticode-signable — so accidentally
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
        Write-MsixLog -Level Warning -Message "No .exe/.dll under $Folder to verify ($ToolName)"
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
        [string]$Destination,
        # Optional SHA-256 (hex) the downloaded file must match. When supplied,
        # the file is hashed after download and a mismatch throws (the partial
        # download is removed). Use for integrity-pinning where Authenticode is
        # unavailable (e.g. msixmgr) or to lock an immutable artifact.
        [string]$ExpectedSha256
    )
    Write-MsixLog -Level Info -Message "Downloading $Url"
    $oldPref = $ProgressPreference
    $ProgressPreference = 'SilentlyContinue'   # MUCH faster on Windows PowerShell 5.1
    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing -ErrorAction Stop
    } finally {
        $ProgressPreference = $oldPref
    }
    if ($ExpectedSha256) {
        $actual = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash
        if ($actual -ne $ExpectedSha256.Trim().ToUpperInvariant()) {
            Remove-Item -LiteralPath $Destination -Force -ErrorAction SilentlyContinue
            throw "SHA-256 mismatch for '$Url'.`n  expected: $($ExpectedSha256.Trim().ToUpperInvariant())`n  actual:   $actual`nThe download was rejected and deleted."
        }
        Write-MsixLog -Level Info -Message "SHA-256 verified: $actual"
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
    if (-not (Test-Path -LiteralPath $DestinationPath)) {
        New-Item -Path $DestinationPath -ItemType Directory -Force | Out-Null
    }
    # SECURITY: .NET Framework's ZipFile.ExtractToDirectory does not sanitise
    # entry names, so a malicious archive (these come from third-party GitHub /
    # NuGet sources) can use '..\' or rooted paths to write outside the
    # destination (Zip-Slip) and overwrite e.g. toolchain binaries. Validate
    # every entry's resolved path stays under the destination root before
    # extracting.
    $root = [System.IO.Path]::GetFullPath($DestinationPath)
    if (-not $root.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $root += [System.IO.Path]::DirectorySeparatorChar
    }
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        foreach ($entry in $zip.Entries) {
            $target = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($DestinationPath, $entry.FullName))
            if (-not $target.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to extract entry that escapes the destination (Zip-Slip): $($entry.FullName)"
            }
            # Directory entries have an empty Name; just ensure the folder exists.
            if ([string]::IsNullOrEmpty($entry.Name)) {
                if (-not (Test-Path -LiteralPath $target)) {
                    New-Item -Path $target -ItemType Directory -Force | Out-Null
                }
                continue
            }
            $dir = [System.IO.Path]::GetDirectoryName($target)
            if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
            }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $target, $true)
        }
    } finally {
        $zip.Dispose()
    }
}

function _MsixGitHubLatest {
    param([string]$Repo)
    $api = "https://api.github.com/repos/$Repo/releases/latest"
    $hdr = @{ 'User-Agent' = 'MSIX-PowerShell-Module' }
    if ($env:GITHUB_TOKEN) { $hdr['Authorization'] = "Bearer $env:GITHUB_TOKEN" }
    return Invoke-RestMethod -Uri $api -Headers $hdr -UseBasicParsing -ErrorAction Stop
}


# =============================================================================
# Toolchain-installer scaffolding (issue #36)
# -----------------------------------------------------------------------------
# Every Install-Msix* / Update-Msix* in the module that targets a single-zip
# Sysinternals-style download (Procmon, DebugView, msixmgr, ...) used to
# repeat ~90 lines of marker-check + temp-dir + download + Authenticode +
# copy + rollback. The two helpers below centralise that scaffolding so each
# wrapper drops to ~15 lines and bug fixes apply in one place.
#
# Installers with version-aware idempotency (PSF tag from GitHub, SDK version
# from NuGet, AppRuntime multi-channel cache) DO NOT use these helpers because
# their acquire / idempotency semantics differ enough that forcing them in
# would create a leaky abstraction. They remain bespoke and are documented as
# such alongside the helper.
# =============================================================================

function _MsixInstallArchiveTool {
    <#
    .SYNOPSIS
        Internal helper: download a zip, Authenticode-verify, stage-copy, then
        write a date-stamped marker. Used by Install-MsixProcMon /
        Install-MsixDebugView / Install-MsixMgr.

    .DESCRIPTION
        Common scaffolding for "download a single zip from a stable URL and
        unpack it under Destination" installers. Idempotent via a marker file
        (re-runs are no-ops unless -Force). Rolls back the Destination folder
        if the install fails AND the folder didn't exist before the call.

        Authenticode verification is on by default. msixmgr is the one tool in
        the module that opts out (upstream signing is broken — see
        microsoft/msix-packaging#710) and supplies a custom warning via
        -SkipVerificationWarning.

        Output object exactly matches what the legacy bespoke installers
        returned: @{ Path; Updated; Source }. The Updated=$true on the
        ShouldProcess-skipped (WhatIf) path is preserved as legacy behaviour.

    .PARAMETER ToolName
        Logical name for error / log messages (e.g. 'Process Monitor').

    .PARAMETER Destination
        Where to extract the archive.

    .PARAMETER MarkerFile
        Full path to the idempotency marker file (e.g. "$dest\procmon.installed").

    .PARAMETER Url
        Download URL.

    .PARAMETER ArchiveFileName
        Filename to use when saving the download to the temp folder. Used by
        Expand-Archive to choose its extraction logic from the extension.

    .PARAMETER VerifyAuthenticode
        Default $true. Set to $false for tools whose upstream signing is
        broken — supply -SkipVerificationWarning to surface why.

    .PARAMETER SkipVerificationWarning
        Warning text emitted via Write-Warning when -VerifyAuthenticode is
        $false. Required in that case so operators are not silently shipped
        unverified binaries.

    .PARAMETER IdempotencyLogMessage
        Override the "already installed" log line. Defaults to
        "$ToolName already installed at $Destination. Use -Force to reinstall."

    .PARAMETER PostInstall
        Script block invoked after the copy succeeds, signature: { param($dest) ... }.
        Use this to set an env-var hint and log the resolved exe path.

    .PARAMETER Force
        Re-run the install even when the marker is present.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$ToolName,
        [Parameter(Mandatory)] [string]$Destination,
        [Parameter(Mandatory)] [string]$MarkerFile,
        [Parameter(Mandatory)] [string]$Url,
        [Parameter(Mandatory)] [string]$ArchiveFileName,
        [bool]$VerifyAuthenticode = $true,
        [string]$SkipVerificationWarning,
        [string]$IdempotencyLogMessage,
        [scriptblock]$PostInstall,
        [switch]$Force,
        # Optional SHA-256 of the downloaded archive. When supplied, the download
        # is rejected unless it matches. Off by default so installs work
        # out of the box; opt in for integrity-pinning (esp. tools whose upstream
        # is unsigned, e.g. msixmgr).
        [string]$ExpectedSha256
    )

    if (-not $IdempotencyLogMessage) {
        $IdempotencyLogMessage = "$ToolName already installed at $Destination. Use -Force to reinstall."
    }

    if ((Test-Path -LiteralPath $MarkerFile) -and -not $Force) {
        Write-MsixLog -Level Info -Message $IdempotencyLogMessage
        return [pscustomobject]@{ Path = $Destination; Updated = $false }
    }

    # ShouldProcess-skipped path: preserve legacy behaviour of returning
    # Updated=$true + the source URL even when nothing was actually done.
    if (-not $PSCmdlet.ShouldProcess($Destination, "Install $ToolName")) {
        return [pscustomobject]@{ Path = $Destination; Updated = $true; Source = $Url }
    }

    $tmpRoot = Join-Path -Path $env:TEMP -ChildPath ("{0}-{1}" -f ([System.IO.Path]::GetFileNameWithoutExtension($ArchiveFileName).ToLowerInvariant()), ([guid]::NewGuid().ToString('N').Substring(0,8)))
    $stage   = Join-Path -Path $tmpRoot -ChildPath 'extracted'
    $archive = Join-Path -Path $tmpRoot -ChildPath $ArchiveFileName
    New-Item -Path $tmpRoot -ItemType Directory -Force | Out-Null
    New-Item -Path $stage   -ItemType Directory -Force | Out-Null

    $destinationExisted = Test-Path -LiteralPath $Destination
    try {
        _MsixDownloadFile -Url $Url -Destination $archive -ExpectedSha256 $ExpectedSha256
        Expand-Archive -LiteralPath $archive -DestinationPath $stage -Force

        if ($VerifyAuthenticode) {
            _MsixVerifyAuthenticodeFolder -Folder $stage -ToolName $ToolName
        } elseif ($SkipVerificationWarning) {
            Write-Warning -Message $SkipVerificationWarning
        }

        New-Item -Path $Destination -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path -Path $stage -ChildPath '*') -Destination $Destination -Recurse -Force
        (Get-Date -Format o) | Set-Content -LiteralPath $MarkerFile -Encoding ascii

        if ($PostInstall) { & $PostInstall $Destination }
    } catch {
        Write-MsixLog -Level Error -Message "$ToolName install rolled back: $_"
        if (-not $destinationExisted) {
            Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
        }
        throw
    } finally {
        Remove-Item -LiteralPath $tmpRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    return [pscustomobject]@{
        Path    = $Destination
        Updated = $true
        Source  = $Url
    }
}


function _MsixUpdateToolByAge {
    <#
    .SYNOPSIS
        Internal helper: age-based updater. Re-runs an install action only
        when the marker timestamp is older than -MaxAgeDays. Used by
        Update-MsixProcMon / Update-MsixDebugView / Update-MsixMgr /
        Update-MsixAppRuntime.

    .DESCRIPTION
        Reads the ISO-8601 timestamp from -MarkerFile (written by
        _MsixInstallArchiveTool) and compares against MaxAgeDays. Calls
        -InstallFresh when no marker exists, -InstallForce when the marker
        is too old, or returns a fresh no-op summary otherwise.

        Whole-function ShouldProcess (matches the previous behaviour of
        Update-MsixProcMon / Update-MsixDebugView / Update-MsixAppRuntime).

    .PARAMETER ToolName
        Logical name used in age log lines.

    .PARAMETER Destination
        Where the tool lives (used as the ShouldProcess target string).

    .PARAMETER MarkerFile
        Full path to the install marker file.

    .PARAMETER MaxAgeDays
        Refresh threshold in days.

    .PARAMETER InstallFresh
        Script block invoked when nothing is cached. Typically calls the
        Install-Msix* with no -Force.

    .PARAMETER InstallForce
        Script block invoked when the marker is too old. Typically calls the
        Install-Msix* with -Force.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$ToolName,
        [Parameter(Mandatory)] [string]$Destination,
        [Parameter(Mandatory)] [string]$MarkerFile,
        [Parameter(Mandatory)] [int]$MaxAgeDays,
        [Parameter(Mandatory)] [scriptblock]$InstallFresh,
        [Parameter(Mandatory)] [scriptblock]$InstallForce
    )

    if (-not $PSCmdlet.ShouldProcess($Destination, "Update $ToolName")) { return }

    if (-not (Test-Path -LiteralPath $MarkerFile)) {
        return & $InstallFresh
    }
    $stamp = [datetime](Get-Content -LiteralPath $MarkerFile -Raw).Trim()
    $age   = (Get-Date) - $stamp
    if ($age.TotalDays -gt $MaxAgeDays) {
        Write-MsixLog -Level Info -Message "$ToolName is $([int]$age.TotalDays) days old; refreshing."
        return & $InstallForce
    }
    Write-MsixLog -Level Info -Message "$ToolName is fresh ($([int]$age.TotalDays) days old; threshold $MaxAgeDays)."
    return [pscustomobject]@{ Path = $Destination; Updated = $false }
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
        cmdlet created it). See signers.json for the allowlist.

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

    if (-not $Destination) { $Destination = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'psf' }

    $release = _MsixGitHubLatest -Repo $script:TMurgentRepo
    $tag     = $release.tag_name
    Write-MsixLog -Level Info -Message "Latest TMurgent PSF release: $tag"

    $marker = Join-Path -Path $Destination -ChildPath 'psf.version'
    if ((Test-Path -LiteralPath $marker) -and -not $Force) {
        $current = (Get-Content -LiteralPath $marker -Raw -ErrorAction SilentlyContinue).Trim()
        if ($current -eq $tag) {
            Write-MsixLog -Level Info -Message "PSF $tag already installed at $Destination. Use -Force to reinstall."
            return [pscustomobject]@{ Path = $Destination; Version = $tag; Updated = $false }
        }
    }

    $asset = $release.assets | Where-Object { $_.name -match $AssetPattern } | Select-Object -First 1
    if (-not $asset) {
        throw "No release asset matching '$AssetPattern' in $tag. Assets: $($release.assets.name -join ', ')"
    }

    $tmp = Join-Path -Path $env:TEMP -ChildPath "tmurgent-psf-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -Path $tmp -ItemType Directory -Force | Out-Null
    $zip = Join-Path -Path $tmp -ChildPath $asset.name

    if ($PSCmdlet.ShouldProcess($Destination, "Install PSF $tag")) {
        $destinationCreated = $false
        try {
            _MsixDownloadFile -Url $asset.browser_download_url -Destination $zip
            _MsixExpandZip -ArchivePath $zip -DestinationPath $tmp

            # H1: verify Authenticode signer on every .exe/.dll before we copy
            # any of them into the toolchain root.
            _MsixVerifyAuthenticodeFolder -Folder $tmp -ToolName 'PSF'

            if (-not (Test-Path -LiteralPath $Destination)) {
                New-Item -Path $Destination -ItemType Directory -Force | Out-Null
                $destinationCreated = $true
            }
            # Copy every file from extracted layout into Destination flatly
            Get-ChildItem -LiteralPath $tmp -Recurse -File | Where-Object { $_.FullName -ne $zip } |
                ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination $Destination -Force }

            Set-Content -Path $marker -Value $tag -Encoding ascii
            Write-MsixLog -Level Info -Message "PSF $tag installed to $Destination"

        } catch {
            Write-MsixLog -Level Error -Message "PSF install rolled back: $_"
            if ($destinationCreated) {
                Remove-Item -LiteralPath $Destination -Recurse -Force -ErrorAction SilentlyContinue
            }
            throw
        } finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
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
    if (-not $Path) { $Path = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'psf' }
    $marker = Join-Path -Path $Path -ChildPath 'psf.version'
    return [pscustomobject]@{
        Path        = $Path
        Installed   = Test-Path -LiteralPath $marker
        Version     = if (Test-Path -LiteralPath $marker) { (Get-Content -LiteralPath $marker -Raw).Trim() } else { $null }
        HasLauncher = Test-Path -LiteralPath (Join-Path -Path $Path -ChildPath 'PsfLauncher32.exe')
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
        Write-MsixLog -Level Info -Message "No PSF found locally; installing."
        return Install-MsixPsfBinary -Destination $Destination
    }

    $latest = (_MsixGitHubLatest -Repo $script:TMurgentRepo).tag_name
    if ($current.Version -eq $latest) {
        Write-MsixLog -Level Info -Message "PSF up to date ($latest)"
        return $current
    }
    Write-MsixLog -Level Info -Message "Update available: $($current.Version) -> $latest"
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
    if (-not $Destination) { $Destination = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'procmon' }
    _MsixInstallArchiveTool `
        -ToolName 'Process Monitor' `
        -Destination $Destination `
        -MarkerFile (Join-Path -Path $Destination -ChildPath 'procmon.installed') `
        -Url $script:ProcmonZipUrl `
        -ArchiveFileName 'ProcessMonitor.zip' `
        -Force:$Force `
        -PostInstall {
            param($dest)
            $exe = Join-Path -Path $dest -ChildPath 'Procmon.exe'
            if (Test-Path -LiteralPath $exe) {
                $env:MSIX_PROCMON_PATH = $exe
                Write-MsixLog -Level Info -Message "Process Monitor installed at $exe"
            } else {
                Write-MsixLog -Level Warning -Message "Procmon.exe not found after extraction; check $dest"
            }
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
    if (-not $Destination) { $Destination = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'procmon' }
    _MsixUpdateToolByAge `
        -ToolName 'Procmon' `
        -Destination $Destination `
        -MarkerFile (Join-Path -Path $Destination -ChildPath 'procmon.installed') `
        -MaxAgeDays $MaxAgeDays `
        -InstallFresh { Install-MsixProcMon -Destination $Destination } `
        -InstallForce { Install-MsixProcMon -Destination $Destination -Force }
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
    if (-not $Destination) { $Destination = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'debugview' }
    _MsixInstallArchiveTool `
        -ToolName 'DebugView' `
        -Destination $Destination `
        -MarkerFile (Join-Path -Path $Destination -ChildPath 'debugview.installed') `
        -Url $script:DebugViewZipUrl `
        -ArchiveFileName 'DebugView.zip' `
        -Force:$Force `
        -PostInstall {
            param($dest)
            $exe = Join-Path -Path $dest -ChildPath 'Dbgview64.exe'
            if (-not (Test-Path -LiteralPath $exe)) { $exe = Join-Path -Path $dest -ChildPath 'Dbgview.exe' }
            if (Test-Path -LiteralPath $exe) {
                $env:MSIX_DEBUGVIEW_PATH = $exe
                Write-MsixLog -Level Info -Message "DebugView installed at $exe"
            } else {
                Write-MsixLog -Level Warning -Message "Dbgview.exe / Dbgview64.exe not found after extraction; check $dest"
            }
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
    if (-not $Destination) { $Destination = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'debugview' }
    _MsixUpdateToolByAge `
        -ToolName 'DebugView' `
        -Destination $Destination `
        -MarkerFile (Join-Path -Path $Destination -ChildPath 'debugview.installed') `
        -MaxAgeDays $MaxAgeDays `
        -InstallFresh { Install-MsixDebugView -Destination $Destination } `
        -InstallForce { Install-MsixDebugView -Destination $Destination -Force }
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
    if (-not $Path) { $Path = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'debugview' }
    $marker = Join-Path -Path $Path -ChildPath 'debugview.installed'
    $exe    = Join-Path -Path $Path -ChildPath 'Dbgview64.exe'
    if (-not (Test-Path -LiteralPath $exe)) { $exe = Join-Path -Path $Path -ChildPath 'Dbgview.exe' }

    return [pscustomobject]@{
        Path        = $Path
        Installed   = Test-Path -LiteralPath $marker
        InstalledOn = if (Test-Path -LiteralPath $marker) { [datetime](Get-Content -LiteralPath $marker -Raw).Trim() } else { $null }
        Executable  = if (Test-Path -LiteralPath $exe) { $exe } else { $null }
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
    Write-MsixLog -Level Info -Message "Microsoft.Windows.SDK.BuildTools version: $Version"

    # ── Idempotency check ─────────────────────────────────────────────────
    $marker = Join-Path -Path $Destination -ChildPath 'Tools\sdk.version'
    if ((Test-Path -LiteralPath $marker) -and -not $Force) {
        $current = (Get-Content -LiteralPath $marker -Raw -ErrorAction SilentlyContinue).Trim()
        if ($current -eq "$Version|$Architecture") {
            Write-MsixLog -Level Info -Message "SDK tools $Version ($Architecture) already installed at $Destination\Tools."
            return [pscustomobject]@{ Path = "$Destination\Tools"; Version = $Version; Architecture = $Architecture; Updated = $false }
        }
    }

    # ── Download + extract ────────────────────────────────────────────────
    $tmp = Join-Path -Path $env:TEMP -ChildPath "sdk-buildtools-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -Path $tmp -ItemType Directory -Force | Out-Null
    $nupkg = Join-Path -Path $tmp -ChildPath "$($script:SdkToolsNuGet).$Version.nupkg"
    $url   = "https://api.nuget.org/v3-flatcontainer/$($script:SdkToolsNuGet.ToLower())/$Version/$($script:SdkToolsNuGet.ToLower()).$Version.nupkg"

    if ($PSCmdlet.ShouldProcess("$Destination\Tools", "Install Microsoft.Windows.SDK.BuildTools $Version ($Architecture)")) {
        $toolsDir = Join-Path -Path $Destination -ChildPath 'Tools'
        $toolsDirExisted = Test-Path -LiteralPath $toolsDir
        try {
            _MsixDownloadFile -Url $url -Destination $nupkg

            $extracted = Join-Path -Path $tmp -ChildPath 'extracted'
            _MsixExpandZip -ArchivePath $nupkg -DestinationPath $extracted

            # Locate the bin\<sdk-ver>\<arch> folder. NuGet packages may have a
            # versioned subdirectory we need to discover.
            $archDir = Get-ChildItem -LiteralPath (Join-Path -Path $extracted -ChildPath 'bin') -Directory -ErrorAction SilentlyContinue |
                       ForEach-Object { Join-Path -Path $_.FullName -ChildPath $Architecture } |
                       Where-Object { Test-Path -LiteralPath (Join-Path -Path $_ -ChildPath 'MakeAppx.exe') } |
                       Sort-Object -Descending |
                       Select-Object -First 1
            if (-not $archDir) {
                throw "MakeAppx.exe not found inside the NuGet package for architecture '$Architecture'."
            }

            # H1: verify every .exe/.dll in the SDK arch folder before we copy
            # them into Tools\ where Get-MsixToolsRoot will surface them.
            _MsixVerifyAuthenticodeFolder -Folder $archDir -ToolName "SDK BuildTools $Version/$Architecture"

            New-Item -Path $toolsDir -ItemType Directory -Force | Out-Null

            # Copy the whole arch folder (MakeAppx, signtool, makepri, plus
            # the AppxPackaging dependency DLLs that signtool needs at runtime).
            Copy-Item -Path "$archDir\*" -Destination $toolsDir -Recurse -Force

            "$Version|$Architecture" | Set-Content -LiteralPath $marker -Encoding ascii
            Write-MsixLog -Level Info -Message "MakeAppx.exe + signtool.exe installed at $toolsDir"

            # Reset the cached tools root so the next Get-MsixToolsRoot picks this up
            Set-MsixToolsRoot -Path $Destination

        } catch {
            Write-MsixLog -Level Error -Message "SDK tools install rolled back: $_"
            if (-not $toolsDirExisted) {
                Remove-Item -LiteralPath $toolsDir -Recurse -Force -ErrorAction SilentlyContinue
            }
            throw
        } finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
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
    $marker = Join-Path -Path $Destination -ChildPath 'Tools\sdk.version'
    if (-not (Test-Path -LiteralPath $marker)) {
        return Install-MsixSdkTool -Destination $Destination -Architecture $Architecture
    }

    # Find latest published version
    $idxUrl = "https://api.nuget.org/v3-flatcontainer/$($script:SdkToolsNuGet.ToLower())/index.json"
    $idx    = Invoke-RestMethod -Uri $idxUrl -UseBasicParsing -ErrorAction Stop
    $latest = ($idx.versions | Where-Object { $_ -notmatch '-' } |
               ForEach-Object { [pscustomobject]@{ Raw=$_; Ver=[version]($_ -replace '[^0-9.]','') } } |
               Sort-Object Ver -Descending | Select-Object -First 1).Raw

    $current = (Get-Content -LiteralPath $marker -Raw).Trim()
    if ($current -eq "$latest|$Architecture") {
        Write-MsixLog -Level Info -Message "SDK tools up to date ($latest, $Architecture)."
        return [pscustomobject]@{ Path = "$Destination\Tools"; Version = $latest; Architecture = $Architecture; Updated = $false }
    }
    Write-MsixLog -Level Info -Message "SDK tools update available: $current -> $latest|$Architecture"
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
    $marker = Join-Path -Path $Destination -ChildPath 'Tools\sdk.version'
    if (-not (Test-Path -LiteralPath $marker)) {
        return [pscustomobject]@{ Path = "$Destination\Tools"; Installed = $false; Version = $null; Architecture = $null }
    }
    $current = (Get-Content -LiteralPath $marker -Raw).Trim()
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
    if (-not $Destination) { $Destination = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'runtime' }

    $marker = Join-Path -Path $Destination -ChildPath 'runtime.installed'
    if ((Test-Path -LiteralPath $marker) -and -not $Force) {
        # Check whether all requested channels are cached; if any is missing
        # we still need to download just that one (don't bail out).
        $missing = $Channels | Where-Object {
            -not (Test-Path -LiteralPath (Join-Path -Path $Destination -ChildPath (_MsixAppRuntimeFileName -Channel $_)))
        }
        if (-not $missing) {
            Write-MsixLog -Level Info -Message "Windows App Runtime ($($Channels -join ', ')) + DesktopAppInstaller cached at $Destination."
            return [pscustomobject]@{
                Path = $Destination; Updated = $false; Channels = $Channels
            }
        }
        $Channels = $missing
        Write-MsixLog -Level Info -Message "Caching additional WindowsAppRuntime channels: $($missing -join ', ')"
    }

    if (-not $PSCmdlet.ShouldProcess($Destination, "Install Windows App Runtime ($($Channels -join ', ')) + DesktopAppInstaller")) { return }

    New-Item -ItemType Directory -Path $Destination -Force | Out-Null

    # Issue #42: fail closed + Authenticode verify EVERY downloaded artifact
    # before we touch the install marker. The previous flow swallowed per-
    # channel download failures and still wrote the marker, so a sandbox
    # could report the runtime cache as installed while required runtime
    # installers were missing. It also skipped signature verification, so
    # the bundle and channel installers could land from any redirect target
    # without being checked against the trusted-publisher allowlist.

    # Track files we created in THIS call so we can clean them up on a
    # failure mid-flight. Files that existed before the call are left alone.
    $createdThisRun = [System.Collections.Generic.List[string]]::new()
    try {
        # ── DesktopAppInstaller msixbundle ────────────────────────────────
        $bundlePath = Join-Path -Path $Destination -ChildPath 'Microsoft.DesktopAppInstaller.msixbundle'
        if ($Force -or -not (Test-Path -LiteralPath $bundlePath)) {
            _MsixDownloadFile -Url $script:DesktopAppInstallerUrl -Destination $bundlePath
            $createdThisRun.Add($bundlePath)
        }
        _MsixVerifyAuthenticodeMsixBundle -Path $bundlePath -ToolName 'DesktopAppInstaller'

        # ── WindowsAppRuntime channel installers (one .exe per channel) ───
        # Treat any download or verification failure as a hard failure --
        # caller can pass -Channels with only the channels they truly need
        # to scope the install.
        $runtimePaths = [System.Collections.Generic.List[string]]::new()
        foreach ($ch in $Channels) {
            $rt = Join-Path -Path $Destination -ChildPath (_MsixAppRuntimeFileName -Channel $ch)
            if ($Force -or -not (Test-Path -LiteralPath $rt)) {
                _MsixDownloadFile -Url (_MsixAppRuntimeUrl -Channel $ch) -Destination $rt
                $createdThisRun.Add($rt)
            }
            _MsixVerifyAuthenticode -Path $rt -ToolName "WindowsAppRuntime/$ch" | Out-Null
            $runtimePaths.Add($rt)
        }

        # Marker is the LAST step -- only written if every requested channel
        # downloaded AND verified. A subsequent Get-MsixAppRuntimeVersion
        # will then see Installed=$true with a confidence guarantee.
        (Get-Date -Format o) | Set-Content -LiteralPath $marker -Encoding ascii
        Write-MsixLog -Level Info -Message "AppRuntime cached + verified: $Destination"

        return [pscustomobject]@{
            Path                  = $Destination
            Updated               = $true
            Channels              = [string[]]$Channels
            DesktopAppInstaller   = $bundlePath
            WindowsAppRuntimeExes = [string[]]$runtimePaths
        }
    } catch {
        # Roll back files we created in THIS call so a partial cache isn't
        # left behind. Files that pre-existed are intentionally preserved.
        foreach ($p in $createdThisRun) {
            if (Test-Path -LiteralPath $p) {
                Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            }
        }
        Write-MsixLog -Level Error -Message "AppRuntime install rolled back: $($_.Exception.Message)"
        throw
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
    if (-not $Destination) { $Destination = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'runtime' }
    _MsixUpdateToolByAge `
        -ToolName 'AppRuntime cache' `
        -Destination $Destination `
        -MarkerFile (Join-Path -Path $Destination -ChildPath 'runtime.installed') `
        -MaxAgeDays $MaxAgeDays `
        -InstallFresh { Install-MsixAppRuntime -Destination $Destination } `
        -InstallForce { Install-MsixAppRuntime -Destination $Destination -Force }
}


function Get-MsixAppRuntimeVersion {
    <#
    .SYNOPSIS
        Reports the cached AppRuntime install timestamp and resolved paths.

    .DESCRIPTION
        Inspects the `runtime.installed` marker plus the bundle and every
        WindowsAppRuntimeInstall-x64-<channel>.exe on disk and returns a
        summary object that Update-MsixAppRuntime / Initialize-MsixToolchain
        consume.

        Issue #42: prior versions looked for a single non-existent
        WindowsAppRuntimeInstall-x64.exe (no channel suffix), so the
        WindowsAppRuntimeExe property was always `$null` once
        Install-MsixAppRuntime started writing channel-specific filenames.
        This cmdlet now enumerates the channel-specific files actually
        present and returns the cached channel list.

    .PARAMETER Path
        Cache folder. Defaults to "(Get-MsixToolsRoot)\runtime".

    .OUTPUTS
        [pscustomobject] with Path, Installed, InstalledOn,
        DesktopAppInstaller (bundle path or $null), Channels (string[],
        zero-length when nothing is cached), and WindowsAppRuntimeExes
        (string[], parallel to Channels).

    .EXAMPLE
        # Check whether the sandbox runtime cache is ready.
        (Get-MsixAppRuntimeVersion).Channels
        # => @('1.4', '1.5', '1.6', '1.7', '1.8')
    #>
    [CmdletBinding()]
    param([string]$Path)

    if (-not $Path) { $Path = Join-Path -Path (Get-MsixToolsRoot) -ChildPath 'runtime' }
    $marker = Join-Path -Path $Path -ChildPath 'runtime.installed'
    $bundle = Join-Path -Path $Path -ChildPath 'Microsoft.DesktopAppInstaller.msixbundle'

    # Channel-aware exe discovery. Filename convention is
    #   WindowsAppRuntimeInstall-x64-<major>.<minor>.exe
    # (set by _MsixAppRuntimeFileName in this file).
    $rx = [regex]'^WindowsAppRuntimeInstall-x64-(?<ch>\d+\.\d+)\.exe$'
    $channels = [System.Collections.Generic.List[string]]::new()
    $exes     = [System.Collections.Generic.List[string]]::new()
    if (Test-Path -LiteralPath $Path) {
        foreach ($file in (Get-ChildItem -LiteralPath $Path -File -Filter 'WindowsAppRuntimeInstall-x64-*.exe' -ErrorAction SilentlyContinue)) {
            $m = $rx.Match($file.Name)
            if ($m.Success) {
                $channels.Add($m.Groups['ch'].Value)
                $exes.Add($file.FullName)
            }
        }
    }

    return [pscustomobject]@{
        Path                  = $Path
        Installed             = Test-Path -LiteralPath $marker
        InstalledOn           = if (Test-Path -LiteralPath $marker) { [datetime](Get-Content -LiteralPath $marker -Raw).Trim() } else { $null }
        DesktopAppInstaller   = if (Test-Path -LiteralPath $bundle) { $bundle } else { $null }
        Channels              = [string[]]$channels
        WindowsAppRuntimeExes = [string[]]$exes
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
