# =============================================================================
# PSGallery update notification
# -----------------------------------------------------------------------------
# Tells an interactive operator when a newer MSIX module version is published,
# so field fixes (data-loss guards, security hardening) actually reach the
# people running the module instead of waiting for them to think to check.
#
# Design constraints, in priority order:
#   1. NEVER break or noticeably slow Import-Module. Enterprise CI imports this
#      module thousands of times; an import that can hang on a network call is
#      worse than no notification at all. Hard timeout, everything swallowed.
#   2. Silent where a message is useless or harmful: CI, non-interactive hosts,
#      and any session that opted out.
#   3. At most one network call per day per user, cached on disk.
#   4. Never fail closed on a parse/network/permission problem - the module must
#      import identically on an air-gapped machine.
# =============================================================================

$script:MsixUpdateCheckUrl = "https://www.powershellgallery.com/api/v2/FindPackagesById()?id='MSIX'&`$filter=IsLatestVersion%20eq%20true&`$select=Version"

function _MsixUpdateCachePath {
    [OutputType([string])]
    param()
    $root = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [IO.Path]::GetTempPath() }
    Join-Path -Path (Join-Path -Path $root -ChildPath 'MSIX') -ChildPath 'update-check.json'
}

function _MsixShouldCheckForUpdate {
    <#
    .SYNOPSIS
        Returns $true when an update check is appropriate for this session.
    #>
    [OutputType([bool])]
    param()

    # Explicit opt-out.
    if ($env:MSIX_NO_UPDATE_CHECK) { return $false }

    # Automation: nobody reads it, and it would add a network dependency to
    # every build. These are the standard markers for the major CI systems.
    foreach ($ci in 'CI', 'TF_BUILD', 'GITHUB_ACTIONS', 'JENKINS_URL', 'TEAMCITY_VERSION', 'GITLAB_CI', 'BUILD_BUILDID') {
        if (Get-Item -Path "Env:\$ci" -ErrorAction SilentlyContinue) { return $false }
    }

    # Non-interactive host (scheduled task, remoting job, -NonInteractive).
    try {
        if (-not [Environment]::UserInteractive) { return $false }
    } catch { return $false }

    return $true
}

function _MsixGetLatestPublishedVersion {
    <#
    .SYNOPSIS
        Returns the newest MSIX version on PSGallery, or $null if unavailable.

    .DESCRIPTION
        Deliberately does NOT use Find-Module: that pulls in PowerShellGet,
        can be slow, and honours repository configuration we do not control.
        A single REST call with a hard timeout is predictable.

        The response is matched with a regex rather than parsed as XML: the
        value needed is one element, and not invoking an XML parser keeps this
        path free of any parser-level concern on untrusted input.
    #>
    [OutputType([version])]
    param([int]$TimeoutSec = 4)

    try {
        $resp = Invoke-WebRequest -Uri $script:MsixUpdateCheckUrl -UseBasicParsing `
                    -TimeoutSec $TimeoutSec -ErrorAction Stop
        $versions = [regex]::Matches([string]$resp.Content, '<d:Version[^>]*>([^<]+)</d:Version>') |
                    ForEach-Object {
                        $v = $null
                        # Strip any prerelease suffix before parsing.
                        if ([version]::TryParse((($_.Groups[1].Value) -split '-')[0], [ref]$v)) { $v }
                    }
        if (-not $versions) { return $null }
        return (@($versions) | Sort-Object -Descending | Select-Object -First 1)
    } catch {
        return $null
    }
}

function _MsixNotifyIfUpdateAvailable {
    <#
    .SYNOPSIS
        Emits a one-line notice when PSGallery has a newer version than the one
        just imported. Fail-silent by contract.

    .PARAMETER CurrentVersion
        The version of the module being imported.

    .PARAMETER MaxCacheAgeHours
        How long a cached result stays authoritative (default 24h).
    #>
    [OutputType([void])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)][version]$CurrentVersion,
        [int]$MaxCacheAgeHours = 24
    )

    # Everything here is best-effort. A failure must never surface to the caller
    # or prevent the module from importing.
    try {
        if (-not (_MsixShouldCheckForUpdate)) { return }

        $cachePath = _MsixUpdateCachePath
        $latest    = $null
        $fresh     = $false

        if (Test-Path -LiteralPath $cachePath) {
            try {
                $cache = Get-Content -LiteralPath $cachePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                $checkedAt = [datetime]::Parse($cache.CheckedAt, [Globalization.CultureInfo]::InvariantCulture)
                if (((Get-Date) - $checkedAt).TotalHours -lt $MaxCacheAgeHours) {
                    $fresh = $true
                    $parsed = $null
                    if ($cache.Latest -and [version]::TryParse([string]$cache.Latest, [ref]$parsed)) { $latest = $parsed }
                }
            } catch {
                # Corrupt or unreadable cache: fall through to a live check.
                $fresh = $false
            }
        }

        if (-not $fresh) {
            $latest = _MsixGetLatestPublishedVersion
            # Record the attempt either way so a persistently offline machine
            # does not retry on every single import.
            try {
                $dir = Split-Path -Parent -Path $cachePath
                if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                    New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -ErrorAction Stop | Out-Null
                }
                $payload = [ordered]@{
                    CheckedAt = (Get-Date).ToString('o')
                    Latest    = if ($latest) { $latest.ToString() } else { '' }
                } | ConvertTo-Json
                [IO.File]::WriteAllText($cachePath, $payload, [Text.UTF8Encoding]::new($false))
            } catch {
                # A read-only or redirected profile just means no caching; the
                # check still worked. Never surface this.
                Write-MsixLog -Level Debug -Message "Update-check cache could not be written: $($_.Exception.Message)"
            }
        }

        if ($latest -and $latest -gt $CurrentVersion) {
            Write-Information -MessageData ("MSIX $CurrentVersion is installed; $latest is available on PowerShell Gallery. Update with: Update-Module MSIX   (silence this with `$env:MSIX_NO_UPDATE_CHECK = '1')") -InformationAction Continue
        }
    } catch {
        # Intentionally silent: an update notice is never worth a failed import.
        Write-MsixLog -Level Debug -Message "Update check skipped: $($_.Exception.Message)"
    }
}
