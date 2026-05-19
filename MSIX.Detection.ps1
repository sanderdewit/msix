# =============================================================================
# Auto-detection helpers
# -----------------------------------------------------------------------------
# Read-only scanners that look at an unpacked MSIX and surface things the
# operator probably wants to act on. They feed into Get-MsixHeuristicFinding
# and (via Invoke-MsixAutoFixFromAnalysis) into the autofix planner.
# =============================================================================

#region Fonts ----------------------------------------------------------------

function Get-MsixFontCandidate {
    <#
    .SYNOPSIS
        Lists font files inside the package (.ttf / .otf / .ttc) — candidates
        for registration via uap4:SharedFonts.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .OUTPUTS
        [pscustomobject] one per font: Name, Path (package-relative), SizeBytes
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-fonts"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.ttf','.otf','.ttc' } |
            ForEach-Object {
                [pscustomobject]@{
                    Name      = $_.Name
                    Path      = $_.FullName.Substring($workspace.Length + 1).Replace('\','/')
                    SizeBytes = $_.Length
                }
            }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region Desktop shortcuts inside the package --------------------------------

function Get-MsixDesktopShortcutCandidate {
    <#
    .SYNOPSIS
        Lists .lnk files dropped under the package's virtualized public Desktop
        (VFS\Common Desktop, VFS\User Desktop, etc.) — common installer
        leftovers that clutter the user's actual desktop after MSIX install.

    .PARAMETER PackagePath
        .msix to scan (read-only).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-shortcuts"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $patterns = @('VFS\\Common Desktop','VFS\\User Desktop','VFS\\Desktop')
        Get-ChildItem $workspace -Recurse -File -Filter *.lnk -ErrorAction SilentlyContinue |
            Where-Object {
                $rel = $_.FullName.Substring($workspace.Length + 1)
                ($patterns | Where-Object { $rel -match $_ }).Count -gt 0
            } |
            ForEach-Object {
                [pscustomobject]@{
                    Name      = $_.Name
                    Path      = $_.FullName.Substring($workspace.Length + 1).Replace('\','/')
                    SizeBytes = $_.Length
                }
            }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


function Remove-MsixDesktopShortcut {
    <#
    .SYNOPSIS
        Removes shortcut files (.lnk) the original installer dropped under
        the package's virtualized desktop folders. Repacks + signs unless
        -SkipSigning / -NoSign.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $patterns = @('VFS\\Common Desktop','VFS\\User Desktop','VFS\\Desktop')
        $removed  = @()
        Get-ChildItem $workspace -Recurse -File -Filter *.lnk -ErrorAction SilentlyContinue |
            Where-Object {
                $rel = $_.FullName.Substring($workspace.Length + 1)
                ($patterns | Where-Object { $rel -match $_ }).Count -gt 0
            } |
            ForEach-Object {
                if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove desktop shortcut')) {
                    $removed += $_.FullName.Substring($workspace.Length + 1)
                    Remove-Item $_.FullName -Force
                }
            }

        if (-not $removed) {
            Write-MsixLog Info 'No desktop shortcuts found in the package.'
            return
        }
        Write-MsixLog Info "Removed: $($removed -join ', ')"

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }
        return [pscustomobject]@{ Removed = $removed; Output = $target }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion

#region Capability hints from PE imports ------------------------------------

# Heuristic: for each well-known DLL name in the package's PE imports, suggest
# a likely-required capability. Best-effort; user should validate via ACP.
$script:DllToCapability = @{
    'wsock32.dll'  = 'internetClientServer'
    'ws2_32.dll'   = 'internetClient'
    'wininet.dll'  = 'internetClient'
    'winhttp.dll'  = 'internetClient'
    'fwpuclnt.dll' = 'privateNetworkClientServer'
    'crypt32.dll'  = 'sharedUserCertificates'    # niche, may not always apply
}

function Get-MsixCapabilityHint {
    <#
    .SYNOPSIS
        Suggests a minimum capability set based on the DLLs imported by
        executables inside the package. Heuristic only — confirm with the
        Application Capability Profiler before publishing.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-caphints"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $hits = New-Object System.Collections.Generic.HashSet[string]
        $allDlls = $script:DllToCapability.Keys
        Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.exe','.dll' } |
            ForEach-Object {
                try {
                    $stream = [IO.File]::OpenRead($_.FullName)
                    try {
                        $buf = New-Object byte[] ([math]::Min($stream.Length, 8MB))
                        $n   = $stream.Read($buf, 0, $buf.Length)
                        $txt = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
                    } finally { $stream.Dispose() }
                    foreach ($d in $allDlls) {
                        if ($txt -match [regex]::Escape($d)) { $null = $hits.Add($script:DllToCapability[$d]) }
                    }
                } catch { Write-MsixLog Debug "PE scan skipped for file: $_" }
            }
        return @($hits) | Sort-Object -Unique
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Nested package detection ---------------------------------------------

function Get-MsixNestedPackageCandidate {
    <#
    .SYNOPSIS
        Lists .msix/.appx/.msixbundle/.appxbundle files found inside the package.

    .DESCRIPTION
        Nested installer packages baked in by the original installer cannot be
        installed from within an MSIX container. This is a detection-only helper;
        there is no automated fix — nested packages require a different deployment
        strategy (side-loading, startScript wrapper, or Intune / SCCM staging).

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .OUTPUTS
        [pscustomobject] one per nested package: Name, Path (package-relative), SizeBytes
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-nested"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.msix','.appx','.msixbundle','.appxbundle' } |
            ForEach-Object {
                [pscustomobject]@{
                    Name      = $_.Name
                    Path      = $_.FullName.Substring($workspace.Length + 1)
                    SizeBytes = $_.Length
                }
            }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion


# Backward-compatible plural aliases
Set-Alias Get-MsixFontCandidates Get-MsixFontCandidate
Set-Alias Get-MsixDesktopShortcutCandidates Get-MsixDesktopShortcutCandidate
Set-Alias Remove-MsixDesktopShortcuts Remove-MsixDesktopShortcut
Set-Alias Get-MsixCapabilityHints Get-MsixCapabilityHint
Set-Alias Get-MsixNestedPackageCandidates Get-MsixNestedPackageCandidate
