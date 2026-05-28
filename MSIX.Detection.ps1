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

    .DESCRIPTION
        Read-only scanner that unpacks the package to a scratch workspace,
        enumerates .ttf / .otf / .ttc files anywhere in the tree, and returns
        their package-relative paths. The workspace is always cleaned up.

        Pipe the Path values into Add-MsixFontExtension to register the
        discovered fonts via uap4:SharedFonts.

        Surfaces a `ManifestFix:SharedFonts` finding via Get-MsixHeuristicFinding
        when the package ships fonts but does not declare them.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # Discover fonts and register them via uap4:SharedFonts in one pipeline
        $fonts = Get-MsixFontCandidate -PackagePath app.msix | Select-Object -ExpandProperty Path
        Add-MsixFontExtension -PackagePath app.msix -FontPaths $fonts -SkipSigning

    .OUTPUTS
        [pscustomobject] one per font: Name, Path (package-relative), SizeBytes
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-fonts"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Get-ChildItem -LiteralPath $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.ttf','.otf','.ttc' } |
            ForEach-Object {
                [pscustomobject]@{
                    Name      = $_.Name
                    Path      = $_.FullName.Substring($workspace.Length + 1).Replace('\','/')
                    SizeBytes = $_.Length
                }
            }
    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
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

    .DESCRIPTION
        Read-only scanner. Matches .lnk files whose package-relative path lies
        under any of `VFS\Common Desktop`, `VFS\User Desktop`, or `VFS\Desktop`.

        Feeds Get-MsixHeuristicFinding (Category=DesktopShortcuts) and is the
        detection half of Remove-MsixDesktopShortcut. No mutation, no signing.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # Surface unwanted desktop shortcuts, then strip them in-place
        Get-MsixDesktopShortcutCandidate -PackagePath app.msix
        Remove-MsixDesktopShortcut -PackagePath app.msix -SkipSigning

    .OUTPUTS
        [pscustomobject] one per shortcut: Name, Path (package-relative), SizeBytes
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-shortcuts"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $patterns = @('VFS\\Common Desktop','VFS\\User Desktop','VFS\\Desktop')
        Get-ChildItem -LiteralPath $workspace -Recurse -File -Filter *.lnk -ErrorAction SilentlyContinue |
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
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


function Remove-MsixDesktopShortcut {
    <#
    .SYNOPSIS
        Removes shortcut files (.lnk) the original installer dropped under
        the package's virtualized desktop folders. Repacks + signs unless
        -SkipSigning / -NoSign.

    .DESCRIPTION
        Mutator counterpart to Get-MsixDesktopShortcutCandidate. Unpacks the
        package, deletes every .lnk under VFS\Common Desktop, VFS\User Desktop
        or VFS\Desktop, repacks, and (unless -SkipSigning) re-signs.

        Idempotent: re-running on a package with no matching shortcuts logs an
        info line and returns without repacking.

        Wired into Invoke-MsixAutoFix via the `-RemoveDesktopShortcuts` switch
        and into Invoke-MsixAutoFixFromAnalysis for the `DesktopShortcuts`
        finding category.

    .PARAMETER PackagePath
        .msix file to mutate.

    .PARAMETER OutputPath
        If set, the repacked package is written here instead of overwriting
        the input.

    .PARAMETER SkipSigning
        Skip the signing pass — useful when chaining multiple fixers and
        signing only once at the end. Alias: -NoSign.

    .PARAMETER Pfx
        Path to a signing certificate (.pfx). Ignored when -SkipSigning is set.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        # Test/dev case: strip desktop shortcuts and skip signing
        Remove-MsixDesktopShortcut -PackagePath app.msix -SkipSigning

    .EXAMPLE
        # Production: strip and re-sign with a dev cert (idempotent)
        Remove-MsixDesktopShortcut -PackagePath app.msix `
            -Pfx cert.pfx -PfxPassword $pw

    .OUTPUTS
        [pscustomobject] with Removed (string[] of package-relative paths) and
        Output (final package path). Returns nothing when no shortcuts matched.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '',
        Justification = 'ShouldProcess is invoked inside _MsixMutatePackage; PSSA cannot trace it through the scriptblock dispatch (issue #40).')]
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    _MsixMutatePackage -PackagePath $PackagePath -Operation 'dshortcut' `
        -OutputPath $OutputPath -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -NoChangeMessage 'No desktop shortcuts found in the package.' `
        -Mutator {
            param($workspace)
            $patterns = @('VFS\\Common Desktop','VFS\\User Desktop','VFS\\Desktop')
            $removed  = @()
            Get-ChildItem -LiteralPath $workspace -Recurse -File -Filter *.lnk -ErrorAction SilentlyContinue |
                Where-Object {
                    $rel = $_.FullName.Substring($workspace.Length + 1)
                    ($patterns | Where-Object { $rel -match $_ }).Count -gt 0
                } |
                ForEach-Object {
                    $removed += $_.FullName.Substring($workspace.Length + 1)
                    Remove-Item -LiteralPath $_.FullName -Force
                }

            if (-not $removed) { return $null }
            Write-MsixLog -Level Info -Message "Removed: $($removed -join ', ')"
            @{ Removed = $removed }
        }.GetNewClosure()
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

    .DESCRIPTION
        Unpacks the package, scans the first 8 MB of each .exe / .dll for
        well-known Win32 DLL imports, and maps them to the capability names a
        packaged app typically needs (e.g. `wininet.dll` -> `internetClient`).

        Returns the union of detected capability names. Feeds the
        `CapabilityHints` finding produced by Get-MsixHeuristicFinding and the
        `AddCapabilityHints` stage of Invoke-MsixAutoFixFromAnalysis.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # Discover hints and add them via Add-MsixCapability
        $hints = Get-MsixCapabilityHint -PackagePath app.msix
        Add-MsixCapability -PackagePath app.msix -Names $hints -SkipSigning

    .OUTPUTS
        [string[]] capability names (sorted, unique).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-caphints"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $hits = [System.Collections.Generic.HashSet[string]]::new()
        $allDlls = $script:DllToCapability.Keys
        Get-ChildItem -LiteralPath $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.exe','.dll' } |
            ForEach-Object {
                try {
                    $stream = [IO.File]::OpenRead($_.FullName)
                    try {
                        $buf = [byte[]]::new(([math]::Min($stream.Length, 8MB)))
                        $n   = $stream.Read($buf, 0, $buf.Length)
                        $txt = [Text.Encoding]::ASCII.GetString($buf, 0, $n)
                    } finally { $stream.Dispose() }
                    foreach ($d in $allDlls) {
                        if ($txt -match [regex]::Escape($d)) { $null = $hits.Add($script:DllToCapability[$d]) }
                    }
                } catch { Write-MsixLog -Level Debug -Message "PE scan skipped for file: $_" }
            }
        return @($hits) | Sort-Object -Unique
    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
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

    .EXAMPLE
        # Surface any nested installer packages — there is no auto-fix
        Get-MsixNestedPackageCandidate -PackagePath app.msix

    .OUTPUTS
        [pscustomobject] one per nested package: Name, Path (package-relative), SizeBytes
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-nested"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Get-ChildItem -LiteralPath $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.msix','.appx','.msixbundle','.appxbundle' } |
            ForEach-Object {
                [pscustomobject]@{
                    Name      = $_.Name
                    Path      = $_.FullName.Substring($workspace.Length + 1)
                    SizeBytes = $_.Length
                }
            }
    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion


#region Plugin / extension-point detection -----------------------------------

# Subdirectory names that strongly suggest "this app loads runtime extensions
# from here". When the package's plugin manager probes write-access at startup
# (or downloads new plugins into the path) those operations fail or vanish
# under default MSIX containerisation. The autofix below turns each detected
# directory into a per-user-writable carve-out.
$script:MsixPluginDirectoryNames = @(
    'plugins','plugin','Plugins',
    'extensions','extension','Extensions',
    'add-ins','addins','Addins','add-in',
    'addons','Addons','add-ons',
    'themes','Themes','skins','Skins',
    'templates','Templates',
    'presets','Presets',
    'macros','Macros',
    'dictionaries','Dictionaries','spellcheck',
    'localization','localizations','lang','Languages','locale','locales',
    'userDefineLangs','userdefinedlangs'
)

function Get-MsixPluginExtensionPoint {
    <#
    .SYNOPSIS
        Lists directories inside the package that look like runtime
        extension points (plugins, themes, add-ins, language packs).

    .DESCRIPTION
        MSIX containerisation virtualises writes to the install directory.
        Apps with a plugin/theme manager typically:

          - probe write-access on the plugin folder at startup (and fail
            before any virtualised write happens),
          - download new plugins into %ProgramFiles%\<app>\plugins\ which
            virtualises to a per-user shadow path the unmodified plugin
            enumerator never looks at.

        This scanner finds those directories from three independent signals
        so we never recommend a fix for an unrelated folder that just happens
        to be called 'Plugins':

          1. Directory NAME matches a curated list of conventions
             ($script:MsixPluginDirectoryNames).
          2. The directory CONTAINS at least one of these signals:
             - a plugin-manifest file (plugin.xml, manifest.json,
               pluginlist.cfg)
             - subfolders with .exe + .dll pairs (typical plugin layout)
             - more than -MinFiles entries (default 1) so empty stub
               folders shipped by the installer are ignored.
          3. The directory is under the main Application's executable
             folder (heuristic: we resolve the Application's Executable
             attribute and only flag folders that live alongside it).

        Detection-only — pair with the Invoke-MsixAutoFixFromAnalysis
        PluginDirectory stage (or call Set-MsixFileSystemWriteVirtualization
        directly) to apply the fix.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .PARAMETER MinFiles
        Minimum number of entries a directory must contain to be flagged.
        Default 1 (empty stub folders are skipped).

    .EXAMPLE
        Get-MsixPluginExtensionPoint -PackagePath app.msix |
            Format-Table Name, RelativePath, MatchSignal

    .OUTPUTS
        [pscustomobject[]] each with Name, RelativePath, MatchSignal,
        FileCount, HasManifest.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [int]$MinFiles = 1
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-plugins"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        # Anchor the scan under the first Application's exe directory if we
        # can resolve it. Without that anchor we'd also flag e.g.
        # VFS\Windows\System32\<random>\Plugins (false positive).
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"
        $apps = @($manifest.Package.Applications.Application)
        $appRoots = [System.Collections.Generic.List[string]]::new()
        foreach ($app in $apps) {
            $exe = $app.GetAttribute('Executable')
            if (-not $exe -or -not $exe.Contains('\')) { continue }
            $rel = $exe.Substring(0, $exe.LastIndexOf('\'))
            $abs = Join-Path -Path $workspace -ChildPath $rel
            if (Test-Path -LiteralPath $abs) {
                $appRoots.Add($abs) | Out-Null
            }
        }
        if ($appRoots.Count -eq 0) {
            # Fall back to the unpack root.
            $appRoots.Add($workspace) | Out-Null
        }

        # Manifest files that indicate a managed plugin discovery system.
        $pluginManifestNames = @('plugin.xml','manifest.json','pluginlist.cfg','plugin.json','plugins.cfg','plugins.xml')

        $seen = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($root in $appRoots) {
            Get-ChildItem -LiteralPath $root -Directory -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $script:MsixPluginDirectoryNames -contains $_.Name } |
                ForEach-Object {
                    $dir = $_.FullName
                    if (-not $seen.Add($dir)) { return }

                    $entries = @(Get-ChildItem -LiteralPath $dir -Force -ErrorAction SilentlyContinue)
                    if ($entries.Count -lt $MinFiles) { return }

                    $manifestHits = @($entries | Where-Object { $pluginManifestNames -contains $_.Name })
                    $hasExeDll    = ($entries.Where({ $_.Extension -in '.exe','.dll' }, 'First', 1)).Count -gt 0

                    # Compose the explanatory signal so the finding line
                    # shows operators why we flagged this directory.
                    $signals = @()
                    $signals += "name '$($_.Name)' matches plugin/theme convention"
                    if ($manifestHits) { $signals += "contains plugin manifest ($($manifestHits.Name -join ', '))" }
                    if ($hasExeDll)    { $signals += 'contains .exe/.dll' }

                    [pscustomobject]@{
                        Name         = $_.Name
                        RelativePath = $dir.Substring($workspace.Length + 1)
                        FileCount    = $entries.Count
                        HasManifest  = [bool]$manifestHits
                        MatchSignal  = $signals -join '; '
                    }
                }
        }
    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion


# Backward-compatible plural aliases
Set-Alias Get-MsixFontCandidates Get-MsixFontCandidate
Set-Alias Get-MsixDesktopShortcutCandidates Get-MsixDesktopShortcutCandidate
Set-Alias Remove-MsixDesktopShortcuts Remove-MsixDesktopShortcut
Set-Alias Get-MsixCapabilityHints Get-MsixCapabilityHint
Set-Alias Get-MsixNestedPackageCandidates Get-MsixNestedPackageCandidate
Set-Alias Get-MsixPluginExtensionPoints Get-MsixPluginExtensionPoint
