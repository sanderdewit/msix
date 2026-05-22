# =============================================================================
# Auto-fix heuristics (TMEditX-style)
# -----------------------------------------------------------------------------
# Each helper here is a small, focused fixer:
#   - "Get-MsixXxxRecommendation" returns a finding object describing whether
#     the package matches the heuristic.
#   - "Add-MsixXxx" / "Remove-MsixXxx" mutate the package idempotently and
#     re-pack it (re-signing unless -SkipSigning).
#
# All of these are opt-in. None are applied by Invoke-MsixPipeline by default.
# Use Invoke-MsixAutoFix to chain a curated set similar to TMEditX's
# AutoFixStage workflow.
# =============================================================================

#region Capabilities --------------------------------------------------------

# Common rescap / standard capabilities admins frequently add to packaged apps
$script:KnownCapabilities = [ordered]@{
    # rescap — <rescap:Capability>
    'runFullTrust'                   = 'rescap'
    'allowElevation'                 = 'rescap'
    'unvirtualizedResources'         = 'rescap'
    'broadFileSystemAccess'          = 'rescap'
    'extendedExecutionUnconstrained' = 'rescap'
    # standard — plain <Capability> (schema enum: only these 5)
    'internetClient'                 = 'standard'
    'internetClientServer'           = 'standard'
    'privateNetworkClientServer'     = 'standard'
    'codeGeneration'                 = 'standard'
    'allJoyn'                        = 'standard'
    # uap — <uap:Capability>
    'documentsLibrary'               = 'uap'
    'picturesLibrary'                = 'uap'
    'videosLibrary'                  = 'uap'
    'musicLibrary'                   = 'uap'
    'removableStorage'               = 'uap'
    'enterpriseAuthentication'       = 'uap'
    'sharedUserCertificates'         = 'uap'
    'userAccountInformation'         = 'uap'
    'objects3D'                      = 'uap'
    'voipCall'                       = 'uap'
    'chat'                           = 'uap'
    'remoteSystem'                   = 'uap'
}

function Get-MsixKnownCapability {
    <#
    .SYNOPSIS
        Returns the capability table this module knows about, with the
        namespace prefix each one belongs in.

    .DESCRIPTION
        Read-only enumeration of the capabilities Add-MsixCapability can
        resolve to a namespace without an explicit -Namespace override.
        Pipe to Where-Object Namespace -eq 'rescap' to filter by class.

    .EXAMPLE
        # Show all rescap capabilities the module recognises
        Get-MsixKnownCapability | Where-Object Namespace -eq 'rescap'

    .OUTPUTS
        [pscustomobject] one per known capability: Name, Namespace.
    #>
    foreach ($k in $script:KnownCapabilities.Keys) {
        [pscustomobject]@{
            Name      = $k
            Namespace = $script:KnownCapabilities[$k]
        }
    }
}

function Add-MsixCapability {
    <#
    .SYNOPSIS
        Adds one or more capabilities (standard or rescap) to a package's
        AppxManifest.xml. Idempotent. Repacks + signs unless -SkipSigning.

    .DESCRIPTION
        For each name in -Names, the namespace is resolved against the
        module's known-capabilities table (Get-MsixKnownCapability) and the
        appropriate `<Capability>` / `<uap:Capability>` / `<rescap:Capability>`
        element is added under `<Package><Capabilities>`. Adds the namespace
        declaration when needed.

        Idempotency: existing entries with the same Name attribute are skipped
        regardless of prefix, so chained autofix stages don't duplicate them.

        Unknown capability names emit a warning and are written as plain
        `<Capability>` (standard namespace). To declare capabilities the
        lookup table doesn't recognise yet, supply -Namespace explicitly so
        the correct prefix is used.

    .PARAMETER PackagePath
        .msix to modify.

    .PARAMETER Names
        Capability names. Looked up against the registry — anything unknown
        gets a warning and is treated as standard unless -Namespace is set.

    .PARAMETER Namespace
        Optional namespace override applied to every name in -Names. Use this
        to declare capabilities the module's known-capabilities table doesn't
        recognise yet (without editing MSIX.Heuristics.ps1#KnownCapabilities).
        One of: 'standard', 'uap', 'uap2', 'uap3', 'uap4', 'uap5', 'uap6',
        'uap7', 'uap8', 'uap10', 'rescap'.

    .PARAMETER OutputPath
        If set, write the repacked package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        # Add runFullTrust and internetClient (idempotent — safe to re-run)
        Add-MsixCapability -PackagePath app.msix `
            -Names runFullTrust,internetClient -SkipSigning

    .EXAMPLE
        # Declare a capability the lookup table doesn't know yet
        Add-MsixCapability -PackagePath app.msix `
            -Names 'previewStore' -Namespace uap8 -SkipSigning

    .EXAMPLE
        # Typical Invoke-MsixAutoFix integration: chained via -Capabilities
        Invoke-MsixAutoFix -PackagePath app.msix `
            -Capabilities runFullTrust,internetClient `
            -Pfx cert.pfx -PfxPassword $pw
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [string[]]$Names,
        [ValidateSet('standard','uap','uap2','uap3','uap4','uap5','uap6','uap7','uap8','uap10','rescap')]
        [string]$Namespace,
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

        $null = Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"

        $caps = $manifest.Package.Capabilities
        if (-not $caps) {
            $caps = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
            $null = $manifest.Package.AppendChild($caps)
        }

        $changed = $false

        foreach ($name in $Names) {
            # Explicit -Namespace overrides the lookup table; otherwise use it.
            $ns = if ($Namespace) { $Namespace } else { $script:KnownCapabilities[$name] }
            # Idempotency: match by LocalName + Name attribute regardless of prefix
            $existing = $caps.ChildNodes | Where-Object {
                ($_.LocalName -eq 'Capability') -and ($_.'Name' -eq $name)
            }
            if ($existing) {
                Write-MsixLog Info "Capability already present: $name"
                continue
            }
            if ($ns -and $ns -ne 'standard') {
                Add-MsixManifestNamespace $manifest $ns
                $nsUri = Get-MsixManifestNamespaceUri $ns
                $node  = $manifest.CreateElement("${ns}:Capability", $nsUri)
            } else {
                # 'standard' or unknown — plain <Capability>; warn if not in the known-good list
                if (-not $ns) {
                    Write-MsixLog Warning "Capability '$name' is not in the known-capabilities table (MSIX.Heuristics.ps1#KnownCapabilities). Creating a plain <Capability> element (standard namespace). If this is a uap/rescap capability, the install may fail at deployment time — verify against https://learn.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations and either add it to the lookup table or pass -Namespace explicitly."
                }
                $node = $manifest.CreateElement('Capability', $manifest.Package.NamespaceURI)
            }
            $node.SetAttribute('Name', $name)
            $null = $caps.AppendChild($node)
            Write-MsixLog Info "Capability added: $name"
            $changed = $true
        }

        if (-not $changed) { return }

        if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save manifest')) {
            Save-MsixManifest $manifest "$workspace\AppxManifest.xml"
        }

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }

    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Uninstaller / desktop shortcut detection ---------------------------

function Get-MsixUninstallerCandidate {
    <#
    .SYNOPSIS
        Lists files inside the package that look like leftover installer or
        uninstaller artefacts. These commonly break MSIX install/uninstall flows
        and should usually be removed before publishing.

    .DESCRIPTION
        Pattern matches against well-known uninstaller filenames
        (uninst*.exe, unins*.exe, setup.exe, install.exe, autorun.inf,
        InstallShield/MSI scratch files).

        Detection-only — pair with Remove-MsixUninstallerArtifact to strip
        the matched files and the matching Uninstall\* registry leftovers.
        Feeds the `UninstallerArtifact` finding in Get-MsixHeuristicFinding.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # List uninstaller leftovers, then remove them in a follow-up call
        Get-MsixUninstallerCandidate -PackagePath app.msix
        Remove-MsixUninstallerArtifact -PackagePath app.msix -SkipSigning

    .OUTPUTS
        [pscustomobject] one per match: Name, Path (package-relative), SizeBytes.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $patterns = @(
        '^uninst.*\.exe$', '^unins.*\.exe$',
        '^setup\.exe$', '^install\.exe$',
        '^_isres.*$', '^autorun\.inf$',
        '^Setup\.msi$', '^uninstall\.exe$',
        '^uninstaller.*\.exe$'
    )
    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-unin"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $name = $_.Name
                ($patterns | Where-Object { $name -match $_ }).Count -gt 0
            } |
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


function Get-MsixUninstallRegistryEntry {
    <#
    .SYNOPSIS
        Reads the package's virtualized HKLM hive (Registry.dat) and returns
        the Uninstall\* subkeys baked in by the original installer. These are
        leftover and don't function inside an MSIX container.

    .DESCRIPTION
        Parses Registry.dat in-memory via offreg.dll (Offline Registry API).
        Walks SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall and the
        WOW6432Node equivalent, captures DisplayName / DisplayVersion /
        Publisher / UninstallString for each entry.

        Works WITHOUT elevation. The original implementation used reg.exe load
        which requires SeBackupPrivilege + SeRestorePrivilege regardless of
        mount point (HKLM, HKU, HKCU). offreg.dll parses the hive from disk
        without mounting it into the live registry, so no privileges are needed.

    .PARAMETER PackagePath
        .msix file (read-only).

    .EXAMPLE
        # Surface leftover uninstall registry entries (no elevation required)
        Get-MsixUninstallRegistryEntry -PackagePath app.msix |
            Select-Object DisplayName, Publisher, UninstallString

    .OUTPUTS
        [pscustomobject[]] each with KeyName, DisplayName, DisplayVersion,
        Publisher, UninstallString, FullPath. Returns an empty array when
        Registry.dat has no Uninstall\* subkeys.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-uninreg"

    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not (Test-Path $datPath)) {
            Write-MsixLog Info 'No Registry.dat in package.'
            return @()
        }

        $hive = _MsixOpenOfflineHive -Path $datPath
        try {
            $entries = [System.Collections.Generic.List[object]]::new()
            foreach ($branch in @(
                'REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )) {
                $branchKey = _MsixOfflineOpenKey -Parent $hive -SubKey $branch
                if ($branchKey -eq [IntPtr]::Zero) { continue }
                try {
                    foreach ($child in (_MsixOfflineEnumSubKeys -Key $branchKey)) {
                        $entries.Add([pscustomobject]@{
                            KeyName         = $child
                            DisplayName     = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$child" -Name 'DisplayName'
                            DisplayVersion  = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$child" -Name 'DisplayVersion'
                            Publisher       = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$child" -Name 'Publisher'
                            UninstallString = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$child" -Name 'UninstallString'
                            FullPath        = "HKLM:\$($branch -replace 'REGISTRY\\MACHINE\\', '')\$child"
                        })
                    }
                } finally {
                    _MsixOfflineCloseKey -Key $branchKey
                }
            }
            return $entries.ToArray()
        } finally {
            _MsixCloseOfflineHive -Hive $hive
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


function Remove-MsixUninstallerArtifact {
    <#
    .SYNOPSIS
        Strips uninstaller-looking files from inside the package AND removes
        their Uninstall\<key> registry entries from Registry.dat (the package's
        virtualized HKLM hive). Repacks + re-signs unless -SkipSigning / -NoSign.

    .DESCRIPTION
        Mutator counterpart to Get-MsixUninstallerCandidate /
        Get-MsixUninstallRegistryEntry. Two-step cleanup:

          1. Remove files inside the package matching -PathPatterns.
          2. Load Registry.dat (when elevated and -KeepRegistry not set) and
             delete Uninstall\<key> subkeys whose DisplayName matches
             -UninstallKeyFilter.

        Repacks and re-signs at the end. Idempotent — a second run on a clean
        package logs "No uninstaller artefacts found." and returns without
        repacking.

        Used by both Invoke-MsixAutoFix (via -RemoveUninstallers) and
        Invoke-MsixAutoFixFromAnalysis (RemoveUninstallers stage).

    .PARAMETER PackagePath
        .msix file to mutate.

    .PARAMETER PathPatterns
        Filename regex patterns. Defaults to a sensible uninstaller list.

    .PARAMETER UninstallKeyFilter
        Regex matched against `DisplayName` of each Uninstall subkey to decide
        whether to delete it. Default `.*` (every entry — they're all leftover
        from the original installer; MSIX doesn't use them).

    .PARAMETER KeepRegistry
        Skip the Registry.dat cleanup; only strip the .exe files.

    .PARAMETER OutputPath
        Write the repacked package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Don't sign the repacked .msix. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        # Full cleanup: strip files + registry, then sign (idempotent)
        Remove-MsixUninstallerArtifact -PackagePath app.msix `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Strip files only, no registry edit, no signing (test/dev)
        Remove-MsixUninstallerArtifact -PackagePath app.msix `
            -KeepRegistry -SkipSigning

    .OUTPUTS
        [pscustomobject] with FilesRemoved (string[]), KeysRemoved (string[]),
        and Output (final package path). Returns nothing when nothing matched.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [string[]]$PathPatterns,
        [string]$UninstallKeyFilter = '.*',
        [switch]$KeepRegistry,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )
    if (-not $PathPatterns) {
        $PathPatterns = @(
            '^uninst.*\.exe$','^unins.*\.exe$','^setup\.exe$','^install\.exe$',
            '^_isres.*$','^autorun\.inf$','^uninstall\.exe$','^uninstaller.*\.exe$'
        )
    }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        # ── Strip files ────────────────────────────────────────────────────
        $removedFiles = @()
        Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $name = $_.Name
                ($PathPatterns | Where-Object { $name -match $_ }).Count -gt 0
            } |
            ForEach-Object {
                if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove uninstaller artefact')) {
                    Remove-Item $_.FullName -Force
                    $removedFiles += $_.FullName.Substring($workspace.Length + 1)
                }
            }

        # ── Strip Registry.dat Uninstall\* entries ────────────────────────
        $removedKeys = @()
        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not $KeepRegistry -and (Test-Path $datPath)) {
            # Parse + mutate the hive via offreg.dll (no elevation required).
            # ORSaveHive cannot overwrite, so we save to a sibling path and replace.
            $newDat = "$datPath.new"
            if (Test-Path -LiteralPath $newDat) { Remove-Item -LiteralPath $newDat -Force }

            $hive = _MsixOpenOfflineHive -Path $datPath
            $modified = $false
            try {
                foreach ($branch in @(
                    'REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                    'REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
                )) {
                    $branchKey = _MsixOfflineOpenKey -Parent $hive -SubKey $branch
                    if ($branchKey -eq [IntPtr]::Zero) { continue }
                    try {
                        $children = _MsixOfflineEnumSubKeys -Key $branchKey
                    } finally {
                        _MsixOfflineCloseKey -Key $branchKey
                    }
                    foreach ($child in $children) {
                        $name = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$child" -Name 'DisplayName'
                        if (-not $name -or ($name -match $UninstallKeyFilter)) {
                            $logical = "$branch\$child"
                            if ($PSCmdlet.ShouldProcess($logical, "Remove Uninstall key '$name'")) {
                                # Uninstall\<app> often has Component subkeys
                                # (per-feature MSI references etc.). ORDeleteKey
                                # is NOT recursive — calling it on a key that
                                # still has children silently fails. Use the
                                # bottom-up recursive helper so the WHOLE
                                # subtree goes away in one call.
                                if (_MsixOfflineDeleteKeyRecursive -Parent $hive -SubKey $logical) {
                                    $removedKeys += if ($name) { $name } else { $child }
                                    $modified = $true
                                } else {
                                    Write-MsixLog Warning "Recursive ORDeleteKey failed for '$logical' — the hive is now in a partial state and will be discarded; the package is unchanged."
                                    # Bail out so we never persist a half-deleted hive.
                                    $modified = $false
                                    break
                                }
                            }
                        }
                    }
                }
                if ($modified) {
                    if (-not (_MsixOfflineSaveHive -Hive $hive -Path $newDat)) {
                        Write-MsixLog Warning 'ORSaveHive failed; Registry.dat is unchanged.'
                        $modified = $false
                    }
                }
            } finally {
                _MsixCloseOfflineHive -Hive $hive
            }
            if ($modified) {
                Move-Item -LiteralPath $newDat -Destination $datPath -Force
            } elseif (Test-Path -LiteralPath $newDat) {
                Remove-Item -LiteralPath $newDat -Force -ErrorAction SilentlyContinue
            }
        }

        if (-not $removedFiles -and -not $removedKeys) {
            Write-MsixLog Info 'No uninstaller artefacts found.'
            return
        }
        if ($removedFiles) { Write-MsixLog Info "Files removed:    $($removedFiles -join ', ')" }
        if ($removedKeys)  { Write-MsixLog Info "Reg keys removed: $($removedKeys -join ', ')" }

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }
        return [pscustomobject]@{
            FilesRemoved = $removedFiles
            KeysRemoved  = $removedKeys
            Output       = $target
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Remove-MsixShellRegistryArtifact {
    <#
    .SYNOPSIS
        Strips legacy shellex/shell context-menu entries from the package's
        Registry.dat so they don't double-register alongside the modern
        desktop4/desktop5 manifest declaration that Add-MsixLegacyContextMenu
        emits.

    .DESCRIPTION
        After Add-MsixLegacyContextMenu adds the manifest-declared verb
        (desktop4:Extension/desktop5:Verb), the package's Registry.dat may
        still contain the original installer's classic shell extension
        registration:

          HKCR\<target>\shellex\ContextMenuHandlers\<HandlerName>
              (default) = "{<clsid>}"
          HKCR\<target>\shell\<verb>
              ExplorerCommandHandler = "{<clsid>}"

        Both forms cause the OS to register the handler AGAIN — the symptom
        is two identical entries in File Explorer's right-click menu. This
        cmdlet walks Registry.dat (via offreg.dll, no elevation needed) and
        removes ONLY the entries that point at CLSIDs we have just declared
        in the manifest. The CLSID class itself (HKCR\CLSID\{...}) is left
        intact — the manifest's com:Extension is the new source of truth.

        The -Entries shape matches what Get-MsixShellContextMenuEntry emits,
        so the autofix orchestrator can hand the exact same set straight
        through after Add-MsixLegacyContextMenu.

    .PARAMETER PackagePath
        .msix to mutate.

    .PARAMETER Entries
        Array of pscustomobjects with at least Target, HandlerName/VerbName,
        and Clsid properties. Typically the auto-fixable subset of
        Get-MsixShellContextMenuEntry.

    .PARAMETER OutputPath
        If set, write the repacked package here.

    .PARAMETER SkipSigning
        Skip signing. Alias: -NoSign.

    .PARAMETER Pfx / PfxPassword / UnsignedOutputPath
        Forwarded to the shared sign/move path.

    .EXAMPLE
        $shell = Get-MsixShellContextMenuEntry -PackagePath app.msix
        Remove-MsixShellRegistryArtifact -PackagePath app.msix -Entries $shell -SkipSigning

    .OUTPUTS
        [pscustomobject] with KeysRemoved (string[]) and Output (final path).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [object[]]$Entries,
        [string]$OutputPath,
        [Alias('NoSign')] [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    if (-not $Entries -or $Entries.Count -eq 0) {
        Write-MsixLog Info 'No shell registry entries supplied; nothing to do.'
        return
    }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath -ErrorAction Stop
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-shellreg"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not (Test-Path $datPath)) {
            Write-MsixLog Info 'No Registry.dat in package — nothing to clean.'
            return
        }

        # Targets to walk under Classes — the same set Get-MsixShellContextMenuEntry uses.
        $targets = @('*', 'Directory', 'Directory\Background', 'AllFilesystemObjects')

        # Build a CLSID set for fast membership testing (lower-cased, both bare
        # and braced forms accepted in inputs).
        $clsidSet = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($e in $Entries) {
            if ($e.Clsid) {
                $bare = $e.Clsid.ToString().Trim().Trim('{', '}').ToLowerInvariant()
                $null = $clsidSet.Add($bare)
            }
        }
        if ($clsidSet.Count -eq 0) {
            Write-MsixLog Warning 'None of the supplied entries had a Clsid; nothing to clean (resolve CLSIDs via Get-MsixShellContextMenuEntry).'
            return
        }

        $newDat = "$datPath.new"
        if (Test-Path -LiteralPath $newDat) { Remove-Item -LiteralPath $newDat -Force }

        $removedKeys = @()
        $hive = _MsixOpenOfflineHive -Path $datPath
        $modified = $false
        try {
            foreach ($prefix in @(
                'REGISTRY\MACHINE\SOFTWARE\Classes',
                'REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Classes'
            )) {
                foreach ($target in $targets) {
                    # ── shellex\ContextMenuHandlers\<name> — delete iff (default) value matches our CLSID
                    $shexBase = "$prefix\$target\shellex\ContextMenuHandlers"
                    $shexKey  = _MsixOfflineOpenKey -Parent $hive -SubKey $shexBase
                    if ($shexKey -ne [IntPtr]::Zero) {
                        try {
                            $handlers = _MsixOfflineEnumSubKeys -Key $shexKey
                        } finally {
                            _MsixOfflineCloseKey -Key $shexKey
                        }
                        foreach ($handler in $handlers) {
                            $logical = "$shexBase\$handler"
                            $value   = _MsixOfflineGetValue -Parent $hive -SubKey $logical -Name ''
                            if (-not $value) { continue }
                            $bare = $value.ToString().Trim().Trim('{', '}').ToLowerInvariant()
                            if ($clsidSet.Contains($bare)) {
                                if ($PSCmdlet.ShouldProcess($logical, 'Remove legacy shellex handler')) {
                                    if (_MsixOfflineDeleteKeyRecursive -Parent $hive -SubKey $logical) {
                                        $removedKeys += $logical
                                        $modified = $true
                                    } else {
                                        Write-MsixLog Warning "Recursive ORDeleteKey failed for '$logical' — discarding partial changes."
                                        $modified = $false
                                        break
                                    }
                                }
                            }
                        }
                    }
                    if ($modified -eq $false -and $removedKeys.Count -gt 0) { break }

                    # ── shell\<verb> — delete iff ExplorerCommandHandler matches our CLSID
                    $shellBase = "$prefix\$target\shell"
                    $shellKey  = _MsixOfflineOpenKey -Parent $hive -SubKey $shellBase
                    if ($shellKey -ne [IntPtr]::Zero) {
                        try {
                            $verbs = _MsixOfflineEnumSubKeys -Key $shellKey
                        } finally {
                            _MsixOfflineCloseKey -Key $shellKey
                        }
                        foreach ($verb in $verbs) {
                            $logical = "$shellBase\$verb"
                            $ech     = _MsixOfflineGetValue -Parent $hive -SubKey $logical -Name 'ExplorerCommandHandler'
                            if (-not $ech) { continue }
                            $bare = $ech.ToString().Trim().Trim('{', '}').ToLowerInvariant()
                            if ($clsidSet.Contains($bare)) {
                                if ($PSCmdlet.ShouldProcess($logical, 'Remove legacy shell verb')) {
                                    if (_MsixOfflineDeleteKeyRecursive -Parent $hive -SubKey $logical) {
                                        $removedKeys += $logical
                                        $modified = $true
                                    } else {
                                        Write-MsixLog Warning "Recursive ORDeleteKey failed for '$logical' — discarding partial changes."
                                        $modified = $false
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if ($modified) {
                if (-not (_MsixOfflineSaveHive -Hive $hive -Path $newDat)) {
                    Write-MsixLog Warning 'ORSaveHive failed; Registry.dat is unchanged.'
                    $modified = $false
                }
            }
        } finally {
            _MsixCloseOfflineHive -Hive $hive
        }
        if ($modified) {
            Move-Item -LiteralPath $newDat -Destination $datPath -Force
        } elseif (Test-Path -LiteralPath $newDat) {
            Remove-Item -LiteralPath $newDat -Force -ErrorAction SilentlyContinue
        }

        if (-not $removedKeys -or $removedKeys.Count -eq 0) {
            Write-MsixLog Info 'No matching legacy shell registry entries found.'
            return
        }
        Write-MsixLog Info "Legacy shell registry entries removed: $($removedKeys.Count)"
        $removedKeys | ForEach-Object { Write-MsixLog Info "  $_" }

        # Repack — share the atomic pack/sign/move path used by the manifest mutators.
        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $scratch = Join-Path $env:TEMP ("msix-shellreg-{0}{1}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)), ([System.IO.Path]::GetExtension($target)))
        $packOk = $false
        try {
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $scratch, '/d', $workspace, '/o')
            Assert-MsixProcessSuccess $r 'MakeAppx pack'
            $packOk = $true
            if (-not $SkipSigning) {
                Invoke-MsixSigning -PackagePath $scratch -Pfx $Pfx -PfxPassword $PfxPassword
            }
            Move-Item -LiteralPath $scratch -Destination $target -Force
            return [pscustomobject]@{
                KeysRemoved = $removedKeys
                Output      = $target
            }
        } catch {
            if ($packOk -and $UnsignedOutputPath) {
                Copy-Item -LiteralPath $scratch -Destination $UnsignedOutputPath -Force -ErrorAction SilentlyContinue
                Write-MsixLog Warning "Signing failed. Unsigned package preserved at: $UnsignedOutputPath"
            }
            throw
        } finally {
            if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue }
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Run-keys (HKLM\Run autostart) ---------------------------------------

function Get-MsixRunKeyEntry {
    <#
    .SYNOPSIS
        Lists the HKLM/HKCU \…\Run\* entries declared by the package — usually
        baked in by the original installer. These don't fire under MSIX and
        admins typically remove them or replace with a startScript.

    .DESCRIPTION
        Inspects User.dat and Registry.dat hives shipped in VFS\… for
        Software\Microsoft\Windows\CurrentVersion\Run\* values via a Unicode
        string scan (best effort — works without elevation). Feeds the
        `RunKey` finding in Get-MsixHeuristicFinding, which in turn drives the
        `ManifestFix:StartupTask` recommendation when the package has no
        windows.startupTask extension declared.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # Find Run-key autostart leftovers
        Get-MsixRunKeyEntry -PackagePath app.msix

    .OUTPUTS
        [pscustomobject[]] each with Hive ('Registry.dat' or 'User.dat') and
        Match (the matched Run-key path).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-runkeys"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        # MSIX packages ship Registry.dat + User.dat for the virtual hive.
        $hits = @()
        foreach ($dat in @('Registry.dat','User.dat')) {
            $datPath = Join-Path $workspace $dat
            if (-not (Test-Path $datPath)) { continue }
            # Best-effort string scan — full hive parsing requires reg.exe load.
            try {
                $bytes = [IO.File]::ReadAllBytes($datPath)
                $text  = [System.Text.Encoding]::Unicode.GetString($bytes)
                $m = [regex]::Matches($text, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run[\w\\]*', 'IgnoreCase')
                foreach ($mm in $m) {
                    $hits += [pscustomobject]@{
                        Hive  = $dat
                        Match = $mm.Value
                    }
                }
            } catch { Write-MsixLog Debug "Run-key scan failed for $dat`: $_" }
        }
        return $hits | Sort-Object Hive,Match -Unique
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Shell context-menu entries -------------------------------------------

function _MsixAbsoluteToVfsRelativeDirect {
    <#
    .SYNOPSIS
        Translates an absolute DLL path (from Registry.dat) to a VFS-relative
        path within an already-unpacked MSIX workspace.
        Returns $null if the file cannot be mapped / does not exist in the package.
    #>
    param([string]$AbsPath, [string]$WorkspacePath)
    if (-not $AbsPath) { return $null }
    $mappings = @(
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('ProgramFiles');           Vfs = 'VFS\ProgramFilesX64' }
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('ProgramFilesX86');        Vfs = 'VFS\ProgramFiles(x86)' }
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('System');                 Vfs = 'VFS\SystemX64' }
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('Windows');                Vfs = 'VFS\Windows' }
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('CommonApplicationData');  Vfs = 'VFS\ProgramData' }
    )
    foreach ($m in $mappings) {
        if ($AbsPath.StartsWith($m.Abs, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rel    = $AbsPath.Substring($m.Abs.Length).TrimStart('\')
            $vfsRel = "$($m.Vfs)\$rel"
            if (Test-Path (Join-Path $WorkspacePath $vfsRel)) { return $vfsRel }
        }
    }
    return $null
}


function _MsixRegPathToVfsRelative {
    <#
    .SYNOPSIS
        Translates an MSIX folder-variable DLL path (e.g. [{ProgramFilesX64}]\app\foo.dll)
        stored in Registry.dat to a VFS-relative path within an already-unpacked workspace.
        Falls through to _MsixAbsoluteToVfsRelativeDirect for plain absolute paths.
        Returns $null if the path cannot be mapped or the file is not present in the package.
    #>
    param([string]$RegPath, [string]$WorkspacePath)
    if (-not $RegPath) { return $null }

    # Folder-variable format: [{VarName}]\rest\of\path
    $varMappings = @(
        [pscustomobject]@{ Var = 'ProgramFilesX64';  Vfs = 'VFS\ProgramFilesX64' }
        [pscustomobject]@{ Var = 'ProgramFilesX86';  Vfs = 'VFS\ProgramFiles(x86)' }
        [pscustomobject]@{ Var = 'ProgramFiles6432'; Vfs = 'VFS\ProgramFilesX64' }
        [pscustomobject]@{ Var = 'System';           Vfs = 'VFS\SystemX64' }
        [pscustomobject]@{ Var = 'SystemX86';        Vfs = 'VFS\System' }
        [pscustomobject]@{ Var = 'Windows';          Vfs = 'VFS\Windows' }
        [pscustomobject]@{ Var = 'CommonAppData';    Vfs = 'VFS\ProgramData' }
        [pscustomobject]@{ Var = 'AppData';          Vfs = 'VFS\AppData\Roaming' }
        [pscustomobject]@{ Var = 'LocalAppData';     Vfs = 'VFS\AppData\Local' }
    )
    foreach ($m in $varMappings) {
        if ($RegPath -match ('^\[\{' + [regex]::Escape($m.Var) + '\}\](.*)$')) {
            $rel    = $Matches[1].TrimStart('\')
            $vfsRel = "$($m.Vfs)\$rel"
            if (Test-Path (Join-Path $WorkspacePath $vfsRel)) { return $vfsRel }
            # Return the mapping even if the file isn't present — caller can use for manifest
            return $vfsRel
        }
    }

    # Plain absolute path fallback
    return _MsixAbsoluteToVfsRelativeDirect -AbsPath $RegPath -WorkspacePath $WorkspacePath
}


function Get-MsixShellContextMenuEntry {
    <#
    .SYNOPSIS
        Scans the package's Registry.dat for shell verbs (Classes\*\shell\…) and
        shellex COM handlers (Classes\*\shellex\ContextMenuHandlers\…) that are
        invisible in File Explorer when outside the MSIX container.

    .DESCRIPTION
        Loads Registry.dat via reg.exe into a temporary HKCU hive (no
        elevation required) and extracts full key paths, CLSIDs, absolute
        DLL paths, and package-relative VFS paths.

        Returned objects have these properties:
          Type         'ShellVerb' or 'ShellExt'
          Target       '*', 'Directory', 'Directory\Background', …
          VerbName     (ShellVerb) the verb label, e.g. 'Open with Notepad++'
          HandlerName  (ShellExt)  handler key name, often same as display name
          Command      (ShellVerb) the command string
          Clsid        (ShellExt)  GUID string e.g. '{AAAA-...}'
          DllPath      (ShellExt)  absolute InProcServer32 path
          VfsDllPath   (ShellExt)  package-relative VFS path if DLL found in pkg

        Uses offreg.dll (Offline Registry API) to parse Registry.dat in memory.
        No elevation required.

        Surfaces `ShellVerb` and `ShellExt` findings via Get-MsixHeuristicFinding;
        ShellExt entries with a resolved Clsid + VfsDllPath are auto-fixable
        through the `AddLegacyContextMenu` stage of Invoke-MsixAutoFixFromAnalysis.

    .PARAMETER PackagePath
        .msix file to inspect.

    .EXAMPLE
        # Surface all shell verbs and shellex handlers (no elevation required)
        Get-MsixShellContextMenuEntry -PackagePath app.msix |
            Format-Table Type, Target, VerbName, HandlerName, Clsid, VfsDllPath

    .OUTPUTS
        [pscustomobject[]] with Type, Target, VerbName/HandlerName, Command,
        Clsid, DllPath, VfsDllPath as documented above.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-shellctx"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not (Test-Path $datPath)) { return @() }

        $results = [System.Collections.Generic.List[object]]::new()
        $clsidGuidRegex = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'

        $hive = _MsixOpenOfflineHive -Path $datPath
        try {
            # Helper: read the InProcServer32 default value from either the
            # 64-bit Classes\CLSID branch or the WOW6432Node fallback.
            function _resolveClsidDll([IntPtr]$h, [string]$clsid) {
                foreach ($prefix in @(
                    'REGISTRY\MACHINE\SOFTWARE\Classes\CLSID',
                    'REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID'
                )) {
                    $v = _MsixOfflineGetValue -Parent $h -SubKey "$prefix\$clsid\InProcServer32" -Name ''
                    if ($v) { return $v }
                }
                return $null
            }

            foreach ($target in @('*', 'Directory', 'Directory\Background', 'AllFilesystemObjects')) {
                $tgtClean = $target

                # ── Shell verbs: Classes\<target>\shell\<verb>
                $shellPath = "REGISTRY\MACHINE\SOFTWARE\Classes\$target\shell"
                $shellKey  = _MsixOfflineOpenKey -Parent $hive -SubKey $shellPath
                if ($shellKey -ne [IntPtr]::Zero) {
                    try {
                        foreach ($verbName in (_MsixOfflineEnumSubKeys -Key $shellKey)) {
                            $verbPath = "$shellPath\$verbName"
                            $ech = _MsixOfflineGetValue -Parent $hive -SubKey $verbPath -Name 'ExplorerCommandHandler'
                            if ($ech) {
                                if ($ech -notmatch '^\{') { $ech = "{$ech}" }
                                $dll = $null; $vfsDll = $null
                                if ($ech -match $clsidGuidRegex) {
                                    $dll = _resolveClsidDll $hive $ech
                                    if ($dll) { $vfsDll = _MsixRegPathToVfsRelative -RegPath $dll -WorkspacePath $workspace }
                                }
                                $results.Add([pscustomobject]@{
                                    Type        = 'ShellExt'
                                    Target      = $tgtClean
                                    HandlerName = $verbName
                                    Command     = $null
                                    Clsid       = $ech
                                    DllPath     = $dll
                                    VfsDllPath  = $vfsDll
                                })
                            } else {
                                $cmd = _MsixOfflineGetValue -Parent $hive -SubKey "$verbPath\command" -Name ''
                                $results.Add([pscustomobject]@{
                                    Type       = 'ShellVerb'
                                    Target     = $tgtClean
                                    VerbName   = $verbName
                                    Command    = $cmd
                                    Clsid      = $null
                                    DllPath    = $null
                                    VfsDllPath = $null
                                })
                            }
                        }
                    } finally {
                        _MsixOfflineCloseKey -Key $shellKey
                    }
                }

                # ── shellex COM handlers: Classes\<target>\shellex\ContextMenuHandlers\<name>
                $shexPath = "REGISTRY\MACHINE\SOFTWARE\Classes\$target\shellex\ContextMenuHandlers"
                $shexKey  = _MsixOfflineOpenKey -Parent $hive -SubKey $shexPath
                if ($shexKey -ne [IntPtr]::Zero) {
                    try {
                        foreach ($handlerName in (_MsixOfflineEnumSubKeys -Key $shexKey)) {
                            $clsid = _MsixOfflineGetValue -Parent $hive -SubKey "$shexPath\$handlerName" -Name ''
                            if ($clsid -and $clsid -notmatch '^\{') { $clsid = "{$clsid}" }
                            $dll = $null; $vfsDll = $null
                            if ($clsid -and $clsid -match $clsidGuidRegex) {
                                $dll = _resolveClsidDll $hive $clsid
                                if ($dll) { $vfsDll = _MsixRegPathToVfsRelative -RegPath $dll -WorkspacePath $workspace }
                            }
                            $results.Add([pscustomobject]@{
                                Type        = 'ShellExt'
                                Target      = $tgtClean
                                HandlerName = $handlerName
                                Command     = $null
                                Clsid       = $clsid
                                DllPath     = $dll
                                VfsDllPath  = $vfsDll
                            })
                        }
                    } finally {
                        _MsixOfflineCloseKey -Key $shexKey
                    }
                }
            }
        } finally {
            _MsixCloseOfflineHive -Hive $hive
        }

        # Deduplicate
        $seen = @{}
        return @($results | Where-Object {
            $key = "$($_.Type)|$($_.Target)|$(if ($_.Type -eq 'ShellVerb') { $_.VerbName } else { $_.HandlerName })"
            if (-not $seen[$key]) { $seen[$key] = $true; $true } else { $false }
        })
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region COM server entries ---------------------------------------------------

function Get-MsixComServerEntry {
    <#
    .SYNOPSIS
        Scans the package's Registry.dat for COM server registrations
        (CLSID\*\InProcServer32 and CLSID\*\LocalServer32) that may need to be
        declared in the manifest via com:Extension (windows.comServer).

    .DESCRIPTION
        When elevated, loads the hive via reg.exe for full extraction: CLSIDs,
        server type, DLL path, VFS-relative path (if the DLL lives in the package),
        and ThreadingModel. Works without elevation: hive is mounted under HKCU.

        Returned objects:
          Clsid          '{XXXXXXXX-...}'
          ServerType     'InProc' | 'LocalServer' | 'Unknown'
          DllPath        absolute InProcServer32 / LocalServer32 path (elevated)
          VfsDllPath     package-relative VFS path if the DLL is in the package
          ThreadingModel e.g. 'Apartment' (InProc, elevated only)

        Surfaces the `ComServer` finding in Get-MsixHeuristicFinding. Entries
        with a resolved VfsDllPath feed the `AddComServer` stage of
        Invoke-MsixAutoFixFromAnalysis, which calls Add-MsixComServerExtension.

    .PARAMETER PackagePath
        .msix file to inspect.

    .EXAMPLE
        # Find COM servers registered in the package's Registry.dat
        Get-MsixComServerEntry -PackagePath app.msix |
            Where-Object ServerType -eq 'InProc'

    .OUTPUTS
        [pscustomobject[]] with Clsid, ServerType, DllPath, VfsDllPath,
        ThreadingModel as documented above.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-comsrv"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not (Test-Path $datPath)) { return @() }

        $results = [System.Collections.Generic.List[object]]::new()
        $clsidGuidRegex = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'

        $hive = _MsixOpenOfflineHive -Path $datPath
        try {
            foreach ($branch in @(
                'REGISTRY\MACHINE\SOFTWARE\Classes\CLSID',
                'REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID'
            )) {
                $branchKey = _MsixOfflineOpenKey -Parent $hive -SubKey $branch
                if ($branchKey -eq [IntPtr]::Zero) { continue }
                try {
                    foreach ($clsid in (_MsixOfflineEnumSubKeys -Key $branchKey)) {
                        if ($clsid -notmatch $clsidGuidRegex) { continue }

                        # InProcServer32 (DLL)
                        $ipBase = "$branch\$clsid\InProcServer32"
                        $dll    = _MsixOfflineGetValue -Parent $hive -SubKey $ipBase -Name ''
                        if ($dll) {
                            $thread = _MsixOfflineGetValue -Parent $hive -SubKey $ipBase -Name 'ThreadingModel'
                            $vfsDll = _MsixAbsoluteToVfsRelativeDirect -AbsPath $dll -WorkspacePath $workspace
                            $results.Add([pscustomobject]@{
                                Clsid          = $clsid
                                ServerType     = 'InProc'
                                DllPath        = $dll
                                VfsDllPath     = $vfsDll
                                ThreadingModel = if ($thread) { $thread } else { 'Apartment' }
                            })
                        }

                        # LocalServer32 (EXE)
                        $lsCmd = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$clsid\LocalServer32" -Name ''
                        if ($lsCmd) {
                            $results.Add([pscustomobject]@{
                                Clsid          = $clsid
                                ServerType     = 'LocalServer'
                                DllPath        = $lsCmd
                                VfsDllPath     = $null
                                ThreadingModel = $null
                            })
                        }
                    }
                } finally {
                    _MsixOfflineCloseKey -Key $branchKey
                }
            }
        } finally {
            _MsixCloseOfflineHive -Hive $hive
        }

        # Deduplicate by CLSID + ServerType
        $seen = @{}
        return @($results | Where-Object {
            $key = "$($_.Clsid)|$($_.ServerType)"
            if (-not $seen[$key]) { $seen[$key] = $true; $true } else { $false }
        })
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Application execution alias auto-suggest ---------------------------

function Get-MsixAliasCandidate {
    <#
    .SYNOPSIS
        Lists package executables that LOOK like good AppExecutionAlias
        candidates — top-level user-facing binaries, not vendored helpers.

    .DESCRIPTION
        Heuristic:
          - .exe under VFS\ProgramFiles* with a manifest entry pointing at it
          - skip msvcr*, vcredist*, setup*, install*, uninst*

        Feeds the `AppExecutionAlias` finding in Get-MsixHeuristicFinding.
        Pass the AppId values to Add-MsixAlias to register the suggestions.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # Surface alias candidates and add the first one with Add-MsixAlias
        $cands = Get-MsixAliasCandidate -PackagePath app.msix |
            Where-Object { -not $_.AlreadyHasAlias }
        Add-MsixAlias -PackagePath app.msix `
            -AppIds $cands.AppId -SkipSigning

    .OUTPUTS
        [pscustomobject[]] each with AppId, Executable, SuggestAlias,
        AlreadyHasAlias.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-alias"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"
        $apps          = @($manifest.Package.Applications.Application)

        $skipPatterns = @(
            '^msvcr','^msvcp','^vcruntime','^ucrtbase',
            '^vcredist','^setup','^install','^uninst',
            '^psf','^msix','^api-ms-win-'
        )

        foreach ($app in $apps) {
            $exe = $app.Executable
            if (-not $exe) { continue }
            $leaf = ($exe.Split('\')[-1]).ToLower()
            $skip = $skipPatterns | Where-Object { $leaf -match $_ }
            if ($skip) { continue }

            $aliasName = ($leaf -replace '\.exe$','') + '.exe'
            $hasAlias  = [bool]($app.Extensions.Extension.AppExecutionAlias.ExecutionAlias)

            [pscustomobject]@{
                AppId        = $app.Id
                Executable   = $exe
                SuggestAlias = $aliasName
                AlreadyHasAlias = $hasAlias
            }
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Splash screen ------------------------------------------------------

function Add-MsixSplashScreen {
    <#
    .SYNOPSIS
        Adds a splash-screen image to the PSF launcher config so users see
        feedback while a slow startScript runs. Requires PSF already to be
        injected (Add-MsixPsfV2 first).

    .DESCRIPTION
        Copies -ImagePath next to the existing config.json (the one created by
        Add-MsixPsfV2) and patches the targeted application's startScript
        section to reference it. Repacks + re-signs unless -SkipSigning.

        Idempotent: re-running with the same -ImagePath / -AppId overwrites
        the splashImage entry to match.

        Integrates with Invoke-MsixAutoFix via -SplashImagePath / -SplashAppId.

    .PARAMETER PackagePath
        .msix to modify (must already use PsfLauncher).

    .PARAMETER ImagePath
        PNG/JPG to display. Copied into the package folder next to config.json.

    .PARAMETER AppId
        Application id whose config.json gets the splash entry.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        # Standalone use after Add-MsixPsfV2 has injected PSF
        Add-MsixSplashScreen -PackagePath app.msix `
            -ImagePath .\splash.png -AppId App `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # As part of an Invoke-MsixAutoFix run (sign-once pattern)
        Invoke-MsixAutoFix -PackagePath app.msix `
            -PsfFixups @(New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log') `
            -SplashImagePath .\splash.png -SplashAppId App `
            -Pfx cert.pfx -PfxPassword $pw
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [string]$ImagePath,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )
    if (-not (Test-Path $ImagePath)) { throw "Splash image not found: $ImagePath" }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        # Find config.json — should be next to PsfLauncher
        $cfgPaths = @(Get-ChildItem $workspace -Recurse -Filter 'config.json' -ErrorAction SilentlyContinue)
        if (-not $cfgPaths) { throw 'config.json not found; run Add-MsixPsfV2 first.' }
        $cfgPath = $cfgPaths[0].FullName
        $cfgDir  = Split-Path $cfgPath -Parent

        # Copy splash next to config.json
        $imageLeaf = (Get-Item $ImagePath).Name
        Copy-Item $ImagePath $cfgDir -Force

        # Patch config.json
        $cfg = Get-Content $cfgPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        foreach ($app in @($cfg.applications)) {
            if ($app.id -ne $AppId) { continue }
            if (-not $app.startScript) {
                $app | Add-Member -NotePropertyName startScript -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            $app.startScript | Add-Member -NotePropertyName splashImage -NotePropertyValue $imageLeaf -Force
        }
        $cfg | ConvertTo-Json -Depth 15 | Set-Content $cfgPath -Encoding utf8

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Version bump --------------------------------------------------------

function Update-MsixPackageVersion {
    <#
    .SYNOPSIS
        Bumps the AppxManifest Identity Version (4-part).

    .PARAMETER Component
        Major | Minor | Build | Revision (default: Build).

    .PARAMETER KeepLastZero
        If $true, leaves the rightmost component at 0 after the bump
        (matches TMEditX's KeepPackageVersionFieldLastAsZero).

    .PARAMETER NewVersion
        Explicit version string overriding -Component. Use this for
        date-based versions etc.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidateSet('Major','Minor','Build','Revision')]
        [string]$Component = 'Build',
        [bool]$KeepLastZero,
        [ValidatePattern(
            '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$',
            ErrorMessage = 'Version must be a 4-part dotted-decimal like 1.2.3.4.'
        )]
        [string]$NewVersion,
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

        $null = Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"
        $current = [version]$manifest.Package.Identity.Version

        if ($NewVersion) {
            $next = [version]$NewVersion
        } else {
            switch ($Component) {
                'Major'    { $next = [version]"$([int]$current.Major + 1).0.0.0" }
                'Minor'    { $next = [version]"$($current.Major).$([int]$current.Minor + 1).0.0" }
                'Build'    { $next = [version]"$($current.Major).$($current.Minor).$([int]$current.Build + 1).0" }
                'Revision' { $next = [version]"$($current.Major).$($current.Minor).$($current.Build).$([int]$current.Revision + 1)" }
            }
            if ($KeepLastZero) {
                # Force the last component to 0 (already done above for Major/Minor/Build)
                if ($Component -eq 'Revision') {
                    $next = [version]"$($current.Major).$($current.Minor).$([int]$current.Build + 1).0"
                }
            }
        }
        $manifest.Package.Identity.Version = $next.ToString(4)
        Write-MsixLog Info "Version: $current -> $next"

        if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save manifest')) {
            Save-MsixManifest $manifest "$workspace\AppxManifest.xml"
        }

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }
        return $next.ToString(4)
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region AutoFix orchestrator -----------------------------------------------

function Invoke-MsixAutoFix {
    <#
    .SYNOPSIS
        Runs a curated set of TMEditX-style auto-fixes against a package in a
        deterministic order, signing only at the very end.

    .DESCRIPTION
        Stages (modelled on TMEditX's AutoFixStage enum):

          PrePsf
            - RemoveUninstallers      strip uninstall*.exe and friends
            - BumpVersion             bump the package version
          Recommended
            - AddCapabilities         add common capabilities
            - AddAliases              register AppExecutionAlias for top-level exes
            - InjectPsf               run Add-MsixPsfV2 with the fixups you supply
            - BundleVcRuntimes        copy missing VC runtime DLLs in
          Optional
            - AddSplashImage          show a splash while a startScript runs

        Every stage writes back into the SAME file (or -OutputPath if set) and
        passes -SkipSigning so we sign once at the end. Use -DryRun to see
        which stages would fire without mutating the package.

    .PARAMETER PackagePath
        .msix to mutate.

    .PARAMETER Capabilities
        Names to add via Add-MsixCapability (rescap or standard, looked up
        against Get-MsixKnownCapability).

    .PARAMETER PsfFixups / PsfAppOptions / PsfWorkingDirectory / PsfAdditionalFiles
        Forwarded to Add-MsixPsfV2.

    .PARAMETER AddAliases
        If set, runs Add-MsixAlias for top-level user-facing executables.
        When -AliasAppIds is supplied, aliases are added only for those apps;
        otherwise Get-MsixAliasCandidate selects candidates automatically and
        skips apps that already have an alias.

    .PARAMETER AliasAppIds
        Optional list of Application IDs to alias. Implies -AddAliases.
        When omitted, Get-MsixAliasCandidate makes the selection.

    .PARAMETER VcRuntimeSourceFolder
        If set, runs Add-MsixVcRuntimeBundle with this source folder.

    .PARAMETER SplashImagePath / SplashAppId
        If set, runs Add-MsixSplashScreen after PSF.

    .PARAMETER VersionBumpComponent
        If set, runs Update-MsixPackageVersion before any other stage.

    .PARAMETER RemoveUninstallers
        If $true, strips uninstaller-looking files first.

    .PARAMETER OutputPath
        If set, all writes go here instead of overwriting -PackagePath.

    .PARAMETER DryRun
        Report which stages would fire, then return — no mutation, no signing.

    .PARAMETER Pfx / PfxPassword
        Signing certificate for the final pass.

    .EXAMPLE
        Invoke-MsixAutoFix -PackagePath app.msix `
            -RemoveUninstallers `
            -Capabilities runFullTrust,internetClient `
            -PsfFixups @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' ) `
            -VersionBumpComponent Build `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the per-stage scriptblocks built up via _Stage.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,

        # PrePsf stage
        [switch]$RemoveUninstallers,
        [switch]$RemoveDesktopShortcuts,
        [ValidateSet('Major','Minor','Build','Revision')]
        [string]$VersionBumpComponent,

        # Recommended stage
        [string[]]$Capabilities,
        [switch]$AddFontExtension,
        [switch]$AddAliases,
        [string[]]$AliasAppIds,
        [hashtable[]]$PsfFixups,
        [hashtable[]]$PsfAppOptions,
        [string]$PsfWorkingDirectory,
        [string[]]$PsfAdditionalFiles,
        [string]$VcRuntimeSourceFolder,

        # Optional stage
        [string]$SplashImagePath,
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'SplashAppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$SplashAppId,

        # Output / signing
        [string]$OutputPath,
        [switch]$DryRun,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    $stages = New-Object System.Collections.Generic.List[object]
    function _Stage([string]$Name, [scriptblock]$Action) {
        $stages.Add([pscustomobject]@{ Name = $Name; Action = $Action })
    }

    # All intermediate stages must write through OutputPath if set so the
    # original is preserved; subsequent stages then read from OutputPath.
    $current = $PackagePath
    if ($OutputPath -and -not $DryRun) {
        Copy-Item $PackagePath $OutputPath -Force
        $current = $OutputPath
    }

    if ($RemoveUninstallers) {
        _Stage 'PrePsf:RemoveUninstallers' {
            Remove-MsixUninstallerArtifact -PackagePath $current -SkipSigning
        }
    }
    if ($RemoveDesktopShortcuts) {
        _Stage 'PrePsf:RemoveDesktopShortcuts' {
            Remove-MsixDesktopShortcut -PackagePath $current -SkipSigning
        }
    }
    if ($VersionBumpComponent) {
        _Stage 'PrePsf:BumpVersion' {
            Update-MsixPackageVersion -PackagePath $current -Component $VersionBumpComponent -SkipSigning
        }
    }
    if ($Capabilities) {
        _Stage 'Recommended:AddCapabilities' {
            Add-MsixCapability -PackagePath $current -Names $Capabilities -SkipSigning
        }
    }
    if ($AddFontExtension) {
        _Stage 'Recommended:AddFontExtension' {
            $fonts = Get-MsixFontCandidate -PackagePath $current
            if ($fonts) {
                Add-MsixFontExtension -PackagePath $current -FontPaths @($fonts | Select-Object -ExpandProperty Path) -SkipSigning
            } else {
                Write-MsixLog Info 'AddFontExtension: no font files found in package.'
            }
        }
    }
    if ($AddAliases -or $AliasAppIds) {
        _Stage 'Recommended:AddAliases' {
            # If explicit AliasAppIds were supplied, honour them; otherwise let
            # Get-MsixAliasCandidate pick the top-level user-facing executables.
            if ($AliasAppIds) {
                Add-MsixAlias -PackagePath $current -AppIds $AliasAppIds -SkipSigning
            } else {
                $candidates = @(Get-MsixAliasCandidate -PackagePath $current |
                    Where-Object { -not $_.AlreadyHasAlias })
                if ($candidates) {
                    Add-MsixAlias -PackagePath $current `
                        -AppIds @($candidates | Select-Object -ExpandProperty AppId) `
                        -SkipSigning
                } else {
                    Write-MsixLog Info 'AddAliases: no eligible alias candidates (all apps already aliased or filtered out).'
                }
            }
        }
    }
    if ($PsfFixups -or $PsfAppOptions) {
        _Stage 'Recommended:InjectPsf' {
            $psfArgs = @{
                PackagePath = $current
                Fixups      = $PsfFixups
                SkipSigning = $true
            }
            if ($PsfAppOptions)         { $psfArgs['AppOptions']        = $PsfAppOptions }
            if ($PsfWorkingDirectory)   { $psfArgs['WorkingDirectory']  = $PsfWorkingDirectory }
            if ($PsfAdditionalFiles)    { $psfArgs['AdditionalFiles']   = $PsfAdditionalFiles }
            Add-MsixPsfV2 @psfArgs
        }
    }
    if ($VcRuntimeSourceFolder) {
        _Stage 'Recommended:BundleVcRuntimes' {
            Add-MsixVcRuntimeBundle -PackagePath $current -SourceFolder $VcRuntimeSourceFolder -SkipSigning
        }
    }
    if ($SplashImagePath -and $SplashAppId) {
        _Stage 'Optional:AddSplashImage' {
            Add-MsixSplashScreen -PackagePath $current -ImagePath $SplashImagePath -AppId $SplashAppId -SkipSigning
        }
    }

    if ($DryRun) {
        Write-MsixLog Info "DryRun: would run $($stages.Count) stages."
        return [pscustomobject]@{
            PackagePath = $PackagePath
            Stages      = $stages.Name
            DryRun      = $true
        }
    }

    if ($PSCmdlet.ShouldProcess($current, "Apply $($stages.Count) auto-fix stages")) {
        foreach ($s in $stages) {
            Write-MsixLog Info "==> $($s.Name)"
            & $s.Action
        }
    }

    # Sign once at the end
    if (-not $stages -or -not $stages.Count) {
        Write-MsixLog Info 'No stages selected; nothing to do.'
        return
    }
    Write-MsixLog Info '==> Sign'
    Invoke-MsixSigning -PackagePath $current -Pfx $Pfx -PfxPassword $PfxPassword

    return [pscustomobject]@{
        PackagePath = $current
        Stages      = $stages.Name
        DryRun      = $false
    }
}


function Invoke-MsixAutoFixFromAnalysis {
    <#
    .SYNOPSIS
        Takes the report produced by Invoke-MsixInvestigation /
        Get-MsixCompatibilityReport and translates each finding into the
        right fixer cmdlet, then runs them sequentially with one signing
        pass at the end. The connect-the-dots layer between analysis and
        remediation.

    .DESCRIPTION
        Maps Findings.Category to a concrete cmdlet:

          UninstallerArtifact                 -> Remove-MsixUninstallerArtifact
          AppExecutionAlias                    -> Add-MsixAlias (only AppIds without an existing alias)
          VcRuntime                            -> Add-MsixVcRuntimeBundle (needs -VcRuntimeSourceFolder)
          ManifestFix:FileSystemWriteVirt..    -> Set-MsixFileSystemWriteVirtualization
          ManifestFix:RegistryWriteVirt..      -> Set-MsixRegistryWriteVirtualization
          ManifestFix:StartupTask              -> Add-MsixStartupTask  (needs -StartupTaskAppId / -StartupTaskName)
          ManifestFix:LoaderSearchPathOverride -> Add-MsixLoaderSearchPathOverride (needs -LoaderPaths)
          FileRedirectionFixup                 -> Add-MsixPsfV2 with the SuggestedFixups already in the report

        Categories that always need extra inputs (VcRuntime, StartupTask,
        LoaderSearchPathOverride) are skipped with a warning unless the
        relevant -* parameter is supplied.

        -DryRun lists the planned fixes without doing anything.

    .PARAMETER Report
        Output of Invoke-MsixInvestigation or Get-MsixCompatibilityReport.

    .PARAMETER PackagePath
        Override (default: $Report.PackagePath).

    .PARAMETER PreferManifestOverPsf
        When both a PSF and a manifest fix are suggested for the same symptom,
        pick the manifest one (modern Windows builds only).
        Default: $true.

    .PARAMETER VcRuntimeSourceFolder
        VS Redist folder; required when a VcRuntime finding is in the report.

    .PARAMETER StartupTaskAppId / StartupTaskName
        Required when a ManifestFix:StartupTask finding is in the report.

    .PARAMETER LoaderPaths
        Required when a ManifestFix:LoaderSearchPathOverride finding is in the report.

    .PARAMETER DryRun
        Print the plan and return without mutating.

    .PARAMETER OutputPath / Pfx / PfxPassword / SkipSigning (alias NoSign)
        Forwarded to the underlying fixers. Signing only happens once at the end.

    .EXAMPLE
        $report = Invoke-MsixInvestigation -PackagePath app.msix
        Invoke-MsixAutoFixFromAnalysis -Report $report `
            -VcRuntimeSourceFolder 'C:\…\VC143.CRT' `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Report,
        [string]$PackagePath,
        [bool]$PreferManifestOverPsf = $true,
        [string]$VcRuntimeSourceFolder,
        [string]$StartupTaskAppId,
        [string]$StartupTaskName,
        [string[]]$LoaderPaths,
        [switch]$DryRun,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not $PackagePath) { $PackagePath = $Report.PackagePath }
    if (-not $PackagePath) { throw 'PackagePath could not be inferred from the report.' }

    # Categorise the findings into a stable plan
    $plan = New-Object System.Collections.Generic.List[object]

    $byCat = @{}
    foreach ($f in @($Report.Findings)) {
        if ($f -and $f.Category) { $byCat[$f.Category] = $true }
    }

    # Stage 1 — strip uninstaller artefacts (files + registry)
    if ($byCat.ContainsKey('UninstallerArtifact') -or $byCat.ContainsKey('UninstallRegistry')) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RemoveUninstallers'
            Reason = 'Findings include uninstaller-looking files and/or leftover Uninstall registry keys'
            Action = { Remove-MsixUninstallerArtifact -PackagePath $current -SkipSigning }
        })
    }

    # Stage 2 — manifest-only virtualization (preferred over PSF when matching)
    $hasFsManifestFix  = $byCat.ContainsKey('ManifestFix:FileSystemWriteVirtualization')
    $hasRegManifestFix = $byCat.ContainsKey('ManifestFix:RegistryWriteVirtualization')
    $hasStartupFix     = $byCat.ContainsKey('ManifestFix:StartupTask')
    $hasLoaderFix      = $byCat.ContainsKey('ManifestFix:LoaderSearchPathOverride')

    if ($hasFsManifestFix -and $PreferManifestOverPsf) {
        $plan.Add([pscustomobject]@{
            Stage  = 'FileSystemWriteVirtualization'
            Reason = 'Package writes to install dir; manifest fix is simpler than PSF'
            Action = { Set-MsixFileSystemWriteVirtualization -PackagePath $current -SkipSigning }
        })
    }
    if ($hasRegManifestFix -and $PreferManifestOverPsf) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RegistryWriteVirtualization'
            Reason = 'Package writes to HKLM; manifest fix is simpler than RegLegacy Hklm2Hkcu'
            Action = { Set-MsixRegistryWriteVirtualization -PackagePath $current -SkipSigning }
        })
    }
    if ($hasStartupFix) {
        if ($StartupTaskAppId -and $StartupTaskName) {
            $plan.Add([pscustomobject]@{
                Stage  = 'StartupTask'
                Reason = 'Replace HKLM\Run autostart with windows.startupTask'
                Action = {
                    Add-MsixStartupTask -PackagePath $current `
                        -AppId $StartupTaskAppId -TaskId "$StartupTaskAppId-AutoStart" `
                        -DisplayName $StartupTaskName -Enabled $true -SkipSigning
                }
            })
        } else {
            Write-MsixLog Warning 'Skipping StartupTask: -StartupTaskAppId and -StartupTaskName are required.'
        }
    }
    if ($hasLoaderFix) {
        if ($LoaderPaths) {
            $plan.Add([pscustomobject]@{
                Stage  = 'LoaderSearchPathOverride'
                Reason = 'Replace DLL load failures with manifest declaration'
                Action = { Add-MsixLoaderSearchPathOverride -PackagePath $current -Paths $LoaderPaths -SkipSigning }
            })
        } else {
            Write-MsixLog Warning 'Skipping LoaderSearchPathOverride: -LoaderPaths is required.'
        }
    }

    # Stage 2b — remove desktop shortcuts
    if ($byCat.ContainsKey('DesktopShortcuts')) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RemoveDesktopShortcuts'
            Reason = 'Package ships .lnk files under VFS desktop folders'
            Action = { Remove-MsixDesktopShortcut -PackagePath $current -SkipSigning }
        })
    }

    # Stage 2c — register fonts via uap4:SharedFonts
    if ($byCat.ContainsKey('ManifestFix:SharedFonts')) {
        $plan.Add([pscustomobject]@{
            Stage  = 'AddFontExtension'
            Reason = 'Package ships font files not registered via uap4:SharedFonts'
            Action = {
                $fonts = Get-MsixFontCandidate -PackagePath $current
                if ($fonts) {
                    $fontPaths = @($fonts | Select-Object -ExpandProperty Path)
                    Add-MsixFontExtension -PackagePath $current -FontPaths $fontPaths -SkipSigning
                }
            }
        })
    }

    # Stage 2d — add capability hints
    $capHintFindings = @($Report.Findings | Where-Object Category -eq 'CapabilityHints')
    if ($capHintFindings) {
        $capHintNames = @($capHintFindings.Evidence -split ',\s*' | Where-Object { $_ } | Sort-Object -Unique)
        if ($capHintNames) {
            $plan.Add([pscustomobject]@{
                Stage  = 'AddCapabilityHints'
                Reason = "PE-import hints suggest capabilities: $($capHintNames -join ', ')"
                Action = { Add-MsixCapability -PackagePath $current -Names $capHintNames -SkipSigning }
            })
        }
    }

    # Stage 2e — plain command-based shell verbs (HKCR\*\shell\<verb>\command)
    # These verbs have no CLSID, so desktop9:fileExplorerClassicContextMenuHandler
    # cannot be applied directly. The correct fix is to wrap the command as a COM
    # surrogate server (IContextMenu), register it via Add-MsixLegacyContextMenu, and
    # update the CLSID references in Registry.dat — a manual operation.
    # ExplorerCommandHandler verbs (which DO have a CLSID) are already classified as
    # ShellExt during detection and handled by stage 2g below.
    if ($byCat.ContainsKey('ShellVerb')) {
        $shellVerbFinding = @($Report.Findings | Where-Object Category -eq 'ShellVerb') | Select-Object -First 1
        $verbNames = ($shellVerbFinding.ShellEntries | ForEach-Object { $_.VerbName } | Where-Object { $_ }) -join ', '
        Write-MsixLog Info "ShellVerb: $($shellVerbFinding.ShellEntries.Count) plain command shell verb(s) detected ($verbNames). Cannot be auto-fixed — desktop9:fileExplorerClassicContextMenuHandler requires a COM CLSID. Convert to a COM surrogate server and use Add-MsixLegacyContextMenu."
    }

    # Stage 2g — COM shellex context menu via desktop4 + desktop5 (TMEditX pattern)
    if ($byCat.ContainsKey('ShellExt')) {
        $shellExtFinding = @($Report.Findings | Where-Object Category -eq 'ShellExt') | Select-Object -First 1
        $autoFixable     = @($shellExtFinding.ShellEntries | Where-Object { $_.Clsid -and $_.VfsDllPath })
        if ($autoFixable) {
            $capturedShellEntries = $autoFixable   # capture for closure
            $plan.Add([pscustomobject]@{
                Stage  = 'AddLegacyContextMenu'
                Reason = "Register $($capturedShellEntries.Count) shellex COM handler(s) via desktop4/desktop5"
                Action = {
                    foreach ($entry in $capturedShellEntries) {
                        $ft = @(if ($entry.Target -eq '*') { '*' } else { $entry.Target })
                        Add-MsixLegacyContextMenu -PackagePath $current `
                            -ShellExtDll $entry.VfsDllPath `
                            -Clsid $entry.Clsid `
                            -DisplayName $entry.HandlerName `
                            -FileTypes $ft `
                            -SkipSigning
                    }
                }
            })

            # Stage 2g.b — strip the OLD shellex/shell registry entries from
            # Registry.dat now that the modern manifest declaration handles
            # them. Without this, the package's HKCR\<target>\shellex\... and
            # HKCR\<target>\shell\... entries persist and the OS registers the
            # handler TWICE — surfacing as duplicate items in File Explorer's
            # right-click menu (issue #28).
            $plan.Add([pscustomobject]@{
                Stage  = 'StripLegacyShellRegistry'
                Reason = "Remove old Registry.dat shell/shellex entries for $($capturedShellEntries.Count) handler(s) so they don't double-register alongside the new desktop4 declaration"
                Action = {
                    Remove-MsixShellRegistryArtifact -PackagePath $current `
                        -Entries $capturedShellEntries -SkipSigning
                }
            })
        } else {
            Write-MsixLog Info "ShellExt: CLSID/VFS DLL path not resolved — run elevated for full detection, then call Add-MsixLegacyContextMenu manually."
        }
    }

    # Stage 2h — COM InProcessServer declaration (com:Extension, windows.comServer)
    if ($byCat.ContainsKey('ComServer')) {
        $comFinding = @($Report.Findings | Where-Object Category -eq 'ComServer') | Select-Object -First 1
        # Entries that have a VFS DLL path (package-bundled, auto-fixable)
        # and are not already handled by the ShellExt stage (SurrogateServer)
        $shellExtClsids = @()
        if ($byCat.ContainsKey('ShellExt')) {
            $seF = @($Report.Findings | Where-Object Category -eq 'ShellExt') | Select-Object -First 1
            $shellExtClsids = @($seF.ShellEntries.Clsid | Where-Object { $_ })
        }
        $autoComServers = @($comFinding.ComEntries | Where-Object {
            $_.VfsDllPath -and $_.Clsid -notin $shellExtClsids
        })
        if ($autoComServers) {
            $capturedComServers = $autoComServers
            $plan.Add([pscustomobject]@{
                Stage  = 'AddComServer'
                Reason = "Declare $($capturedComServers.Count) bundled COM InProcessServer(s) in the manifest"
                Action = {
                    $serverSpecs = @($capturedComServers | ForEach-Object {
                        @{ Clsid = $_.Clsid; VfsDllPath = $_.VfsDllPath; ThreadingModel = $_.ThreadingModel }
                    })
                    Add-MsixComServerExtension -PackagePath $current -Servers $serverSpecs -SkipSigning
                }
            })
        } else {
            Write-MsixLog Info "ComServer: no auto-fixable InProc servers (run elevated for DLL path resolution)."
        }
    }

    # Stage 2i — AppExecutionAlias suggestions
    # Get-MsixAliasCandidate emits one AppExecutionAlias finding per top-level
    # user-facing exe that lacks an alias. Auto-fix: register the alias for the
    # AppIds carried on those findings.
    if ($byCat.ContainsKey('AppExecutionAlias')) {
        $aliasFindings = @($Report.Findings | Where-Object Category -eq 'AppExecutionAlias')
        $aliasAppIds   = @($aliasFindings | ForEach-Object { $_.AppId } | Where-Object { $_ } | Sort-Object -Unique)
        if ($aliasAppIds) {
            $capturedAliasIds = $aliasAppIds
            $plan.Add([pscustomobject]@{
                Stage  = 'AddAliases'
                Reason = "Register AppExecutionAlias for $($capturedAliasIds.Count) app(s): $($capturedAliasIds -join ', ')"
                Action = { Add-MsixAlias -PackagePath $current -AppIds $capturedAliasIds -SkipSigning }
            })
        }
    }

    # Stage 3 — VC runtime bundle
    if ($byCat.ContainsKey('VcRuntime')) {
        if ($VcRuntimeSourceFolder) {
            $plan.Add([pscustomobject]@{
                Stage  = 'BundleVcRuntimes'
                Reason = 'Package references VC runtime DLLs that are not bundled'
                Action = { Add-MsixVcRuntimeBundle -PackagePath $current -SourceFolder $VcRuntimeSourceFolder -SkipSigning }
            })
        } else {
            Write-MsixLog Warning 'Skipping VcRuntime bundle: -VcRuntimeSourceFolder is required.'
        }
    }

    # Stage 4 — PSF fixups (only those NOT already covered by a manifest fix)
    if ($Report.SuggestedFixups -and $Report.SuggestedFixups.Count -gt 0) {
        $skipPsfFs  = $hasFsManifestFix  -and $PreferManifestOverPsf
        $skipPsfReg = $hasRegManifestFix -and $PreferManifestOverPsf
        $kept = @($Report.SuggestedFixups | Where-Object {
            -not (
                ($skipPsfFs  -and $_.dll -in 'FileRedirectionFixup.dll','MFRFixup.dll') -or
                ($skipPsfReg -and $_.dll -eq 'RegLegacyFixups.dll')
            )
        })
        if ($kept.Count -gt 0) {
            $plan.Add([pscustomobject]@{
                Stage  = 'InjectPsf'
                Reason = "Apply $($kept.Count) PSF fixup(s) from analysis"
                Action = { Add-MsixPsfV2 -PackagePath $current -Fixups $kept -SkipSigning }
            })
        }
    }

    if (-not $plan -or -not $plan.Count) {
        Write-MsixLog Info 'Nothing actionable in the report. Either no findings or all need manual parameters.'
        return [pscustomobject]@{
            PackagePath = $PackagePath
            Plan        = @()
            DryRun      = [bool]$DryRun
        }
    }

    # Emit the plan
    Write-MsixLog Info '─── AutoFix plan ───'
    foreach ($p in $plan) {
        Write-MsixLog Info "  $($p.Stage)  ($($p.Reason))"
    }

    if ($DryRun) {
        return [pscustomobject]@{
            PackagePath = $PackagePath
            Plan        = $plan
            DryRun      = $true
        }
    }

    # Stage execution — write to OutputPath if asked, otherwise overwrite in-place
    $current = $PackagePath
    if ($OutputPath -and ($OutputPath -ne $PackagePath)) {
        Copy-Item $PackagePath $OutputPath -Force
        $current = $OutputPath
    }

    foreach ($p in $plan) {
        Write-MsixLog Info "==> $($p.Stage)"
        & $p.Action
    }

    if (-not $SkipSigning) {
        Write-MsixLog Info '==> Sign'
        Invoke-MsixSigning -PackagePath $current -Pfx $Pfx -PfxPassword $PfxPassword
    } else {
        Write-MsixLog Info 'NoSign requested; package left unsigned.'
    }

    return [pscustomobject]@{
        PackagePath = $current
        Plan        = $plan
        DryRun      = $false
    }
}
#endregion

#region Static analysis adapter --------------------------------------------

function Get-MsixHeuristicFinding {
    <#
    .SYNOPSIS
        Runs every read-only TMEditX-style analyzer against a package and
        returns merged findings. Used by Get-MsixStaticAnalysis to expand the
        report.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $out = New-Object System.Collections.Generic.List[object]

    # Uninstaller artefacts
    foreach ($u in Get-MsixUninstallerCandidate -PackagePath $PackagePath) {
        $out.Add([pscustomobject]@{
            Severity = 'Warning'
            Category = 'UninstallerArtifact'
            Symptom  = "Looks like a leftover installer artefact: $($u.Name)"
            Recommendation = "Remove-MsixUninstallerArtifact -PackagePath '$PackagePath'"
            Evidence = $u.Path
            AppId    = $null
        })
    }

    # Run keys
    foreach ($r in Get-MsixRunKeyEntry -PackagePath $PackagePath) {
        $out.Add([pscustomobject]@{
            Severity = 'Info'
            Category = 'RunKey'
            Symptom  = "Package's $($r.Hive) ships an autostart Run entry."
            Recommendation = "Use a PSF startScript or an HKCU Run entry instead — packaged HKLM Run keys do not fire."
            Evidence = $r.Match
            AppId    = $null
        })
    }

    # Alias suggestions
    foreach ($a in Get-MsixAliasCandidate -PackagePath $PackagePath) {
        if ($a.AlreadyHasAlias) { continue }
        $out.Add([pscustomobject]@{
            Severity = 'Info'
            Category = 'AppExecutionAlias'
            Symptom  = "$($a.AppId) has no AppExecutionAlias."
            Recommendation = "Add-MsixAlias -PackagePath '$PackagePath' -AppIds '$($a.AppId)' (suggested alias: $($a.SuggestAlias))"
            Evidence = $a.Executable
            AppId    = $a.AppId
        })
    }

    # VC runtime missing
    try {
        $vc = Get-MsixVcRuntimeReference -PackagePath $PackagePath
        if ($vc.Missing) {
            $out.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'VcRuntime'
                Symptom  = "References VC runtime DLLs that are not bundled: $($vc.Missing -join ', ')"
                Recommendation = "Add-MsixVcRuntimeBundle -PackagePath '$PackagePath' -SourceFolder <vs-redist-folder>"
                Evidence = $vc.Missing -join ', '
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "VC runtime heuristic skipped: $_" }

    # ── Fonts inside the package (suggest uap4:SharedFonts) ────────────────
    try {
        $fonts = Get-MsixFontCandidate -PackagePath $PackagePath
        if ($fonts) {
            $out.Add([pscustomobject]@{
                Severity = 'Info'
                Category = 'ManifestFix:SharedFonts'
                Symptom  = "Package ships $($fonts.Count) font file(s) but doesn't register them via uap4:SharedFonts."
                Recommendation = "Add-MsixFontExtension -PackagePath '$PackagePath' -FontPaths (Get-MsixFontCandidate -PackagePath '$PackagePath' | Select-Object -ExpandProperty Path)"
                Evidence = ($fonts | Select-Object -First 5 -ExpandProperty Name) -join ', '
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Font heuristic skipped: $_" }

    # ── Desktop shortcuts inside the package (suggest removal) ──────────────
    try {
        $sc = Get-MsixDesktopShortcutCandidate -PackagePath $PackagePath
        if ($sc) {
            $out.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'DesktopShortcuts'
                Symptom  = "Package ships $($sc.Count) .lnk file(s) under VFS\Common Desktop / VFS\Desktop."
                Recommendation = "Remove-MsixDesktopShortcut -PackagePath '$PackagePath'"
                Evidence = ($sc | Select-Object -First 3 -ExpandProperty Name) -join ', '
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Desktop shortcut heuristic skipped: $_" }

    # ── Capability hints from PE imports (suggest Add-MsixCapability) ───────
    try {
        $caps = Get-MsixCapabilityHint -PackagePath $PackagePath
        if ($caps) {
            $out.Add([pscustomobject]@{
                Severity = 'Info'
                Category = 'CapabilityHints'
                Symptom  = "PE imports suggest the app may need: $($caps -join ', ')"
                Recommendation = "Add-MsixCapability -PackagePath '$PackagePath' -Names $($caps -join ',')  (validate with Application Capability Profiler first)"
                Evidence = $caps -join ', '
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Capability hints heuristic skipped: $_" }

    # ── Uninstall registry leftovers ────────────────────────────────────────
    try {
        $uninst = Get-MsixUninstallRegistryEntry -PackagePath $PackagePath
        if ($uninst) {
            $out.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'UninstallRegistry'
                Symptom  = "Package's Registry.dat has $($uninst.Count) Uninstall\* leftover key(s)."
                Recommendation = "Remove-MsixUninstallerArtifact -PackagePath '$PackagePath'  (run elevated to also strip the registry entries)"
                Evidence = ($uninst | Select-Object -First 3 -ExpandProperty DisplayName) -join ', '
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Uninstall registry heuristic skipped: $_" }

    # ── Shell context-menu entries invisible outside the MSIX container ───────
    try {
        $shellMenus    = Get-MsixShellContextMenuEntry -PackagePath $PackagePath
        $verbEntries   = @($shellMenus | Where-Object Type -eq 'ShellVerb')
        $shellextEntries = @($shellMenus | Where-Object Type -eq 'ShellExt')

        if ($verbEntries) {
            $out.Add([pscustomobject]@{
                Severity       = 'Warning'
                Category       = 'ShellVerb'
                Symptom        = "Registry.dat declares $($verbEntries.Count) shell verb(s) ($($verbEntries.VerbName -join ', ')) that are invisible in File Explorer outside the MSIX container."
                Recommendation = "Plain command shell verbs require a COM surrogate to surface in File Explorer under MSIX. Convert the command to a COM in-process server, then call: Add-MsixLegacyContextMenu -PackagePath '$PackagePath' -ShellExtDll <VFS-dll> -Clsid <new-guid> -DisplayName '<verb>' -FileTypes '*'  (desktop9:fileExplorerClassicContextMenuHandler). Note: Add-MsixShellVerbExtension generates uap3:SupportedVerbs which is for Open-With file-type associations, NOT for context menu entries."
                Evidence       = ($verbEntries | ForEach-Object { "$($_.Target)\shell\$($_.VerbName)" }) -join '; '
                AppId          = $null
                ShellEntries   = $verbEntries
            })
        }

        if ($shellextEntries) {
            $out.Add([pscustomobject]@{
                Severity       = 'Error'
                Category       = 'ShellExt'
                Symptom        = "Registry.dat declares $($shellextEntries.Count) in-process shell handler(s) ($($shellextEntries.HandlerName -join ', ')) that will not load under MSIX. Includes both shellex\ContextMenuHandlers and shell verb keys with ExplorerCommandHandler (COM-delegating verbs)."
                Recommendation = "Add-MsixLegacyContextMenu -PackagePath '$PackagePath' -ShellExtDll <VFS-relative-dll> -Clsid <clsid> -DisplayName <name>  (Win11 21H2+: desktop9:fileExplorerClassicContextMenuHandler + com:SurrogateServer)"
                Evidence       = ($shellextEntries | ForEach-Object {
                    $regPath = if ($_.Clsid -and ($_.DllPath -or $_.VfsDllPath)) {
                        # ExplorerCommandHandler verb or shellex entry with resolved CLSID
                        "$($_.Target)\shell\$($_.HandlerName) [ExplorerCommandHandler=$($_.Clsid)]$(if ($_.VfsDllPath) { " -> $($_.VfsDllPath)" })"
                    } else {
                        "$($_.Target)\shellex\ContextMenuHandlers\$($_.HandlerName)$(if ($_.Clsid) { " [$($_.Clsid)]" })"
                    }
                    $regPath
                }) -join '; '
                AppId          = $null
                ShellEntries   = $shellextEntries
            })
        }
    } catch {
        Write-MsixLog Debug "Shell context-menu heuristic failed: $_"
    }

    # ── COM server registrations in Registry.dat ──────────────────────────────
    try {
        $comEntries = Get-MsixComServerEntry -PackagePath $PackagePath
        # Only surface InProc servers with a resolvable VFS DLL (package-bundled);
        # LocalServer and Unknown-type entries can't be auto-fixed and produce noise.
        $inprocPkg  = @($comEntries | Where-Object { $_.ServerType -eq 'InProc' -and $_.VfsDllPath })
        if ($inprocPkg) {
            $out.Add([pscustomobject]@{
                Severity       = 'Info'
                Category       = 'ComServer'
                Symptom        = "Registry.dat registers $($inprocPkg.Count) in-process COM server(s) with DLLs inside the package. External COM clients cannot activate them without a com:Extension declaration in the manifest."
                Recommendation = "Add-MsixComServerExtension -PackagePath '$PackagePath' -Servers @($($inprocPkg | ForEach-Object { "@{ Clsid='$($_.Clsid)'; VfsDllPath='$($_.VfsDllPath)'; ThreadingModel='$($_.ThreadingModel)' }" } | Select-Object -First 2 | Join-String -Separator ', '))"
                Evidence       = ($inprocPkg | ForEach-Object { "$($_.Clsid) → $($_.VfsDllPath)" }) -join '; '
                AppId          = $null
                ComEntries     = $inprocPkg
            })
        }
    } catch {
        Write-MsixLog Debug "COM server heuristic failed: $_"
    }

    # ── Nested installer packages inside the package ─────────────────────────
    try {
        $nested = @(Get-MsixNestedPackageCandidate -PackagePath $PackagePath)
        if ($nested) {
            $out.Add([pscustomobject]@{
                Severity       = 'Warning'
                Category       = 'NestedPackage'
                Symptom        = "Package contains $($nested.Count) nested installer package(s) that cannot be installed from within the MSIX container."
                Recommendation = 'Remove these files and deploy the nested packages separately (Intune / SCCM staging, or a startScript wrapper that calls winget / msiexec on a staged copy).'
                Evidence       = ($nested | Select-Object -First 3 -ExpandProperty Name) -join ', '
                AppId          = $null
            })
        }
    } catch {
        Write-MsixLog Debug "Nested package heuristic failed: $_"
    }

    # ── Manifest-level findings (alternatives to PSF) ───────────────────────
    try {
        $toolsRoot = Get-MsixToolsRoot
        $fileinfo  = Get-Item $PackagePath
        $tmp = New-MsixWorkspace "$($fileinfo.BaseName)-mfheur"
        try {
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $tmp, '/o')
            if ($r.ExitCode -eq 0) {
                [xml]$mf = Get-MsixManifest "$tmp\AppxManifest.xml"
                $exts    = @($mf.Package.Extensions.Extension)
                $appExts = @($mf.Package.Applications.Application.Extensions.Extension)

                # FileSystem/RegistryWriteVirtualization live in <Properties> (desktop6 namespace),
                # NOT in <Extensions>. Check for the flag element by local name + namespace-uri.
                $d6Uri      = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/6'
                $hasFsVirt  = [bool]($mf.Package.Properties.SelectSingleNode(
                    "*[local-name()='FileSystemWriteVirtualization' and namespace-uri()='$d6Uri']"))
                $hasRegVirt = [bool]($mf.Package.Properties.SelectSingleNode(
                    "*[local-name()='RegistryWriteVirtualization' and namespace-uri()='$d6Uri']"))
                $hasInstVirt = ($exts.Category -contains 'windows.installedLocationVirtualization')
                # LoaderSearchPathOverride can be at Package-level OR Application-level
                # (the function was moved to Application-level; check both for idempotency).
                $hasLoaderOv = $false
                foreach ($e in (@($exts) + @($appExts))) {
                    if ($e.SelectSingleNode('*[local-name()="LoaderSearchPathOverride"]')) {
                        $hasLoaderOv = $true; break
                    }
                }

                # If we already detected write-permission risk via static or
                # trace findings AND the package isn't using the manifest fix,
                # surface that as a more lightweight alternative to PSF.
                $needsWriteFix = $out | Where-Object Category -in 'FileRedirectionFixup','UninstallerArtifact'
                if ($needsWriteFix -and -not $hasFsVirt -and -not $hasInstVirt) {
                    $out.Add([pscustomobject]@{
                        Severity = 'Info'
                        Category = 'ManifestFix:FileSystemWriteVirtualization'
                        Symptom  = 'Package writes to its install location but no manifest virtualization extension is set.'
                        Recommendation = "Set-MsixFileSystemWriteVirtualization -PackagePath '$PackagePath'  (Win10 19041+; alternative to PSF FileRedirectionFixup for the broad case)"
                        Evidence = 'No desktop6:FileSystemWriteVirtualization in <Properties>'
                        AppId    = $null
                    })
                }

                $needsRegFix = $out | Where-Object Category -eq 'RegLegacyFixups'
                if ($needsRegFix -and -not $hasRegVirt) {
                    $out.Add([pscustomobject]@{
                        Severity = 'Info'
                        Category = 'ManifestFix:RegistryWriteVirtualization'
                        Symptom  = 'Package writes to HKLM but no manifest registry virtualization is set.'
                        Recommendation = "Set-MsixRegistryWriteVirtualization -PackagePath '$PackagePath'  (Win10 19041+; alternative to RegLegacy Hklm2Hkcu)"
                        Evidence = 'No desktop6:RegistryWriteVirtualization in <Properties>'
                        AppId    = $null
                    })
                }

                # HKLM Run keys but no startupTask extension
                $hasStartupTask = $false
                foreach ($e in $appExts) {
                    if ($e.Category -eq 'windows.startupTask') { $hasStartupTask = $true; break }
                }
                $hasRunKeys = $out | Where-Object Category -eq 'RunKey'
                if ($hasRunKeys -and -not $hasStartupTask) {
                    $out.Add([pscustomobject]@{
                        Severity = 'Info'
                        Category = 'ManifestFix:StartupTask'
                        Symptom  = 'Package contains autostart Run keys but declares no windows.startupTask.'
                        Recommendation = "Add-MsixStartupTask -PackagePath '$PackagePath' -AppId <app> -TaskId <id> -DisplayName <name>"
                        Evidence = 'Run-key entries in Registry.dat / User.dat'
                        AppId    = $null
                    })
                }

                # DLL load failures suggest LoaderSearchPathOverride
                $dllFindings = $out | Where-Object Category -eq 'DynamicLibraryFixup'
                if ($dllFindings -and -not $hasLoaderOv) {
                    $out.Add([pscustomobject]@{
                        Severity = 'Info'
                        Category = 'ManifestFix:LoaderSearchPathOverride'
                        Symptom  = 'DLL load failures reported but no uap6:LoaderSearchPathOverride is set.'
                        Recommendation = "Add-MsixLoaderSearchPathOverride -PackagePath '$PackagePath' -Paths 'VFS/ProgramFilesX64/<App>/lib'  (manifest alternative to DynamicLibraryFixup)"
                        Evidence = 'LoadLibrary failure(s) in trace output'
                        AppId    = $null
                    })
                }

                # Suppress ShellExt finding if the manifest already declares desktop9 COM handlers.
                # desktop9 extensions are at Application-level ($appExts); check both levels for safety.
                $hasLegacyCtxMenu = (@($exts) + @($appExts)) | Where-Object {
                    $_.Category -in @('windows.fileExplorerClassicContextMenuHandler','windows.fileExplorerClassicDragDropContextMenuHandler')
                }
                if ($hasLegacyCtxMenu) {
                    $toRemove = @($out | Where-Object Category -eq 'ShellExt')
                    foreach ($rem in $toRemove) { [void]$out.Remove($rem) }
                }

                # Suppress ShellVerb finding if the manifest already declares FTA or IExplorerCommand menus
                $hasFta            = $appExts | Where-Object { $_.Category -eq 'windows.fileTypeAssociation' }
                $hasModernCtxMenu  = $appExts | Where-Object { $_.Category -eq 'windows.fileExplorerContextMenus' }
                if ($hasFta -or $hasModernCtxMenu) {
                    $toRemove = @($out | Where-Object Category -eq 'ShellVerb')
                    foreach ($rem in $toRemove) { [void]$out.Remove($rem) }
                }

                # Suppress ComServer finding if all CLSIDs are already declared in the manifest
                $comFinding = @($out | Where-Object Category -eq 'ComServer')
                if ($comFinding) {
                    $declaredClsids = @($mf.SelectNodes("//*[local-name()='Class']/@Id") | ForEach-Object { $_.Value })
                    $stillMissing   = @($comFinding[0].ComEntries | Where-Object { $_.Clsid -notin $declaredClsids })
                    if (-not $stillMissing) {
                        [void]$out.Remove($comFinding[0])
                    } elseif ($stillMissing.Count -lt $comFinding[0].ComEntries.Count) {
                        # Partial: update the finding to only the missing ones
                        $comFinding[0].ComEntries = $stillMissing
                    }
                }
            }
        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-MsixLog Debug "Manifest-fix heuristic failed: $_"
    }

    return $out
}
#endregion


# Backward-compatible plural aliases
Set-Alias Get-MsixKnownCapabilities Get-MsixKnownCapability
Set-Alias Get-MsixUninstallerCandidates Get-MsixUninstallerCandidate
Set-Alias Get-MsixUninstallRegistryEntries Get-MsixUninstallRegistryEntry
Set-Alias Remove-MsixUninstallerArtifacts Remove-MsixUninstallerArtifact
Set-Alias Get-MsixRunKeyEntries Get-MsixRunKeyEntry
Set-Alias Get-MsixShellContextMenuEntries Get-MsixShellContextMenuEntry
Set-Alias Get-MsixComServerEntries Get-MsixComServerEntry
Set-Alias Get-MsixAliasCandidates Get-MsixAliasCandidate
Set-Alias Get-MsixHeuristicFindings Get-MsixHeuristicFinding
