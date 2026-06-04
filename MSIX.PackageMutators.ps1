# =============================================================================
# MSIX package mutators (split from MSIX.Heuristics.ps1 in issue #38)
# -----------------------------------------------------------------------------
# Functions that modify a .msix in place via _MsixMutatePackage:
#   Add-MsixCapability, Remove-Msix*Artifact, Add-MsixSplashScreen,
#   Update-MsixPackageVersion. Each wraps the unpack -> mutate ->
#   atomic-repack-sign-move helper defined in MSIX.Pipeline.ps1.
# Scanners (Get-Msix*) live in MSIX.Scanners.ps1.
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

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package at this path
        for inspection. The user's -PackagePath is left byte-equal to before
        the call in this scenario.

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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '',
        Justification = 'ShouldProcess is invoked inside _MsixMutatePackage; PSSA cannot trace it through the scriptblock dispatch (issue #37).')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Names',
        Justification = 'Captured by the -Mutator scriptblock via GetNewClosure().')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Namespace',
        Justification = 'Captured by the -Mutator scriptblock via GetNewClosure().')]
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
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $null = _MsixMutatePackage -PackagePath $PackagePath -Operation 'cap' `
        -OutputPath $OutputPath -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -NoChangeMessage 'No capabilities added.' `
        -Mutator {
            param($workspace)
            $null = Test-MsixManifest -Path "$workspace\AppxManifest.xml"
            [xml]$manifest = Get-MsixManifest -Path "$workspace\AppxManifest.xml"

            $caps = $manifest.Package.Capabilities
            if (-not $caps) {
                $caps = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
                $null = $manifest.Package.AppendChild($caps)
            }

            $added = @()
            foreach ($name in $Names) {
                # Explicit -Namespace overrides the lookup table; otherwise use it.
                $ns = if ($Namespace) { $Namespace } else { $script:KnownCapabilities[$name] }
                # Idempotency: match by LocalName + Name attribute regardless of prefix
                $existing = $caps.ChildNodes | Where-Object {
                    ($_.LocalName -eq 'Capability') -and ($_.'Name' -eq $name)
                }
                if ($existing) {
                    Write-MsixLog -Level Info -Message "Capability already present: $name"
                    continue
                }
                if ($ns -and $ns -ne 'standard') {
                    Add-MsixManifestNamespace -Manifest $manifest -Prefix $ns
                    $nsUri = Get-MsixManifestNamespaceUri -Prefix $ns
                    $node  = $manifest.CreateElement("${ns}:Capability", $nsUri)
                } else {
                    if (-not $ns) {
                        Write-MsixLog -Level Warning -Message "Capability '$name' is not in the known-capabilities table (MSIX.Heuristics.ps1#KnownCapabilities). Creating a plain <Capability> element (standard namespace). If this is a uap/rescap capability, the install may fail at deployment time — verify against https://learn.microsoft.com/en-us/windows/uwp/packaging/app-capability-declarations and either add it to the lookup table or pass -Namespace explicitly."
                    }
                    $node = $manifest.CreateElement('Capability', $manifest.Package.NamespaceURI)
                }
                $node.SetAttribute('Name', $name)
                $null = $caps.AppendChild($node)
                Write-MsixLog -Level Info -Message "Capability added: $name"
                $added += $name
            }

            if (-not $added) { return $null }

            Save-MsixManifest -Manifest $manifest -Path "$workspace\AppxManifest.xml"
            @{ CapabilitiesAdded = $added }
        }.GetNewClosure()
}
#endregion

# ---------------------------------------------------------------------------
# Uninstaller / updater / shell-registry mutators
# ---------------------------------------------------------------------------

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

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package at this path
        for inspection. The user's -PackagePath is left byte-equal to before
        the call in this scenario.

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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'UninstallKeyFilter',
        Justification = 'Captured by the -Mutator scriptblock via GetNewClosure() (issue #37).')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'KeepRegistry',
        Justification = 'Captured by the -Mutator scriptblock via GetNewClosure() (issue #37).')]
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
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )
    if (-not $PathPatterns) {
        $PathPatterns = @(
            '^uninst.*\.exe$','^unins.*\.exe$','^setup\.exe$','^install\.exe$',
            '^_isres.*$','^autorun\.inf$','^uninstall\.exe$','^uninstaller.*\.exe$'
        )
    }

    _MsixMutatePackage -PackagePath $PackagePath -Operation 'uninstrm' `
        -OutputPath $OutputPath -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -NoChangeMessage 'No uninstaller artefacts found.' `
        -Mutator {
            param($workspace)

            # ── Strip files ────────────────────────────────────────────────
            $removedFiles = @()
            Get-ChildItem -LiteralPath $workspace -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $name = $_.Name
                    ($PathPatterns | Where-Object { $name -match $_ }).Count -gt 0
                } |
                ForEach-Object {
                    Remove-Item -LiteralPath $_.FullName -Force
                    $removedFiles += $_.FullName.Substring($workspace.Length + 1)
                }

            # ── Strip Registry.dat Uninstall\* entries ────────────────────
            $removedKeys = @()
            $datPath = Join-Path -Path $workspace -ChildPath 'Registry.dat'
            if (-not $KeepRegistry -and (Test-Path -LiteralPath $datPath)) {
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
                                    Write-MsixLog -Level Warning -Message "Recursive ORDeleteKey failed for '$logical' — the hive is now in a partial state and will be discarded; the package is unchanged."
                                    # Bail out so we never persist a half-deleted hive.
                                    $modified = $false
                                    break
                                }
                            }
                        }
                    }
                    if ($modified) {
                        if (-not (_MsixOfflineSaveHive -Hive $hive -Path $newDat)) {
                            Write-MsixLog -Level Warning -Message 'ORSaveHive failed; Registry.dat is unchanged.'
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

            if (-not $removedFiles -and -not $removedKeys) { return $null }
            if ($removedFiles) { Write-MsixLog -Level Info -Message "Files removed:    $($removedFiles -join ', ')" }
            if ($removedKeys)  { Write-MsixLog -Level Info -Message "Reg keys removed: $($removedKeys -join ', ')" }
            @{ FilesRemoved = $removedFiles; KeysRemoved = $removedKeys }
        }.GetNewClosure()
}

function Remove-MsixUpdaterArtifact {
    <#
    .SYNOPSIS
        Strips auto-updater binaries and scheduled-task XMLs from inside the
        package. Repacks + re-signs unless -SkipSigning / -NoSign.

    .DESCRIPTION
        Mutator counterpart to Get-MsixUpdaterCandidate. Two-step cleanup:

          1. Remove files inside the package whose leaf name matches
             -PathPatterns (default = the known updater set).
          2. Remove *.xml files under any Tasks\ or VFS\Windows\Tasks\
             subdirectory (scheduled-task artefacts that ship with installers
             but cannot fire from inside the MSIX container).

        Repacks via a scratch path and re-signs at the end. Idempotent — a
        second run on a clean package logs "No updater artefacts found."
        and returns without repacking.

        Does NOT touch Registry.dat — updater registry entries (e.g. Run-key
        autostart) are detected separately via Get-MsixRunKeyEntry and the
        existing uninstall-registry / shell-registry cleanup paths.

        Used by both Invoke-MsixAutoFix (via -RemoveUpdaters) and
        Invoke-MsixAutoFixFromAnalysis (RemoveUpdaters stage).

    .PARAMETER PackagePath
        .msix file to mutate.

    .PARAMETER PathPatterns
        Filename regex patterns. Defaults to the same set
        Get-MsixUpdaterCandidate uses.

    .PARAMETER OutputPath
        Write the repacked package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Don't sign the repacked .msix. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package at this path
        for inspection.

    .EXAMPLE
        # Strip updater binaries and scheduled-task XMLs, then sign
        Remove-MsixUpdaterArtifact -PackagePath app.msix `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Test/dev — strip without signing
        Remove-MsixUpdaterArtifact -PackagePath app.msix -SkipSigning

    .OUTPUTS
        [pscustomobject] with FilesRemoved (string[]), TasksRemoved (string[]),
        and Output (final package path). Returns nothing when nothing matched.

    .NOTES
        Pair with Get-MsixRunKeyEntry to surface Run-key autostart leftovers
        that updaters often plant in Registry.dat / User.dat.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [string[]]$PathPatterns,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )
    if (-not $PathPatterns) {
        $PathPatterns = @(
            '^.*updater?\.exe$',
            '^.*updatesvc.*\.exe$',
            '^.*sparkle.*\.(dll|exe)$',
            '^.*squirrel.*\.exe$',
            '^GoogleUpdate.*\.exe$',
            '^MicrosoftEdgeUpdate.*\.exe$',
            '^omaha.*\.exe$',
            '^.*autoupdater?.*\.exe$',
            '^.*maintenanceservice.*\.exe$',
            '^.*winsparkle.*\.(dll|exe)$'
        )
    }
    $excludePatterns = @('^psf', '^msvc', '^vcruntime', '^api-ms-win-', '^msix')

    _MsixMutatePackage -PackagePath $PackagePath -Operation 'updrm' `
        -WorkspaceSuffix '-updrm' `
        -OutputPath $OutputPath -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -NoChangeMessage 'No updater artefacts found.' `
        -Mutator {
            param($workspace)

            # ── Strip updater binaries ─────────────────────────────────────
            $removedFiles = @()
            Get-ChildItem -LiteralPath $workspace -Recurse -File -ErrorAction SilentlyContinue |
                Where-Object {
                    $name = $_.Name
                    $skip = $false
                    foreach ($ex in $excludePatterns) {
                        if ($name -match $ex) { $skip = $true; break }
                    }
                    if ($skip) { return $false }
                    ($PathPatterns | Where-Object { $name -match $_ }).Count -gt 0
                } |
                ForEach-Object {
                    Remove-Item -LiteralPath $_.FullName -Force
                    $removedFiles += $_.FullName.Substring($workspace.Length + 1)
                }

            # ── Strip scheduled-task XMLs ──────────────────────────────────
            $removedTasks = @()
            Get-ChildItem -LiteralPath $workspace -Recurse -File -Filter '*.xml' -ErrorAction SilentlyContinue |
                Where-Object {
                    $rel = $_.FullName.Substring($workspace.Length + 1).ToLowerInvariant()
                    ($rel -match '(^|\\)tasks\\') -or ($rel -match '\\vfs\\windows\\tasks\\')
                } |
                ForEach-Object {
                    Remove-Item -LiteralPath $_.FullName -Force
                    $removedTasks += $_.FullName.Substring($workspace.Length + 1)
                }

            if (-not $removedFiles -and -not $removedTasks) { return $null }
            if ($removedFiles) { Write-MsixLog -Level Info -Message "Files removed: $($removedFiles -join ', ')" }
            if ($removedTasks) { Write-MsixLog -Level Info -Message "Tasks removed: $($removedTasks -join ', ')" }
            @{ FilesRemoved = $removedFiles; TasksRemoved = $removedTasks }
        }.GetNewClosure()
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
        Write-MsixLog -Level Info -Message 'No shell registry entries supplied; nothing to do.'
        return
    }

    _MsixMutatePackage -PackagePath $PackagePath -Operation 'shellreg' `
        -WorkspaceSuffix '-shellreg' `
        -OutputPath $OutputPath -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -NoChangeMessage 'No matching legacy shell registry entries found.' `
        -Mutator {
            param($workspace)

            $datPath = Join-Path -Path $workspace -ChildPath 'Registry.dat'
            if (-not (Test-Path -LiteralPath $datPath)) {
                Write-MsixLog -Level Info -Message 'No Registry.dat in package — nothing to clean.'
                return $null
            }

            # Targets to walk under Classes — the same set Get-MsixShellContextMenuEntry uses.
            $targets = @('*', 'Directory', 'Directory\Background', 'Folder', 'Drive', 'AllFilesystemObjects')

            # Build a CLSID set for fast membership testing (lower-cased, both bare
            # and braced forms accepted in inputs).
            $clsidSet = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($e in $Entries) {
                if ($e.Clsid) {
                    $bare = $e.Clsid.ToString().Trim().Trim('{', '}').ToLowerInvariant()
                    $null = $clsidSet.Add($bare)
                }
            }
            if ($clsidSet.Count -eq 0) {
                Write-MsixLog -Level Warning -Message 'None of the supplied entries had a Clsid; nothing to clean (resolve CLSIDs via Get-MsixShellContextMenuEntry).'
                return $null
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
                                    if (_MsixOfflineDeleteKeyRecursive -Parent $hive -SubKey $logical) {
                                        $removedKeys += $logical
                                        $modified = $true
                                    } else {
                                        Write-MsixLog -Level Warning -Message "Recursive ORDeleteKey failed for '$logical' — discarding partial changes."
                                        $modified = $false
                                        break
                                    }
                                }
                            }
                        }
                        if ($modified -eq $false -and $removedKeys.Count -gt 0) { break }

                        # ── shellex\DragDropHandlers\<name> — delete iff (default) value matches our CLSID
                        $dragBase = "$prefix\$target\shellex\DragDropHandlers"
                        $dragKey  = _MsixOfflineOpenKey -Parent $hive -SubKey $dragBase
                        if ($dragKey -ne [IntPtr]::Zero) {
                            try {
                                $handlers = _MsixOfflineEnumSubKeys -Key $dragKey
                            } finally {
                                _MsixOfflineCloseKey -Key $dragKey
                            }
                            foreach ($handler in $handlers) {
                                $logical = "$dragBase\$handler"
                                $value   = _MsixOfflineGetValue -Parent $hive -SubKey $logical -Name ''
                                if (-not $value) { continue }
                                $bare = $value.ToString().Trim().Trim('{', '}').ToLowerInvariant()
                                if ($clsidSet.Contains($bare)) {
                                    if (_MsixOfflineDeleteKeyRecursive -Parent $hive -SubKey $logical) {
                                        $removedKeys += $logical
                                        $modified = $true
                                    } else {
                                        Write-MsixLog -Level Warning -Message "Recursive ORDeleteKey failed for '$logical' — discarding partial changes."
                                        $modified = $false
                                        break
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
                                    if (_MsixOfflineDeleteKeyRecursive -Parent $hive -SubKey $logical) {
                                        $removedKeys += $logical
                                        $modified = $true
                                    } else {
                                        Write-MsixLog -Level Warning -Message "Recursive ORDeleteKey failed for '$logical' — discarding partial changes."
                                        $modified = $false
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
                if ($modified) {
                    if (-not (_MsixOfflineSaveHive -Hive $hive -Path $newDat)) {
                        Write-MsixLog -Level Warning -Message 'ORSaveHive failed; Registry.dat is unchanged.'
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

            if (-not $removedKeys -or $removedKeys.Count -eq 0) { return $null }

            Write-MsixLog -Level Info -Message "Legacy shell registry entries removed: $($removedKeys.Count)"
            $removedKeys | ForEach-Object { Write-MsixLog -Level Info -Message "  $_" }
            @{ KeysRemoved = $removedKeys }
        }.GetNewClosure()
}
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

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package at this path
        for inspection. The user's -PackagePath is left byte-equal to before
        the call in this scenario.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '',
        Justification = 'ShouldProcess is invoked inside _MsixMutatePackage; PSSA cannot trace it through the scriptblock dispatch (issue #40).')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'AppId',
        Justification = 'Captured by the -Mutator scriptblock via GetNewClosure().')]
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
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )
    if (-not (Test-Path -LiteralPath $ImagePath)) { throw "Splash image not found: $ImagePath" }

    $null = _MsixMutatePackage -PackagePath $PackagePath -Operation 'splash' `
        -OutputPath $OutputPath -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -NoChangeMessage 'No splash screen changes required.' `
        -Mutator {
            param($workspace)

            # Find config.json — should be next to PsfLauncher
            $cfgPaths = @(Get-ChildItem -LiteralPath $workspace -Recurse -Filter 'config.json' -ErrorAction SilentlyContinue)
            if (-not $cfgPaths) { throw 'config.json not found; run Add-MsixPsfV2 first.' }
            $cfgPath = $cfgPaths[0].FullName
            $cfgDir  = Split-Path -LiteralPath $cfgPath -Parent

            # Copy splash next to config.json
            $imageLeaf = (Get-Item -LiteralPath $ImagePath).Name
            Copy-Item -LiteralPath $ImagePath -Destination $cfgDir -Force

            # Patch config.json
            $cfg = Get-Content -LiteralPath $cfgPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            foreach ($app in @($cfg.applications)) {
                if ($app.id -ne $AppId) { continue }
                if (-not $app.startScript) {
                    $app | Add-Member -NotePropertyName startScript -NotePropertyValue ([pscustomobject]@{}) -Force
                }
                $app.startScript | Add-Member -NotePropertyName splashImage -NotePropertyValue $imageLeaf -Force
            }
            $cfg | ConvertTo-Json -Depth 15 | Set-Content -LiteralPath $cfgPath -Encoding utf8
            @{ SplashImage = $imageLeaf; AppId = $AppId }
        }.GetNewClosure()
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

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package at this path
        for inspection. The user's -PackagePath is left byte-equal to before
        the call in this scenario.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '',
        Justification = 'ShouldProcess is invoked inside _MsixMutatePackage; PSSA cannot trace it through the scriptblock dispatch (issue #40).')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Component',
        Justification = 'Captured by the -Mutator scriptblock via GetNewClosure().')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'KeepLastZero',
        Justification = 'Captured by the -Mutator scriptblock via GetNewClosure().')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'NewVersion',
        Justification = 'Captured by the -Mutator scriptblock via GetNewClosure().')]
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
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $result = _MsixMutatePackage -PackagePath $PackagePath -Operation 'vbump' `
        -OutputPath $OutputPath -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -NoChangeMessage 'Version unchanged.' `
        -Mutator {
            param($workspace)
            $null = Test-MsixManifest -Path "$workspace\AppxManifest.xml"
            [xml]$manifest = Get-MsixManifest -Path "$workspace\AppxManifest.xml"
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
                if ($KeepLastZero -and $Component -eq 'Revision') {
                    $next = [version]"$($current.Major).$($current.Minor).$([int]$current.Build + 1).0"
                }
            }
            $manifest.Package.Identity.Version = $next.ToString(4)
            Write-MsixLog -Level Info -Message "Version: $current -> $next"
            Save-MsixManifest -Manifest $manifest -Path "$workspace\AppxManifest.xml"
            @{ PreviousVersion = $current.ToString(4); NewVersion = $next.ToString(4) }
        }.GetNewClosure()

    if ($result) { return $result.NewVersion }
}
#endregion


# ---------------------------------------------------------------------------
# Plural-noun back-compat aliases (issue #38: preserved across the heuristics
# file split — every alias defined in the pre-split MSIX.Heuristics.ps1 still
# resolves to the same singular cmdlet).
# ---------------------------------------------------------------------------
Set-Alias Get-MsixKnownCapabilities       Get-MsixKnownCapability
Set-Alias Remove-MsixUninstallerArtifacts Remove-MsixUninstallerArtifact
