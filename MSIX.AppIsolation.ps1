# =============================================================================
# Win32 App Isolation
# -----------------------------------------------------------------------------
# Adds the rescap capabilities + iso namespace that turn a regular MSIX-packaged
# Win32 app into an "isolated" one. The isolation feature provides an OS-level
# sandbox with broker-mediated access to filesystem, devices, and protected APIs.
#
# Reference:
#   https://learn.microsoft.com/windows/win32/secauthz/app-isolation-overview
#   https://learn.microsoft.com/windows/win32/secauthz/app-isolation-supported-capabilities
#
# Important: this is OPT-IN. Most MSIX packages should NOT enable isolation —
# many legacy apps will break because they rely on broad filesystem/registry
# access. Use this only after validating the app under isolation manually.
#
# Minimum runtime: Windows 11 24H2 (build 26100) or later.
# =============================================================================

# Documented isolated-app capabilities.
# Source: https://learn.microsoft.com/windows/win32/secauthz/app-isolation-supported-capabilities
# Key = capability name; Value = short description for Get-MsixIsolationCapability output.
$script:KnownIsolationCapabilities = [ordered]@{
    # ── On the MS Learn page (documented and validated) ───────────────────
    'isolatedWin32-print'                      = 'Print via the Win32 printing infrastructure'
    'isolatedWin32-sysTrayIcon'                = 'Display notifications from the system tray'
    'isolatedWin32-shellExtensionContextMenu'  = 'Display COM-based context menu entries'
    'isolatedWin32-promptForAccess'            = 'Prompt users for file access at runtime'
    'isolatedWin32-accessToPublisherDirectory' = 'Access directories ending with the publisher ID'
    # Minimal-access group (for apps that cannot use prompting):
    'isolatedWin32-dotNetBreadcrumbStore'      = 'Minimal access to the .NET breadcrumb store'
    'isolatedWin32-profilesRootMinimal'        = 'Minimal access to the profiles root'
    'isolatedWin32-userProfileMinimal'         = 'Minimal access to the user profile'
    'isolatedWin32-volumeRootMinimal'          = 'Minimal access to the volume root'
    # ── Extended capabilities used in practice (pre-dating the MS Learn page) ─
    'isolatedWin32-accessFromLowIntegrityLevel' = 'Allow access from low-integrity-level processes'
    'isolatedWin32-userProfile'                = 'Full user profile access'
    'isolatedWin32-printDocumentsFolder'       = 'Access to the print documents folder'
    'isolatedWin32-printDocumentsContents'     = 'Access to print document contents'
    'isolatedWin32-fullFileSystemAccess'       = 'Full file system access'
    'isolatedWin32-allowElevation'             = 'Allow elevation'
    'isolatedWin32-attachToHostInterop'        = 'Attach to the host process for interop'
    'isolatedWin32-internetClient'             = 'Outbound internet access'
    'isolatedWin32-internetClientServer'       = 'Inbound and outbound internet access'
    'isolatedWin32-privateNetworkClientServer' = 'Home/work network access'
    'isolatedWin32-bluetooth'                  = 'Bluetooth access'
    'isolatedWin32-networking'                 = 'General networking access'
    'isolatedWin32-removableStorage'           = 'Removable storage access'
}

# Device capabilities supported under Win32 app isolation.
# These use <DeviceCapability Name="…"/> in the default namespace — NOT rescap:Capability.
# Source: UWP capabilities section of the MS Learn page above.
$script:KnownIsolationDeviceCapabilities = [ordered]@{
    'microphone' = 'Access to the microphone audio feed'
    'webcam'     = 'Access to built-in camera or external webcam video feed'
}

function Get-MsixIsolationCapability {
    <#
    .SYNOPSIS
        Returns the set of well-known Win32-app-isolation capabilities the module
        is aware of. Use this list to decide what to pass into Add-MsixAppIsolation.

    .DESCRIPTION
        Returns one object per capability with the following properties:
          Name        — the string to pass to Add-MsixAppIsolation -Capabilities.
          ElementType — 'rescap:Capability' (isolatedWin32-*) or 'DeviceCapability'
                        (microphone, webcam). Add-MsixAppIsolation picks the correct
                        XML element automatically.
          Description — short human-readable summary from the MS Learn page.

    .OUTPUTS
        [pscustomobject] with Name, ElementType, Description.
    #>
    foreach ($entry in $script:KnownIsolationCapabilities.GetEnumerator()) {
        [pscustomobject]@{
            Name        = $entry.Key
            ElementType = 'rescap:Capability'
            Description = $entry.Value
        }
    }
    foreach ($entry in $script:KnownIsolationDeviceCapabilities.GetEnumerator()) {
        [pscustomobject]@{
            Name        = $entry.Key
            ElementType = 'DeviceCapability'
            Description = $entry.Value
        }
    }
}


function Add-MsixAppIsolation {
    <#
    .SYNOPSIS
        Makes a packaged Win32 app run isolated (in an AppContainer) by switching
        the Application to the partial-trust entry point, declaring the AppContainer
        trust level, and removing runFullTrust.

    .DESCRIPTION
        The isolation boundary is the AppContainer TrustLevel. To actually drop a
        packaged Win32 app into an AppContainer you must (per the MSIX
        AppContainer guidance, https://learn.microsoft.com/windows/msix/msix-container):
          1. set Application EntryPoint to "Windows.PartialTrustApplication"
             (the full-trust entry point hard-requires runFullTrust, which keeps
             the process full-trust — so it can never isolate);
          2. declare TrustLevel="appContainer"; and
          3. REMOVE the runFullTrust capability.
        This cmdlet does all three. (The earlier capability-only / FullTrust
        approach never isolated — the app stayed full-trust.)

        Two modes (-Mode), both built on the same AppContainer base
        (PartialTrustApplication + appContainer + no runFullTrust):

          AppContainer (default) — the GA "packagedClassicApp" AppContainer:
            uap10:TrustLevel="appContainer", uap10:RuntimeBehavior="packagedClassicApp".
            Ungranted access is denied (no consent prompts). Available since
            Windows 10 2004 (build 19041). -Capabilities here are standard
            package capabilities (e.g. internetClient, broadFileSystemAccess,
            microphone) resolved to their namespace automatically.

          AppSilo — the Win32 App Isolation silo (PREVIEW, Win11 24H2 / build
            26100+): adds uap18:RuntimeBehavior="appSilo",
            uap18:EntryPoint="Isolated.App", and the isolatedWin32-* capability
            broker (consent prompts via isolatedWin32-promptForAccess, etc.).
            appSilo is a further specialisation of appContainer. -Capabilities
            here are isolatedWin32-* / device capabilities. MinVersion is raised
            to 10.0.26100.0 (so the package will no longer install before 24H2).

        Repacks and re-signs the package.

        WARNING: opt-in. Many legacy apps break under isolation because they
        expect broad filesystem/registry access. Validate with the Application
        Capability Profiler (ACP) first:
        https://github.com/microsoft/win32-app-isolation/releases

        NOTE: Packages built with the Package Support Framework (PSF) — Application
        Executable PsfLauncher*.exe — cannot be isolated. PSF injects fixup DLLs
        into the target process, which AppContainer blocks. This cmdlet warns when
        it detects a PSF launcher.

        NOTE: A package that declares a windows.comServer extension (e.g. a COM
        shell context-menu like NppShell) CANNOT be isolated — that extension is
        invalid with a partial-trust entry point and MakeAppx rejects it. This
        cmdlet throws with guidance; strip the COM server + its context-menu first.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER Mode
        AppContainer (default) — GA packagedClassicApp AppContainer.
        AppSilo — preview Win32 App Isolation silo with the broker.

    .PARAMETER Capabilities
        Capabilities to declare. In -Mode AppContainer these are standard package
        capability names (default: none — strictest). In -Mode AppSilo these are
        isolatedWin32-* / device capabilities (default: isolatedWin32-promptForAccess).

    .PARAMETER AppId
        Restrict the isolation attributes to the Application with this Id.
        Default: every <Application> in the package.

    .PARAMETER RemoveComServer
        A windows.comServer extension is invalid with a partial-trust entry
        point, so a package that declares one (e.g. a COM shell context-menu
        like NppShell) cannot be isolated and this cmdlet throws. With this
        switch the COM server AND its Explorer context-menu verbs are stripped
        instead — that functionality is LOST, but the app can then isolate.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package.

    .PARAMETER Pfx
        Signing certificate.

    .PARAMETER PfxPassword
        Signing certificate.

    .EXAMPLE
        # GA AppContainer (strict): the app runs in an AppContainer, ungranted
        # access is denied.
        Add-MsixAppIsolation -PackagePath app.msix -SkipSigning

    .EXAMPLE
        # AppContainer with internet + a known folder granted.
        Add-MsixAppIsolation -PackagePath app.msix `
            -Capabilities internetClient -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Win32 App Isolation silo (preview) with the file-access broker.
        Add-MsixAppIsolation -PackagePath app.msix -Mode AppSilo `
            -Capabilities 'isolatedWin32-promptForAccess' -SkipSigning
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'AppId',
        Justification = 'Captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [ValidateSet('AppContainer', 'AppSilo')]
        [string]$Mode = 'AppContainer',
        [string[]]$Capabilities,
        [string]$AppId,
        [switch]$RemoveComServer,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    # Per-mode default capability set.
    if (-not $PSBoundParameters.ContainsKey('Capabilities')) {
        $Capabilities = if ($Mode -eq 'AppSilo') { @('isolatedWin32-promptForAccess') } else { @() }
    }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add App Isolation ($Mode)")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -WhatIfPreview:$isWhatIf `
        -Activity "Add App Isolation ($Mode)" -Mutate {
        param([xml]$manifest)
        _MsixApplyAppIsolation -Manifest $manifest -Mode $Mode -Capabilities $Capabilities -AppId $AppId -RemoveComServer:$RemoveComServer
    }
}


function _MsixApplyAppIsolation {
    # Module-private core of Add-MsixAppIsolation: applies the isolation model
    # (entry point, trust level, runFullTrust removal, capabilities) to an
    # in-memory manifest. Shared with Invoke-MsixPipeline's AppIsolation stage
    # so the two paths can never diverge again (issue #97).
    param(
        [Parameter(Mandatory)][xml]$Manifest,
        [ValidateSet('AppContainer', 'AppSilo')]
        [string]$Mode = 'AppContainer',
        [string[]]$Capabilities = @(),
        [string]$AppId,
        [switch]$RemoveComServer
    )
        $manifest = $Manifest

        # Validate capability names against the mode (warn only).
        foreach ($c in $Capabilities) {
            if ($Mode -eq 'AppSilo') {
                $known = $script:KnownIsolationCapabilities.Contains($c) -or $script:KnownIsolationDeviceCapabilities.Contains($c)
                if (-not $known) {
                    Write-MsixLog -Level Warning -Message "'$c' is not a documented Win32-isolation capability. Verify against MS Learn before publishing."
                }
            } else {
                if ($c -like 'isolatedWin32-*') {
                    Write-MsixLog -Level Warning -Message "'$c' is an appSilo (Win32 App Isolation) capability and is ignored in -Mode AppContainer. Use -Mode AppSilo for isolatedWin32-* capabilities, or pass a standard package capability name here."
                }
            }
        }

        # ── Namespaces + minimum-version floor ────────────────────────────────
        Add-MsixManifestNamespace -Manifest $manifest -Prefix 'uap10'
        $uap10Uri = Get-MsixManifestNamespaceUri -Prefix 'uap10'
        $uap18Uri = Get-MsixManifestNamespaceUri -Prefix 'uap18'   # for cleanup in both modes
        if ($Mode -eq 'AppSilo') {
            Add-MsixManifestNamespace -Manifest $manifest -Prefix 'uap18'
            Add-MsixManifestNamespace -Manifest $manifest -Prefix 'rescap'
            Set-MsixManifestMaxVersionTested -Manifest $manifest -MinBuild 26100

            # appSilo (preview) only engages when the package targets 24H2.
            $isoMin = [version]'10.0.26100.0'
            $desktopTdf = @($manifest.Package.Dependencies.TargetDeviceFamily) |
                Where-Object { $_.GetAttribute('Name') -eq 'Windows.Desktop' }
            if (-not $desktopTdf) {
                Write-MsixLog -Level Warning -Message 'No Windows.Desktop TargetDeviceFamily found; cannot raise MinVersion. appSilo requires a Windows.Desktop target at MinVersion 10.0.26100.0.'
            }
            foreach ($tdf in $desktopTdf) {
                $cur = $null
                $parsed = [version]::TryParse($tdf.GetAttribute('MinVersion'), [ref]$cur)
                if (-not $parsed -or $cur -lt $isoMin) {
                    $tdf.SetAttribute('MinVersion', '10.0.26100.0')
                    Write-MsixLog -Level Warning -Message "TargetDeviceFamily 'Windows.Desktop' MinVersion raised to 10.0.26100.0 (required for the appSilo preview). The package will no longer install on Windows older than 24H2."
                }
            }
        }

        # ── Locate target Application(s) ──────────────────────────────────────
        $apps = @($manifest.Package.Applications.Application)
        if ($AppId) {
            $apps = @($apps | Where-Object { $_.GetAttribute('Id') -eq $AppId })
            if (-not $apps) { throw "Application '$AppId' not found in the manifest." }
        }
        if (-not $apps) { throw 'No <Application> element found in the manifest.' }

        # A windows.comServer extension cannot coexist with a partial-trust
        # entry point — MakeAppx rejects it ("The 'windows.comServer' Extension
        # can't be declared with Partial Trust EntryPoint", 0x80080204). A COM
        # shell extension (e.g. NppShell) therefore blocks isolation outright.
        # -RemoveComServer strips it (plus the context-menu verbs that need it);
        # otherwise fail fast with guidance instead of a cryptic repack error.
        $comServers = @($manifest.SelectNodes("//*[local-name()='Extension' and @Category='windows.comServer']"))
        if ($comServers.Count -gt 0) {
            if (-not $RemoveComServer) {
                throw "Cannot isolate this package: it declares a 'windows.comServer' extension, which is incompatible with the partial-trust (AppContainer) entry point that isolation requires. Re-run with -RemoveComServer to strip the COM server and its shell context-menu (losing that functionality), or remove them manually first."
            }
            foreach ($node in $comServers) {
                $null = $node.ParentNode.RemoveChild($node)
            }
            Write-MsixLog -Level Warning -Message "Removed $($comServers.Count) windows.comServer extension(s) (-RemoveComServer): COM activation from this package is gone."

            # The desktop4/desktop9 context-menu verbs reference the removed
            # COM classes; without their server they are dead weight (and the
            # classic handler category is itself full-trust-only). Strip them.
            $menuCats = 'windows.fileExplorerContextMenus', 'windows.fileExplorerClassicContextMenuHandler'
            foreach ($cat in $menuCats) {
                foreach ($node in @($manifest.SelectNodes("//*[local-name()='Extension' and @Category='$cat']"))) {
                    $null = $node.ParentNode.RemoveChild($node)
                    Write-MsixLog -Level Warning -Message "Removed '$cat' extension (-RemoveComServer): its COM server no longer exists. The Explorer context menu is gone."
                }
            }
            # Prune Extensions containers left empty by the removals.
            foreach ($ext in @($manifest.SelectNodes("//*[local-name()='Extensions']"))) {
                if (-not $ext.HasChildNodes) { $null = $ext.ParentNode.RemoveChild($ext) }
            }
        }

        foreach ($app in $apps) {
            # PSF launcher cannot be isolated (cross-process DLL injection is
            # blocked in an AppContainer).
            $exe = $app.GetAttribute('Executable')
            if ($exe -match 'PsfLauncher\d*\.exe$') {
                Write-MsixLog -Level Warning -Message "Application '$($app.GetAttribute('Id'))' launches via the Package Support Framework (Executable '$exe'). PSF and AppContainer isolation are mutually exclusive: PSF injects fixup DLLs into the target process, which AppContainer blocks. This package will NOT run isolated. Run Remove-MsixPsf first to strip the framework and restore the real executable."
            }

            # The partial-trust entry point is what lets the app drop to
            # AppContainer (and lets runFullTrust be removed — the full-trust
            # entry point hard-requires it, which keeps the process full-trust).
            $app.SetAttribute('EntryPoint', 'Windows.PartialTrustApplication')

            # Idempotent + clean mode switch: remove any prior isolation attrs in
            # BOTH namespaces before setting the mode-specific ones.
            foreach ($ln in 'EntryPoint', 'TrustLevel', 'RuntimeBehavior') {
                foreach ($uri in $uap10Uri, $uap18Uri) {
                    $old = $app.GetAttributeNode($ln, $uri)
                    if ($old) { $null = $app.Attributes.Remove($old) }
                }
            }

            if ($Mode -eq 'AppSilo') {
                $attrs = @(
                    @{ Prefix = 'uap18'; Uri = $uap18Uri; Name = 'EntryPoint';      Value = 'Isolated.App' },
                    @{ Prefix = 'uap18'; Uri = $uap18Uri; Name = 'TrustLevel';      Value = 'appContainer' },
                    @{ Prefix = 'uap18'; Uri = $uap18Uri; Name = 'RuntimeBehavior'; Value = 'appSilo' }
                )
            } else {
                $attrs = @(
                    @{ Prefix = 'uap10'; Uri = $uap10Uri; Name = 'TrustLevel';      Value = 'appContainer' },
                    @{ Prefix = 'uap10'; Uri = $uap10Uri; Name = 'RuntimeBehavior'; Value = 'packagedClassicApp' }
                )
            }
            foreach ($a in $attrs) {
                $attr = $manifest.CreateAttribute($a.Prefix, $a.Name, $a.Uri)
                $attr.Value = $a.Value
                $null = $app.Attributes.Append($attr)
            }
            Write-MsixLog -Level Info -Message "Isolation set on Application '$($app.GetAttribute('Id'))' (Mode=$Mode, EntryPoint=Windows.PartialTrustApplication, TrustLevel=appContainer)."
        }

        # ── Capabilities block ────────────────────────────────────────────────
        $capsNode = $manifest.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
            $null     = $manifest.Package.AppendChild($capsNode)
        }

        # runFullTrust is incompatible with AppContainer and is NOT required by
        # the partial-trust entry point. Always remove it — this is the change
        # that actually lets the app fall into the AppContainer.
        foreach ($n in @($capsNode.ChildNodes)) {
            if ($n.LocalName -eq 'Capability' -and $n.GetAttribute('Name') -eq 'runFullTrust') {
                $null = $capsNode.RemoveChild($n)
                Write-MsixLog -Level Info -Message 'Removed runFullTrust (incompatible with AppContainer; the partial-trust entry point does not require it).'
            }
        }

        # Assemble the capability list.
        $wantedCaps = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $Capabilities) { if ($c) { $null = $wantedCaps.Add($c) } }

        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
        foreach ($cap in $wantedCaps) {
            if ($Mode -eq 'AppContainer' -and $cap -like 'isolatedWin32-*') { continue }  # warned earlier

            $isDeviceCap = $script:KnownIsolationDeviceCapabilities.Contains($cap)

            # Pick element + namespace.
            if ($isDeviceCap) {
                $localName = 'DeviceCapability'
            } else {
                $localName = 'Capability'
            }

            # Idempotency: skip if already present (match LocalName + Name).
            $exists = $false
            foreach ($child in $capsNode.ChildNodes) {
                if ($child.LocalName -eq $localName -and $child.GetAttribute('Name') -eq $cap) { $exists = $true; break }
            }
            if ($exists) { Write-MsixLog -Level Info -Message "Capability already present: $cap"; continue }

            if ($isDeviceCap) {
                $node = $manifest.CreateElement('DeviceCapability', $manifest.Package.NamespaceURI)
            }
            elseif ($Mode -eq 'AppSilo') {
                # isolatedWin32-* live in rescap.
                $node = $manifest.CreateElement('rescap:Capability', $rescapUri)
            }
            else {
                # AppContainer: resolve a standard package capability to its namespace.
                $ns = $script:KnownCapabilities[$cap]
                if ($ns -and $ns -ne 'standard') {
                    Add-MsixManifestNamespace -Manifest $manifest -Prefix $ns
                    $nsUri = Get-MsixManifestNamespaceUri -Prefix $ns
                    $node  = $manifest.CreateElement("${ns}:Capability", $nsUri)
                } else {
                    if (-not $ns) {
                        Write-MsixLog -Level Warning -Message "Capability '$cap' is not in the known-capabilities table; emitting a plain <Capability>. Verify it is valid for an AppContainer app."
                    }
                    $node = $manifest.CreateElement('Capability', $manifest.Package.NamespaceURI)
                }
            }
            $node.SetAttribute('Name', $cap)
            $null = $capsNode.AppendChild($node)
            Write-MsixLog -Level Info -Message "Capability added: $cap"
        }
}


function Remove-MsixAppIsolation {
    <#
    .SYNOPSIS
        Reverses Add-MsixAppIsolation: returns the app to a normal full-trust
        packaged app (Windows.FullTrustApplication + runFullTrust) and strips the
        AppContainer / appSilo attributes and isolatedWin32-* capabilities.

    .DESCRIPTION
        Removes the uap10/uap18 isolation attributes (TrustLevel / RuntimeBehavior
        / uap18:EntryPoint) from each <Application>, sets EntryPoint back to
        "Windows.FullTrustApplication", re-adds the runFullTrust capability (the
        normal packaged-Win32 default), and deletes any isolatedWin32-* capabilities.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package.

    .PARAMETER Pfx
        Signing certificate.

    .PARAMETER PfxPassword
        Signing certificate.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    PROCESS {
        # Pre-check: any isolation attrs or isolatedWin32-* caps present?
        $preCheck  = Get-MsixManifest -Path $PackagePath
        $uap10Uri  = Get-MsixManifestNamespaceUri -Prefix 'uap10'
        $uap18Uri  = Get-MsixManifestNamespaceUri -Prefix 'uap18'
        $hasCaps = @($preCheck.Package.Capabilities.ChildNodes) |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.Name -like 'isolatedWin32-*' }
        $hasAttrs = @($preCheck.Package.Applications.Application) | Where-Object {
            $_.GetAttributeNode('TrustLevel', $uap10Uri) -or $_.GetAttributeNode('RuntimeBehavior', $uap10Uri) -or
            $_.GetAttributeNode('TrustLevel', $uap18Uri) -or $_.GetAttributeNode('RuntimeBehavior', $uap18Uri)
        }
        if (-not $hasCaps -and -not $hasAttrs) {
            Write-MsixLog -Level Info -Message 'No isolation capabilities or attributes found; nothing to do.'
            return
        }

        $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Remove App Isolation')

        _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
            -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
            -WhatIfPreview:$isWhatIf `
            -Activity 'Remove App Isolation' -Mutate {
            param([xml]$manifest)

            $u10 = Get-MsixManifestNamespaceUri -Prefix 'uap10'
            $u18 = Get-MsixManifestNamespaceUri -Prefix 'uap18'

            foreach ($app in @($manifest.Package.Applications.Application)) {
                # Strip uap10 + uap18 isolation attributes.
                foreach ($ln in 'EntryPoint', 'TrustLevel', 'RuntimeBehavior') {
                    foreach ($uri in $u10, $u18) {
                        $node = $app.GetAttributeNode($ln, $uri)
                        if ($node) {
                            $null = $app.Attributes.Remove($node)
                            Write-MsixLog -Level Info -Message "Removed isolation attribute $ln from Application '$($app.GetAttribute('Id'))'."
                        }
                    }
                }
                # Restore the normal full-trust packaged-Win32 entry point.
                $app.SetAttribute('EntryPoint', 'Windows.FullTrustApplication')
            }

            $capsNode = $manifest.Package.Capabilities
            if (-not $capsNode) {
                $capsNode = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
                $null     = $manifest.Package.AppendChild($capsNode)
            }

            # Strip isolatedWin32-* capabilities.
            foreach ($n in @($capsNode.ChildNodes)) {
                if ($n.LocalName -eq 'Capability' -and $n.Name -like 'isolatedWin32-*') {
                    $null = $capsNode.RemoveChild($n)
                    Write-MsixLog -Level Info -Message "Removed: $($n.Name)"
                }
            }

            # Re-add runFullTrust (required by the restored full-trust entry point).
            $hasRft = $false
            foreach ($n in $capsNode.ChildNodes) {
                if ($n.LocalName -eq 'Capability' -and $n.GetAttribute('Name') -eq 'runFullTrust') { $hasRft = $true; break }
            }
            if (-not $hasRft) {
                Add-MsixManifestNamespace -Manifest $manifest -Prefix 'rescap'
                $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
                $rft = $manifest.CreateElement('rescap:Capability', $rescapUri)
                $rft.SetAttribute('Name', 'runFullTrust')
                $null = $capsNode.AppendChild($rft)
                Write-MsixLog -Level Info -Message 'Re-added runFullTrust (required by Windows.FullTrustApplication).'
            }
        }
    }
}


function Test-MsixIsolation {
    <#
    .SYNOPSIS
        Verifies whether a package WOULD isolate (static manifest check) or a
        running process actually IS isolated (AppContainer token check).

    .DESCRIPTION
        Two modes:

        Package (static): parses the manifest and reports EntryPoint, trust
        level, runtime behavior, detected isolation Mode (None / AppContainer /
        AppSilo), runFullTrust presence, blockers (PSF launcher entry point,
        windows.comServer extension) and a bottom-line WouldIsolate verdict
        with reasons. This catches the classic trap: a manifest that LOOKS
        isolated (uap18 attributes present) but keeps the full-trust entry
        point + runFullTrust and therefore never isolates.

        Process (runtime): reads the process token and reports IsAppContainer
        (the definitive S-1-15-2-* AppContainer SID check), the SID, the
        integrity level and the executable path — so a same-named desktop
        install can't be mistaken for the packaged app. Prompts alone are NOT
        proof of isolation (ASR rules also prompt); the token is.

    .PARAMETER PackagePath
        Static mode: the .msix file to analyse (read-only).

    .PARAMETER ProcessId
        Runtime mode: a process id to inspect.

    .PARAMETER PackageFamilyName
        Runtime mode: inspect every running process whose executable lives in
        this installed package's InstallLocation.

    .EXAMPLE
        # Before install: will this package isolate?
        Test-MsixIsolation -PackagePath .\app-isolated.msix

    .EXAMPLE
        # After launch: is the packaged app REALLY in an AppContainer?
        Test-MsixIsolation -PackageFamilyName 'NotepadPP_abcdef123'

    .EXAMPLE
        # Spot-check a single process
        Test-MsixIsolation -ProcessId 4242

    .OUTPUTS
        Static: [pscustomobject] with Mode, EntryPoint, TrustLevel,
        RuntimeBehavior, HasRunFullTrust, Blockers, WouldIsolate, Reasons.
        Runtime: [pscustomobject] per process with IsAppContainer,
        AppContainerSid, IntegrityLevel, ExecutablePath, Isolated.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Package')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Package')]
        [string]$PackagePath,
        [Parameter(Mandatory, ParameterSetName = 'Process')]
        [int]$ProcessId,
        [Parameter(Mandatory, ParameterSetName = 'Family')]
        [string]$PackageFamilyName
    )

    if ($PSCmdlet.ParameterSetName -eq 'Package') {
        [xml]$manifest = Get-MsixManifest -Path $PackagePath

        $uap10Uri = Get-MsixManifestNamespaceUri -Prefix 'uap10'
        $uap18Uri = Get-MsixManifestNamespaceUri -Prefix 'uap18'

        $capsNode = $manifest.Package.Capabilities
        $hasRft = $false
        if ($capsNode) {
            $hasRft = [bool]($capsNode.ChildNodes | Where-Object {
                $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust' })
        }
        $hasComServer = $null -ne $manifest.SelectSingleNode("//*[local-name()='Extension' and @Category='windows.comServer']")

        foreach ($app in @($manifest.Package.Applications.Application)) {
            $entry   = $app.GetAttribute('EntryPoint')
            $tl10    = $app.GetAttribute('TrustLevel', $uap10Uri)
            $rb10    = $app.GetAttribute('RuntimeBehavior', $uap10Uri)
            $tl18    = $app.GetAttribute('TrustLevel', $uap18Uri)
            $rb18    = $app.GetAttribute('RuntimeBehavior', $uap18Uri)
            $exe     = $app.GetAttribute('Executable')

            $mode = 'None'
            if ($rb18 -eq 'appSilo') { $mode = 'AppSilo' }
            elseif ($rb10 -eq 'packagedClassicApp' -and $tl10 -eq 'appContainer') { $mode = 'AppContainer' }

            $trustLevel = $tl18
            if (-not $trustLevel) { $trustLevel = $tl10 }
            $runtimeBehavior = $rb18
            if (-not $runtimeBehavior) { $runtimeBehavior = $rb10 }

            $blockers = [System.Collections.Generic.List[string]]::new()
            if ($exe -match 'PsfLauncher\d*\.exe$') { $null = $blockers.Add('PSF launcher entry point (fixup injection is blocked in an AppContainer)') }
            if ($hasComServer) { $null = $blockers.Add('windows.comServer extension (invalid with a partial-trust entry point)') }

            $reasons = [System.Collections.Generic.List[string]]::new()
            if ($mode -eq 'None')  { $null = $reasons.Add('no AppContainer/AppSilo runtime behavior declared') }
            if ($entry -ne 'Windows.PartialTrustApplication') { $null = $reasons.Add("EntryPoint is '$entry' — must be 'Windows.PartialTrustApplication' to drop into an AppContainer") }
            if ($hasRft) { $null = $reasons.Add('runFullTrust capability present — keeps the process full-trust') }
            foreach ($b in $blockers) { $null = $reasons.Add($b) }

            $minVersionOk = $true
            if ($mode -eq 'AppSilo') {
                $tdf = @($manifest.Package.Dependencies.TargetDeviceFamily) |
                    Where-Object { $_.GetAttribute('Name') -eq 'Windows.Desktop' } | Select-Object -First 1
                $minVersionOk = $false
                if ($tdf) {
                    $v = $null
                    if ([version]::TryParse($tdf.GetAttribute('MinVersion'), [ref]$v)) { $minVersionOk = ($v -ge [version]'10.0.26100.0') }
                }
                if (-not $minVersionOk) { $null = $reasons.Add('AppSilo requires Windows.Desktop MinVersion 10.0.26100.0') }
            }

            [pscustomobject]@{
                PSTypeName       = 'MSIX.IsolationStatus'
                ApplicationId    = $app.GetAttribute('Id')
                Executable       = $exe
                Mode             = $mode
                EntryPoint       = $entry
                TrustLevel       = $trustLevel
                RuntimeBehavior  = $runtimeBehavior
                HasRunFullTrust  = $hasRft
                Blockers         = @($blockers)
                WouldIsolate     = ($reasons.Count -eq 0)
                Reasons          = @($reasons)
            }
        }
        return
    }

    # ── Runtime: process-token inspection ────────────────────────────────
    _MsixEnsureTokenInspector

    $procs = @()
    if ($PSCmdlet.ParameterSetName -eq 'Process') {
        $procs = @(Get-Process -Id $ProcessId -ErrorAction Stop)
    } else {
        $pkg = Get-AppxPackage | Where-Object { $_.PackageFamilyName -eq $PackageFamilyName } | Select-Object -First 1
        if (-not $pkg) { throw "Installed package with family name '$PackageFamilyName' not found for the current user." }
        $loc = $pkg.InstallLocation
        $procs = @(Get-Process | Where-Object { $_.Path -and $_.Path.StartsWith($loc, [System.StringComparison]::OrdinalIgnoreCase) })
        if (-not $procs) {
            Write-MsixLog -Level Warning -Message "No running processes found under '$loc'. Launch the packaged app first (and note: a same-named desktop install does not count)."
            return
        }
    }

    foreach ($p in $procs) {
        $info = [MsixTokenInspector]::Inspect($p.Id)
        $integrity = switch ($info.IntegrityRid) {
            { $_ -lt 0x1000 }  { 'Untrusted'; break }
            { $_ -lt 0x2000 }  { 'Low'; break }
            { $_ -lt 0x3000 }  { 'Medium'; break }
            { $_ -lt 0x4000 }  { 'High'; break }
            default            { 'System' }
        }
        [pscustomobject]@{
            PSTypeName      = 'MSIX.IsolationRuntimeStatus'
            ProcessId       = $p.Id
            ProcessName     = $p.ProcessName
            ExecutablePath  = $p.Path
            IsPackagedPath  = ($p.Path -like '*\WindowsApps\*')
            IsAppContainer  = $info.IsAppContainer
            AppContainerSid = $info.AppContainerSid
            IntegrityLevel  = $integrity
            Isolated        = $info.IsAppContainer
        }
    }
}


function _MsixEnsureTokenInspector {
    # Compiles the P/Invoke token inspector once per session. Reading ANOTHER
    # process's token requires QueryLimitedInformation access; the definitive
    # isolation signal is TokenIsAppContainer + the S-1-15-2-* AppContainer SID.
    if ('MsixTokenInspector' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public class MsixTokenInfo
{
    public bool IsAppContainer;
    public string AppContainerSid;
    public uint IntegrityRid;
}

public static class MsixTokenInspector
{
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr token, int infoClass, IntPtr info, int len, out int retLen);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    static extern bool ConvertSidToStringSid(IntPtr sid, out string sidString);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthority(IntPtr sid, uint index);
    [DllImport("advapi32.dll")]
    static extern IntPtr GetSidSubAuthorityCount(IntPtr sid);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr handle);

    const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    const uint TOKEN_QUERY = 0x0008;
    const int TokenIntegrityLevel = 25;
    const int TokenIsAppContainer = 29;
    const int TokenAppContainerSid = 31;

    public static MsixTokenInfo Inspect(int pid)
    {
        MsixTokenInfo result = new MsixTokenInfo();
        IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (process == IntPtr.Zero)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed for PID " + pid);
        IntPtr token = IntPtr.Zero;
        try
        {
            if (!OpenProcessToken(process, TOKEN_QUERY, out token))
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed for PID " + pid);

            int retLen;
            IntPtr buf = Marshal.AllocHGlobal(4);
            try
            {
                if (GetTokenInformation(token, TokenIsAppContainer, buf, 4, out retLen))
                    result.IsAppContainer = Marshal.ReadInt32(buf) != 0;
            }
            finally { Marshal.FreeHGlobal(buf); }

            if (result.IsAppContainer)
            {
                GetTokenInformation(token, TokenAppContainerSid, IntPtr.Zero, 0, out retLen);
                if (retLen > 0)
                {
                    IntPtr acBuf = Marshal.AllocHGlobal(retLen);
                    try
                    {
                        if (GetTokenInformation(token, TokenAppContainerSid, acBuf, retLen, out retLen))
                        {
                            IntPtr sid = Marshal.ReadIntPtr(acBuf);   // TOKEN_APPCONTAINER_INFORMATION.TokenAppContainer
                            string sidString;
                            if (sid != IntPtr.Zero && ConvertSidToStringSid(sid, out sidString))
                                result.AppContainerSid = sidString;
                        }
                    }
                    finally { Marshal.FreeHGlobal(acBuf); }
                }
            }

            GetTokenInformation(token, TokenIntegrityLevel, IntPtr.Zero, 0, out retLen);
            if (retLen > 0)
            {
                IntPtr ilBuf = Marshal.AllocHGlobal(retLen);
                try
                {
                    if (GetTokenInformation(token, TokenIntegrityLevel, ilBuf, retLen, out retLen))
                    {
                        IntPtr sid = Marshal.ReadIntPtr(ilBuf);       // TOKEN_MANDATORY_LABEL.Label.Sid
                        if (sid != IntPtr.Zero)
                        {
                            byte count = Marshal.ReadByte(GetSidSubAuthorityCount(sid));
                            result.IntegrityRid = (uint)Marshal.ReadInt32(GetSidSubAuthority(sid, (uint)(count - 1)));
                        }
                    }
                }
                finally { Marshal.FreeHGlobal(ilBuf); }
            }
        }
        finally
        {
            if (token != IntPtr.Zero) CloseHandle(token);
            CloseHandle(process);
        }
        return result;
    }
}
'@
}


function Get-MsixIsolationAdvice {
    <#
    .SYNOPSIS
        Turns access-denied rows from a ProcMon trace of an isolated app into
        concrete capability / consent suggestions for Add-MsixAppIsolation.

    .DESCRIPTION
        Run the app under isolation, capture with Invoke-MsixProcMonCapture,
        pull the failures with Get-MsixProcMonFailure, and feed them here.
        Each ACCESS DENIED row is mapped to a suggestion:

          - user-profile paths     -> AppSilo: isolatedWin32-promptForAccess /
                                      isolatedWin32-userProfileMinimal;
                                      AppContainer: use the file dialog (implicit
                                      consent) — no standard capability grants
                                      broad profile access.
          - ProgramData\<publisher> -> isolatedWin32-accessToPublisherDirectory.
          - TCP/UDP operations      -> internetClient (AppContainer) /
                                      isolatedWin32-internetClient (AppSilo).
          - HKLM writes             -> no capability exists; the app needs a
                                      code change or cannot be isolated.

        Suggestions are aggregated (one per capability) with example paths and
        hit counts, ordered by hits.

    .PARAMETER Failures
        Failure rows (from Get-MsixProcMonFailure) or any objects with
        Path / Operation / Result properties. Accepts pipeline input.

    .PARAMETER CsvPath
        Alternative input: a ProcMon CSV export to read directly.

    .PARAMETER Mode
        Which isolation mode you are targeting; picks the capability
        vocabulary for the suggestions. Default: AppSilo.

    .EXAMPLE
        $pml  = Invoke-MsixProcMonCapture -ScriptBlock { Start-Process notepad++ -Wait }
        Get-MsixProcMonFailure -PmlPath $pml | Get-MsixIsolationAdvice -Mode AppSilo

    .EXAMPLE
        Get-MsixIsolationAdvice -CsvPath .\trace.csv -Mode AppContainer

    .OUTPUTS
        [pscustomobject] per suggestion: SuggestedCapability, Mode, Hits,
        ExamplePaths, Rationale.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Objects')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(ParameterSetName = 'Objects', ValueFromPipeline)]
        [object[]]$Failures,
        [Parameter(Mandatory, ParameterSetName = 'Csv')]
        [string]$CsvPath,
        [ValidateSet('AppContainer', 'AppSilo')]
        [string]$Mode = 'AppSilo'
    )

    BEGIN {
        $all = [System.Collections.Generic.List[object]]::new()
    }
    PROCESS {
        foreach ($f in @($Failures)) { if ($null -ne $f) { $null = $all.Add($f) } }
    }
    END {
        if ($PSCmdlet.ParameterSetName -eq 'Csv') {
            if (-not (Test-Path -LiteralPath $CsvPath)) { throw "CSV not found: $CsvPath" }
            foreach ($row in (Import-Csv -Path $CsvPath)) { $null = $all.Add($row) }
        }

        $denied = @($all | Where-Object { $_.Result -match 'ACCESS DENIED|ACCESS_DENIED' })
        if (-not $denied) {
            Write-MsixLog -Level Info -Message 'No ACCESS DENIED rows found — nothing blocked; no additional capabilities suggested.'
            return
        }

        $profileRx  = '\\Users\\[^\\]+\\(Documents|Desktop|Pictures|Music|Videos|Downloads)'
        $progDataRx = '\\ProgramData\\'
        $hklmRx     = '^HKLM'
        $netRx      = '^(TCP|UDP)'

        $buckets = @{}
        function script:_MsixAdviceAdd {
            param([hashtable]$Buckets, [string]$Key, [string]$Capability, [string]$Rationale, [object]$Row)
            if (-not $Buckets.ContainsKey($Key)) {
                $Buckets[$Key] = @{ Capability = $Capability; Rationale = $Rationale; Hits = 0; Paths = [System.Collections.Generic.List[string]]::new() }
            }
            $Buckets[$Key].Hits++
            $p = [string]$Row.Path
            if ($p -and $Buckets[$Key].Paths.Count -lt 5 -and -not $Buckets[$Key].Paths.Contains($p)) { $null = $Buckets[$Key].Paths.Add($p) }
        }

        foreach ($row in $denied) {
            $path = [string]$row.Path
            $op   = [string]$row.Operation

            if ($op -match $netRx) {
                $cap = if ($Mode -eq 'AppSilo') { 'isolatedWin32-internetClient' } else { 'internetClient' }
                _MsixAdviceAdd -Buckets $buckets -Key 'net' -Capability $cap -Rationale 'Network operations were denied.' -Row $row
            }
            elseif ($path -match $hklmRx -and $op -match 'RegSetValue|RegCreateKey') {
                _MsixAdviceAdd -Buckets $buckets -Key 'hklm' -Capability '(none — HKLM writes)' -Rationale 'The app writes to HKLM. No isolation capability grants that; the app needs a code change (per-user settings) or cannot be isolated.' -Row $row
            }
            elseif ($path -match $progDataRx) {
                _MsixAdviceAdd -Buckets $buckets -Key 'progdata' -Capability 'isolatedWin32-accessToPublisherDirectory' -Rationale 'ProgramData access: works if the directory name ends with your publisher ID (AppSilo publisher-directory consent).' -Row $row
            }
            elseif ($path -match $profileRx) {
                $cap = if ($Mode -eq 'AppSilo') { 'isolatedWin32-promptForAccess' } else { '(implicit consent — use the file dialog)' }
                $why = if ($Mode -eq 'AppSilo') { 'User-profile file access denied; the broker prompts on first access (alternative: isolatedWin32-userProfileMinimal for silent minimal access).' } else { 'User-profile access is denied in AppContainer mode; only user-driven flows (file dialog / FTA / drag-drop) grant it. Consider -Mode AppSilo for brokered prompts.' }
                _MsixAdviceAdd -Buckets $buckets -Key 'profile' -Capability $cap -Rationale $why -Row $row
            }
            else {
                _MsixAdviceAdd -Buckets $buckets -Key 'other' -Capability '(review individually)' -Rationale 'Denied paths outside the known consent patterns — check whether the app can take a code change, or validate under -Mode AppSilo with isolatedWin32-promptForAccess.' -Row $row
            }
        }

        $buckets.Values | Sort-Object -Property Hits -Descending | ForEach-Object {
            [pscustomobject]@{
                PSTypeName          = 'MSIX.IsolationAdvice'
                SuggestedCapability = $_.Capability
                Mode                = $Mode
                Hits                = $_.Hits
                ExamplePaths        = @($_.Paths)
                Rationale           = $_.Rationale
            }
        }
    }
}


# Backward-compatible plural aliases
Set-Alias Get-MsixIsolationCapabilities Get-MsixIsolationCapability
