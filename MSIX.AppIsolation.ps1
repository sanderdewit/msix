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
        .msix file to modify.

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

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package.

    .PARAMETER Pfx / PfxPassword
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

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add App Isolation ($Mode)")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -WhatIfPreview:$isWhatIf `
        -Activity "Add App Isolation ($Mode)" -Mutate {
        param([xml]$manifest)

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
        # Fail fast with guidance instead of letting the repack die cryptically.
        if ($manifest.SelectSingleNode("//*[local-name()='Extension' and @Category='windows.comServer']")) {
            throw "Cannot isolate this package: it declares a 'windows.comServer' extension, which is incompatible with the partial-trust (AppContainer) entry point that isolation requires. Remove the COM server and its shell context-menu (the com:Extension 'windows.comServer' and the desktop4 'windows.fileExplorerContextMenus' extension) before isolating."
        }

        foreach ($app in $apps) {
            # PSF launcher cannot be isolated (cross-process DLL injection is
            # blocked in an AppContainer).
            $exe = $app.GetAttribute('Executable')
            if ($exe -match 'PsfLauncher\d*\.exe$') {
                Write-MsixLog -Level Warning -Message "Application '$($app.GetAttribute('Id'))' launches via the Package Support Framework (Executable '$exe'). PSF and AppContainer isolation are mutually exclusive: PSF injects fixup DLLs into the target process, which AppContainer blocks. This package will NOT run isolated. Re-package without PSF (point Executable at the real .exe; drop PsfLauncher*/PsfRuntime*/FileRedirectionFixup*/config.json) first."
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
        .msix file to modify.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package.

    .PARAMETER Pfx / PfxPassword
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


# Backward-compatible plural aliases
Set-Alias Get-MsixIsolationCapabilities Get-MsixIsolationCapability
