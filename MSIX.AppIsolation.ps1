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
        Enables Win32 App Isolation on an MSIX package: sets the uap18 isolation
        attributes on each <Application>, declares the requested isolated-Win32
        capabilities, and reconciles the runFullTrust capability.

    .DESCRIPTION
        Adding an isolatedWin32-* capability alone does NOT isolate an app — the
        isolation is switched on by the uap18 attributes on <Application>. This
        cmdlet writes the full set the MS Learn guidance requires:

          - Declares the `uap18` and `rescap` namespaces (and adds them to
            IgnorableNamespaces) if absent.
          - On every <Application> (or just -AppId), sets:
                EntryPoint="Windows.FullTrustApplication"
                uap18:EntryPoint="Isolated.App"
                uap18:TrustLevel="appContainer"
                uap18:RuntimeBehavior="appSilo"
          - Adds one <rescap:Capability>/<DeviceCapability> per -Capabilities.
          - If the package has a COM context-menu (windows.comServer /
            FileExplorerContextMenus), auto-adds
            `isolatedWin32-shellExtensionContextMenu` so the menu runs under
            isolation.
          - Ensures runFullTrust (see below).
          - Bumps MaxVersionTested to 10.0.26100.0 (the documented minimum).

        runFullTrust: an isolated app keeps EntryPoint="Windows.FullTrustApplication"
        (the down-level entry point), and the AppxManifest schema REQUIRES the
        runFullTrust capability for that entry point — MakeAppx rejects the
        package without it (error 80080204). runFullTrust and isolation are
        therefore NOT mutually exclusive; they are required together. Isolation
        is enforced by the uap18 appContainer/appSilo attributes, not by the
        absence of runFullTrust.
          - Default: ENSURE runFullTrust is present (add if missing) and log why.
          - -RemoveRunFullTrust: force-remove it. Warns that the repack will fail
            on toolchains that still require it for the FullTrust entry point.
          - -KeepRunFullTrust: retain it silently (the default already keeps it;
            this just suppresses the explanatory note).

        Repacks and re-signs the package.

        WARNING: this is opt-in. Many existing MSIX packages will break under
        isolation because the app expects broad filesystem/registry access.
        Validate with the Application Capability Profiler (ACP) first:
        https://github.com/microsoft/win32-app-isolation/releases

    .PARAMETER PackagePath
        .msix file to modify.

    .PARAMETER Capabilities
        Capabilities to add. Defaults to a conservative starter set:
        promptForAccess + accessFromLowIntegrityLevel.

    .PARAMETER AppId
        Restrict the uap18 isolation attributes to the Application with this Id.
        Default: every <Application> in the package.

    .PARAMETER RemoveRunFullTrust
        Force-remove the runFullTrust capability even when a blocking extension
        (e.g. firewallRules) is present.

    .PARAMETER KeepRunFullTrust
        Never remove the runFullTrust capability.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package.

    .PARAMETER Pfx / PfxPassword
        Signing certificate.

    .EXAMPLE
        Add-MsixAppIsolation -PackagePath app.msix `
            -Capabilities 'isolatedWin32-promptForAccess','isolatedWin32-userProfileMinimal' `
            -Pfx cert.pfx -PfxPassword 'P@ss'

    .EXAMPLE
        # A packaged Win32 app whose only full-trust reason is its shell
        # context menu: isolation keeps the menu via the isolation capability
        # and drops runFullTrust automatically.
        Add-MsixAppIsolation -PackagePath npp.msix -SkipSigning
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'AppId',
        Justification = 'Captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [string[]]$Capabilities = @(
            'isolatedWin32-promptForAccess',
            'isolatedWin32-accessFromLowIntegrityLevel'
        ),
        [string]$AppId,
        [switch]$RemoveRunFullTrust,
        [switch]$KeepRunFullTrust,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if ($RemoveRunFullTrust -and $KeepRunFullTrust) {
        throw '-RemoveRunFullTrust and -KeepRunFullTrust are mutually exclusive.'
    }

    foreach ($c in $Capabilities) {
        $knownIsolated = $script:KnownIsolationCapabilities.Contains($c)
        $knownDevice   = $script:KnownIsolationDeviceCapabilities.Contains($c)
        if (-not $knownIsolated -and -not $knownDevice) {
            Write-MsixLog -Level Warning -Message "'$c' is not in the documented capability set. Verify against MS Learn before publishing."
        }
    }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add App Isolation')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -WhatIfPreview:$isWhatIf `
        -Activity 'Add App Isolation' -Mutate {
        param([xml]$manifest)

        Add-MsixManifestNamespace -Manifest $manifest -Prefix 'uap18'
        Add-MsixManifestNamespace -Manifest $manifest -Prefix 'rescap'
        # Win32 App Isolation requires Win11 24H2 (build 26100)
        Set-MsixManifestMaxVersionTested -Manifest $manifest -MinBuild 26100

        $uap18Uri  = Get-MsixManifestNamespaceUri -Prefix 'uap18'
        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'

        # ── Application isolation attributes ──────────────────────────────────
        # These are what actually enable isolation; the capability alone does not.
        $apps = @($manifest.Package.Applications.Application)
        if ($AppId) {
            $apps = @($apps | Where-Object { $_.GetAttribute('Id') -eq $AppId })
            if (-not $apps) { throw "Application '$AppId' not found in the manifest." }
        }
        if (-not $apps) { throw 'No <Application> element found in the manifest.' }

        foreach ($app in $apps) {
            # Base entry point stays Windows.FullTrustApplication (down-level OS
            # ignores the uap18 attrs and runs the app as a normal Win32 app).
            $app.SetAttribute('EntryPoint', 'Windows.FullTrustApplication')

            foreach ($pair in @(
                @{ Name = 'EntryPoint';      Value = 'Isolated.App'  },
                @{ Name = 'TrustLevel';      Value = 'appContainer'  },
                @{ Name = 'RuntimeBehavior'; Value = 'appSilo'       }
            )) {
                # Idempotent: drop any existing uap18:<name> before re-adding so
                # re-runs don't duplicate, and a CreateAttribute(prefix,...) keeps
                # the serialized prefix deterministic (uap18:).
                $old = $app.GetAttributeNode($pair.Name, $uap18Uri)
                if ($old) { $null = $app.Attributes.Remove($old) }
                $attr = $manifest.CreateAttribute('uap18', $pair.Name, $uap18Uri)
                $attr.Value = $pair.Value
                $null = $app.Attributes.Append($attr)
            }
            $idForLog = $app.GetAttribute('Id')
            Write-MsixLog -Level Info -Message "Isolation attributes set on Application '$idForLog' (TrustLevel=appContainer, RuntimeBehavior=appSilo)."
        }

        # ── Capabilities block ────────────────────────────────────────────────
        $capsNode = $manifest.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
            $null     = $manifest.Package.AppendChild($capsNode)
        }

        # If the package surfaces a COM-based shell context menu, it needs the
        # isolation-native capability (the replacement for runFullTrust for that
        # extension). Auto-include it so the menu survives isolation.
        $wantedCaps = [System.Collections.Generic.List[string]]::new()
        foreach ($c in $Capabilities) { $wantedCaps.Add($c) }
        $hasComServer = $null -ne $manifest.SelectSingleNode("//*[local-name()='Extension' and @Category='windows.comServer']")
        $hasCtxMenu   = $null -ne $manifest.SelectSingleNode("//*[local-name()='FileExplorerContextMenus']")
        if (($hasComServer -or $hasCtxMenu) -and -not $wantedCaps.Contains('isolatedWin32-shellExtensionContextMenu')) {
            $wantedCaps.Add('isolatedWin32-shellExtensionContextMenu')
            Write-MsixLog -Level Info -Message 'COM context-menu detected: auto-adding isolatedWin32-shellExtensionContextMenu (isolation-native replacement for runFullTrust).'
        }

        foreach ($cap in $wantedCaps) {
            # Device capabilities use <DeviceCapability> (default namespace);
            # isolatedWin32-* capabilities use <rescap:Capability>.
            $isDeviceCap = $script:KnownIsolationDeviceCapabilities.Contains($cap)
            $targetLocal = if ($isDeviceCap) { 'DeviceCapability' } else { 'Capability' }

            $alreadyThere = $false
            foreach ($child in $capsNode.ChildNodes) {
                if ($child.LocalName -eq $targetLocal -and $child.GetAttribute('Name') -eq $cap) {
                    $alreadyThere = $true
                    break
                }
            }
            if ($alreadyThere) {
                Write-MsixLog -Level Info -Message "Capability already present: $cap"
                continue
            }

            if ($isDeviceCap) {
                $node = $manifest.CreateElement('DeviceCapability', $manifest.Package.NamespaceURI)
            } else {
                $node = $manifest.CreateElement('rescap:Capability', $rescapUri)
            }
            $node.SetAttribute('Name', $cap)
            $null = $capsNode.AppendChild($node)
            Write-MsixLog -Level Info -Message "Capability added: $cap"
        }

        # ── runFullTrust reconciliation ───────────────────────────────────────
        # The isolated app retains EntryPoint="Windows.FullTrustApplication" (the
        # down-level entry point that lets it still run as a normal Win32 app on
        # OSes without isolation support). The AppxManifest schema REQUIRES the
        # runFullTrust capability for that entry point — MakeAppx rejects the
        # package without it (error 80080204). So by default we ENSURE
        # runFullTrust is present and explain why; the app is still isolated via
        # the uap18 appContainer/appSilo attributes, and a COM context menu runs
        # via isolatedWin32-shellExtensionContextMenu. -RemoveRunFullTrust forces
        # removal for toolchains/runtimes that accept the isolated entry point
        # without it (the repack will fail on toolchains that don't).
        $rftNode = $null
        foreach ($child in $capsNode.ChildNodes) {
            if ($child.LocalName -eq 'Capability' -and $child.GetAttribute('Name') -eq 'runFullTrust') {
                $rftNode = $child
                break
            }
        }
        if ($RemoveRunFullTrust) {
            if ($rftNode) { $null = $capsNode.RemoveChild($rftNode) }
            Write-MsixLog -Level Warning -Message 'Removed runFullTrust (-RemoveRunFullTrust). NOTE: EntryPoint="Windows.FullTrustApplication" normally requires it and MakeAppx may reject the repack (error 80080204) unless your packaging toolchain/runtime supports the isolated entry point without runFullTrust.'
        }
        else {
            if (-not $rftNode) {
                $rftNode = $manifest.CreateElement('rescap:Capability', $rescapUri)
                $rftNode.SetAttribute('Name', 'runFullTrust')
                $null = $capsNode.AppendChild($rftNode)
            }
            if ($KeepRunFullTrust) {
                Write-MsixLog -Level Info -Message 'runFullTrust retained (-KeepRunFullTrust).'
            } else {
                Write-MsixLog -Level Info -Message 'runFullTrust retained: required by EntryPoint="Windows.FullTrustApplication" (the down-level entry point the isolated app keeps). Isolation is enforced by uap18 appContainer/appSilo; a COM context menu runs via isolatedWin32-shellExtensionContextMenu. Pass -RemoveRunFullTrust only if your toolchain supports dropping it.'
            }
        }
    }
}


function Remove-MsixAppIsolation {
    <#
    .SYNOPSIS
        Reverses Add-MsixAppIsolation: strips every `isolatedWin32-*` capability
        and the uap18 isolation attributes (TrustLevel / RuntimeBehavior /
        uap18:EntryPoint) from each <Application>.

    .DESCRIPTION
        Removes the uap18 isolation attributes so the app no longer runs in an
        AppContainer silo, and deletes the isolatedWin32-* capabilities. The base
        EntryPoint="Windows.FullTrustApplication" is left intact. runFullTrust is
        NOT re-added — its original presence can't be inferred, so re-add it
        explicitly with Add-MsixCapability if the app needs it.

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
        # Quick pre-check: does the package have isolation caps OR uap18 attrs?
        $preCheck  = Get-MsixManifest -Path $PackagePath
        $uap18Uri  = Get-MsixManifestNamespaceUri -Prefix 'uap18'
        $hasCaps = @($preCheck.Package.Capabilities.ChildNodes) |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.Name -like 'isolatedWin32-*' }
        $hasAttrs = @($preCheck.Package.Applications.Application) |
            Where-Object { $_.GetAttributeNode('TrustLevel', $uap18Uri) -or $_.GetAttributeNode('RuntimeBehavior', $uap18Uri) }
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

            $u18 = Get-MsixManifestNamespaceUri -Prefix 'uap18'

            # Strip the uap18 isolation attributes from every Application.
            foreach ($app in @($manifest.Package.Applications.Application)) {
                foreach ($local in 'EntryPoint', 'TrustLevel', 'RuntimeBehavior') {
                    $node = $app.GetAttributeNode($local, $u18)
                    if ($node) {
                        $null = $app.Attributes.Remove($node)
                        Write-MsixLog -Level Info -Message "Removed uap18:$local from Application '$($app.GetAttribute('Id'))'."
                    }
                }
            }

            # Strip isolatedWin32-* capabilities.
            $capsNode = $manifest.Package.Capabilities
            if ($capsNode) {
                foreach ($n in @($capsNode.ChildNodes)) {
                    if ($n.LocalName -eq 'Capability' -and $n.Name -like 'isolatedWin32-*') {
                        $null = $capsNode.RemoveChild($n)
                        Write-MsixLog -Level Info -Message "Removed: $($n.Name)"
                    }
                }
            }
        }
    }
}


# Backward-compatible plural aliases
Set-Alias Get-MsixIsolationCapabilities Get-MsixIsolationCapability
