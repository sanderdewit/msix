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
        Enables Win32 App Isolation on an MSIX package by adding the rescap
        namespace and the requested isolated-Win32 capabilities to the manifest.

    .DESCRIPTION
        Modifies AppxManifest.xml to:
          - Declare the `rescap` namespace if not already present.
          - Add a <Capabilities> block (or augment the existing one).
          - Insert one <rescap:Capability Name="…"/> element per capability.
          - Bump MaxVersionTested to 10.0.26100.0 (the documented minimum).

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
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [string[]]$Capabilities = @(
            'isolatedWin32-promptForAccess',
            'isolatedWin32-accessFromLowIntegrityLevel'
        ),
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    foreach ($c in $Capabilities) {
        $knownIsolated = $script:KnownIsolationCapabilities.Contains($c)
        $knownDevice   = $script:KnownIsolationDeviceCapabilities.Contains($c)
        if (-not $knownIsolated -and -not $knownDevice) {
            Write-MsixLog -Level Warning -Message "'$c' is not in the documented capability set. Verify against MS Learn before publishing."
        }
    }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add App Isolation capabilities')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -WhatIfPreview:$isWhatIf `
        -Activity 'Add App Isolation capabilities' -Mutate {
        param([xml]$manifest)

        Add-MsixManifestNamespace -Manifest $manifest -Prefix 'rescap'
        # Win32 App Isolation requires Win11 24H2 (build 26100)
        Set-MsixManifestMaxVersionTested -Manifest $manifest -MinBuild 26100

        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
        $capsNode  = $manifest.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
            $null     = $manifest.Package.AppendChild($capsNode)
        }

        foreach ($cap in $Capabilities) {
            # Device capabilities use <DeviceCapability> (default namespace);
            # isolatedWin32-* capabilities use <rescap:Capability>.
            $isDeviceCap   = $script:KnownIsolationDeviceCapabilities.Contains($cap)
            $targetLocal   = if ($isDeviceCap) { 'DeviceCapability' } else { 'Capability' }

            # Idempotent: skip if the element with this Name attribute already exists.
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
    }
}


function Remove-MsixAppIsolation {
    <#
    .SYNOPSIS
        Removes all `isolatedWin32-*` capabilities from a package, undoing
        Add-MsixAppIsolation.

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
        # Quick pre-check: does the package even have isolation caps?
        $preCheck = Get-MsixManifest -Path $PackagePath
        $hasCaps = @($preCheck.Package.Capabilities.ChildNodes) |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.Name -like 'isolatedWin32-*' }
        if (-not $hasCaps) {
            Write-MsixLog -Level Info -Message 'No isolation capabilities found; nothing to do.'
            return
        }

        $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Remove App Isolation capabilities')

        _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
            -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
            -WhatIfPreview:$isWhatIf `
            -Activity 'Remove App Isolation capabilities' -Mutate {
            param([xml]$manifest)
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
