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

# Documented isolated-app capabilities. Add more as Microsoft publishes them.
$script:KnownIsolationCapabilities = @(
    'isolatedWin32-promptForAccess',
    'isolatedWin32-accessFromLowIntegrityLevel',
    'isolatedWin32-userProfileMinimal',
    'isolatedWin32-userProfile',
    'isolatedWin32-printDocumentsFolder',
    'isolatedWin32-printDocumentsContents',
    'isolatedWin32-fullFileSystemAccess',
    'isolatedWin32-allowElevation',
    'isolatedWin32-attachToHostInterop',
    'isolatedWin32-internetClient',
    'isolatedWin32-internetClientServer',
    'isolatedWin32-privateNetworkClientServer',
    'isolatedWin32-bluetooth',
    'isolatedWin32-networking',
    'isolatedWin32-removableStorage'
)

function Get-MsixIsolationCapability {
    <#
    .SYNOPSIS
        Returns the set of well-known Win32-app-isolation capabilities the module
        is aware of. Use this list to decide what to pass into Add-MsixAppIsolation.
    #>
    return $script:KnownIsolationCapabilities
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
        if ($c -notmatch '^isolatedWin32-') {
            Write-MsixLog Warning "'$c' doesn't look like a Win32 isolation capability (expected 'isolatedWin32-*'). Adding anyway."
        }
        if ($script:KnownIsolationCapabilities -notcontains $c) {
            Write-MsixLog Warning "'$c' is not in the documented capability set. Verify against MS Learn before publishing."
        }
    }

    if (-not $PSCmdlet.ShouldProcess($PackagePath, 'Add App Isolation capabilities')) { return }

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -Activity 'Add App Isolation capabilities' -Mutate {
        param([xml]$manifest)

        Add-MsixManifestNamespace $manifest 'rescap'
        # Win32 App Isolation requires Win11 24H2 (build 26100)
        Set-MsixManifestMaxVersionTested $manifest -MinBuild 26100

        $rescapUri = Get-MsixManifestNamespaceUri 'rescap'
        $capsNode  = $manifest.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
            $null     = $manifest.Package.AppendChild($capsNode)
        }

        foreach ($cap in $Capabilities) {
            # Idempotent: skip if already present
            $existing = $capsNode.ChildNodes | Where-Object {
                $_.LocalName -eq 'Capability' -and $_.Name -eq $cap
            }
            if ($existing) {
                Write-MsixLog Info "Capability already present: $cap"
                continue
            }
            $node = $manifest.CreateElement('rescap:Capability', $rescapUri)
            $node.SetAttribute('Name', $cap)
            $null = $capsNode.AppendChild($node)
            Write-MsixLog Info "Capability added: $cap"
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
            Write-MsixLog Info 'No isolation capabilities found; nothing to do.'
            return
        }

        if (-not $PSCmdlet.ShouldProcess($PackagePath, 'Remove App Isolation capabilities')) { return }

        _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
            -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
            -Activity 'Remove App Isolation capabilities' -Mutate {
            param([xml]$manifest)
            $capsNode = $manifest.Package.Capabilities
            if ($capsNode) {
                foreach ($n in @($capsNode.ChildNodes)) {
                    if ($n.LocalName -eq 'Capability' -and $n.Name -like 'isolatedWin32-*') {
                        $null = $capsNode.RemoveChild($n)
                        Write-MsixLog Info "Removed: $($n.Name)"
                    }
                }
            }
        }
    }
}


# Backward-compatible plural aliases
Set-Alias Get-MsixIsolationCapabilities Get-MsixIsolationCapability
