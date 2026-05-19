# =============================================================================
# Manifest-only fixers
# -----------------------------------------------------------------------------
# Cmdlets that solve compatibility problems by ADDING the right element to
# AppxManifest.xml — no PSF DLL injection required. These are the modern
# alternatives to (and where applicable, complements of) PSF.
#
# Coverage:
#
#   Properties-level (under <Package><Properties> — NOT <Extensions>):
#     Set-MsixFileSystemWriteVirtualization   desktop6  (Win10 19041+)  ← flag + virtualization:ExcludedDirectories
#     Set-MsixRegistryWriteVirtualization     desktop6  (Win10 19041+)  ← flag + virtualization:ExcludedKeys
#
#   Package-level extensions (under <Package><Extensions>):
#     Set-MsixInstalledLocationVirtualization uap10     (Win10 19041+)  ← schema: Package-level only
#     Add-MsixFontExtension                   uap4      (Win10 14393+)  ← schema: Package-level only
#
#   Application-level extensions (under <Application><Extensions>):
#     Add-MsixLoaderSearchPathOverride        uap6      (Win10 17134+)
#     Add-MsixComServerExtension              com       (always)
#     Add-MsixFirewallRule                    desktop2  (Win10 15063+)
#     Add-MsixProtocolHandler                 uap       (always)
#     Add-MsixFileTypeAssociation             uap       (always)
#     Add-MsixStartupTask                     uap5      (Win10 15063+)
#
# Each cmdlet:
#   - Adds the required namespace declarations (idempotent)
#   - Bumps MaxVersionTested when a feature requires a newer build
#   - Repacks and (unless -SkipSigning) re-signs the package
#   - Supports -OutputPath for non-destructive runs
# =============================================================================

#region Private helper -------------------------------------------------------

function _MsixMutateManifest {
    <#
    Shared unpack/edit/repack/sign cycle. The $Mutate scriptblock receives the
    parsed [xml] manifest and is expected to mutate it in place.

    Atomic pack-then-sign: the new package is always built in a scratch
    location in $env:TEMP. Only after signing succeeds is it moved to
    $target. If signing fails, the original $target file is left untouched.

    -UnsignedOutputPath  When supplied AND signing fails, the unsigned
                         scratch package is copied to this path before
                         being cleaned up — so the caller can inspect it
                         or sign it manually.

    -SaveManifestTo  When specified, the mutated AppxManifest.xml is copied to
                     this path BEFORE MakeAppx packs. Useful for diagnosing
                     schema validation failures: you can inspect the exact XML
                     that MakeAppx rejected without digging into %TEMP%.

    -WhatIfPreview   When set, runs the unpack + transform + pack stages so the
                     user can preview what the modified package would look
                     like, but SKIPS the destructive final steps (signing and
                     the Move-Item that replaces the target). If
                     -UnsignedOutputPath is supplied, the unsigned scratch
                     package is copied there so the user can inspect it.
                     The original target file is never touched.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [scriptblock]$Mutate,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$Activity = 'Mutate manifest',
        [string]$SaveManifestTo,
        [string]$UnsignedOutputPath,
        [switch]$WhatIfPreview
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath -ErrorAction Stop
    $workspace = New-MsixWorkspace $fileinfo.BaseName

    $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
    Assert-MsixProcessSuccess $r 'MakeAppx unpack'

    $null = Test-MsixManifest "$workspace\AppxManifest.xml"
    [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"

    $manifest = Invoke-MsixManifestTransform -Manifest $manifest -Transform $Mutate

    Save-MsixManifest $manifest "$workspace\AppxManifest.xml"

    if ($SaveManifestTo) {
        Copy-Item "$workspace\AppxManifest.xml" $SaveManifestTo -Force
        Write-MsixLog Info "Debug manifest saved to: $SaveManifestTo"
    }

    $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
    $scratchExt = [System.IO.Path]::GetExtension($target)
    if (-not $scratchExt) { $scratchExt = '.msix' }
    $scratch = Join-Path $env:TEMP ("msix-pack-{0}{1}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)), $scratchExt)
    $packSucceeded = $false
    $signSucceeded = $false
    try {
        Write-MsixLog Info "$Activity -> $target"
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack','/p',$scratch,'/d',$workspace,'/o')
        Assert-MsixProcessSuccess $r 'MakeAppx pack'
        $packSucceeded = $true

        if ($WhatIfPreview) {
            Write-MsixLog Info "[WhatIf] Would replace '$target' with mutated package. Signing skipped."
            if ($UnsignedOutputPath) {
                Copy-Item -LiteralPath $scratch -Destination $UnsignedOutputPath -Force -ErrorAction Stop
                Write-MsixLog Info "[WhatIf] Preview package copied to: $UnsignedOutputPath"
            }
            return $null
        }

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $scratch -Pfx $Pfx -PfxPassword $PfxPassword
        }
        $signSucceeded = $true

        Move-Item -LiteralPath $scratch -Destination $target -Force
        return Get-Item -LiteralPath $target -ErrorAction Stop
    } catch {
        if ($packSucceeded -and -not $signSucceeded -and $UnsignedOutputPath) {
            try {
                Copy-Item -LiteralPath $scratch -Destination $UnsignedOutputPath -Force -ErrorAction Stop
                Write-MsixLog Warning "Signing failed. Unsigned package preserved at: $UnsignedOutputPath"
            } catch {
                Write-MsixLog Error "Signing failed AND unsigned-output copy to '$UnsignedOutputPath' failed: $_"
            }
        } elseif ($packSucceeded -and -not $signSucceeded) {
            Write-MsixLog Warning "Signing failed. Original target '$target' is unchanged. Pass -UnsignedOutputPath to preserve the unsigned package next time."
        }
        throw
    } finally {
        if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue }
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


function _MsixGetOrCreatePackageExtensions {
    param([xml]$Manifest)
    $ext = $Manifest.Package.Extensions
    if (-not $ext) {
        $ext = $Manifest.CreateElement('Extensions', $Manifest.Package.NamespaceURI)
        $null = $Manifest.Package.AppendChild($ext)
    }
    return $ext
}


function Invoke-MsixManifestTransform {
    <#
    Pure manifest transform — no file IO, no signing.
    Accepts an [xml] or MSIX.ManifestDocument, runs $Transform against it,
    returns the mutated [xml]. Used internally by _MsixMutateManifest.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Manifest,
        [Parameter(Mandatory)] [scriptblock] $Transform
    )
    # Normalise to raw [xml] — callers that pass MSIX.ManifestDocument get its .Document
    $xml = if ($Manifest.PSTypeNames -contains 'MSIX.ManifestDocument') {
        $Manifest.Document
    } elseif ($Manifest -is [System.Xml.XmlDocument]) {
        $Manifest
    } else {
        [xml]$Manifest
    }
    & $Transform $xml
    return $xml
}


function _MsixGetOrCreateApplicationExtensions {
    # Returns the Application XmlElement, creating its <Extensions> child if absent.
    # When $AppId is empty, defaults to the first Application in the manifest.
    param([xml]$Manifest, [string]$AppId)
    $app = Get-MsixManifestApplication -Manifest $Manifest -AppId $AppId
    if (-not $app) {
        $apps = @(Get-MsixManifestApplication -Manifest $Manifest)
        if ($AppId) { throw "Application '$AppId' not found. Available: $(($apps | ForEach-Object { $_.GetAttribute('Id') }) -join ', ')" }
        else        { throw 'No Application elements found in the manifest.' }
    }
    # Use SelectSingleNode (namespace-agnostic) so property access quirks do not bite us.
    if (-not $app.SelectSingleNode('*[local-name()="Extensions"]')) {
        $extNode = $Manifest.CreateElement('Extensions', $Manifest.Package.NamespaceURI)
        $null    = $app.AppendChild($extNode)
    }
    return $app
}

#endregion

#region File / registry write virtualization (desktop6) ---------------------

function Set-MsixFileSystemWriteVirtualization {
    <#
    .SYNOPSIS
        Disables (default) or enables filesystem write virtualization for the
        package, with optional excluded directories.

    .DESCRIPTION
        Sets <desktop6:FileSystemWriteVirtualization> inside <Properties>
        to 'disabled' by default (MSIX enables write virtualization out of the
        box; for most converted Win32 apps the right fix is to disable it so
        writes reach the real file system).

        Pass -Enable to write 'enabled' instead.

        When -ExcludedDirectories is supplied (default: LocalAppData +
        RoamingAppData), a <virtualization:FileSystemWriteVirtualization> element
        is also written in <Properties> — matching the structure produced by the
        MSIX Packaging Tool. The excluded dirs are always written alongside the
        disabled/enabled flag (the commercial tool does both together).

        Also adds rescap:Capability Name="unvirtualizedResources" automatically
        (required by the MSIX schema whenever this element is present).

        Requires Windows 10 build 19041+. MaxVersionTested is bumped automatically.

        NOTE: Goes in <Properties>, NOT in <Extensions>. The MSIX schema does NOT
        accept 'windows.filesystemwritevirtualization' as an Extensions Category.

    .PARAMETER PackagePath
        .msix file to mutate.

    .PARAMETER Enable
        Write 'enabled' instead of the default 'disabled'.

    .PARAMETER ExcludedDirectories
        Paths excluded from virtualization. Defaults to LocalAppData and
        RoamingAppData — the same defaults as the MSIX Packaging Tool.
        Use KnownFolder tokens (e.g. '$(KnownFolder:LocalAppData)') or
        VFS-relative paths. Pass @() to suppress excluded-dirs entirely.

    .PARAMETER OutputPath / SkipSigning / Pfx / PfxPassword
        See Add-MsixPsfV2.

    .EXAMPLE
        # Disable write virtualization (the standard MSIX-conversion fix):
        Set-MsixFileSystemWriteVirtualization -PackagePath app.msix -Pfx cert.pfx -PfxPassword 'P@ss'

    .EXAMPLE
        # Disable with a custom extra exclusion:
        Set-MsixFileSystemWriteVirtualization -PackagePath app.msix `
            -ExcludedDirectories '$(KnownFolder:LocalAppData)','$(KnownFolder:RoamingAppData)','VFS/ProgramFilesX64/App/Cache' `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [switch]$Enable,
        [string[]]$ExcludedDirectories = @('$(KnownFolder:LocalAppData)', '$(KnownFolder:RoamingAppData)'),
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Set FileSystemWriteVirtualization')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'desktop6:FileSystemWriteVirtualization' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'desktop6'
        Add-MsixManifestNamespace $M 'rescap'
        Set-MsixManifestMaxVersionTested $M -MinBuild 19041

        $props = $M.Package.Properties
        $d6    = Get-MsixManifestNamespaceUri 'desktop6'

        # ── desktop6 flag element (idempotent) ─────────────────────────────
        $flag = $props.SelectSingleNode(
            '*[local-name()="FileSystemWriteVirtualization" and ' +
            'namespace-uri()="' + $d6 + '"]')
        if (-not $flag) {
            $flag = $M.CreateElement('desktop6:FileSystemWriteVirtualization', $d6)
            $null = $props.AppendChild($flag)
        }
        $flag.InnerText = if ($Enable) { 'enabled' } else { 'disabled' }
        Write-MsixLog Info "desktop6:FileSystemWriteVirtualization set to '$($flag.InnerText)'."

        # ── virtualization:ExcludedDirectories ────────────────────────────
        # Always written alongside the flag (matches commercial tool behaviour).
        $virtUri  = Get-MsixManifestNamespaceUri 'virtualization'
        $virtNode = $props.SelectSingleNode(
            '*[local-name()="FileSystemWriteVirtualization" and ' +
            'namespace-uri()="' + $virtUri + '"]')
        if ($virtNode) { $null = $props.RemoveChild($virtNode) }

        if ($ExcludedDirectories.Count -gt 0) {
            Add-MsixManifestNamespace $M 'virtualization'
            $virtNode = $M.CreateElement('virtualization:FileSystemWriteVirtualization', $virtUri)
            $dirs     = $M.CreateElement('virtualization:ExcludedDirectories', $virtUri)
            foreach ($dir in $ExcludedDirectories) {
                $entry = $M.CreateElement('virtualization:ExcludedDirectory', $virtUri)
                $entry.InnerText = $dir
                $null = $dirs.AppendChild($entry)
            }
            $null = $virtNode.AppendChild($dirs)
            $null = $props.AppendChild($virtNode)
            Write-MsixLog Info "virtualization:FileSystemWriteVirtualization: $($ExcludedDirectories.Count) excluded dir(s)."
        }

        # ── unvirtualizedResources capability (required by the schema) ─────
        $rescapUri = Get-MsixManifestNamespaceUri 'rescap'
        $capsNode  = $M.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $M.CreateElement('Capabilities', $M.Package.NamespaceURI)
            $null     = $M.Package.AppendChild($capsNode)
        }
        $alreadyCap = $capsNode.ChildNodes | Where-Object {
            $_.LocalName -eq 'Capability' -and $_.Name -eq 'unvirtualizedResources'
        }
        if (-not $alreadyCap) {
            $cap = $M.CreateElement('rescap:Capability', $rescapUri)
            $cap.SetAttribute('Name', 'unvirtualizedResources')
            $null = $capsNode.AppendChild($cap)
            Write-MsixLog Info "Capability added: unvirtualizedResources"
        }
    }
}


function Set-MsixRegistryWriteVirtualization {
    <#
    .SYNOPSIS
        Disables (default) or enables registry write virtualization for the
        package, with optional excluded registry keys.

    .DESCRIPTION
        Sets <desktop6:RegistryWriteVirtualization> inside <Properties>
        to 'disabled' by default (MSIX enables registry write virtualization out
        of the box; for most converted Win32 apps the fix is to disable it).

        Pass -Enable to write 'enabled' instead.

        When -ExcludedKeys is supplied, a <virtualization:RegistryWriteVirtualization>
        element is also written in <Properties> with the excluded key list.

        Also adds rescap:Capability Name="unvirtualizedResources" automatically.

        Requires Windows 10 build 19041+.

        NOTE: Goes in <Properties>, NOT in <Extensions>.

    .PARAMETER Enable
        Write 'enabled' instead of the default 'disabled'.

    .PARAMETER ExcludedKeys
        Registry key paths that should NOT be virtualized
        (e.g. 'SOFTWARE\Vendor\PublicKeys'). No defaults — omit to skip the
        virtualization:RegistryWriteVirtualization section entirely.

    .EXAMPLE
        Set-MsixRegistryWriteVirtualization -PackagePath app.msix -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [switch]$Enable,
        [string[]]$ExcludedKeys,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Set RegistryWriteVirtualization')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'desktop6:RegistryWriteVirtualization' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'desktop6'
        Add-MsixManifestNamespace $M 'rescap'
        Set-MsixManifestMaxVersionTested $M -MinBuild 19041

        $props = $M.Package.Properties
        $d6    = Get-MsixManifestNamespaceUri 'desktop6'

        # ── desktop6 flag element (idempotent) ─────────────────────────────
        $flag = $props.SelectSingleNode(
            '*[local-name()="RegistryWriteVirtualization" and ' +
            'namespace-uri()="' + $d6 + '"]')
        if (-not $flag) {
            $flag = $M.CreateElement('desktop6:RegistryWriteVirtualization', $d6)
            $null = $props.AppendChild($flag)
        }
        $flag.InnerText = if ($Enable) { 'enabled' } else { 'disabled' }
        Write-MsixLog Info "desktop6:RegistryWriteVirtualization set to '$($flag.InnerText)'."

        # ── virtualization:ExcludedKeys (optional) ─────────────────────────
        $virtUri  = Get-MsixManifestNamespaceUri 'virtualization'
        $virtNode = $props.SelectSingleNode(
            '*[local-name()="RegistryWriteVirtualization" and ' +
            'namespace-uri()="' + $virtUri + '"]')
        if ($virtNode) { $null = $props.RemoveChild($virtNode) }

        if ($ExcludedKeys.Count -gt 0) {
            Add-MsixManifestNamespace $M 'virtualization'
            $virtNode = $M.CreateElement('virtualization:RegistryWriteVirtualization', $virtUri)
            $keys     = $M.CreateElement('virtualization:ExcludedKeys', $virtUri)
            foreach ($k in $ExcludedKeys) {
                $entry = $M.CreateElement('virtualization:ExcludedKey', $virtUri)
                $entry.InnerText = $k
                $null = $keys.AppendChild($entry)
            }
            $null = $virtNode.AppendChild($keys)
            $null = $props.AppendChild($virtNode)
            Write-MsixLog Info "virtualization:RegistryWriteVirtualization: $($ExcludedKeys.Count) excluded key(s)."
        }

        # ── unvirtualizedResources capability (required by the schema) ─────
        $rescapUri = Get-MsixManifestNamespaceUri 'rescap'
        $capsNode  = $M.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $M.CreateElement('Capabilities', $M.Package.NamespaceURI)
            $null     = $M.Package.AppendChild($capsNode)
        }
        $alreadyCap = $capsNode.ChildNodes | Where-Object {
            $_.LocalName -eq 'Capability' -and $_.Name -eq 'unvirtualizedResources'
        }
        if (-not $alreadyCap) {
            $cap = $M.CreateElement('rescap:Capability', $rescapUri)
            $cap.SetAttribute('Name', 'unvirtualizedResources')
            $null = $capsNode.AppendChild($cap)
            Write-MsixLog Info "Capability added: unvirtualizedResources"
        }
    }
}


function Set-MsixInstalledLocationVirtualization {
    <#
    .SYNOPSIS
        Adds (or removes) the uap10:InstalledLocationVirtualization extension,
        making writes to the install dir survive at a per-user location with
        explicit update-time policy.

    .DESCRIPTION
        Smarter than Set-MsixFileSystemWriteVirtualization for cases where you
        need explicit control over what happens to user-modified, deleted, and
        added files when the package is updated.

        Min OS: Windows 10 2004 (build 19041+). MaxVersionTested is bumped
        automatically.

    .PARAMETER ModifiedItems / DeletedItems / AddedItems
        Each accepts 'keep' or 'reset'. Defaults match TMEditX:
        ModifiedItems=keep, DeletedItems=reset, AddedItems=keep.

    .EXAMPLE
        Set-MsixInstalledLocationVirtualization -PackagePath app.msix `
            -DeletedItems keep -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidateSet('keep','reset')] [string]$ModifiedItems = 'keep',
        [ValidateSet('keep','reset')] [string]$DeletedItems  = 'reset',
        [ValidateSet('keep','reset')] [string]$AddedItems    = 'keep',
        [switch]$Disable,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Set InstalledLocationVirtualization')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'uap10:InstalledLocationVirtualization' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'uap10'
        Set-MsixManifestMaxVersionTested $M -MinBuild 19041

        $pkgExt = _MsixGetOrCreatePackageExtensions $M
        $cat    = 'windows.installedLocationVirtualization'
        $existing = $pkgExt.ChildNodes | Where-Object {
            $_.LocalName -eq 'Extension' -and $_.Category -eq $cat
        }
        foreach ($e in @($existing)) { $null = $pkgExt.RemoveChild($e) }
        if ($Disable) {
            Write-MsixLog Info 'InstalledLocationVirtualization disabled.'
            return
        }

        $u10 = Get-MsixManifestNamespaceUri 'uap10'
        $ext = $M.CreateElement('uap10:Extension', $u10)
        $ext.SetAttribute('Category', $cat)
        $body = $M.CreateElement('uap10:InstalledLocationVirtualization', $u10)
        $upd  = $M.CreateElement('uap10:UpdateActions', $u10)
        $upd.SetAttribute('ModifiedItems', $ModifiedItems)
        $upd.SetAttribute('DeletedItems',  $DeletedItems)
        $upd.SetAttribute('AddedItems',    $AddedItems)
        $null = $body.AppendChild($upd)
        $null = $ext.AppendChild($body)
        $null = $pkgExt.AppendChild($ext)
        Write-MsixLog Info "uap10:InstalledLocationVirtualization added (Mod=$ModifiedItems, Del=$DeletedItems, Add=$AddedItems)."
    }
}

#endregion

#region Loader search path override (uap6) ----------------------------------

function Add-MsixLoaderSearchPathOverride {
    <#
    .SYNOPSIS
        Adds package-relative directories to the DLL loader search path for a
        specific application — a manifest alternative to DynamicLibraryFixup
        for the simple "DLL not found" case.

    .DESCRIPTION
        Min OS: Windows 10 build 17134 (1803). MaxVersionTested is bumped
        automatically.

    .PARAMETER AppId
        Id of the Application element to extend.
        Defaults to the first Application in the manifest.

    .PARAMETER Paths
        Up to 5 package-relative directory paths (forward slashes). Each is
        added as a uap6:LoaderSearchPathEntry under the override element.

    .EXAMPLE
        Add-MsixLoaderSearchPathOverride -PackagePath app.msix `
            -Paths 'VFS/ProgramFilesX64/App/lib','VFS/ProgramFilesX64/App/bin' `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidateCount(1,5)]
        [string[]]$Paths,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add LoaderSearchPathOverride')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'uap6:LoaderSearchPathOverride' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'uap6'
        Set-MsixManifestMaxVersionTested $M -MinBuild 17134

        $app    = _MsixGetOrCreateApplicationExtensions $M $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')

        # Find an existing override or create one.
        $existing = $appExt.ChildNodes |
            Where-Object {
                $_.LocalName -eq 'Extension' -and
                ($_.SelectSingleNode('*[local-name()="LoaderSearchPathOverride"]'))
            } | Select-Object -First 1

        if ($existing) {
            $body = $existing.SelectSingleNode('*[local-name()="LoaderSearchPathOverride"]')
        } else {
            $u6   = Get-MsixManifestNamespaceUri 'uap6'
            $ext  = $M.CreateElement('uap6:Extension', $u6)
            $ext.SetAttribute('Category', 'windows.loaderSearchPathOverride')
            $body = $M.CreateElement('uap6:LoaderSearchPathOverride', $u6)
            $null = $ext.AppendChild($body)
            $null = $appExt.AppendChild($ext)
        }

        $u6 = Get-MsixManifestNamespaceUri 'uap6'
        foreach ($p in $Paths) {
            # Idempotent: skip if same entry already present
            $already = $body.ChildNodes | Where-Object {
                $_.LocalName -eq 'LoaderSearchPathEntry' -and $_.LoaderSearchPath -eq $p
            }
            if ($already) {
                Write-MsixLog Info "LoaderSearchPathEntry already present: $p"
                continue
            }
            $entry = $M.CreateElement('uap6:LoaderSearchPathEntry', $u6)
            $entry.SetAttribute('LoaderSearchPath', $p)
            $null = $body.AppendChild($entry)
            Write-MsixLog Info "LoaderSearchPathEntry added: $p"
        }

        # Schema caps at 5 entries
        $count = ($body.ChildNodes | Where-Object LocalName -eq 'LoaderSearchPathEntry').Count
        if ($count -gt 5) {
            throw "uap6:LoaderSearchPathOverride only supports 5 entries; package now has $count."
        }
    }
}

#endregion

#region Firewall rule (desktop2) --------------------------------------------

function Add-MsixFirewallRule {
    <#
    .SYNOPSIS
        Registers a Windows Firewall rule that's installed/removed alongside
        the MSIX package.

    .DESCRIPTION
        Adds a desktop2:FirewallRules extension under Package/Extensions.
        Replaces ad-hoc netsh / New-NetFirewallRule calls in installer scripts —
        the rule lifecycle now follows the package.

        Min OS: Windows 10 build 15063.

    .PARAMETER AppId
        Application ID to validate against the manifest. Firewall rules are
        emitted at package scope, as required by the Windows manifest schema.

    .PARAMETER Executable
        The executable subject to the rule (package-relative path).

    .PARAMETER Direction
        'in' (inbound) or 'out' (outbound).

    .PARAMETER Protocol
        TCP, UDP, ICMPv4, ICMPv6 (case-insensitive).

    .PARAMETER LocalPort
        Single port or range (e.g. 1337, 5000-5010, '*' for any).

    .PARAMETER Profile
        domain | private | public | all (default: all).

    .EXAMPLE
        Add-MsixFirewallRule -PackagePath app.msix -AppId App `
            -Executable 'VFS/ProgramFilesX64/App/server.exe' `
            -Direction in -Protocol TCP -LocalPort 5000-5010 `
            -Pfx cert.pfx -PfxPassword 'P@ss'

    .NOTES
        Min OS: Windows 10 1703 (build 15063+). MaxVersionTested is bumped
        automatically.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [Parameter(Mandatory)] [string]$Executable,
        [Parameter(Mandatory)]
        [ValidateSet('in','out')]
        [string]$Direction,
        [Parameter(Mandatory)]
        [ValidateSet('TCP','UDP','ICMPv4','ICMPv6')]
        [string]$Protocol,
        [string]$LocalPort = '*',
        [ValidateSet('domain','private','public','all')]
        [string]$FwProfile = 'all',
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add firewall rule for $AppId")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'desktop2:FirewallRules' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'desktop2'
        Add-MsixManifestNamespace $M 'rescap'
        Set-MsixManifestMaxVersionTested $M -MinBuild 15063

        $app = Get-MsixManifestApplication -Manifest $M -AppId $AppId
        if (-not $app) { throw "Application '$AppId' not found in the manifest." }

        $d2  = Get-MsixManifestNamespaceUri 'desktop2'

        # windows.firewallRules is a package-level extension:
        # Package/Extensions/desktop2:Extension/desktop2:FirewallRules
        $pkgExt = _MsixGetOrCreatePackageExtensions $M
        $rulesParent = $null
        foreach ($e in @($pkgExt.ChildNodes | Where-Object { $_.LocalName -eq 'Extension' -and $_.Category -eq 'windows.firewallRules' })) {
            $rules = $e.SelectSingleNode('*[local-name()="FirewallRules"]')
            if ($rules.Executable -eq $Executable) { $rulesParent = $rules; break }
        }
        if (-not $rulesParent) {
            $ext = $M.CreateElement('desktop2:Extension', $d2)
            $ext.SetAttribute('Category', 'windows.firewallRules')
            $rulesParent = $M.CreateElement('desktop2:FirewallRules', $d2)
            $rulesParent.SetAttribute('Executable', $Executable)
            $null = $ext.AppendChild($rulesParent)
            $null = $pkgExt.AppendChild($ext)
        }

        $rescapUri = Get-MsixManifestNamespaceUri 'rescap'
        $capsNode  = $M.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $M.CreateElement('Capabilities', $M.Package.NamespaceURI)
            $null = $M.Package.AppendChild($capsNode)
        }
        $hasFullTrust = $capsNode.ChildNodes | Where-Object {
            $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust'
        }
        if (-not $hasFullTrust) {
            $cap = $M.CreateElement('rescap:Capability', $rescapUri)
            $cap.SetAttribute('Name', 'runFullTrust')
            $null = $capsNode.AppendChild($cap)
            Write-MsixLog Info 'Capability added: runFullTrust'
        }

        # Idempotent rule add
        $rule = $M.CreateElement('desktop2:Rule', $d2)
        $rule.SetAttribute('Direction',   $Direction)
        $rule.SetAttribute('IPProtocol',  $Protocol)
        $rule.SetAttribute('Profile',     $FwProfile)
        if ($LocalPort -ne '*') {
            if ($LocalPort -match '^(\d+)-(\d+)$') {
                $rule.SetAttribute('LocalPortMin', $matches[1])
                $rule.SetAttribute('LocalPortMax', $matches[2])
            } else {
                $rule.SetAttribute('LocalPortMin', $LocalPort)
                $rule.SetAttribute('LocalPortMax', $LocalPort)
            }
        }
        $null = $rulesParent.AppendChild($rule)
        Write-MsixLog Info "FirewallRule: $Direction $Protocol $LocalPort -> $Executable"
    }
}

#endregion

#region Protocol handler / FTA / Startup task -------------------------------

function Add-MsixProtocolHandler {
    <#
    .SYNOPSIS
        Registers a custom URL protocol (e.g. myapp://) handled by an
        application in the package.

    .PARAMETER Name
        Protocol scheme, no trailing colon (e.g. 'contoso').

    .PARAMETER DisplayName
        Friendly name shown to users.

    .EXAMPLE
        Add-MsixProtocolHandler -PackagePath app.msix -AppId App `
            -Name contoso -DisplayName 'Contoso Launcher' `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'Protocol Name must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen (no spaces).'
        )]
        [string]$Name,
        [string]$DisplayName,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add protocol $Name")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'uap:Protocol' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'uap'

        $app   = _MsixGetOrCreateApplicationExtensions $M $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        $uap    = Get-MsixManifestNamespaceUri 'uap'

        # Idempotent: same Name already declared?
        $already = $appExt.SelectNodes('*[local-name()="Extension" and @Category="windows.protocol"]') |
                   ForEach-Object { $_.SelectSingleNode('*[local-name()="Protocol" and @Name="' + $Name + '"]') } |
                   Where-Object { $_ }
        if ($already) {
            Write-MsixLog Info "Protocol '$Name' already registered."
            return
        }

        $ext  = $M.CreateElement('uap:Extension', $uap)
        $ext.SetAttribute('Category', 'windows.protocol')
        $proto = $M.CreateElement('uap:Protocol', $uap)
        $proto.SetAttribute('Name', $Name)
        if ($DisplayName) {
            $dn = $M.CreateElement('uap:DisplayName', $uap)
            $dn.InnerText = $DisplayName
            $null = $proto.AppendChild($dn)
        }
        $null = $ext.AppendChild($proto)
        $null = $appExt.AppendChild($ext)
        Write-MsixLog Info "Protocol added: $Name"
    }
}


function Add-MsixFileTypeAssociation {
    <#
    .SYNOPSIS
        Registers a file type association (ProgID-style) so opening files of
        the given extension(s) launches the packaged app.

    .PARAMETER Name
        Internal association name (lowercase, no spaces). e.g. 'contosodoc'.

    .PARAMETER FileTypes
        Extensions (with leading dot) — '.txt', '.csv', ...

    .PARAMETER DisplayName
        Friendly name in the Open With… dialog.

    .EXAMPLE
        Add-MsixFileTypeAssociation -PackagePath app.msix -AppId App `
            -Name contosodoc -FileTypes '.cdoc','.cdocx' -DisplayName 'Contoso Document' `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'FTA Name must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$Name,
        [Parameter(Mandatory)]
        [ValidateScript({
            foreach ($t in $_) {
                # Allow optional leading dot — function auto-prefixes '.' to bare names.
                if ($t -notmatch '^\.?[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$') {
                    throw "Invalid file type: '$t'. Allowed: '.ext' or 'ext' (alphanumeric/underscore/dot/hyphen, max 32 chars after dot)."
                }
            }
            $true
        })]
        [string[]]$FileTypes,
        [string]$DisplayName,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add FTA $Name")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'uap:FileTypeAssociation' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'uap'

        $app   = _MsixGetOrCreateApplicationExtensions $M $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        $uap    = Get-MsixManifestNamespaceUri 'uap'

        $ext  = $M.CreateElement('uap:Extension', $uap)
        $ext.SetAttribute('Category', 'windows.fileTypeAssociation')

        $fta = $M.CreateElement('uap:FileTypeAssociation', $uap)
        $fta.SetAttribute('Name', $Name.ToLower())
        if ($DisplayName) {
            $dn = $M.CreateElement('uap:DisplayName', $uap)
            $dn.InnerText = $DisplayName
            $null = $fta.AppendChild($dn)
        }

        $supported = $M.CreateElement('uap:SupportedFileTypes', $uap)
        foreach ($ft in $FileTypes) {
            if (-not $ft.StartsWith('.')) { $ft = ".$ft" }
            $type = $M.CreateElement('uap:FileType', $uap)
            $type.InnerText = $ft.ToLower()
            $null = $supported.AppendChild($type)
        }
        $null = $fta.AppendChild($supported)
        $null = $ext.AppendChild($fta)
        $null = $appExt.AppendChild($ext)
        Write-MsixLog Info "FTA $Name registered for: $($FileTypes -join ', ')"
    }
}


function Add-MsixStartupTask {
    <#
    .SYNOPSIS
        Registers a startup task — the manifest-native, properly-firing
        replacement for HKLM\…\Run autostart entries (which packaged apps
        don't honour).

    .PARAMETER TaskId
        Unique ID for the task (alphanumeric, no spaces).

    .PARAMETER DisplayName
        Friendly name shown in Settings > Startup apps.

    .PARAMETER Enabled
        Whether the task starts enabled. Users can flip this in Settings.

    .PARAMETER Executable
        Optional override (default: the Application's Executable).

    .EXAMPLE
        Add-MsixStartupTask -PackagePath app.msix -AppId App `
            -TaskId ContosoStartup -DisplayName 'Contoso' -Enabled $true `
            -Pfx cert.pfx -PfxPassword 'P@ss'

    .NOTES
        Min OS: Windows 10 1703 (build 15063+). MaxVersionTested is bumped
        automatically.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'TaskId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$TaskId,
        [Parameter(Mandatory)] [string]$DisplayName,
        [bool]$Enabled = $true,
        [string]$Executable,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add StartupTask $TaskId")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'uap5:StartupTask' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'uap5'
        Set-MsixManifestMaxVersionTested $M -MinBuild 15063

        $app   = _MsixGetOrCreateApplicationExtensions $M $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        $u5    = Get-MsixManifestNamespaceUri 'uap5'

        # Idempotent: same TaskId?
        $already = $appExt.SelectNodes('*[local-name()="Extension" and @Category="windows.startupTask"]') |
                   ForEach-Object { $_.SelectSingleNode('*[local-name()="StartupTask" and @TaskId="' + $TaskId + '"]') } |
                   Where-Object { $_ }
        if ($already) {
            Write-MsixLog Info "StartupTask '$TaskId' already registered."
            return
        }

        $exeAttr = if ($Executable) { $Executable } else { $app.Executable }
        $ext = $M.CreateElement('uap5:Extension', $u5)
        $ext.SetAttribute('Category',   'windows.startupTask')
        $ext.SetAttribute('Executable', $exeAttr)
        $ext.SetAttribute('EntryPoint', 'Windows.FullTrustApplication')

        $task = $M.CreateElement('uap5:StartupTask', $u5)
        $task.SetAttribute('TaskId',      $TaskId)
        $task.SetAttribute('Enabled',     ([string]$Enabled).ToLower())
        $task.SetAttribute('DisplayName', $DisplayName)
        $null = $ext.AppendChild($task)
        $null = $appExt.AppendChild($ext)
        Write-MsixLog Info "StartupTask added: $TaskId (Enabled=$Enabled)"
    }
}

#endregion

#region Shared fonts (uap4) -------------------------------------------------

function Add-MsixFontExtension {
    <#
    .SYNOPSIS
        Registers font files shipped inside the package with the OS via the
        uap4:SharedFonts manifest extension. Once installed, other apps see
        the fonts too.

    .PARAMETER FontPaths
        Package-relative paths to .ttf / .otf / .ttc files (forward slashes).
        Use Get-MsixFontCandidate to discover them.

    .EXAMPLE
        $fonts = Get-MsixFontCandidate -PackagePath app.msix | Select-Object -ExpandProperty Path
        Add-MsixFontExtension -PackagePath app.msix -FontPaths $fonts -Pfx cert.pfx -PfxPassword 'P@ss'

    .NOTES
        Min OS: Windows 10 1607 (build 14393+).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [string[]]$FontPaths,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add SharedFonts')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'uap4:SharedFonts' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'uap4'
        $u4 = Get-MsixManifestNamespaceUri 'uap4'

        $pkgExt = _MsixGetOrCreatePackageExtensions $M
        $cat    = 'windows.sharedFonts'
        $existing = $pkgExt.ChildNodes | Where-Object {
            $_.LocalName -eq 'Extension' -and $_.Category -eq $cat
        } | Select-Object -First 1
        if (-not $existing) {
            $existing = $M.CreateElement('uap4:Extension', $u4)
            $existing.SetAttribute('Category', $cat)
            $body = $M.CreateElement('uap4:SharedFonts', $u4)
            $null = $existing.AppendChild($body)
            $null = $pkgExt.AppendChild($existing)
        } else {
            $body = $existing.SelectSingleNode('*[local-name()="SharedFonts"]')
        }

        $alreadyFiles = $body.ChildNodes |
            Where-Object { $_.LocalName -eq 'Font' } |
            ForEach-Object { $_.File }

        foreach ($p in $FontPaths) {
            $rel = $p.Replace('\','/')
            if ($alreadyFiles -contains $rel) {
                Write-MsixLog Info "Font already registered: $rel"
                continue
            }
            $node = $M.CreateElement('uap4:Font', $u4)
            $node.SetAttribute('File', $rel)
            $null = $body.AppendChild($node)
            Write-MsixLog Info "Font registered: $rel"
        }
    }
}

#endregion

#region Brand metadata ------------------------------------------------------

function Set-MsixBrandMetadata {
    <#
    .SYNOPSIS
        Bulk-updates the user-facing identity strings (DisplayName,
        PublisherDisplayName, Description, Logo) under <Properties>.

    .DESCRIPTION
        The ones inside <Properties> are what users see in Settings > Apps.
        Per-application VisualElements (also a DisplayName / Description) are
        left alone unless you pass -ApplyToApplications.

    .PARAMETER ApplyToApplications
        If set, also propagate DisplayName / Description into every
        Application's uap:VisualElements block.

    .EXAMPLE
        Set-MsixBrandMetadata -PackagePath app.msix `
            -DisplayName 'Contoso Expenses' `
            -PublisherDisplayName 'Contoso Ltd' `
            -Description 'Customer-facing expense tracker.' `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [string]$DisplayName,
        [string]$PublisherDisplayName,
        [string]$Description,
        [string]$LogoPath,
        [switch]$ApplyToApplications,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    if (-not ($DisplayName -or $PublisherDisplayName -or $Description -or $LogoPath)) {
        throw 'Pass at least one of -DisplayName / -PublisherDisplayName / -Description / -LogoPath.'
    }
    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Set brand metadata')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'Brand metadata' -Mutate {
        param([xml]$M)
        $props = $M.Package.Properties
        if (-not $props) {
            $props = $M.CreateElement('Properties', $M.Package.NamespaceURI)
            $null  = $M.Package.AppendChild($props)
        }

        function _SetChild($Parent, $LocalName, $Value, $Ns) {
            if (-not $Value) { return }
            $node = $Parent.SelectSingleNode("*[local-name()='$LocalName']")
            if (-not $node) {
                $node = $M.CreateElement($LocalName, $Ns)
                $null = $Parent.AppendChild($node)
            }
            $node.InnerText = $Value
        }
        _SetChild -Parent $props -LocalName 'DisplayName'           -Value $DisplayName           -Ns $M.Package.NamespaceURI
        _SetChild -Parent $props -LocalName 'PublisherDisplayName'  -Value $PublisherDisplayName  -Ns $M.Package.NamespaceURI
        _SetChild -Parent $props -LocalName 'Description'           -Value $Description           -Ns $M.Package.NamespaceURI
        _SetChild -Parent $props -LocalName 'Logo'                  -Value $LogoPath              -Ns $M.Package.NamespaceURI

        if ($ApplyToApplications) {
            foreach ($app in @($M.Package.Applications.Application)) {
                $vis = $app.SelectSingleNode("*[local-name()='VisualElements']")
                if (-not $vis) { continue }
                if ($DisplayName) { $vis.SetAttribute('DisplayName', $DisplayName) }
                if ($Description) { $vis.SetAttribute('Description', $Description) }
            }
        }
        Write-MsixLog Info 'Brand metadata updated.'
    }
}


function Add-MsixShellVerbExtension {
    <#
    .SYNOPSIS
        Adds a shell verb to an Application so it appears in File Explorer's
        context menu — the manifest-native replacement for HKCR\*\shell\<verb>
        registry entries.

    .DESCRIPTION
        Creates uap:Extension (windows.fileTypeAssociation) with a
        uap3:SupportedVerbs/uap3:Verb entry. When -FileTypes is omitted,
        uap:SupportsAnyFileType is used, mirroring the HKCR\*\shell pattern
        (verb appears on all file types). Specific extensions can be listed
        to scope the verb to those types only.

        Note: uap:SupportsAnyFileType does NOT add the verb to folder/directory
        targets. HKCR\Directory\shell entries have no direct MSIX manifest
        equivalent via FTA; use Add-MsixFileExplorerContextMenu for that case.

        Min OS: Windows 10 1709 (build 16299+). MaxVersionTested is bumped
        automatically.

    .PARAMETER AppId
        Application Id to attach the extension to.

    .PARAMETER VerbId
        Short slug used as the verb identifier (no spaces, alphanumeric).
        Auto-derived from -VerbDisplayName if omitted.

    .PARAMETER VerbDisplayName
        Text shown in the context menu.

    .PARAMETER Parameters
        Command-line arguments appended after the app executable.
        Defaults to '"%1"' (the file path).

    .PARAMETER FileTypes
        Extensions the verb applies to ('.txt', '.log', ...).
        Omit to use uap:SupportsAnyFileType (all file types).

    .PARAMETER AssocName
        Internal FileTypeAssociation name. Defaults to a slug of -VerbId.

    .EXAMPLE
        # "Open with Notepad++" context menu item on all file types
        Add-MsixShellVerbExtension -PackagePath app.msix -AppId App `
            -VerbDisplayName 'Open with Notepad++' -Pfx cert.pfx -PfxPassword 'P@ss'

    .EXAMPLE
        # Verb limited to specific extensions
        Add-MsixShellVerbExtension -PackagePath app.msix -AppId App `
            -VerbId 'editlog' -VerbDisplayName 'Edit in MyApp' `
            -FileTypes '.log','.txt' -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [Parameter(Mandatory)] [string]$VerbDisplayName,
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'VerbId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$VerbId,
        [string]$Parameters = '"%1"',
        [string[]]$FileTypes,
        [string]$AssocName,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath,
        # Debug: copy the mutated AppxManifest.xml here BEFORE packing,
        # so you can inspect the exact XML that MakeAppx validates.
        [string]$SaveManifestTo
    )

    if (-not $VerbId) {
        $VerbId = ($VerbDisplayName -replace '[^a-zA-Z0-9]', '').ToLower()
        if (-not $VerbId) { $VerbId = 'open' }
    }
    if (-not $AssocName) { $AssocName = $VerbId }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add shell verb '$VerbDisplayName'")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -WhatIfPreview:$isWhatIf `
        -SaveManifestTo $SaveManifestTo `
        -Activity "Add shell verb '$VerbDisplayName'" -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'uap'
        Add-MsixManifestNamespace $M 'uap2'
        Add-MsixManifestNamespace $M 'uap3'
        # uap2:SupportedVerbs + uap3:Verb require build 16299+ (Win10 1709).
        Set-MsixManifestMaxVersionTested $M -MinBuild 16299

        $app    = _MsixGetOrCreateApplicationExtensions $M $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        $uap    = Get-MsixManifestNamespaceUri 'uap'
        $uap2   = Get-MsixManifestNamespaceUri 'uap2'
        $uap3   = Get-MsixManifestNamespaceUri 'uap3'

        # Schema structure (per MSIX manifest spec):
        #   <uap:Extension Category="windows.fileTypeAssociation">   ← uap namespace
        #     <uap3:FileTypeAssociation Name="...">                  ← substitution-group child
        #       <uap:SupportedFileTypes> ... </uap:SupportedFileTypes>
        #       <uap2:SupportedVerbs>
        #         <uap3:Verb Id="..." Parameters="...">Label</uap3:Verb>
        #       </uap2:SupportedVerbs>
        #     </uap3:FileTypeAssociation>
        #   </uap:Extension>
        # NOTE: the EXTENSION element must be uap:Extension; uap3:Extension does NOT
        # support the windows.fileTypeAssociation category and causes a schema error.
        $ext = $M.CreateElement('uap:Extension', $uap)
        $ext.SetAttribute('Category', 'windows.fileTypeAssociation')

        $fta = $M.CreateElement('uap3:FileTypeAssociation', $uap3)
        # IMPORTANT: do NOT inline the -replace expression as a method argument.
        # PowerShell parses SetAttribute('Name', $x -replace pat, repl) as the
        # 3-arg overload SetAttribute(localName, namespaceURI, value), treating
        # the -replace result as the namespaceURI — producing d6p1:Name="" and
        # a spurious xmlns:d6p1="<slug>" declaration that MakeAppx rejects.
        $assocSlug = $AssocName.ToLower() -replace '[^a-z0-9\-]', ''
        $fta.SetAttribute('Name', $assocSlug)

        # File-type scope
        $supported = $M.CreateElement('uap:SupportedFileTypes', $uap)
        if ($FileTypes) {
            foreach ($ft in $FileTypes) {
                if (-not $ft.StartsWith('.')) { $ft = ".$ft" }
                $node = $M.CreateElement('uap:FileType', $uap)
                $node.InnerText = $ft.ToLower()
                $null = $supported.AppendChild($node)
            }
        } else {
            # Wildcard — mirrors HKCR\*\shell\<verb> pattern
            $any = $M.CreateElement('uap:SupportsAnyFileType', $uap)
            $null = $supported.AppendChild($any)
        }
        $null = $fta.AppendChild($supported)

        # Verb element
        $verbs    = $M.CreateElement('uap2:SupportedVerbs', $uap2)
        $verbElem = $M.CreateElement('uap3:Verb', $uap3)
        $verbElem.SetAttribute('Id', $VerbId)
        if ($Parameters) { $verbElem.SetAttribute('Parameters', $Parameters) }
        $verbElem.InnerText = $VerbDisplayName
        $null = $verbs.AppendChild($verbElem)
        $null = $fta.AppendChild($verbs)

        $null = $ext.AppendChild($fta)
        $null = $appExt.AppendChild($ext)

        $scope = if ($FileTypes) { $FileTypes -join ', ' } else { 'all file types (SupportsAnyFileType)' }
        Write-MsixLog Info "Shell verb '$VerbDisplayName' (Id=$VerbId) registered for: $scope"
    }
}


function Add-MsixComServerExtension {
    <#
    .SYNOPSIS
        Declares COM in-process server(s) in the manifest (com:Extension,
        windows.comServer) so they are activatable across the package boundary.

    .DESCRIPTION
        Adds com:InProcessServer entries for each CLSID supplied inside the
        Application's <Extensions> node. The DLL must exist in the package as a
        VFS-relative path. Idempotent — already-declared CLSIDs are silently skipped.

        Use this for COM servers that need to be activated by code OUTSIDE the
        package. COM servers self-activated by the app's own processes work via
        registry virtualization and generally do not need explicit declaration.

    .PARAMETER AppId
        Id of the Application element to extend.
        Defaults to the first Application in the manifest.

    .PARAMETER Servers
        Array of hashtables, each with:
          Clsid          '{XXXXXXXX-...}' (required)
          VfsDllPath     package-relative path, e.g. 'VFS\ProgramFilesX64\...' (required)
          ThreadingModel 'Apartment' | 'Free' | 'Both' | 'Neutral' (default: 'Apartment')

    .EXAMPLE
        Add-MsixComServerExtension -PackagePath app.msix `
            -Servers @(
                @{ Clsid='{AAAA-...}'; VfsDllPath='VFS\ProgramFilesX64\App\com.dll' }
            ) -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidateScript({
            foreach ($srv in $_) {
                if (-not $srv.Clsid) {
                    throw "Each -Servers entry must include a 'Clsid' key."
                }
                if ($srv.Clsid -notmatch '^(\{)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(\})?$') {
                    throw "Invalid Clsid '$($srv.Clsid)': must be a GUID like 12345678-1234-1234-1234-123456789abc (curly braces optional)."
                }
                if (-not $srv.VfsDllPath) {
                    throw "Each -Servers entry must include a 'VfsDllPath' key."
                }
            }
            $true
        })]
        [hashtable[]]$Servers,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add COM server extension(s)')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -WhatIfPreview:$isWhatIf `
        -Activity 'Add COM server extension(s)' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace $M 'com'
        Add-MsixManifestNamespace $M 'rescap'

        $comUri = Get-MsixManifestNamespaceUri 'com'
        $app    = _MsixGetOrCreateApplicationExtensions $M $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')

        # One com:Extension wrapping all servers
        $comExt    = $M.CreateElement('com:Extension', $comUri)
        $comExt.SetAttribute('Category', 'windows.comServer')
        $comServer = $M.CreateElement('com:ComServer', $comUri)
        $added     = 0

        foreach ($srv in $Servers) {
            # Strip braces — manifest schema expects bare GUID (ST_GUID), no {}
            $clsid     = $srv.Clsid.Trim().Trim('{', '}')
            $vfsDll    = $srv.VfsDllPath
            $threading = if ($srv.ThreadingModel) { $srv.ThreadingModel } else { 'Apartment' }

            # Idempotency — skip if CLSID already declared anywhere in the manifest
            if ($M.SelectSingleNode("//*[local-name()='Class' and @Id='$clsid']")) {
                Write-MsixLog Info "COM class $clsid already declared; skipping."
                continue
            }

            $ips   = $M.CreateElement('com:InProcessServer', $comUri)
            $path  = $M.CreateElement('com:Path', $comUri)
            $path.InnerText = $vfsDll
            $class = $M.CreateElement('com:Class', $comUri)
            $class.SetAttribute('Id', $clsid)             # ST_GUID — no braces
            $class.SetAttribute('ThreadingModel', $threading)

            $null = $ips.AppendChild($path)
            $null = $ips.AppendChild($class)
            $null = $comServer.AppendChild($ips)
            Write-MsixLog Info "COM InProcessServer declared: $clsid → $vfsDll"
            $added++
        }

        if ($added -gt 0) {
            $null = $comExt.AppendChild($comServer)
            $null = $appExt.AppendChild($comExt)

            # Auto-inject runFullTrust (required for COM servers exposed to
            # callers outside the package). Mirrors Add-MsixFirewallRule's
            # canonical pattern: idempotent — skip if already present.
            $rescapUri = Get-MsixManifestNamespaceUri 'rescap'
            $capsNode  = $M.Package.Capabilities
            if (-not $capsNode) {
                $capsNode = $M.CreateElement('Capabilities', $M.Package.NamespaceURI)
                $null = $M.Package.AppendChild($capsNode)
            }
            $hasFullTrust = $capsNode.ChildNodes | Where-Object {
                $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust'
            }
            if (-not $hasFullTrust) {
                $cap = $M.CreateElement('rescap:Capability', $rescapUri)
                $cap.SetAttribute('Name', 'runFullTrust')
                $null = $capsNode.AppendChild($cap)
                Write-MsixLog Info 'Capability added: runFullTrust'
            }
        } else {
            Write-MsixLog Info 'No new COM servers to declare (all already present).'
        }
    }
}

#endregion

