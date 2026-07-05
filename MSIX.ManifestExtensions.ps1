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
    $workspace = New-MsixWorkspace -PackageName $fileinfo.BaseName

    $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
    Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unpack'

    $null = Test-MsixManifest -Path "$workspace\AppxManifest.xml"
    [xml]$manifest = Get-MsixManifest -Path "$workspace\AppxManifest.xml"

    $manifest = Invoke-MsixManifestTransform -Manifest $manifest -Transform $Mutate

    Save-MsixManifest -Manifest $manifest -Path "$workspace\AppxManifest.xml"

    if ($SaveManifestTo) {
        Copy-Item -Path "$workspace\AppxManifest.xml" -Destination $SaveManifestTo -Force
        Write-MsixLog -Level Info -Message "Debug manifest saved to: $SaveManifestTo"
    }

    $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
    $scratchExt = [System.IO.Path]::GetExtension($target)
    if (-not $scratchExt) { $scratchExt = '.msix' }
    $scratch = Join-Path -Path $env:TEMP -ChildPath ("msix-pack-{0}{1}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)), $scratchExt)
    $packSucceeded = $false
    $signSucceeded = $false
    try {
        Write-MsixLog -Level Info -Message "$Activity -> $target"
        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack','/p',$scratch,'/d',$workspace,'/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx pack'
        $packSucceeded = $true

        if ($WhatIfPreview) {
            Write-MsixLog -Level Info -Message "[WhatIf] Would replace '$target' with mutated package. Signing skipped."
            if ($UnsignedOutputPath) {
                Copy-Item -LiteralPath $scratch -Destination $UnsignedOutputPath -Force -ErrorAction Stop
                Write-MsixLog -Level Info -Message "[WhatIf] Preview package copied to: $UnsignedOutputPath"
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
                Write-MsixLog -Level Warning -Message "Signing failed. Unsigned package preserved at: $UnsignedOutputPath"
            } catch {
                Write-MsixLog -Level Error -Message "Signing failed AND unsigned-output copy to '$UnsignedOutputPath' failed: $_"
            }
        } elseif ($packSucceeded -and -not $signSucceeded) {
            Write-MsixLog -Level Warning -Message "Signing failed. Original target '$target' is unchanged. Pass -UnsignedOutputPath to preserve the unsigned package next time."
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
    .SYNOPSIS
        Runs a pure in-memory manifest transform — no file IO, no signing.

    .DESCRIPTION
        Accepts an [xml] document or MSIX.ManifestDocument wrapper, binds the
        supplied scriptblock to the module session state (so module-private
        helpers resolve), invokes it against the manifest, and returns the
        mutated [xml]. Used internally by _MsixMutateManifest; also useful for
        testing manifest edits without a pack/sign cycle.

    .PARAMETER Manifest
        The manifest to transform: [xml], MSIX.ManifestDocument, or raw XML
        text (routed through the hardened XXE-safe loader).

    .PARAMETER Transform
        Scriptblock receiving the [xml] document as its first argument.

    .EXAMPLE
        [xml]$m = Get-MsixManifest -Path 'C:\work\AppxManifest.xml'
        Invoke-MsixManifestTransform -Manifest $m -Transform {
            param([xml]$x)
            Set-MsixManifestPublisher -Manifest $x -Publisher 'CN=New'
        }

    .OUTPUTS
        [xml] — the mutated manifest document.
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
        # SECURITY: a raw [xml] cast on a string invokes XmlDocument.LoadXml with
        # the default resolver and DTD processing enabled (XXE). Route untrusted
        # manifest text through the hardened loader instead.
        _MsixLoadXmlSecure -XmlText ([string]$Manifest)
    }
    # Bind the transform to this module's session state so module-private
    # helpers it calls always resolve regardless of where the block was created.
    # Falls back to the block as-is if it is already bound to a different module.
    $boundTransform = $Transform
    if ($ExecutionContext.SessionState.Module) {
        try { $boundTransform = $ExecutionContext.SessionState.Module.NewBoundScriptBlock($Transform) } catch { $boundTransform = $Transform }
    }
    & $boundTransform $xml
    return $xml
}


function _MsixGetOrCreateApplicationExtensions {
    # Returns the Application XmlElement, creating its <Extensions> child if absent.
    # When $AppId is empty, defaults to the first Application in the manifest.
    param([xml]$Manifest, [string]$AppId)
    # Get-MsixManifestApplication validates -AppId as non-empty, so only pass
    # it when the caller actually specified one (empty = first Application).
    if ($AppId) {
        $app = Get-MsixManifestApplication -Manifest $Manifest -AppId $AppId
    } else {
        $app = @(Get-MsixManifestApplication -Manifest $Manifest) | Select-Object -First 1
    }
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
        The .msix file to mutate.

    .PARAMETER Enable
        Write 'enabled' instead of the default 'disabled'.

    .PARAMETER ExcludedDirectories
        Paths excluded from virtualization. Defaults to LocalAppData and
        RoamingAppData — the same defaults as the MSIX Packaging Tool.
        Use KnownFolder tokens (e.g. '$(KnownFolder:LocalAppData)') or
        VFS-relative paths. Pass @() to suppress excluded-dirs entirely.

    .PARAMETER OutputPath
        See Add-MsixPsfV2.

    .PARAMETER SkipSigning
        See Add-MsixPsfV2.

    .PARAMETER Pfx
        See Add-MsixPsfV2.

    .PARAMETER PfxPassword
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
        Add-MsixManifestNamespace -Manifest $M -Prefix 'desktop6'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'rescap'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 19041

        $props = $M.Package.Properties
        $d6    = Get-MsixManifestNamespaceUri -Prefix 'desktop6'

        # ── desktop6 flag element (idempotent) ─────────────────────────────
        $flag = $props.SelectSingleNode(
            '*[local-name()="FileSystemWriteVirtualization" and ' +
            'namespace-uri()="' + $d6 + '"]')
        if (-not $flag) {
            $flag = $M.CreateElement('desktop6:FileSystemWriteVirtualization', $d6)
            $null = $props.AppendChild($flag)
        }
        $flag.InnerText = if ($Enable) { 'enabled' } else { 'disabled' }
        Write-MsixLog -Level Info -Message "desktop6:FileSystemWriteVirtualization set to '$($flag.InnerText)'."

        # ── virtualization:ExcludedDirectories ────────────────────────────
        # Always written alongside the flag (matches commercial tool behaviour).
        $virtUri  = Get-MsixManifestNamespaceUri -Prefix 'virtualization'
        $virtNode = $props.SelectSingleNode(
            '*[local-name()="FileSystemWriteVirtualization" and ' +
            'namespace-uri()="' + $virtUri + '"]')
        if ($virtNode) { $null = $props.RemoveChild($virtNode) }

        # SECURITY/CORRECTNESS (issue #81): virtualization:ExcludedDirectory only
        # accepts a KnownFolder token of the form $(KnownFolder:Name) optionally
        # followed by \subpath — it is the MSIX schema's documented pattern
        #   \$\([kK][nN][oO][wW][nN][fF][oO][lL][dD][eE][rR]:[A-Za-z0-9]{1,32}\)(\\.+)?
        # An install-relative / VFS path such as 'VFS/ProgramFilesX64/App/Lang'
        # CANNOT be expressed here and makes MakeAppx fail schema validation.
        # Normalise separators, drop invalid entries with a clear warning, and
        # only emit the element when at least one valid token remains — so this
        # function can never produce a manifest MakeAppx rejects.
        $knownFolderRx = [regex]'^\$\(KnownFolder:[A-Za-z0-9]{1,32}\)(\\.+)?$'
        $validDirs = [System.Collections.Generic.List[string]]::new()
        foreach ($dir in $ExcludedDirectories) {
            # ExcludedDirectory uses backslash separators inside the subpath.
            $norm = ([string]$dir).Replace('/', '\')
            if ($knownFolderRx.IsMatch($norm)) {
                if (-not $validDirs.Contains($norm)) { $validDirs.Add($norm) }
            } else {
                Write-MsixLog -Level Warning -Message "Skipping ExcludedDirectory '$dir': virtualization:ExcludedDirectory only accepts a `$(KnownFolder:Name)[\subpath] token, not an install-relative/VFS path. Use the PSF FileRedirection route (Add-MsixPsfV2 / -LegacyPluginFix) for install-directory passthrough."
            }
        }

        if ($validDirs.Count -gt 0) {
            Add-MsixManifestNamespace -Manifest $M -Prefix 'virtualization'
            $virtNode = $M.CreateElement('virtualization:FileSystemWriteVirtualization', $virtUri)
            $dirs     = $M.CreateElement('virtualization:ExcludedDirectories', $virtUri)
            foreach ($dir in $validDirs) {
                $entry = $M.CreateElement('virtualization:ExcludedDirectory', $virtUri)
                $entry.InnerText = $dir
                $null = $dirs.AppendChild($entry)
            }
            $null = $virtNode.AppendChild($dirs)
            $null = $props.AppendChild($virtNode)
            Write-MsixLog -Level Info -Message "virtualization:FileSystemWriteVirtualization: $($validDirs.Count) excluded dir(s)."
        } elseif ($ExcludedDirectories.Count -gt 0) {
            Write-MsixLog -Level Warning -Message 'No valid KnownFolder ExcludedDirectory tokens remained; emitting the disabled flag only (no virtualization:ExcludedDirectories element).'
        }

        # ── unvirtualizedResources capability (required by the schema) ─────
        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
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
            Write-MsixLog -Level Info -Message "Capability added: unvirtualizedResources"
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
        Registry key paths that should be passed through to the host registry
        instead of being virtualized. Only HKEY_CURRENT_USER\* paths are valid
        — HKLM exclusions are not supported by the schema and will throw.
        Maximum 512 chars per key path. Duplicates (case-insensitive) are
        collapsed. No defaults — omit to skip the
        virtualization:RegistryWriteVirtualization section entirely.

    .EXAMPLE
        Set-MsixRegistryWriteVirtualization -PackagePath app.msix -Pfx cert.pfx -PfxPassword 'P@ss'

    .EXAMPLE
        # Selectively pass through specific HKCU subkeys to the host registry
        Set-MsixRegistryWriteVirtualization -PackagePath app.msix `
            -ExcludedKeys 'HKEY_CURRENT_USER\SOFTWARE\Contoso','HKEY_CURRENT_USER\SOFTWARE\Contoso\v2' `
            -Pfx cert.pfx -PfxPassword $pw
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [switch]$Enable,
        [string[]]$ExcludedKeys = @(),
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

        # ── validate -ExcludedKeys before any mutation ─────────────────────
        $validatedKeys = @()
        if ($ExcludedKeys.Count -gt 0) {
            foreach ($key in $ExcludedKeys) {
                if ([string]::IsNullOrWhiteSpace($key)) {
                    throw "ExcludedKeys entries may not be empty or whitespace."
                }
                if ($key -notmatch '^HKEY_CURRENT_USER\\') {
                    throw "ExcludedKeys may only contain HKEY_CURRENT_USER paths. Got: '$key'"
                }
                if ($key.Length -gt 512) {
                    throw "ExcludedKeys entry exceeds 512 chars ($($key.Length)): '$key'"
                }
            }
            # Case-insensitive dedupe, preserve first-seen order.
            $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($key in $ExcludedKeys) {
                if ($seen.Add($key)) { $validatedKeys += $key }
            }
        }

        Add-MsixManifestNamespace -Manifest $M -Prefix 'desktop6'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'rescap'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 19041

        $props = $M.Package.Properties
        $d6    = Get-MsixManifestNamespaceUri -Prefix 'desktop6'

        # ── desktop6 flag element (idempotent) ─────────────────────────────
        $flag = $props.SelectSingleNode(
            '*[local-name()="RegistryWriteVirtualization" and ' +
            'namespace-uri()="' + $d6 + '"]')
        if (-not $flag) {
            $flag = $M.CreateElement('desktop6:RegistryWriteVirtualization', $d6)
            $null = $props.AppendChild($flag)
        }
        $flag.InnerText = if ($Enable) { 'enabled' } else { 'disabled' }
        Write-MsixLog -Level Info -Message "desktop6:RegistryWriteVirtualization set to '$($flag.InnerText)'."

        # ── virtualization:ExcludedKeys (optional) ─────────────────────────
        $virtUri  = Get-MsixManifestNamespaceUri -Prefix 'virtualization'
        $virtNode = $props.SelectSingleNode(
            '*[local-name()="RegistryWriteVirtualization" and ' +
            'namespace-uri()="' + $virtUri + '"]')
        if ($virtNode) { $null = $props.RemoveChild($virtNode) }

        if ($validatedKeys.Count -gt 0) {
            Add-MsixManifestNamespace -Manifest $M -Prefix 'virtualization'
            $virtNode = $M.CreateElement('virtualization:RegistryWriteVirtualization', $virtUri)
            $keys     = $M.CreateElement('virtualization:ExcludedKeys', $virtUri)
            foreach ($k in $validatedKeys) {
                $entry = $M.CreateElement('virtualization:ExcludedKey', $virtUri)
                $entry.SetAttribute('Key', $k)
                $null = $keys.AppendChild($entry)
            }
            $null = $virtNode.AppendChild($keys)
            $null = $props.AppendChild($virtNode)
            Write-MsixLog -Level Info -Message "virtualization:RegistryWriteVirtualization: $($validatedKeys.Count) excluded key(s)."
        }

        # ── unvirtualizedResources capability (required by the schema) ─────
        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
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
            Write-MsixLog -Level Info -Message "Capability added: unvirtualizedResources"
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

    .PARAMETER ModifiedItems
        Each accepts 'keep' or 'reset'. Defaults match TMEditX:
        ModifiedItems=keep, DeletedItems=reset, AddedItems=keep.

    .PARAMETER DeletedItems
        Each accepts 'keep' or 'reset'. Defaults match TMEditX:
        ModifiedItems=keep, DeletedItems=reset, AddedItems=keep.

    .PARAMETER AddedItems
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
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap10'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 19041

        $pkgExt = _MsixGetOrCreatePackageExtensions -Manifest $M
        $cat    = 'windows.installedLocationVirtualization'
        $existing = $pkgExt.ChildNodes | Where-Object {
            $_.LocalName -eq 'Extension' -and $_.Category -eq $cat
        }
        foreach ($e in @($existing)) { $null = $pkgExt.RemoveChild($e) }
        if ($Disable) {
            Write-MsixLog -Level Info -Message 'InstalledLocationVirtualization disabled.'
            return
        }

        $u10 = Get-MsixManifestNamespaceUri -Prefix 'uap10'
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
        Write-MsixLog -Level Info -Message "uap10:InstalledLocationVirtualization added (Mod=$ModifiedItems, Del=$DeletedItems, Add=$AddedItems)."
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
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap6'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 17134

        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
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
            $u6   = Get-MsixManifestNamespaceUri -Prefix 'uap6'
            $ext  = $M.CreateElement('uap6:Extension', $u6)
            $ext.SetAttribute('Category', 'windows.loaderSearchPathOverride')
            $body = $M.CreateElement('uap6:LoaderSearchPathOverride', $u6)
            $null = $ext.AppendChild($body)
            $null = $appExt.AppendChild($ext)
        }

        $u6 = Get-MsixManifestNamespaceUri -Prefix 'uap6'
        foreach ($p in $Paths) {
            # Idempotent: skip if same entry already present
            $already = $body.ChildNodes | Where-Object {
                $_.LocalName -eq 'LoaderSearchPathEntry' -and $_.LoaderSearchPath -eq $p
            }
            if ($already) {
                Write-MsixLog -Level Info -Message "LoaderSearchPathEntry already present: $p"
                continue
            }
            $entry = $M.CreateElement('uap6:LoaderSearchPathEntry', $u6)
            $entry.SetAttribute('LoaderSearchPath', $p)
            $null = $body.AppendChild($entry)
            Write-MsixLog -Level Info -Message "LoaderSearchPathEntry added: $p"
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
        Add-MsixManifestNamespace -Manifest $M -Prefix 'desktop2'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'rescap'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 15063

        $app = Get-MsixManifestApplication -Manifest $M -AppId $AppId
        if (-not $app) { throw "Application '$AppId' not found in the manifest." }

        $d2  = Get-MsixManifestNamespaceUri -Prefix 'desktop2'

        # windows.firewallRules is a package-level extension:
        # Package/Extensions/desktop2:Extension/desktop2:FirewallRules
        $pkgExt = _MsixGetOrCreatePackageExtensions -Manifest $M
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

        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
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
            Write-MsixLog -Level Info -Message 'Capability added: runFullTrust'
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
        Write-MsixLog -Level Info -Message "FirewallRule: $Direction $Protocol $LocalPort -> $Executable"
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
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap'

        $app   = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        $uap    = Get-MsixManifestNamespaceUri -Prefix 'uap'

        # Idempotent: same Name already declared?
        $already = $appExt.SelectNodes('*[local-name()="Extension" and @Category="windows.protocol"]') |
                   ForEach-Object { $_.SelectSingleNode('*[local-name()="Protocol" and @Name="' + $Name + '"]') } |
                   Where-Object { $_ }
        if ($already) {
            Write-MsixLog -Level Info -Message "Protocol '$Name' already registered."
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
        Write-MsixLog -Level Info -Message "Protocol added: $Name"
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

    .PARAMETER Logo
        Package-relative path to the per-type icon (e.g. Assets\doc.png).
        Without it, associated files show the app tile icon. The image must
        already exist inside the package.

    .PARAMETER InfoTip
        Hover tooltip for files of this type.

    .PARAMETER OpenIsSafe
        Sets EditFlags OpenIsSafe="true" (the type is safe to open
        automatically, e.g. from a browser download prompt).

    .PARAMETER AlwaysUnsafe
        Sets EditFlags AlwaysUnsafe="true" (never open without prompting).
        Mutually exclusive with -OpenIsSafe.

    .PARAMETER Verbs
        Extra context-menu verbs beyond open. Array of hashtables:
        @{ Id = 'edit'; Parameters = '--edit "%1"'; DisplayName = 'Edit' }.
        Emitted as uap2:SupportedVerbs / uap3:Verb.

    .EXAMPLE
        Add-MsixFileTypeAssociation -PackagePath app.msix -AppId App `
            -Name contosodoc -FileTypes '.cdoc','.cdocx' -DisplayName 'Contoso Document' `
            -Pfx cert.pfx -PfxPassword 'P@ss'

    .EXAMPLE
        # Rich FTA: icon, tooltip, safe-open, plus an Edit verb (issue #119)
        Add-MsixFileTypeAssociation -PackagePath app.msix -AppId App `
            -Name contosodoc -FileTypes '.cdoc' -DisplayName 'Contoso Document' `
            -Logo 'Assets\cdoc.png' -InfoTip 'Contoso document file' -OpenIsSafe `
            -Verbs @(@{ Id = 'edit'; Parameters = '--edit "%1"'; DisplayName = 'Edit' }) `
            -SkipSigning
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
        [string]$Logo,
        [string]$InfoTip,
        [switch]$OpenIsSafe,
        [switch]$AlwaysUnsafe,
        [hashtable[]]$Verbs,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    if ($OpenIsSafe -and $AlwaysUnsafe) { throw '-OpenIsSafe and -AlwaysUnsafe are mutually exclusive.' }
    foreach ($v in @($Verbs | Where-Object { $null -ne $_ })) {
        if (-not $v.Id) { throw "Each -Verbs entry needs an Id key (got: $($v.Keys -join ', '))." }
    }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add FTA $Name")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'uap:FileTypeAssociation' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap'

        $app   = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        $uap    = Get-MsixManifestNamespaceUri -Prefix 'uap'

        $ext  = $M.CreateElement('uap:Extension', $uap)
        $ext.SetAttribute('Category', 'windows.fileTypeAssociation')

        $fta = $M.CreateElement('uap:FileTypeAssociation', $uap)
        $fta.SetAttribute('Name', $Name.ToLower())

        # Schema-mandated child order: DisplayName, Logo, InfoTip, EditFlags,
        # SupportedFileTypes, SupportedVerbs (issue #119).
        if ($DisplayName) {
            $dn = $M.CreateElement('uap:DisplayName', $uap)
            $dn.InnerText = $DisplayName
            $null = $fta.AppendChild($dn)
        }
        if ($Logo) {
            $logoNode = $M.CreateElement('uap:Logo', $uap)
            $logoNode.InnerText = $Logo.Replace('/', '\')
            $null = $fta.AppendChild($logoNode)
        }
        if ($InfoTip) {
            $tip = $M.CreateElement('uap:InfoTip', $uap)
            $tip.InnerText = $InfoTip
            $null = $fta.AppendChild($tip)
        }
        if ($OpenIsSafe -or $AlwaysUnsafe) {
            $flags = $M.CreateElement('uap:EditFlags', $uap)
            if ($OpenIsSafe)   { $flags.SetAttribute('OpenIsSafe',   'true') }
            if ($AlwaysUnsafe) { $flags.SetAttribute('AlwaysUnsafe', 'true') }
            $null = $fta.AppendChild($flags)
        }

        $supported = $M.CreateElement('uap:SupportedFileTypes', $uap)
        foreach ($ft in $FileTypes) {
            if (-not $ft.StartsWith('.')) { $ft = ".$ft" }
            $type = $M.CreateElement('uap:FileType', $uap)
            $type.InnerText = $ft.ToLower()
            $null = $supported.AppendChild($type)
        }
        $null = $fta.AppendChild($supported)

        if ($Verbs) {
            Add-MsixManifestNamespace -Manifest $M -Prefix 'uap2'
            Add-MsixManifestNamespace -Manifest $M -Prefix 'uap3'
            $uap2 = Get-MsixManifestNamespaceUri -Prefix 'uap2'
            $uap3 = Get-MsixManifestNamespaceUri -Prefix 'uap3'
            $verbsNode = $M.CreateElement('uap2:SupportedVerbs', $uap2)
            foreach ($v in $Verbs) {
                $verbNode = $M.CreateElement('uap3:Verb', $uap3)
                $verbNode.SetAttribute('Id', [string]$v.Id)
                if ($v.Parameters) { $verbNode.SetAttribute('Parameters', [string]$v.Parameters) }
                $verbText = if ($v.DisplayName) { [string]$v.DisplayName } else { [string]$v.Id }
                $verbNode.InnerText = $verbText
                $null = $verbsNode.AppendChild($verbNode)
            }
            $null = $fta.AppendChild($verbsNode)
        }

        $null = $ext.AppendChild($fta)
        $null = $appExt.AppendChild($ext)
        Write-MsixLog -Level Info -Message "FTA $Name registered for: $($FileTypes -join ', ')"
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
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap5'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 15063

        $app   = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        $u5    = Get-MsixManifestNamespaceUri -Prefix 'uap5'

        # Idempotent: same TaskId?
        $already = $appExt.SelectNodes('*[local-name()="Extension" and @Category="windows.startupTask"]') |
                   ForEach-Object { $_.SelectSingleNode('*[local-name()="StartupTask" and @TaskId="' + $TaskId + '"]') } |
                   Where-Object { $_ }
        if ($already) {
            Write-MsixLog -Level Info -Message "StartupTask '$TaskId' already registered."
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
        Write-MsixLog -Level Info -Message "StartupTask added: $TaskId (Enabled=$Enabled)"
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
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap4'
        $u4 = Get-MsixManifestNamespaceUri -Prefix 'uap4'

        # windows.sharedFonts is an APPLICATION-level extension — placing it
        # under Package/Extensions fails MakeAppx schema validation
        # ("uap4:Extension is unexpected according to content model of parent
        # element Extensions"). Register it under the first Application.
        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        $cat    = 'windows.sharedFonts'
        $existing = $appExt.ChildNodes | Where-Object {
            $_.LocalName -eq 'Extension' -and $_.Category -eq $cat
        } | Select-Object -First 1
        if (-not $existing) {
            $existing = $M.CreateElement('uap4:Extension', $u4)
            $existing.SetAttribute('Category', $cat)
            $body = $M.CreateElement('uap4:SharedFonts', $u4)
            $null = $existing.AppendChild($body)
            $null = $appExt.AppendChild($existing)
        } else {
            $body = $existing.SelectSingleNode('*[local-name()="SharedFonts"]')
        }

        $alreadyFiles = $body.ChildNodes |
            Where-Object { $_.LocalName -eq 'Font' } |
            ForEach-Object { $_.File }

        foreach ($p in $FontPaths) {
            $rel = $p.Replace('\','/')
            if ($alreadyFiles -contains $rel) {
                Write-MsixLog -Level Info -Message "Font already registered: $rel"
                continue
            }
            $node = $M.CreateElement('uap4:Font', $u4)
            $node.SetAttribute('File', $rel)
            $null = $body.AppendChild($node)
            Write-MsixLog -Level Info -Message "Font registered: $rel"
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
            # A pri-localized value: Windows resolves the DISPLAYED string from
            # resources.pri, so replacing only the manifest text is a silent
            # no-op at runtime (issue #109). Overwrite anyway (the reference is
            # gone afterwards, which un-localizes the field) but tell the
            # operator why the change may not show until the pri stops winning.
            if ($node.InnerText -match '^ms-resource:') {
                Write-MsixLog -Level Warning -Message ("{0} was pri-localized ('{1}'). The displayed value comes from resources.pri; after this edit the literal manifest value is used for THIS field, but other pri-backed fields stay localized. If the displayed name does not change, rebuild resources.pri with makepri.exe." -f $LocalName, $node.InnerText)
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
        Write-MsixLog -Level Info -Message 'Brand metadata updated.'
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
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap2'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap3'
        # uap2:SupportedVerbs + uap3:Verb require build 16299+ (Win10 1709).
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 16299

        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        $uap    = Get-MsixManifestNamespaceUri -Prefix 'uap'
        $uap2   = Get-MsixManifestNamespaceUri -Prefix 'uap2'
        $uap3   = Get-MsixManifestNamespaceUri -Prefix 'uap3'

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
        Write-MsixLog -Level Info -Message "Shell verb '$VerbDisplayName' (Id=$VerbId) registered for: $scope"
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
        # Package-level windows.comServer requires the com4 schema (v10/4) —
        # MakeAppx hard-errors on the bare 'com' namespace at package scope:
        #   "Extension 'windows.comServer' must be
        #    'http://schemas.microsoft.com/appx/manifest/com/windows10/4'
        #    or newer on package level."
        Add-MsixManifestNamespace -Manifest $M -Prefix 'com4'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'rescap'

        $comUri = Get-MsixManifestNamespaceUri -Prefix 'com4'

        # AppId is retained for backward compat / sanity check only.
        # com:Extension/windows.comServer declares a CLSID for system-wide
        # COM activation. The shell and other consumers look it up at the
        # PACKAGE level, never inside Applications/Application/Extensions.
        # Installing into Application/Extensions used to silently work for
        # MakeAppx but the OS never registered the shell handler at runtime
        # (root cause of the "legacy context menu doesn't appear" bug).
        if ($AppId) {
            $null = Get-MsixManifestApplication -Manifest $M -AppId $AppId
        }
        $appExt = _MsixGetOrCreatePackageExtensions -Manifest $M

        # One com4:Extension wrapping all servers
        $comExt    = $M.CreateElement('com4:Extension', $comUri)
        $comExt.SetAttribute('Category', 'windows.comServer')
        $comServer = $M.CreateElement('com4:ComServer', $comUri)
        $added     = 0

        foreach ($srv in $Servers) {
            # Strip braces — manifest schema expects bare GUID (ST_GUID), no {}
            $clsid     = $srv.Clsid.Trim().Trim('{', '}')
            $vfsDll    = $srv.VfsDllPath
            $threading = if ($srv.ThreadingModel) { $srv.ThreadingModel } else { 'Apartment' }

            # Idempotency — skip if CLSID already declared anywhere in the manifest
            if ($M.SelectSingleNode("//*[local-name()='Class' and @Id='$clsid']")) {
                Write-MsixLog -Level Info -Message "COM class $clsid already declared; skipping."
                continue
            }

            $ips   = $M.CreateElement('com4:InProcessServer', $comUri)
            $path  = $M.CreateElement('com4:Path', $comUri)
            $path.InnerText = $vfsDll
            $class = $M.CreateElement('com4:Class', $comUri)
            $class.SetAttribute('Id', $clsid)             # ST_GUID — no braces
            $class.SetAttribute('ThreadingModel', $threading)

            $null = $ips.AppendChild($path)
            $null = $ips.AppendChild($class)
            $null = $comServer.AppendChild($ips)
            Write-MsixLog -Level Info -Message "COM InProcessServer declared: $clsid → $vfsDll"
            $added++
        }

        if ($added -gt 0) {
            $null = $comExt.AppendChild($comServer)
            $null = $appExt.AppendChild($comExt)

            # Auto-inject runFullTrust (required for COM servers exposed to
            # callers outside the package). Mirrors Add-MsixFirewallRule's
            # canonical pattern: idempotent — skip if already present.
            $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
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
                Write-MsixLog -Level Info -Message 'Capability added: runFullTrust'
            }
        } else {
            Write-MsixLog -Level Info -Message 'No new COM servers to declare (all already present).'
        }
    }
}

#endregion


#region Packaged services (desktop6, issue #112) ----------------------------

function Add-MsixService {
    <#
    .SYNOPSIS
        Declares a packaged Windows service (desktop6 windows.service) so the
        service installs/starts with the MSIX package.

    .DESCRIPTION
        Adds a desktop6:Extension Category="windows.service" with a
        desktop6:Service child under the target Application, declares the
        required restricted capabilities (packagedServices; plus
        localSystemServices when -StartAccount localSystem), and raises
        MaxVersionTested to 10.0.19041.0 (packaged services shipped in
        Windows 10 2004).

        This turns the "windows service detected - unsupported" finding from
        the limitation scanner into a fixable declaration: agents, updaters
        and licensing services can ship inside the package.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER AppId
        Application to attach the service to (default: first Application).

    .PARAMETER Executable
        Package-relative path to the service executable
        (e.g. VFS\ProgramFilesX64\App\agent.exe).

    .PARAMETER Name
        Service name (SCM name).

    .PARAMETER StartupType
        auto | demand | manual (schema values: auto starts with Windows).
        Default: auto.

    .PARAMETER StartAccount
        localService (default) | localSystem | networkService.
        localSystem additionally requires the localSystemServices restricted
        capability, which is added automatically (Store submissions need
        approval for it; sideload/enterprise installs are fine).

    .PARAMETER Arguments
        Optional command-line arguments for the service.

    .PARAMETER Dependencies
        Optional service names this service depends on (SCM dependencies).

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        # Package an agent service that starts with Windows as LocalService
        Add-MsixService -PackagePath app.msix `
            -Executable 'VFS\ProgramFilesX64\App\agent.exe' `
            -Name 'ContosoAgent' -StartupType auto -StartAccount localService `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # LocalSystem service with SCM dependencies (adds localSystemServices)
        Add-MsixService -PackagePath app.msix `
            -Executable 'VFS\ProgramFilesX64\App\licsvc.exe' `
            -Name 'ContosoLicense' -StartAccount localSystem `
            -Dependencies 'rpcss' -SkipSigning

    .LINK
        https://learn.microsoft.com/windows/msix/desktop/convert-a-windows-service
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
        [string]$AppId,
        [Parameter(Mandatory)] [string]$Executable,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9_.-]+$')]
        [string]$Name,
        [ValidateSet('auto', 'demand', 'manual')]
        [string]$StartupType = 'auto',
        [ValidateSet('localService', 'localSystem', 'networkService')]
        [string]$StartAccount = 'localService',
        [string]$Arguments,
        [string[]]$Dependencies,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add packaged service '$Name'")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity "Add packaged service '$Name'" -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'desktop6'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'rescap'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 19041
        $d6 = Get-MsixManifestNamespaceUri -Prefix 'desktop6'

        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')

        # Idempotency: same service Name already declared?
        if ($M.SelectSingleNode("//*[local-name()='Service' and @Name='$Name']")) {
            Write-MsixLog -Level Info -Message "Packaged service '$Name' already declared - skipping."
            return
        }

        $ext = $M.CreateElement('desktop6:Extension', $d6)
        $ext.SetAttribute('Category',   'windows.service')
        $ext.SetAttribute('Executable', $Executable.Replace('/', '\'))
        $ext.SetAttribute('EntryPoint', 'Windows.FullTrustApplication')

        $svc = $M.CreateElement('desktop6:Service', $d6)
        $svc.SetAttribute('Name',         $Name)
        $svc.SetAttribute('StartupType',  $StartupType)
        $svc.SetAttribute('StartAccount', $StartAccount)
        if ($Arguments) { $svc.SetAttribute('Arguments', $Arguments) }

        if ($Dependencies) {
            $depsNode = $M.CreateElement('desktop6:Dependencies', $d6)
            foreach ($dep in $Dependencies) {
                $depNode = $M.CreateElement('desktop6:DependentService', $d6)
                $depNode.SetAttribute('Name', $dep)
                $null = $depsNode.AppendChild($depNode)
            }
            $null = $svc.AppendChild($depsNode)
        }

        $null = $ext.AppendChild($svc)
        $null = $appExt.AppendChild($ext)

        # Required restricted capabilities.
        $capsNode = $M.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $M.CreateElement('Capabilities', $M.Package.NamespaceURI)
            $null     = $M.Package.AppendChild($capsNode)
        }
        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
        $needed = @('packagedServices')
        if ($StartAccount -eq 'localSystem') { $needed += 'localSystemServices' }
        foreach ($cap in $needed) {
            $exists = $capsNode.ChildNodes | Where-Object {
                $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq $cap }
            if (-not $exists) {
                $node = $M.CreateElement('rescap:Capability', $rescapUri)
                $node.SetAttribute('Name', $cap)
                $null = $capsNode.AppendChild($node)
                Write-MsixLog -Level Info -Message "Capability added: $cap"
            }
        }
        Write-MsixLog -Level Info -Message "Packaged service '$Name' declared (StartupType=$StartupType, StartAccount=$StartAccount)."
    }
}

#endregion

#region Package dependencies (issue #115) ------------------------------------

# Well-known framework packages: correct Publisher strings so callers only
# need the name. All Microsoft-published frameworks share the corporate CN.
$script:KnownFrameworkPublishers = @{
    'Microsoft.VCLibs.140.00'            = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    'Microsoft.VCLibs.140.00.UWPDesktop' = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    'Microsoft.WindowsAppRuntime.1.4'    = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    'Microsoft.WindowsAppRuntime.1.5'    = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    'Microsoft.WindowsAppRuntime.1.6'    = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    'Microsoft.NET.Native.Framework.2.2' = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    'Microsoft.NET.Native.Runtime.2.2'   = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
    'Microsoft.UI.Xaml.2.8'              = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
}

function Add-MsixPackageDependency {
    <#
    .SYNOPSIS
        Declares a <PackageDependency> (framework dependency) in the manifest -
        e.g. VCLibs or the Windows App SDK runtime.

    .DESCRIPTION
        Adds (or updates) a PackageDependency element under
        Package/Dependencies. For well-known Microsoft frameworks the
        Publisher string is filled in automatically; for custom frameworks
        pass -Publisher explicitly.

        Idempotent: if the dependency already exists, MinVersion is raised
        when the requested version is higher (never lowered).

        Alternative to bundling: Add-MsixVcRuntimeBundle copies VC runtime
        DLLs INTO the package; this cmdlet declares a dependency on the
        VCLibs framework package instead (smaller package, but the framework
        must be present/deployable on the target).

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER Name
        Dependency package name (e.g. Microsoft.VCLibs.140.00.UWPDesktop).

    .PARAMETER MinVersion
        Minimum version, four parts (e.g. 14.0.33321.0).

    .PARAMETER Publisher
        Publisher DN of the dependency. Auto-filled for well-known Microsoft
        frameworks; mandatory for anything unknown.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        # Depend on VCLibs Desktop instead of bundling the DLLs
        Add-MsixPackageDependency -PackagePath app.msix `
            -Name Microsoft.VCLibs.140.00.UWPDesktop -MinVersion 14.0.33321.0 -SkipSigning

    .EXAMPLE
        # Custom in-house framework
        Add-MsixPackageDependency -PackagePath app.msix `
            -Name Contoso.SharedRuntime -MinVersion 1.2.0.0 `
            -Publisher 'CN=Contoso Ltd' -SkipSigning
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9.-]{2,49}$')]
        [string]$Name,
        [Parameter(Mandatory)]
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$MinVersion,
        [string]$Publisher,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    if (-not $Publisher) {
        if ($script:KnownFrameworkPublishers.ContainsKey($Name)) {
            $Publisher = $script:KnownFrameworkPublishers[$Name]
        } else {
            throw "Unknown framework '$Name' - pass -Publisher explicitly (well-known: $($script:KnownFrameworkPublishers.Keys -join ', '))."
        }
    }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add package dependency '$Name'")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity "Add package dependency '$Name'" -Mutate {
        param([xml]$M)

        $deps = $M.Package.SelectSingleNode('*[local-name()="Dependencies"]')
        if (-not $deps) {
            $deps = $M.CreateElement('Dependencies', $M.Package.NamespaceURI)
            $null = $M.Package.AppendChild($deps)
        }

        $existing = $deps.SelectSingleNode("*[local-name()='PackageDependency' and @Name='$Name']")
        if ($existing) {
            $cur = $null
            if ([version]::TryParse($existing.GetAttribute('MinVersion'), [ref]$cur) -and $cur -ge [version]$MinVersion) {
                Write-MsixLog -Level Info -Message "PackageDependency '$Name' already at MinVersion $cur (>= $MinVersion) - skipping."
                return
            }
            $existing.SetAttribute('MinVersion', $MinVersion)
            Write-MsixLog -Level Info -Message "PackageDependency '$Name' MinVersion raised to $MinVersion."
            return
        }

        $node = $M.CreateElement('PackageDependency', $M.Package.NamespaceURI)
        $node.SetAttribute('Name',       $Name)
        $node.SetAttribute('MinVersion', $MinVersion)
        $node.SetAttribute('Publisher',  $Publisher)
        $null = $deps.AppendChild($node)
        Write-MsixLog -Level Info -Message "PackageDependency added: $Name >= $MinVersion."
    }
}

#endregion

#region Shell handler extensions (issue #113) --------------------------------

function Add-MsixShellHandlerExtension {
    <#
    .SYNOPSIS
        Declares a preview, thumbnail or property shell handler for file types
        (registry-free COM + the desktop2 handler element on an FTA).

    .DESCRIPTION
        Registers the handler DLL as a com:SurrogateServer class and attaches
        the matching desktop2 element to a file-type association:

          Preview   -> desktop2:DesktopPreviewHandler   (preview pane)
          Property  -> desktop2:DesktopPropertyHandler  (details/properties)
          Thumbnail -> desktop2:ThumbnailHandler        (thumbnail images)

        The handler element is added to an existing FileTypeAssociation with
        the given -FtaName, or a minimal FTA (Name + SupportedFileTypes) is
        created. Per the schema, ThumbnailHandler requires the application to
        use the full-trust entry point.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER AppId
        Application to attach to (default: first Application).

    .PARAMETER Kind
        Preview | Property | Thumbnail.

    .PARAMETER Clsid
        GUID of the handler COM class (braces optional).

    .PARAMETER Dll
        Package-relative path to the handler DLL
        (e.g. VFS\ProgramFilesX64\App\PreviewHandler.dll).

    .PARAMETER FileTypes
        Extensions the handler serves (e.g. '.contoso', '.log').

    .PARAMETER FtaName
        Name of the FileTypeAssociation to attach to / create
        (lowercase letters, digits, dot, dash). Default: derived from Kind.

    .PARAMETER DisplayName
        Display name for the COM surrogate server. Default: FtaName.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        # Preview pane support for .contoso files
        Add-MsixShellHandlerExtension -PackagePath app.msix -Kind Preview `
            -Clsid '{D7E6F1A2-3B4C-4D5E-9F00-112233445566}' `
            -Dll 'VFS\ProgramFilesX64\App\PreviewHandler.dll' `
            -FileTypes '.contoso' -SkipSigning

    .EXAMPLE
        # Thumbnails for a custom image format
        Add-MsixShellHandlerExtension -PackagePath app.msix -Kind Thumbnail `
            -Clsid 'a1b2c3d4-e5f6-4789-abcd-ef0123456789' `
            -Dll 'VFS\ProgramFilesX64\App\Thumbs.dll' `
            -FileTypes '.cimg' -Pfx cert.pfx -PfxPassword $pw

    .LINK
        https://learn.microsoft.com/uwp/schemas/appxpackage/uapmanifestschema/element-desktop2-desktoppreviewhandler
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidateSet('Preview', 'Property', 'Thumbnail')]
        [string]$Kind,
        [Parameter(Mandatory)]
        [ValidatePattern('^(\{)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(\})?$')]
        [string]$Clsid,
        [Parameter(Mandatory)] [string]$Dll,
        [Parameter(Mandatory)]
        [ValidatePattern('^\.[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$')]
        [string[]]$FileTypes,
        [ValidatePattern('^[a-z0-9.-]+$')]
        [string]$FtaName,
        [string]$DisplayName,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $ClsidBare = $Clsid.Trim().Trim('{', '}').ToLowerInvariant()
    if (-not $FtaName)     { $FtaName = $Kind.ToLowerInvariant() + 'handler' }
    if (-not $DisplayName) { $DisplayName = $FtaName }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add $Kind handler")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity "Add $Kind handler" -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'com'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'desktop2'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 15063

        $comUri = Get-MsixManifestNamespaceUri -Prefix 'com'
        $uapUri = Get-MsixManifestNamespaceUri -Prefix 'uap'
        $d2Uri  = Get-MsixManifestNamespaceUri -Prefix 'desktop2'

        $handlerElement = switch ($Kind) {
            'Preview'   { 'desktop2:DesktopPreviewHandler' }
            'Property'  { 'desktop2:DesktopPropertyHandler' }
            'Thumbnail' { 'desktop2:ThumbnailHandler' }
        }

        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')

        # ── COM surrogate for the handler class (idempotent) ─────────────
        if (-not $M.SelectSingleNode("//*[local-name()='Class' and @Id='$ClsidBare']")) {
            $comExt    = $M.CreateElement('com:Extension', $comUri)
            $comExt.SetAttribute('Category', 'windows.comServer')
            $comServer = $M.CreateElement('com:ComServer', $comUri)
            $surrogate = $M.CreateElement('com:SurrogateServer', $comUri)
            $surrogate.SetAttribute('DisplayName', $DisplayName)
            $class = $M.CreateElement('com:Class', $comUri)
            $class.SetAttribute('Id',             $ClsidBare)
            $class.SetAttribute('Path',           $Dll.Replace('/', '\'))
            $class.SetAttribute('ThreadingModel', 'STA')
            $null = $surrogate.AppendChild($class)
            $null = $comServer.AppendChild($surrogate)
            $null = $comExt.AppendChild($comServer)
            $null = $appExt.AppendChild($comExt)
        }

        # ── FTA carrying the handler element ─────────────────────────────
        $fta = $appExt.SelectSingleNode("*[local-name()='Extension' and @Category='windows.fileTypeAssociation']/*[local-name()='FileTypeAssociation' and @Name='$FtaName']")
        if (-not $fta) {
            $ftaExt = $M.CreateElement('uap:Extension', $uapUri)
            $ftaExt.SetAttribute('Category', 'windows.fileTypeAssociation')
            $fta = $M.CreateElement('uap:FileTypeAssociation', $uapUri)
            $fta.SetAttribute('Name', $FtaName)
            $sft = $M.CreateElement('uap:SupportedFileTypes', $uapUri)
            foreach ($ft in $FileTypes) {
                $ftNode = $M.CreateElement('uap:FileType', $uapUri)
                $ftNode.InnerText = $ft.ToLowerInvariant()
                $null = $sft.AppendChild($ftNode)
            }
            $null = $fta.AppendChild($sft)
            $null = $ftaExt.AppendChild($fta)
            $null = $appExt.AppendChild($ftaExt)
        }

        if ($fta.SelectSingleNode("*[local-name()='$($handlerElement.Split(':')[1])']")) {
            Write-MsixLog -Level Info -Message "$Kind handler already declared on FTA '$FtaName' - skipping."
            return
        }
        $handler = $M.CreateElement($handlerElement, $d2Uri)
        $handler.SetAttribute('Clsid', $ClsidBare)
        $null = $fta.AppendChild($handler)
        Write-MsixLog -Level Info -Message "$Kind handler $ClsidBare declared on FTA '$FtaName' ($($FileTypes -join ', '))."
    }
}

#endregion

#region Toast notification activator (issue #114) ----------------------------

function Add-MsixToastActivator {
    <#
    .SYNOPSIS
        Declares a toast-notification COM activator so clicking a toast
        (re)activates the packaged Win32 app.

    .DESCRIPTION
        Adds desktop:Extension Category="windows.toastNotificationActivation"
        with the ToastActivatorCLSID, plus the matching com:ComServer
        ExeServer class registration. Without both, action clicks on toasts
        raised by a packaged Win32 app go nowhere.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER AppId
        Application to attach to (default: first Application).

    .PARAMETER Clsid
        GUID of the activator COM class (braces optional). Must match the
        CLSID the app passes to its notification library.

    .PARAMETER Executable
        Package-relative path to the exe hosting the activator (usually the
        main app exe).

    .PARAMETER Arguments
        Optional arguments for the activation launch (e.g.
        '-ToastActivated').

    .PARAMETER DisplayName
        Display name for the COM server. Default: 'Toast activator'.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        Add-MsixToastActivator -PackagePath app.msix `
            -Clsid '{ff1a2b3c-4d5e-6f70-8899-aabbccddeeff}' `
            -Executable 'VFS\ProgramFilesX64\App\app.exe' `
            -Arguments '-ToastActivated' -SkipSigning

    .LINK
        https://learn.microsoft.com/windows/apps/design/shell/tiles-and-notifications/send-local-toast-desktop
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidatePattern('^(\{)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(\})?$')]
        [string]$Clsid,
        [Parameter(Mandatory)] [string]$Executable,
        [string]$Arguments,
        [string]$DisplayName = 'Toast activator',
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $ClsidBare = $Clsid.Trim().Trim('{', '}').ToLowerInvariant()
    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add toast activator')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'Add toast activator' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'com'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'desktop'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 16299

        $comUri  = Get-MsixManifestNamespaceUri -Prefix 'com'
        $deskUri = Get-MsixManifestNamespaceUri -Prefix 'desktop'

        if ($M.SelectSingleNode("//*[local-name()='Extension' and @Category='windows.toastNotificationActivation']")) {
            Write-MsixLog -Level Info -Message 'Toast activator already declared - skipping.'
            return
        }

        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')

        # ── COM ExeServer hosting the activator ──────────────────────────
        $comExt    = $M.CreateElement('com:Extension', $comUri)
        $comExt.SetAttribute('Category', 'windows.comServer')
        $comServer = $M.CreateElement('com:ComServer', $comUri)
        $exeServer = $M.CreateElement('com:ExeServer', $comUri)
        $exeServer.SetAttribute('Executable',  $Executable.Replace('/', '\'))
        $exeServer.SetAttribute('DisplayName', $DisplayName)
        if ($Arguments) { $exeServer.SetAttribute('Arguments', $Arguments) }
        $class = $M.CreateElement('com:Class', $comUri)
        $class.SetAttribute('Id', $ClsidBare)
        $null = $exeServer.AppendChild($class)
        $null = $comServer.AppendChild($exeServer)
        $null = $comExt.AppendChild($comServer)
        $null = $appExt.AppendChild($comExt)

        # ── Toast activation extension ────────────────────────────────────
        $toastExt = $M.CreateElement('desktop:Extension', $deskUri)
        $toastExt.SetAttribute('Category', 'windows.toastNotificationActivation')
        $toast = $M.CreateElement('desktop:ToastNotificationActivation', $deskUri)
        $toast.SetAttribute('ToastActivatorCLSID', $ClsidBare)
        $null = $toastExt.AppendChild($toast)
        $null = $appExt.AppendChild($toastExt)
        Write-MsixLog -Level Info -Message "Toast activator $ClsidBare declared (Executable=$Executable)."
    }
}

#endregion

#region Mutable package directories (issue #116) -----------------------------

function Set-MsixMutablePackageDirectory {
    <#
    .SYNOPSIS
        Declares desktop6:MutablePackageDirectories - a writable mirror of the
        install directory under %ProgramFiles%\ModifiableWindowsApps.

    .DESCRIPTION
        The OS-native alternative to write-virtualization/PSF redirection for
        plugin- and mod-heavy apps: Windows projects the package's install
        directory to %ProgramFiles%\ModifiableWindowsApps\<Target> and keeps
        it writable. Requires the restricted 'modifiableApp' capability
        (added automatically).

        NOTE: this feature is gated - designed for desktop games/apps and
        requires the target directory name to be approved for Store
        distribution; enterprise sideload works when the capability is
        accepted at deploy time. Where that gate is a problem, stay with
        Set-MsixFileSystemWriteVirtualization or PSF FileRedirection (see
        TEST-PLAN Scenario 4).

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER Directory
        Folder name under %ProgramFiles%\ModifiableWindowsApps that receives
        the writable projection (typically the product name).

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        Set-MsixMutablePackageDirectory -PackagePath game.msix `
            -Directory 'ContosoRacer' -Pfx cert.pfx -PfxPassword $pw

    .LINK
        https://learn.microsoft.com/uwp/schemas/appxpackage/uapmanifestschema/element-desktop6-mutablepackagedirectories
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$')]
        [string]$Directory,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Set mutable package directory '$Directory'")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity "Mutable package directory '$Directory'" -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'desktop6'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'rescap'
        Set-MsixManifestMaxVersionTested -Manifest $M -MinBuild 18362
        $d6 = Get-MsixManifestNamespaceUri -Prefix 'desktop6'

        # Per the schema (element-desktop6-mutablepackagedirectories):
        # Package/Extensions > desktop6:Extension
        # Category="windows.mutablePackageDirectories" > MutablePackageDirectories
        # > MutablePackageDirectory Target="..." (Target UNPREFIXED).
        $pkgExt = _MsixGetOrCreatePackageExtensions -Manifest $M
        $dirs = $M.SelectSingleNode("//*[local-name()='MutablePackageDirectories']")
        if (-not $dirs) {
            $ext = $M.CreateElement('desktop6:Extension', $d6)
            $ext.SetAttribute('Category', 'windows.mutablePackageDirectories')
            $dirs = $M.CreateElement('desktop6:MutablePackageDirectories', $d6)
            $null = $ext.AppendChild($dirs)
            $null = $pkgExt.AppendChild($ext)
        }
        $already = @($dirs.ChildNodes) | Where-Object {
            $_.LocalName -eq 'MutablePackageDirectory' -and $_.GetAttribute('Target') -eq $Directory
        }
        if ($already) {
            Write-MsixLog -Level Info -Message "MutablePackageDirectory '$Directory' already declared - skipping."
        } else {
            $dir = $M.CreateElement('desktop6:MutablePackageDirectory', $d6)
            $dir.SetAttribute('Target', $Directory)
            $null = $dirs.AppendChild($dir)
            Write-MsixLog -Level Info -Message "MutablePackageDirectory '$Directory' declared (projects to %ProgramFiles%\ModifiableWindowsApps\$Directory)."
        }

        $capsNode = $M.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $M.CreateElement('Capabilities', $M.Package.NamespaceURI)
            $null     = $M.Package.AppendChild($capsNode)
        }
        $exists = $capsNode.ChildNodes | Where-Object {
            $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'modifiableApp' }
        if (-not $exists) {
            $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
            $node = $M.CreateElement('rescap:Capability', $rescapUri)
            $node.SetAttribute('Name', 'modifiableApp')
            $null = $capsNode.AppendChild($node)
            Write-MsixLog -Level Info -Message 'Capability added: modifiableApp'
        }
    }
}

#endregion

#region Niche extension points (issue #120) ----------------------------------

function Add-MsixAppExtensionHost {
    <#
    .SYNOPSIS
        Declares the application as a plugin HOST (uap3 windows.appExtensionHost)
        so extension packages can target it by contract name.

    .DESCRIPTION
        Adds uap3:Extension Category="windows.appExtensionHost" with one
        uap3:Name per contract. Extension packages then declare
        windows.appExtension with a matching Name and Windows brokers
        discovery via the AppExtensionCatalog API.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER AppId
        Application to attach to (default: first Application).

    .PARAMETER Name
        One or more extension-contract names the host consumes
        (reverse-DNS convention, e.g. com.contoso.myapp.plugin).

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        Add-MsixAppExtensionHost -PackagePath host.msix `
            -Name 'com.contoso.editor.plugin' -SkipSigning

    .LINK
        https://learn.microsoft.com/windows/uwp/launch-resume/how-to-create-an-extensible-app
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$')]
        [string[]]$Name,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add AppExtensionHost')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'Add AppExtensionHost' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap3'
        $u3 = Get-MsixManifestNamespaceUri -Prefix 'uap3'
        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')

        $hostNode = $M.SelectSingleNode("//*[local-name()='AppExtensionHost']")
        if (-not $hostNode) {
            $ext = $M.CreateElement('uap3:Extension', $u3)
            $ext.SetAttribute('Category', 'windows.appExtensionHost')
            $hostNode = $M.CreateElement('uap3:AppExtensionHost', $u3)
            $null = $ext.AppendChild($hostNode)
            $null = $appExt.AppendChild($ext)
        }
        foreach ($n in $Name) {
            $exists = @($hostNode.ChildNodes) | Where-Object { $_.LocalName -eq 'Name' -and $_.InnerText -eq $n }
            if ($exists) { Write-MsixLog -Level Info -Message "AppExtensionHost name already declared: $n"; continue }
            $nameNode = $M.CreateElement('uap3:Name', $u3)
            $nameNode.InnerText = $n
            $null = $hostNode.AppendChild($nameNode)
            Write-MsixLog -Level Info -Message "AppExtensionHost contract declared: $n"
        }
    }
}


function Add-MsixAppExtension {
    <#
    .SYNOPSIS
        Declares the application as a PLUGIN (uap3 windows.appExtension)
        targeting a host's extension-contract name.

    .DESCRIPTION
        Adds uap3:Extension Category="windows.appExtension" with the contract
        Name (matching the host's AppExtensionHost declaration), this
        extension's Id, DisplayName/Description, and the PublicFolder whose
        content the host may read.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER AppId
        Application to attach to (default: first Application).

    .PARAMETER Name
        The HOST contract name this extension plugs into
        (e.g. com.contoso.editor.plugin).

    .PARAMETER Id
        Identifier for this extension, unique within the package.

    .PARAMETER DisplayName
        Human-readable extension name. Default: the Id.

    .PARAMETER Description
        Short description. Default: the DisplayName.

    .PARAMETER PublicFolder
        Package-relative folder exposed read-only to the host. Default 'Public'.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        Add-MsixAppExtension -PackagePath plugin.msix `
            -Name 'com.contoso.editor.plugin' -Id 'markdown-tools' `
            -DisplayName 'Markdown tools' -SkipSigning

    .LINK
        https://learn.microsoft.com/windows/uwp/launch-resume/how-to-create-an-extensible-app
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$')]
        [string]$Name,
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')]
        [string]$Id,
        [string]$DisplayName,
        [string]$Description,
        [string]$PublicFolder = 'Public',
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    if (-not $DisplayName) { $DisplayName = $Id }
    if (-not $Description) { $Description = $DisplayName }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add AppExtension '$Id'")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity "Add AppExtension '$Id'" -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap3'
        $u3 = Get-MsixManifestNamespaceUri -Prefix 'uap3'
        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')

        if ($M.SelectSingleNode("//*[local-name()='AppExtension' and @Id='$Id']")) {
            Write-MsixLog -Level Info -Message "AppExtension '$Id' already declared - skipping."
            return
        }

        $ext = $M.CreateElement('uap3:Extension', $u3)
        $ext.SetAttribute('Category', 'windows.appExtension')
        $ax = $M.CreateElement('uap3:AppExtension', $u3)
        $ax.SetAttribute('Name',         $Name)
        $ax.SetAttribute('Id',           $Id)
        $ax.SetAttribute('DisplayName',  $DisplayName)
        $ax.SetAttribute('Description',  $Description)
        $ax.SetAttribute('PublicFolder', $PublicFolder.Replace('/', '\'))
        $null = $ext.AppendChild($ax)
        $null = $appExt.AppendChild($ext)
        Write-MsixLog -Level Info -Message "AppExtension '$Id' declared against host contract '$Name'."
    }
}


function Add-MsixAutoPlayHandler {
    <#
    .SYNOPSIS
        Declares an AutoPlay handler (uap windows.autoPlayContent /
        windows.autoPlayDevice) so the app appears in the AutoPlay dialog.

    .DESCRIPTION
        Content kind: fires on volume/content events (e.g.
        ShowPicturesOnArrival, PlayMusicFilesOnArrival). Device kind: fires on
        device events (WPD interface arrival). One uap:LaunchAction per call;
        call repeatedly for multiple verbs.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER AppId
        Application to attach to (default: first Application).

    .PARAMETER Kind
        Content | Device.

    .PARAMETER Verb
        Verb string passed to app activation (e.g. 'show').

    .PARAMETER ActionDisplayName
        Text shown in the AutoPlay dialog.

    .PARAMETER ContentEvent
        (Kind=Content) e.g. ShowPicturesOnArrival, PlayMusicFilesOnArrival,
        StorageOnArrival.

    .PARAMETER DeviceEvent
        (Kind=Device) e.g. WPD\ImageSource.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        Add-MsixAutoPlayHandler -PackagePath app.msix -Kind Content `
            -Verb show -ActionDisplayName 'Import photos' `
            -ContentEvent ShowPicturesOnArrival -SkipSigning

    .LINK
        https://learn.microsoft.com/windows/uwp/launch-resume/auto-launching-with-autoplay
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidateSet('Content', 'Device')]
        [string]$Kind,
        [Parameter(Mandatory)] [string]$Verb,
        [Parameter(Mandatory)] [string]$ActionDisplayName,
        [string]$ContentEvent,
        [string]$DeviceEvent,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    if ($Kind -eq 'Content' -and -not $ContentEvent) { throw '-ContentEvent is required for -Kind Content.' }
    if ($Kind -eq 'Device'  -and -not $DeviceEvent)  { throw '-DeviceEvent is required for -Kind Device.' }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Add AutoPlay $Kind handler")

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity "Add AutoPlay $Kind handler" -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap'
        $uapUri = Get-MsixManifestNamespaceUri -Prefix 'uap'
        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')

        $category  = if ($Kind -eq 'Content') { 'windows.autoPlayContent' } else { 'windows.autoPlayDevice' }
        $container = if ($Kind -eq 'Content') { 'uap:AutoPlayContent' } else { 'uap:AutoPlayDevice' }

        $node = $appExt.SelectSingleNode("*[local-name()='Extension' and @Category='$category']/*")
        if (-not $node) {
            $ext = $M.CreateElement('uap:Extension', $uapUri)
            $ext.SetAttribute('Category', $category)
            $node = $M.CreateElement($container, $uapUri)
            $null = $ext.AppendChild($node)
            $null = $appExt.AppendChild($ext)
        }

        $dup = @($node.ChildNodes) | Where-Object {
            $_.LocalName -eq 'LaunchAction' -and $_.GetAttribute('Verb') -eq $Verb
        }
        if ($dup) { Write-MsixLog -Level Info -Message "AutoPlay verb '$Verb' already declared - skipping."; return }

        $action = $M.CreateElement('uap:LaunchAction', $uapUri)
        $action.SetAttribute('Verb', $Verb)
        $action.SetAttribute('ActionDisplayName', $ActionDisplayName)
        if ($Kind -eq 'Content') { $action.SetAttribute('ContentEvent', $ContentEvent) }
        else                     { $action.SetAttribute('DeviceEvent',  $DeviceEvent) }
        $null = $node.AppendChild($action)
        Write-MsixLog -Level Info -Message "AutoPlay $Kind handler declared (Verb=$Verb)."
    }
}


function Add-MsixShareTarget {
    <#
    .SYNOPSIS
        Declares the app as a Share-charm target (uap windows.shareTarget) so
        it appears in the Windows Share sheet for the given types/formats.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER AppId
        Application to attach to (default: first Application).

    .PARAMETER FileTypes
        Extensions the app accepts (e.g. '.png','.jpg').
        Omit together with -SupportsAnyFileType/-DataFormats for formats-only.

    .PARAMETER SupportsAnyFileType
        Accept any shared file type.

    .PARAMETER DataFormats
        Data formats accepted (e.g. 'Text', 'WebLink', 'Bitmap').

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        Add-MsixShareTarget -PackagePath app.msix `
            -FileTypes '.png','.jpg' -DataFormats Bitmap -SkipSigning

    .LINK
        https://learn.microsoft.com/windows/uwp/app-to-app/receive-data
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
        [string]$AppId,
        [string[]]$FileTypes,
        [switch]$SupportsAnyFileType,
        [string[]]$DataFormats,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    if (-not $FileTypes -and -not $SupportsAnyFileType -and -not $DataFormats) {
        throw 'Pass at least one of -FileTypes / -SupportsAnyFileType / -DataFormats.'
    }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add ShareTarget')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'Add ShareTarget' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'uap'
        $uapUri = Get-MsixManifestNamespaceUri -Prefix 'uap'
        $app    = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')

        if ($M.SelectSingleNode("//*[local-name()='Extension' and @Category='windows.shareTarget']")) {
            Write-MsixLog -Level Info -Message 'ShareTarget already declared - skipping.'
            return
        }

        $ext = $M.CreateElement('uap:Extension', $uapUri)
        $ext.SetAttribute('Category', 'windows.shareTarget')
        $st = $M.CreateElement('uap:ShareTarget', $uapUri)

        if ($SupportsAnyFileType -or $FileTypes) {
            $sft = $M.CreateElement('uap:SupportedFileTypes', $uapUri)
            if ($SupportsAnyFileType) {
                $null = $sft.AppendChild($M.CreateElement('uap:SupportsAnyFileType', $uapUri))
            } else {
                foreach ($ft in $FileTypes) {
                    if (-not $ft.StartsWith('.')) { $ft = ".$ft" }
                    $t = $M.CreateElement('uap:FileType', $uapUri)
                    $t.InnerText = $ft.ToLowerInvariant()
                    $null = $sft.AppendChild($t)
                }
            }
            $null = $st.AppendChild($sft)
        }
        foreach ($df in @($DataFormats | Where-Object { $_ })) {
            $d = $M.CreateElement('uap:DataFormat', $uapUri)
            $d.InnerText = $df
            $null = $st.AppendChild($d)
        }

        $null = $ext.AppendChild($st)
        $null = $appExt.AppendChild($ext)
        Write-MsixLog -Level Info -Message 'ShareTarget declared.'
    }
}


function Add-MsixFullTrustProcess {
    <#
    .SYNOPSIS
        Declares a full-trust companion process (desktop windows.fullTrustProcess)
        that a UWP main app can launch via FullTrustProcessLauncher.

    .DESCRIPTION
        Adds desktop:Extension Category="windows.fullTrustProcess" with the
        executable and optional parameter groups, plus the runFullTrust
        capability the launcher API requires. This is the INVERSE direction of
        most of this module (UWP main app + Win32 companion); for packaged
        Win32 apps the main executable is already full trust.

    .PARAMETER PackagePath
        The .msix file to modify.

    .PARAMETER AppId
        Application to attach to (default: first Application).

    .PARAMETER Executable
        Package-relative path of the full-trust exe.

    .PARAMETER ParameterGroups
        Optional array of hashtables: @{ GroupId = 'sync'; Parameters = '/sync' }.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the signing pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package here.

    .EXAMPLE
        Add-MsixFullTrustProcess -PackagePath app.msix `
            -Executable 'FullTrust\companion.exe' `
            -ParameterGroups @(@{ GroupId = 'sync'; Parameters = '/sync' }) `
            -SkipSigning

    .LINK
        https://learn.microsoft.com/uwp/schemas/appxpackage/uapmanifestschema/element-desktop-extension
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
        [string]$AppId,
        [Parameter(Mandatory)] [string]$Executable,
        [hashtable[]]$ParameterGroups,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    foreach ($g in @($ParameterGroups | Where-Object { $null -ne $_ })) {
        if (-not $g.GroupId) { throw "Each -ParameterGroups entry needs a GroupId key (got: $($g.Keys -join ', '))." }
    }

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add fullTrustProcess')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
                        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
                        -UnsignedOutputPath $UnsignedOutputPath `
                        -WhatIfPreview:$isWhatIf `
                        -Activity 'Add fullTrustProcess' -Mutate {
        param([xml]$M)
        Add-MsixManifestNamespace -Manifest $M -Prefix 'desktop'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'rescap'
        $deskUri = Get-MsixManifestNamespaceUri -Prefix 'desktop'
        $app     = _MsixGetOrCreateApplicationExtensions -Manifest $M -AppId $AppId
        $appExt  = $app.SelectSingleNode('*[local-name()="Extensions"]')

        if ($M.SelectSingleNode("//*[local-name()='Extension' and @Category='windows.fullTrustProcess']")) {
            Write-MsixLog -Level Info -Message 'fullTrustProcess already declared - skipping.'
            return
        }

        $ext = $M.CreateElement('desktop:Extension', $deskUri)
        $ext.SetAttribute('Category',   'windows.fullTrustProcess')
        $ext.SetAttribute('Executable', $Executable.Replace('/', '\'))
        if ($ParameterGroups) {
            $ftp = $M.CreateElement('desktop:FullTrustProcess', $deskUri)
            foreach ($g in $ParameterGroups) {
                $grp = $M.CreateElement('desktop:ParameterGroup', $deskUri)
                $grp.SetAttribute('GroupId', [string]$g.GroupId)
                $params = if ($g.Parameters) { [string]$g.Parameters } else { '' }
                $grp.SetAttribute('Parameters', $params)
                $null = $ftp.AppendChild($grp)
            }
            $null = $ext.AppendChild($ftp)
        }
        $null = $appExt.AppendChild($ext)

        # FullTrustProcessLauncher requires runFullTrust.
        $capsNode = $M.Package.Capabilities
        if (-not $capsNode) {
            $capsNode = $M.CreateElement('Capabilities', $M.Package.NamespaceURI)
            $null     = $M.Package.AppendChild($capsNode)
        }
        $has = $capsNode.ChildNodes | Where-Object {
            $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust' }
        if (-not $has) {
            $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
            $cap = $M.CreateElement('rescap:Capability', $rescapUri)
            $cap.SetAttribute('Name', 'runFullTrust')
            $null = $capsNode.AppendChild($cap)
            Write-MsixLog -Level Info -Message 'Capability added: runFullTrust (required by FullTrustProcessLauncher).'
        }
        Write-MsixLog -Level Info -Message "fullTrustProcess declared (Executable=$Executable)."
    }
}

#endregion
