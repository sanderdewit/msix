# =============================================================================
# Sparse shell-extension merge
# -----------------------------------------------------------------------------
# Some packages ship an inner *.msix (a "sparse" sub-package) that declares a
# COM SurrogateServer shell extension. When the outer package installs into
# the read-only WindowsApps store, the inner package cannot be activated —
# the surrogate host (dllhost.exe) cannot traverse into the nested .msix at
# runtime, and the inner manifest's Path attributes are relative to the
# inner package's own root, not the outer VFS layout.
#
# Import-MsixSparseShellExtension lifts the inner manifest's declarations
# (Extensions and any required namespaces) into the outer manifest, rewrites
# every com:Class/@Path to be package-relative under the outer VFS, copies
# the inner payload (DLLs, resources, etc.) alongside, optionally deletes
# the now-unused inner .msix, then repacks/signs atomically.
# =============================================================================

function Import-MsixSparseShellExtension {
    <#
    .SYNOPSIS
        Merges a nested (sparse) inner .msix package's COM shell-extension
        declarations into the outer package's manifest so the surrogate host
        can activate them post-install.

    .DESCRIPTION
        Outer/inner package pattern:

          outer.msix
            └── VFS\ProgramFilesX64\App\contextMenu\Inner.msix     ← sparse
                  └── AppxManifest.xml (declares com:Class etc.)
                  └── ShellExt.dll

        The inner package is not deployable from inside the outer package —
        Windows cannot install a sub-package out of WindowsApps, and the COM
        surrogate cannot traverse the inner zip to load the DLL.

        The fix is to:

          1. Copy the inner payload (DLLs, resources, …) into the outer VFS
             at the same path the inner package sat at.
          2. Lift every <*:Extension> element from the inner manifest's
             <Package><Extensions> into the outer manifest's <Package><Extensions>.
          3. Rewrite com:Class/@Path to be package-relative — prepending the
             outer-VFS directory the inner sat in.
          4. Delete the now-unused inner .msix (unless -KeepInnerPackage).
          5. Bump MaxVersionTested to 17763+ (desktop4 context menus require
             Win10 1809 or later).
          6. Repack + atomically sign (mirrors Remove-MsixUninstallerArtifact).

    .PARAMETER PackagePath
        Outer .msix file to mutate.

    .PARAMETER NestedPackagePath
        Package-relative path to the inner .msix. When omitted, the function
        calls Get-MsixNestedPackageCandidate and picks the first candidate
        (warns if there is more than one).

    .PARAMETER OutputPath
        Write the repacked package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Don't sign the repacked package. Alias: -NoSign.

    .PARAMETER Pfx / PfxPassword / UnsignedOutputPath
        Forwarded to the shared sign/move path.

    .PARAMETER KeepInnerPackage
        Preserve the inner .msix file inside the outer package. Default is to
        delete it because, after the merge, it has no consumer.

    .OUTPUTS
        [pscustomobject] with NestedPackagePath, BasePath, ExtensionsMerged,
        FilesCopied, PathsFixed, Output.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [string]$NestedPackagePath,
        [string]$OutputPath,
        [Alias('NoSign')] [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath,
        [switch]$KeepInnerPackage
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath -ErrorAction Stop
    $workspace = New-MsixWorkspace -PackageName "$($fileinfo.BaseName)-sparse"
    $inner     = Join-Path -Path $env:TEMP -ChildPath ("msix-inner-{0}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))

    try {
        # ── Unpack outer ──────────────────────────────────────────────────
        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unpack (outer)'

        # ── Resolve the nested package path ──────────────────────────────
        if (-not $NestedPackagePath) {
            $candidates = @(Get-MsixNestedPackageCandidate -PackagePath $PackagePath)
            if (-not $candidates -or $candidates.Count -eq 0) {
                Write-MsixLog -Level Info -Message 'No nested package found inside the outer .msix; nothing to merge.'
                return
            }
            if ($candidates.Count -gt 1) {
                Write-MsixLog -Level Warning -Message ("Multiple nested packages found ({0}). Picking the first: {1}. Pass -NestedPackagePath to be explicit." -f $candidates.Count, $candidates[0].Path)
            }
            $NestedPackagePath = $candidates[0].Path
        }

        $innerPkg = Join-Path -Path $workspace -ChildPath $NestedPackagePath
        if (-not (Test-Path -LiteralPath $innerPkg)) {
            throw "Nested package not found inside outer workspace: $NestedPackagePath"
        }

        # ── Compute base path (the directory the inner package sat in) ──
        # NestedPackagePath looks like 'VFS\ProgramFilesX64\App\sub\Inner.msix';
        # $basePath = 'VFS\ProgramFilesX64\App\sub' (no trailing separator).
        $basePath = Split-Path -Parent $NestedPackagePath
        if ($null -eq $basePath) { $basePath = '' }
        Write-MsixLog -Level Info -Message "Sparse merge: inner='$NestedPackagePath' basePath='$basePath'"

        # ── Unpack inner ──────────────────────────────────────────────────
        New-Item -ItemType Directory -Path $inner -Force | Out-Null
        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $innerPkg, '/d', $inner, '/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unpack (inner)'

        # ── Load both manifests via the XML-safe helper ──────────────────
        $outerManifestPath = Join-Path -Path $workspace -ChildPath 'AppxManifest.xml'
        $innerManifestPath = Join-Path -Path $inner -ChildPath 'AppxManifest.xml'
        $outerXml = Get-MsixManifest -Path $outerManifestPath
        $innerXml = Get-MsixManifest -Path $innerManifestPath

        $outerPkgEl = $outerXml.DocumentElement   # <Package>
        $innerPkgEl = $innerXml.DocumentElement

        # ── Merge namespace declarations ─────────────────────────────────
        # For every xmlns:* on the inner <Package> not already present on the
        # outer <Package>, copy it across. Prefer Add-MsixManifestNamespace
        # when the prefix is one we know (it also updates IgnorableNamespaces).
        $outerExistingUris = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($a in $outerPkgEl.Attributes) {
            if ($a.Prefix -eq 'xmlns' -or $a.Name -eq 'xmlns') {
                $null = $outerExistingUris.Add($a.Value)
            }
        }
        foreach ($a in $innerPkgEl.Attributes) {
            $isNs = ($a.Prefix -eq 'xmlns') -or ($a.Name -eq 'xmlns')
            if (-not $isNs) { continue }
            if ($outerExistingUris.Contains($a.Value)) { continue }

            $prefix = if ($a.Prefix -eq 'xmlns') { $a.LocalName } else { $null }
            $known  = if ($prefix) { Get-MsixManifestNamespaceUri -Prefix $prefix } else { $null }
            if ($prefix -and $known -and $known -eq $a.Value) {
                Add-MsixManifestNamespace -Manifest $outerXml -Prefix $prefix
            } elseif ($prefix) {
                # Unknown prefix — set the xmlns attribute directly
                $outerPkgEl.SetAttribute("xmlns:$prefix", $a.Value)
                Write-MsixLog -Level Debug -Message "Merged unknown namespace prefix '$prefix' -> $($a.Value)"
            }
            $null = $outerExistingUris.Add($a.Value)
        }

        # ── Locate (or create) outer <Package><Extensions> ───────────────
        $outerExtensions = $null
        foreach ($child in $outerPkgEl.ChildNodes) {
            if ($child.LocalName -eq 'Extensions' -and $child.ParentNode -eq $outerPkgEl) {
                $outerExtensions = $child
                break
            }
        }
        if (-not $outerExtensions) {
            $outerExtensions = $outerXml.CreateElement('Extensions', $outerPkgEl.NamespaceURI)
            $null = $outerPkgEl.AppendChild($outerExtensions)
        }

        # ── Locate inner <Package><Extensions> ───────────────────────────
        $innerExtensions = $null
        foreach ($child in $innerPkgEl.ChildNodes) {
            if ($child.LocalName -eq 'Extensions' -and $child.ParentNode -eq $innerPkgEl) {
                $innerExtensions = $child
                break
            }
        }

        $extensionsMerged = 0
        $pathsFixed       = 0

        if ($innerExtensions) {
            foreach ($extNode in @($innerExtensions.ChildNodes)) {
                if ($extNode.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                if ($extNode.LocalName -ne 'Extension') { continue }

                # ImportNode (deep) so foreign-namespace nodes keep their URIs.
                $cloned = $outerXml.ImportNode($extNode, $true)
                $null = $outerExtensions.AppendChild($cloned)
                $extensionsMerged++

                # Rewrite every com:Class/@Path inside this just-imported subtree.
                # com:Class can live at varying depths under com:Extension —
                # walk the subtree.
                $stack = [System.Collections.Generic.Stack[System.Xml.XmlNode]]::new()
                $stack.Push($cloned)
                while ($stack.Count -gt 0) {
                    $n = $stack.Pop()
                    if ($n.NodeType -eq [System.Xml.XmlNodeType]::Element -and $n.LocalName -eq 'Class') {
                        $pathAttr = $n.Attributes['Path']
                        if ($pathAttr) {
                            $old = $pathAttr.Value
                            if ($old) {
                                $alreadyRelative = (
                                    $old -match '^[A-Za-z]:[\\/]' -or
                                    $old.StartsWith('VFS\') -or
                                    $old.StartsWith('VFS/') -or
                                    $old.StartsWith('\\')
                                )
                                if (-not $alreadyRelative) {
                                    $new = if ($basePath) { (Join-Path -Path $basePath -ChildPath $old) } else { $old }
                                    $pathAttr.Value = $new
                                    $pathsFixed++
                                    Write-MsixLog -Level Info -Message "Sparse merge: Path '$old' -> '$new'"
                                } else {
                                    Write-MsixLog -Level Debug -Message "Sparse merge: leaving already-rooted Path '$old' alone"
                                }
                            }
                        }
                    }
                    foreach ($c in $n.ChildNodes) { $stack.Push($c) }
                }
            }
        }

        # ── Copy inner payload into outer VFS ─────────────────────────────
        $skipNames = @(
            'AppxManifest.xml',
            'AppxBlockMap.xml',
            'AppxSignature.p7x',
            '[Content_Types].xml',
            'Resources.pri',
            'resources.pri'
        )
        $destRoot = if ($basePath) { (Join-Path -Path $workspace -ChildPath $basePath) } else { $workspace }
        if (-not (Test-Path -LiteralPath $destRoot)) {
            New-Item -ItemType Directory -Path $destRoot -Force | Out-Null
        }

        $filesCopied = 0
        foreach ($item in Get-ChildItem -LiteralPath $inner -Recurse -File -ErrorAction SilentlyContinue) {
            $rel = $item.FullName.Substring($inner.Length).TrimStart('\','/')
            # Skip top-level package metadata files
            if ($skipNames -contains $item.Name) {
                # only skip when at the inner root, not deeper
                $top = ($rel -split '[\\/]')[0]
                if ($top -eq $item.Name) { continue }
            }
            # Skip AppxMetadata\* (always under that folder name at root)
            if ($rel -match '^AppxMetadata[\\/]') { continue }

            $destPath = Join-Path -Path $destRoot -ChildPath $rel
            $destDir  = Split-Path -Parent $destPath
            if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }
            Copy-Item -LiteralPath $item.FullName -Destination $destPath -Force
            $filesCopied++
        }
        Write-MsixLog -Level Info -Message "Sparse merge: copied $filesCopied file(s) into '$basePath'"

        # ── Delete the inner .msix unless asked to keep ──────────────────
        if (-not $KeepInnerPackage) {
            if ($PSCmdlet.ShouldProcess($innerPkg, 'Remove nested .msix')) {
                Remove-Item -LiteralPath $innerPkg -Force -ErrorAction SilentlyContinue
                Write-MsixLog -Level Info -Message "Sparse merge: removed inner package '$NestedPackagePath'"
            }
        }

        # ── Bump MaxVersionTested for desktop4 context menus ─────────────
        Set-MsixManifestMaxVersionTested -Manifest $outerXml -MinBuild 17763

        # ── Save merged outer manifest ───────────────────────────────────
        Save-MsixManifest -Manifest $outerXml -Path $outerManifestPath

        # ── Repack — atomic scratch / sign / move ────────────────────────
        $target  = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $scratch = Join-Path -Path $env:TEMP -ChildPath ("msix-sparse-{0}{1}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)), ([System.IO.Path]::GetExtension($target)))
        $packOk  = $false
        try {
            $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $scratch, '/d', $workspace, '/o')
            Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx pack'
            $packOk = $true
            if (-not $SkipSigning) {
                Invoke-MsixSigning -PackagePath $scratch -Pfx $Pfx -PfxPassword $PfxPassword
            }
            Move-Item -LiteralPath $scratch -Destination $target -Force
            return [pscustomobject]@{
                NestedPackagePath = $NestedPackagePath
                BasePath          = $basePath
                ExtensionsMerged  = $extensionsMerged
                FilesCopied       = $filesCopied
                PathsFixed        = $pathsFixed
                Output            = $target
            }
        } catch {
            if ($packOk -and $UnsignedOutputPath) {
                Copy-Item -LiteralPath $scratch -Destination $UnsignedOutputPath -Force -ErrorAction SilentlyContinue
                Write-MsixLog -Level Warning -Message "Signing failed. Unsigned package preserved at: $UnsignedOutputPath"
            }
            throw
        } finally {
            if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue }
        }
    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $inner) { Remove-Item -LiteralPath $inner -Recurse -Force -ErrorAction SilentlyContinue }
    }
}
