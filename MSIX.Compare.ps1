# =============================================================================
# Compare-MsixPackage
# -----------------------------------------------------------------------------
# Diffs two MSIX packages by:
#   - Identity / Properties / Capabilities / Dependencies (manifest)
#   - Application list (Id, Executable, Extensions categories)
#   - File list (added / removed / size-changed / hash-changed)
#   - Signing state (signer thumbprint + status)
#
# The diff is structured so it can be fed into a CI build to gate releases:
#   $diff.HasChanges
#   $diff.ManifestChanges
#   $diff.FileChanges
#   $diff.SigningChanges
# =============================================================================

function _MsixUnpackForCompare {
    param([string]$PackagePath, [string]$Tag)
    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-$Tag"
    $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
    Assert-MsixProcessSuccess $r 'MakeAppx unpack'
    return $workspace
}

function _ComparePackageManifest {
    param([xml]$LeftManifest, [xml]$RightManifest)

    $changes = [System.Collections.Generic.List[object]]::new()

    function _Add { param([string]$Field, $Left, $Right)
        if ($Left -ne $Right) {
            $changes.Add([pscustomobject]@{
                Field = $Field; Left = $Left; Right = $Right
            })
        }
    }
    _Add -Field 'Identity.Name'                  -Left $LeftManifest.Package.Identity.Name      -Right $RightManifest.Package.Identity.Name
    _Add -Field 'Identity.Publisher'             -Left $LeftManifest.Package.Identity.Publisher -Right $RightManifest.Package.Identity.Publisher
    _Add -Field 'Identity.Version'               -Left $LeftManifest.Package.Identity.Version   -Right $RightManifest.Package.Identity.Version
    _Add -Field 'Identity.ProcessorArchitecture' -Left $LeftManifest.Package.Identity.ProcessorArchitecture -Right $RightManifest.Package.Identity.ProcessorArchitecture
    _Add -Field 'Properties.DisplayName'         -Left $LeftManifest.Package.Properties.DisplayName        -Right $RightManifest.Package.Properties.DisplayName
    _Add -Field 'Properties.PublisherDisplayName' -Left $LeftManifest.Package.Properties.PublisherDisplayName -Right $RightManifest.Package.Properties.PublisherDisplayName
    _Add -Field 'Dependencies.MinVersion'        -Left $LeftManifest.Package.Dependencies.TargetDeviceFamily.MinVersion       -Right $RightManifest.Package.Dependencies.TargetDeviceFamily.MinVersion
    _Add -Field 'Dependencies.MaxVersionTested'  -Left $LeftManifest.Package.Dependencies.TargetDeviceFamily.MaxVersionTested -Right $RightManifest.Package.Dependencies.TargetDeviceFamily.MaxVersionTested

    # Capability set diff
    $leftCaps  = @($LeftManifest.Package.Capabilities.Capability  | ForEach-Object { $_.Name }) | Sort-Object
    $rightCaps = @($RightManifest.Package.Capabilities.Capability | ForEach-Object { $_.Name }) | Sort-Object
    if (($leftCaps -join '|') -ne ($rightCaps -join '|')) {
        $changes.Add([pscustomobject]@{
            Field = 'Capabilities'
            Left  = $leftCaps -join ', '
            Right = $rightCaps -join ', '
        })
    }

    # Application diff (by Id)
    $leftApps  = @($LeftManifest.Package.Applications.Application)  | ForEach-Object { @{ Id=$_.Id; Exe=$_.Executable } }
    $rightApps = @($RightManifest.Package.Applications.Application) | ForEach-Object { @{ Id=$_.Id; Exe=$_.Executable } }

    foreach ($l in $leftApps) {
        $r = $rightApps | Where-Object { $_.Id -eq $l.Id } | Select-Object -First 1
        if (-not $r) {
            $changes.Add([pscustomobject]@{ Field = "Application[$($l.Id)]"; Left = $l.Exe; Right = '<removed>' })
        } elseif ($l.Exe -ne $r.Exe) {
            $changes.Add([pscustomobject]@{ Field = "Application[$($l.Id)].Executable"; Left = $l.Exe; Right = $r.Exe })
        }
    }
    foreach ($r in $rightApps) {
        if (-not ($leftApps | Where-Object { $_.Id -eq $r.Id })) {
            $changes.Add([pscustomobject]@{ Field = "Application[$($r.Id)]"; Left = '<absent>'; Right = $r.Exe })
        }
    }

    return ,$changes
}


function _CompareFileSets {
    param([string]$LeftRoot, [string]$RightRoot)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    function _Snapshot([string]$root) {
        Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                $rel = $_.FullName.Substring($root.Length + 1)
                $hash = $null
                try {
                    $stream = [IO.File]::OpenRead($_.FullName)
                    try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') }
                    finally { $stream.Dispose() }
                } catch { Write-MsixLog -Level Debug -Message "Hash failed for $($_.FullName): $_" }
                [pscustomobject]@{
                    Rel   = $rel
                    Size  = $_.Length
                    Hash  = $hash
                }
            }
    }

    $left  = @(_Snapshot $LeftRoot)
    $right = @(_Snapshot $RightRoot)

    $leftIndex  = @{}; foreach ($f in $left)  { $leftIndex[$f.Rel]  = $f }
    $rightIndex = @{}; foreach ($f in $right) { $rightIndex[$f.Rel] = $f }

    $diff = [System.Collections.Generic.List[object]]::new()

    foreach ($k in $leftIndex.Keys) {
        if (-not $rightIndex.ContainsKey($k)) {
            $diff.Add([pscustomobject]@{ Path = $k; Status = 'Removed';  LeftSize = $leftIndex[$k].Size; RightSize = $null })
        } else {
            $l = $leftIndex[$k]; $r = $rightIndex[$k]
            if ($l.Hash -ne $r.Hash) {
                $diff.Add([pscustomobject]@{
                    Path      = $k
                    Status    = if ($l.Size -ne $r.Size) { 'Modified-Size' } else { 'Modified-Content' }
                    LeftSize  = $l.Size
                    RightSize = $r.Size
                })
            }
        }
    }
    foreach ($k in $rightIndex.Keys) {
        if (-not $leftIndex.ContainsKey($k)) {
            $diff.Add([pscustomobject]@{ Path = $k; Status = 'Added'; LeftSize = $null; RightSize = $rightIndex[$k].Size })
        }
    }

    return ,$diff
}


function Compare-MsixPackage {
    <#
    .SYNOPSIS
        Diffs two .msix files. Returns a structured result with manifest /
        file / signing changes.

    .DESCRIPTION
        Unpacks both packages into temporary workspaces and compares:

          - Manifest    Identity (Name, Publisher, Version, Architecture),
                        Properties (DisplayName, PublisherDisplayName),
                        Dependencies (MinVersion, MaxVersionTested),
                        Capabilities, and the Application list (by Id and
                        Executable).
          - Files       Per relative path, computed as Added / Removed /
                        Modified-Size / Modified-Content (SHA256). Paths
                        matching -ExcludePathPattern are skipped (default
                        list ignores AppxBlockMap, [Content_Types].xml,
                        AppxSignature -- which churn on every build).
          - Signing     Get-AuthenticodeSignature on both files; Status,
                        Thumbprint, Subject are diffed.

        Workspaces are cleaned up afterwards. The output is designed to be
        consumed by CI gates: `if (-not $diff.HasChanges) { ... }`.

    .PARAMETER LeftPath
        The 'old' / baseline .msix file.

    .PARAMETER RightPath
        The 'new' / candidate .msix file.

    .PARAMETER ExcludePathPattern
        Regexes of file relative paths to ignore in the file diff. Default
        is '\\AppxBlockMap', '\\\[Content_Types\]', '\\AppxSignature' --
        package metadata that changes on every rebuild and is rarely
        interesting.

    .OUTPUTS
        [pscustomobject] with:
          - LeftPath, RightPath  the inputs.
          - HasChanges           [bool] true if any of the three change-sets
                                 below is non-empty.
          - ManifestChanges      list of @{ Field; Left; Right }.
          - FileChanges          list of @{ Path; Status; LeftSize; RightSize }
                                 where Status is one of Added, Removed,
                                 Modified-Size, Modified-Content.
          - SigningChanges       list of @{ Field; Left; Right } for Status,
                                 Thumbprint, Subject.

    .EXAMPLE
        $diff = Compare-MsixPackage -LeftPath old.msix -RightPath new.msix
        $diff.HasChanges
        $diff.ManifestChanges | Format-Table
        $diff.FileChanges     | Format-Table

    .EXAMPLE
        # Skip auto-generated package metadata (this is also the default)
        Compare-MsixPackage -LeftPath a.msix -RightPath b.msix `
            -ExcludePathPattern '\\AppxBlockMap','\\\[Content_Types\]','\\AppxSignature'

    .EXAMPLE
        # CI gate: fail the build when anything other than the version bumps
        $diff = Compare-MsixPackage -LeftPath baseline.msix -RightPath candidate.msix
        if ($diff.FileChanges.Count -gt 0 -or $diff.SigningChanges.Count -gt 0) {
            throw 'Unexpected change set'
        }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$LeftPath,
        [Parameter(Mandatory)] [string]$RightPath,
        [string[]]$ExcludePathPattern = @('\\AppxBlockMap', '\\\[Content_Types\]', '\\AppxSignature')
    )

    $leftWs  = _MsixUnpackForCompare -PackagePath $LeftPath  -Tag 'left'
    $rightWs = _MsixUnpackForCompare -PackagePath $RightPath -Tag 'right'

    try {
        $null = Test-MsixManifest "$leftWs\AppxManifest.xml"
        $null = Test-MsixManifest "$rightWs\AppxManifest.xml"
        [xml]$leftManifest  = Get-MsixManifest "$leftWs\AppxManifest.xml"
        [xml]$rightManifest = Get-MsixManifest "$rightWs\AppxManifest.xml"

        $manifestChanges = _ComparePackageManifest -LeftManifest $leftManifest -RightManifest $rightManifest

        $fileChanges = _CompareFileSets -LeftRoot $leftWs -RightRoot $rightWs
        if ($ExcludePathPattern) {
            $fileChanges = $fileChanges | Where-Object {
                $row = $_
                ($ExcludePathPattern | Where-Object { $row.Path -match $_ }).Count -eq 0
            }
        }

        # Signing state
        $sigL = Get-AuthenticodeSignature -FilePath $LeftPath
        $sigR = Get-AuthenticodeSignature -FilePath $RightPath
        $signingChanges = [System.Collections.Generic.List[object]]::new()
        if ($sigL.Status -ne $sigR.Status) {
            $signingChanges.Add([pscustomobject]@{ Field='Status';     Left=$sigL.Status;                       Right=$sigR.Status })
        }
        if ($sigL.SignerCertificate.Thumbprint -ne $sigR.SignerCertificate.Thumbprint) {
            $signingChanges.Add([pscustomobject]@{ Field='Thumbprint'; Left=$sigL.SignerCertificate.Thumbprint; Right=$sigR.SignerCertificate.Thumbprint })
        }
        if ($sigL.SignerCertificate.Subject -ne $sigR.SignerCertificate.Subject) {
            $signingChanges.Add([pscustomobject]@{ Field='Subject';    Left=$sigL.SignerCertificate.Subject;    Right=$sigR.SignerCertificate.Subject })
        }

        $hasChanges = ($manifestChanges.Count -gt 0) -or ($fileChanges.Count -gt 0) -or ($signingChanges.Count -gt 0)

        return [pscustomobject]@{
            LeftPath        = $LeftPath
            RightPath       = $RightPath
            HasChanges      = $hasChanges
            ManifestChanges = $manifestChanges
            FileChanges     = $fileChanges
            SigningChanges  = $signingChanges
        }
    } finally {
        Remove-Item -LiteralPath $leftWs  -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $rightWs -Recurse -Force -ErrorAction SilentlyContinue
    }
}
