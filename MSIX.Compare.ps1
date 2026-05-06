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
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-$Tag"
    $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
    Assert-MsixProcessSuccess $r 'MakeAppx unpack'
    return $workspace
}

function _ComparePackageManifest {
    param([xml]$LeftManifest, [xml]$RightManifest)

    $changes = New-Object System.Collections.Generic.List[object]

    function _Add { param([string]$Field, $Left, $Right)
        if ($Left -ne $Right) {
            $changes.Add([pscustomobject]@{
                Field = $Field; Left = $Left; Right = $Right
            })
        }
    }
    _Add 'Identity.Name'                  $LeftManifest.Package.Identity.Name      $RightManifest.Package.Identity.Name
    _Add 'Identity.Publisher'             $LeftManifest.Package.Identity.Publisher $RightManifest.Package.Identity.Publisher
    _Add 'Identity.Version'               $LeftManifest.Package.Identity.Version   $RightManifest.Package.Identity.Version
    _Add 'Identity.ProcessorArchitecture' $LeftManifest.Package.Identity.ProcessorArchitecture $RightManifest.Package.Identity.ProcessorArchitecture
    _Add 'Properties.DisplayName'         $LeftManifest.Package.Properties.DisplayName        $RightManifest.Package.Properties.DisplayName
    _Add 'Properties.PublisherDisplayName' $LeftManifest.Package.Properties.PublisherDisplayName $RightManifest.Package.Properties.PublisherDisplayName
    _Add 'Dependencies.MinVersion'        $LeftManifest.Package.Dependencies.TargetDeviceFamily.MinVersion       $RightManifest.Package.Dependencies.TargetDeviceFamily.MinVersion
    _Add 'Dependencies.MaxVersionTested'  $LeftManifest.Package.Dependencies.TargetDeviceFamily.MaxVersionTested $RightManifest.Package.Dependencies.TargetDeviceFamily.MaxVersionTested

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
        Get-ChildItem $root -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                $rel = $_.FullName.Substring($root.Length + 1)
                $hash = $null
                try {
                    $stream = [IO.File]::OpenRead($_.FullName)
                    try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-','') }
                    finally { $stream.Dispose() }
                } catch {}
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

    $diff = New-Object System.Collections.Generic.List[object]

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

    .PARAMETER LeftPath / RightPath
        The two packages to compare.

    .PARAMETER ExcludePathPattern
        Regexes of file relative paths to ignore in the file diff (good for
        timestamps, [Content_Types].xml, AppxBlockMap, AppxSignature).

    .EXAMPLE
        $diff = Compare-MsixPackage -LeftPath old.msix -RightPath new.msix
        $diff.HasChanges
        $diff.ManifestChanges | Format-Table
        $diff.FileChanges     | Format-Table

    .EXAMPLE
        # Skip auto-generated package metadata
        Compare-MsixPackage -LeftPath a.msix -RightPath b.msix `
            -ExcludePathPattern '\\AppxBlockMap','\\\[Content_Types\]','\\AppxSignature'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$LeftPath,
        [Parameter(Mandatory)] [string]$RightPath,
        [string[]]$ExcludePathPattern = @('\\AppxBlockMap', '\\\[Content_Types\]', '\\AppxSignature')
    )

    $leftWs  = _MsixUnpackForCompare $LeftPath  'left'
    $rightWs = _MsixUnpackForCompare $RightPath 'right'

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
        $signingChanges = New-Object System.Collections.Generic.List[object]
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
        Remove-Item $leftWs  -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $rightWs -Recurse -Force -ErrorAction SilentlyContinue
    }
}
