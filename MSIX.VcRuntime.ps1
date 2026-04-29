# =============================================================================
# Visual C++ Runtime detection + bundling
# -----------------------------------------------------------------------------
# Many legacy Win32 apps depend on the VC++ redistributable (msvcp140.dll,
# vcruntime140.dll, ucrtbase.dll …). When packaged as MSIX they cannot rely on
# WinSxS-shared copies, and the OS image MAY not have the right runtime.
#
# This module:
#   - Detects which VC runtime DLLs an unpacked MSIX references.
#   - Identifies whether they're already bundled in the package.
#   - Optionally copies the right architecture-matched DLLs in from a source
#     folder (e.g. Microsoft Visual Studio's redist), so the package becomes
#     self-contained.
#
# References:
#   - TMEditX UCVCRuntimes (v0.9 modelled on this)
#   - https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files
# =============================================================================

# Canonical runtime DLL set (release + debug).
$script:KnownVcRuntimeDlls = @(
    # Release CRT
    'msvcp140.dll', 'msvcp140_1.dll', 'msvcp140_2.dll',
    'vcruntime140.dll', 'vcruntime140_1.dll',
    'ucrtbase.dll',
    'concrt140.dll', 'mfc140.dll', 'mfc140u.dll',
    # Debug CRT
    'msvcp140d.dll', 'msvcp140_1d.dll', 'msvcp140_2d.dll',
    'vcruntime140d.dll', 'vcruntime140_1d.dll',
    'ucrtbased.dll',
    'concrt140d.dll', 'mfc140d.dll', 'mfc140ud.dll',
    # Older toolsets that some apps still ship
    'msvcr120.dll', 'msvcr110.dll', 'msvcr100.dll',
    'msvcp120.dll', 'msvcp110.dll', 'msvcp100.dll',
    'msvcr120_clr0400.dll'
)


function Get-MsixVcRuntimeReferences {
    <#
    .SYNOPSIS
        Walks the unpacked package and returns:
          - References   the VC runtime DLLs imported by .exe/.dll files
                         (best-effort: scans PE imports via dumpbin or string match)
          - Bundled      the VC runtime DLLs that ARE present in the package
          - Missing      References that are NOT present in the package

    .DESCRIPTION
        Static check, nothing is mutated. Use Add-MsixVcRuntimeBundle to bring
        the missing DLLs into the package.

    .PARAMETER PackagePath
        .msix file (will be unpacked into a workspace, then cleaned up).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-vcrt"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $allFiles = Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue
        $bundled  = $allFiles | Where-Object { $script:KnownVcRuntimeDlls -contains $_.Name.ToLower() } |
                     ForEach-Object {
                         [pscustomobject]@{
                             Name         = $_.Name.ToLower()
                             Path         = $_.FullName.Substring($workspace.Length + 1)
                             SizeBytes    = $_.Length
                             Architecture = (_GetPeArchitecture $_.FullName)
                         }
                     }

        # Best-effort PE import scan.
        $references = @{}
        foreach ($exe in @($allFiles | Where-Object { $_.Extension -in '.exe','.dll' })) {
            $imports = _GetPeImports $exe.FullName
            foreach ($imp in $imports) {
                $low = $imp.ToLower()
                if ($script:KnownVcRuntimeDlls -contains $low) {
                    if (-not $references.ContainsKey($low)) {
                        $references[$low] = @()
                    }
                    $references[$low] += $exe.FullName.Substring($workspace.Length + 1)
                }
            }
        }

        $bundledNames = @($bundled.Name)
        $missing      = @($references.Keys | Where-Object { $_ -notin $bundledNames })

        return [pscustomobject]@{
            PackagePath = $fileinfo.FullName
            References  = $references
            Bundled     = $bundled
            Missing     = $missing
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


function _GetPeArchitecture {
    param([string]$Path)
    try {
        # Read PE header machine field at the offset stored at 0x3C
        $bytes = [byte[]]::new(2)
        $fs = [System.IO.File]::OpenRead($Path)
        try {
            $fs.Position = 0x3C
            $offBuf      = [byte[]]::new(4)
            $null        = $fs.Read($offBuf, 0, 4)
            $peOffset    = [BitConverter]::ToInt32($offBuf, 0)
            $fs.Position = $peOffset + 4
            $null        = $fs.Read($bytes, 0, 2)
        } finally {
            $fs.Dispose()
        }
        switch ([BitConverter]::ToUInt16($bytes, 0)) {
            0x014C  { 'x86' }
            0x8664  { 'x64' }
            0xAA64  { 'arm64' }
            default { 'unknown' }
        }
    } catch {
        'unknown'
    }
}


function _GetPeImports {
    param([string]$Path)
    # Cheap fallback: scan strings for known DLL names. Works for almost all
    # Win32 executables without needing dumpbin (Visual Studio).
    try {
        $stream = [System.IO.File]::OpenRead($Path)
        try {
            $buf = New-Object byte[] ([math]::Min($stream.Length, 8MB))
            $n   = $stream.Read($buf, 0, $buf.Length)
            $txt = [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
        } finally { $stream.Dispose() }
        $hits = New-Object System.Collections.Generic.HashSet[string]
        foreach ($dll in $script:KnownVcRuntimeDlls) {
            if ($txt -match [regex]::Escape($dll)) { $null = $hits.Add($dll) }
        }
        return @($hits)
    } catch {
        @()
    }
}


function Add-MsixVcRuntimeBundle {
    <#
    .SYNOPSIS
        Copies VC++ runtime DLLs into an MSIX package so the app no longer
        relies on host-side WinSxS / VCRedist.

    .DESCRIPTION
        Detects the missing VC runtime DLLs (per Get-MsixVcRuntimeReferences),
        finds them under -SourceFolder (architecture-aware), copies them next
        to the application executable(s), repacks, and signs.

    .PARAMETER PackagePath
        .msix to modify.

    .PARAMETER SourceFolder
        Folder containing release-built VC runtime DLLs. Typically the
        VS redist directory:
          %ProgramFiles%\Microsoft Visual Studio\<ver>\<edition>\VC\Redist\MSVC\<ver>\<arch>\Microsoft.VC*.CRT

    .PARAMETER Architecture
        x86 or x64. Defaults to whichever the package's first executable uses.

    .PARAMETER Names
        Override the DLL list (default: missing DLLs detected by analysis).

    .PARAMETER OutputPath / SkipSigning / Pfx / PfxPassword
        See Add-MsixPsfV2.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [string]$SourceFolder,
        [ValidateSet('x86','x64','auto')]
        [string]$Architecture = 'auto',
        [string[]]$Names,
        [string]$OutputPath,
        [switch]$SkipSigning,
        [string]$Pfx,
        [string]$PfxPassword
    )

    if (-not (Test-Path $SourceFolder)) {
        throw "VC runtime source folder not found: $SourceFolder"
    }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName

    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"
        $apps          = @($manifest.Package.Applications.Application)

        # Determine architecture if auto
        if ($Architecture -eq 'auto') {
            $sample = Join-Path $workspace $apps[0].Executable
            $Architecture = if (Test-Path $sample) { (_GetPeArchitecture $sample) } else { 'x86' }
            if ($Architecture -notin 'x86','x64') { $Architecture = 'x86' }
            Write-MsixLog Info "Architecture auto-detected: $Architecture"
        }

        # Resolve DLLs to copy
        if (-not $Names) {
            $analysis = Get-MsixVcRuntimeReferences -PackagePath $PackagePath
            $Names    = $analysis.Missing
            if (-not $Names) {
                Write-MsixLog Info 'No missing VC runtime DLLs detected; nothing to bundle.'
                return
            }
            Write-MsixLog Info "Will bundle missing DLLs: $($Names -join ', ')"
        }

        # Locate each DLL under SourceFolder. Heuristic search.
        $copied = @()
        foreach ($name in $Names) {
            $hit = Get-ChildItem $SourceFolder -Recurse -Filter $name -ErrorAction SilentlyContinue |
                   Where-Object {
                       (_GetPeArchitecture $_.FullName) -eq $Architecture
                   } | Select-Object -First 1
            if (-not $hit) {
                Write-MsixLog Warning "$name not found under $SourceFolder for $Architecture"
                continue
            }
            # Copy into the same folder as the first executable
            $exeRel  = $apps[0].Executable
            $destDir = if ($exeRel.Contains('\')) {
                Join-Path $workspace $exeRel.Substring(0, $exeRel.LastIndexOf('\'))
            } else { $workspace }
            if ($PSCmdlet.ShouldProcess($destDir, "Copy $name")) {
                Copy-Item $hit.FullName $destDir -Force
                $copied += $name
            }
        }

        if ($copied.Count -eq 0) {
            Write-MsixLog Warning 'No VC runtime DLLs were copied; aborting.'
            return
        }

        # Repack
        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$target`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }

        return [pscustomobject]@{ PackagePath = $target; Bundled = $copied; Architecture = $Architecture }

    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
