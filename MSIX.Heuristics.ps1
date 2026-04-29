# =============================================================================
# Auto-fix heuristics (TMEditX-style)
# -----------------------------------------------------------------------------
# Each helper here is a small, focused fixer:
#   - "Get-MsixXxxRecommendation" returns a finding object describing whether
#     the package matches the heuristic.
#   - "Add-MsixXxx" / "Remove-MsixXxx" mutate the package idempotently and
#     re-pack it (re-signing unless -SkipSigning).
#
# All of these are opt-in. None are applied by Invoke-MsixPipeline by default.
# Use Invoke-MsixAutoFix to chain a curated set similar to TMEditX's
# AutoFixStage workflow.
# =============================================================================

#region Capabilities --------------------------------------------------------

# Common rescap / standard capabilities admins frequently add to packaged apps
$script:KnownCapabilities = [ordered]@{
    'runFullTrust'              = 'rescap'
    'allowElevation'            = 'rescap'
    'unvirtualizedResources'    = 'rescap'
    'broadFileSystemAccess'     = 'rescap'
    'extendedExecutionUnconstrained' = 'rescap'
    'internetClient'            = 'standard'
    'internetClientServer'      = 'standard'
    'privateNetworkClientServer' = 'standard'
    'codeGeneration'            = 'standard'
    'documentsLibrary'          = 'standard'
    'picturesLibrary'           = 'standard'
    'videosLibrary'             = 'standard'
    'musicLibrary'              = 'standard'
    'removableStorage'          = 'standard'
}

function Get-MsixKnownCapabilities {
    <#
    .SYNOPSIS
        Returns the capability table this module knows about, with the
        namespace prefix each one belongs in.
    #>
    foreach ($k in $script:KnownCapabilities.Keys) {
        [pscustomobject]@{
            Name      = $k
            Namespace = $script:KnownCapabilities[$k]
        }
    }
}

function Add-MsixCapability {
    <#
    .SYNOPSIS
        Adds one or more capabilities (standard or rescap) to a package's
        AppxManifest.xml. Idempotent. Repacks + signs unless -SkipSigning.

    .PARAMETER PackagePath
        .msix to modify.

    .PARAMETER Names
        Capability names. Looked up against the registry — anything unknown
        is treated as standard.

    .PARAMETER OutputPath / SkipSigning / Pfx / PfxPassword
        See Add-MsixPsfV2.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [string[]]$Names,
        [string]$OutputPath,
        [switch]$SkipSigning,
        [string]$Pfx,
        [string]$PfxPassword
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"

        $caps = $manifest.Package.Capabilities
        if (-not $caps) {
            $caps = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
            $null = $manifest.Package.AppendChild($caps)
        }

        $rescapUri = Get-MsixManifestNamespaceUri 'rescap'
        $changed = $false

        foreach ($name in $Names) {
            $isRescap = $script:KnownCapabilities[$name] -eq 'rescap'
            $existing = $caps.ChildNodes | Where-Object {
                ($_.LocalName -eq 'Capability') -and ($_.Name -eq $name)
            }
            if ($existing) {
                Write-MsixLog Info "Capability already present: $name"
                continue
            }
            if ($isRescap) {
                Add-MsixManifestNamespace $manifest 'rescap'
                $node = $manifest.CreateElement('rescap:Capability', $rescapUri)
            } else {
                $node = $manifest.CreateElement('Capability', $manifest.Package.NamespaceURI)
            }
            $node.SetAttribute('Name', $name)
            $null = $caps.AppendChild($node)
            Write-MsixLog Info "Capability added: $name"
            $changed = $true
        }

        if (-not $changed) { return }

        if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save manifest')) {
            Save-MsixManifest $manifest "$workspace\AppxManifest.xml"
        }

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$target`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }

    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Uninstaller / desktop shortcut detection ---------------------------

function Get-MsixUninstallerCandidates {
    <#
    .SYNOPSIS
        Lists files inside the package that look like leftover installer or
        uninstaller artefacts. These commonly break MSIX install/uninstall flows
        and should usually be removed before publishing.

    .DESCRIPTION
        Pattern matches against well-known uninstaller filenames
        (uninst*.exe, unins*.exe, setup.exe, install.exe, autorun.inf,
        InstallShield/MSI scratch files).

    .PARAMETER PackagePath
        .msix to scan (read-only).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $patterns = @(
        '^uninst.*\.exe$', '^unins.*\.exe$',
        '^setup\.exe$', '^install\.exe$',
        '^_isres.*$', '^autorun\.inf$',
        '^Setup\.msi$', '^uninstall\.exe$',
        '^uninstaller.*\.exe$'
    )
    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-unin"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $name = $_.Name
                ($patterns | Where-Object { $name -match $_ }).Count -gt 0
            } |
            ForEach-Object {
                [pscustomobject]@{
                    Name      = $_.Name
                    Path      = $_.FullName.Substring($workspace.Length + 1)
                    SizeBytes = $_.Length
                }
            }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


function Remove-MsixUninstallerArtifacts {
    <#
    .SYNOPSIS
        Strips uninstaller-looking files from inside the package. Repacks +
        re-signs unless -SkipSigning. Pass -PathPatterns to override defaults.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [string[]]$PathPatterns,
        [string]$OutputPath,
        [switch]$SkipSigning,
        [string]$Pfx,
        [string]$PfxPassword
    )
    if (-not $PathPatterns) {
        $PathPatterns = @(
            '^uninst.*\.exe$','^unins.*\.exe$','^setup\.exe$','^install\.exe$',
            '^_isres.*$','^autorun\.inf$','^uninstall\.exe$','^uninstaller.*\.exe$'
        )
    }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $removed = @()
        Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $name = $_.Name
                ($PathPatterns | Where-Object { $name -match $_ }).Count -gt 0
            } |
            ForEach-Object {
                if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove uninstaller artefact')) {
                    Remove-Item $_.FullName -Force
                    $removed += $_.FullName.Substring($workspace.Length + 1)
                }
            }

        if (-not $removed) {
            Write-MsixLog Info 'No uninstaller-looking files found.'
            return
        }
        Write-MsixLog Info "Removed: $($removed -join ', ')"

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$target`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Run-keys (HKLM\Run autostart) ---------------------------------------

function Get-MsixRunKeyEntries {
    <#
    .SYNOPSIS
        Lists the HKLM/HKCU \…\Run\* entries declared by the package — usually
        baked in by the original installer. These don't fire under MSIX and
        admins typically remove them or replace with a startScript.
    .DESCRIPTION
        Inspects User.dat and Registry.dat hives shipped in VFS\… for
        Software\Microsoft\Windows\CurrentVersion\Run\* values.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-runkeys"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        # MSIX packages ship Registry.dat + User.dat for the virtual hive.
        $hits = @()
        foreach ($dat in @('Registry.dat','User.dat')) {
            $datPath = Join-Path $workspace $dat
            if (-not (Test-Path $datPath)) { continue }
            # Best-effort string scan — full hive parsing requires reg.exe load.
            try {
                $bytes = [IO.File]::ReadAllBytes($datPath)
                $text  = [System.Text.Encoding]::Unicode.GetString($bytes)
                $m = [regex]::Matches($text, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run[\w\\]*', 'IgnoreCase')
                foreach ($mm in $m) {
                    $hits += [pscustomobject]@{
                        Hive  = $dat
                        Match = $mm.Value
                    }
                }
            } catch {}
        }
        return $hits | Sort-Object Hive,Match -Unique
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Application execution alias auto-suggest ---------------------------

function Get-MsixAliasCandidates {
    <#
    .SYNOPSIS
        Lists package executables that LOOK like good AppExecutionAlias
        candidates — top-level user-facing binaries, not vendored helpers.

    .DESCRIPTION
        Heuristic:
          - .exe under VFS\ProgramFiles* with a manifest entry pointing at it
          - skip msvcr*, vcredist*, setup*, install*, uninst*
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-alias"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"
        $apps          = @($manifest.Package.Applications.Application)

        $skipPatterns = @(
            '^msvcr','^msvcp','^vcruntime','^ucrtbase',
            '^vcredist','^setup','^install','^uninst',
            '^psf','^msix','^api-ms-win-'
        )

        foreach ($app in $apps) {
            $exe = $app.Executable
            if (-not $exe) { continue }
            $leaf = ($exe.Split('\')[-1]).ToLower()
            $skip = $skipPatterns | Where-Object { $leaf -match $_ }
            if ($skip) { continue }

            $aliasName = ($leaf -replace '\.exe$','') + '.exe'
            $hasAlias  = [bool]($app.Extensions.Extension.AppExecutionAlias.ExecutionAlias)

            [pscustomobject]@{
                AppId        = $app.Id
                Executable   = $exe
                SuggestAlias = $aliasName
                AlreadyHasAlias = $hasAlias
            }
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Splash screen ------------------------------------------------------

function Add-MsixSplashScreen {
    <#
    .SYNOPSIS
        Adds a splash-screen image to the PSF launcher config so users see
        feedback while a slow startScript runs. Requires PSF already to be
        injected (Add-MsixPsfV2 first).

    .PARAMETER PackagePath
        .msix to modify (must already use PsfLauncher).

    .PARAMETER ImagePath
        PNG/JPG to display. Copied into the package folder.

    .PARAMETER AppId
        Application id whose config.json gets the splash entry.

    .PARAMETER OutputPath / SkipSigning / Pfx / PfxPassword
        See Add-MsixPsfV2.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [string]$ImagePath,
        [Parameter(Mandatory)] [string]$AppId,
        [string]$OutputPath,
        [switch]$SkipSigning,
        [string]$Pfx,
        [string]$PfxPassword
    )
    if (-not (Test-Path $ImagePath)) { throw "Splash image not found: $ImagePath" }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        # Find config.json — should be next to PsfLauncher
        $cfgPaths = @(Get-ChildItem $workspace -Recurse -Filter 'config.json' -ErrorAction SilentlyContinue)
        if (-not $cfgPaths) { throw 'config.json not found; run Add-MsixPsfV2 first.' }
        $cfgPath = $cfgPaths[0].FullName
        $cfgDir  = Split-Path $cfgPath -Parent

        # Copy splash next to config.json
        $imageLeaf = (Get-Item $ImagePath).Name
        Copy-Item $ImagePath $cfgDir -Force

        # Patch config.json
        $cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
        foreach ($app in @($cfg.applications)) {
            if ($app.id -ne $AppId) { continue }
            if (-not $app.startScript) {
                $app | Add-Member -NotePropertyName startScript -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            $app.startScript | Add-Member -NotePropertyName splashImage -NotePropertyValue $imageLeaf -Force
        }
        $cfg | ConvertTo-Json -Depth 15 | Set-Content $cfgPath -Encoding utf8

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$target`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Version bump --------------------------------------------------------

function Update-MsixPackageVersion {
    <#
    .SYNOPSIS
        Bumps the AppxManifest Identity Version (4-part).

    .PARAMETER Component
        Major | Minor | Build | Revision (default: Build).

    .PARAMETER KeepLastZero
        If $true, leaves the rightmost component at 0 after the bump
        (matches TMEditX's KeepPackageVersionFieldLastAsZero).

    .PARAMETER NewVersion
        Explicit version string overriding -Component. Use this for
        date-based versions etc.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [ValidateSet('Major','Minor','Build','Revision')]
        [string]$Component = 'Build',
        [bool]$KeepLastZero,
        [string]$NewVersion,
        [string]$OutputPath,
        [switch]$SkipSigning,
        [string]$Pfx,
        [string]$PfxPassword
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"
        $current = [version]$manifest.Package.Identity.Version

        if ($NewVersion) {
            $next = [version]$NewVersion
        } else {
            switch ($Component) {
                'Major'    { $next = [version]"$([int]$current.Major + 1).0.0.0" }
                'Minor'    { $next = [version]"$($current.Major).$([int]$current.Minor + 1).0.0" }
                'Build'    { $next = [version]"$($current.Major).$($current.Minor).$([int]$current.Build + 1).0" }
                'Revision' { $next = [version]"$($current.Major).$($current.Minor).$($current.Build).$([int]$current.Revision + 1)" }
            }
            if ($KeepLastZero) {
                # Force the last component to 0 (already done above for Major/Minor/Build)
                if ($Component -eq 'Revision') {
                    $next = [version]"$($current.Major).$($current.Minor).$([int]$current.Build + 1).0"
                }
            }
        }
        $manifest.Package.Identity.Version = $next.ToString(4)
        Write-MsixLog Info "Version: $current -> $next"

        if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save manifest')) {
            Save-MsixManifest $manifest "$workspace\AppxManifest.xml"
        }

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$target`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }
        return $next.ToString(4)
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region AutoFix orchestrator -----------------------------------------------

function Invoke-MsixAutoFix {
    <#
    .SYNOPSIS
        Runs a curated set of TMEditX-style auto-fixes against a package in a
        deterministic order, signing only at the very end.

    .DESCRIPTION
        Stages (modelled on TMEditX's AutoFixStage enum):

          PrePsf
            - RemoveUninstallers      strip uninstall*.exe and friends
            - BumpVersion             bump the package version
          Recommended
            - AddCapabilities         add common capabilities
            - InjectPsf               run Add-MsixPsfV2 with the fixups you supply
            - BundleVcRuntimes        copy missing VC runtime DLLs in
          Optional
            - AddSplashImage          show a splash while a startScript runs

        Every stage writes back into the SAME file (or -OutputPath if set) and
        passes -SkipSigning so we sign once at the end. Use -DryRun to see
        which stages would fire without mutating the package.

    .PARAMETER PackagePath
        .msix to mutate.

    .PARAMETER Capabilities
        Names to add via Add-MsixCapability (rescap or standard, looked up
        against Get-MsixKnownCapabilities).

    .PARAMETER PsfFixups / PsfAppOptions / PsfWorkingDirectory / PsfAdditionalFiles
        Forwarded to Add-MsixPsfV2.

    .PARAMETER VcRuntimeSourceFolder
        If set, runs Add-MsixVcRuntimeBundle with this source folder.

    .PARAMETER SplashImagePath / SplashAppId
        If set, runs Add-MsixSplashScreen after PSF.

    .PARAMETER VersionBumpComponent
        If set, runs Update-MsixPackageVersion before any other stage.

    .PARAMETER RemoveUninstallers
        If $true, strips uninstaller-looking files first.

    .PARAMETER OutputPath
        If set, all writes go here instead of overwriting -PackagePath.

    .PARAMETER DryRun
        Report which stages would fire, then return — no mutation, no signing.

    .PARAMETER Pfx / PfxPassword
        Signing certificate for the final pass.

    .EXAMPLE
        Invoke-MsixAutoFix -PackagePath app.msix `
            -RemoveUninstallers `
            -Capabilities runFullTrust,internetClient `
            -PsfFixups @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' ) `
            -VersionBumpComponent Build `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,

        # PrePsf stage
        [switch]$RemoveUninstallers,
        [ValidateSet('Major','Minor','Build','Revision')]
        [string]$VersionBumpComponent,

        # Recommended stage
        [string[]]$Capabilities,
        [hashtable[]]$PsfFixups,
        [hashtable[]]$PsfAppOptions,
        [string]$PsfWorkingDirectory,
        [string[]]$PsfAdditionalFiles,
        [string]$VcRuntimeSourceFolder,

        # Optional stage
        [string]$SplashImagePath,
        [string]$SplashAppId,

        # Output / signing
        [string]$OutputPath,
        [switch]$DryRun,
        [string]$Pfx,
        [string]$PfxPassword
    )

    $stages = New-Object System.Collections.Generic.List[object]
    function _Stage([string]$Name, [scriptblock]$Action) {
        $stages.Add([pscustomobject]@{ Name = $Name; Action = $Action })
    }

    # All intermediate stages must write through OutputPath if set so the
    # original is preserved; subsequent stages then read from OutputPath.
    $current = $PackagePath
    if ($OutputPath -and -not $DryRun) {
        Copy-Item $PackagePath $OutputPath -Force
        $current = $OutputPath
    }

    if ($RemoveUninstallers) {
        _Stage 'PrePsf:RemoveUninstallers' {
            Remove-MsixUninstallerArtifacts -PackagePath $current -SkipSigning
        }
    }
    if ($VersionBumpComponent) {
        _Stage 'PrePsf:BumpVersion' {
            Update-MsixPackageVersion -PackagePath $current -Component $VersionBumpComponent -SkipSigning
        }
    }
    if ($Capabilities) {
        _Stage 'Recommended:AddCapabilities' {
            Add-MsixCapability -PackagePath $current -Names $Capabilities -SkipSigning
        }
    }
    if ($PsfFixups -or $PsfAppOptions) {
        _Stage 'Recommended:InjectPsf' {
            $args = @{
                PackagePath = $current
                Fixups      = $PsfFixups
                SkipSigning = $true
            }
            if ($PsfAppOptions)         { $args['AppOptions']        = $PsfAppOptions }
            if ($PsfWorkingDirectory)   { $args['WorkingDirectory']  = $PsfWorkingDirectory }
            if ($PsfAdditionalFiles)    { $args['AdditionalFiles']   = $PsfAdditionalFiles }
            Add-MsixPsfV2 @args
        }
    }
    if ($VcRuntimeSourceFolder) {
        _Stage 'Recommended:BundleVcRuntimes' {
            Add-MsixVcRuntimeBundle -PackagePath $current -SourceFolder $VcRuntimeSourceFolder -SkipSigning
        }
    }
    if ($SplashImagePath -and $SplashAppId) {
        _Stage 'Optional:AddSplashImage' {
            Add-MsixSplashScreen -PackagePath $current -ImagePath $SplashImagePath -AppId $SplashAppId -SkipSigning
        }
    }

    if ($DryRun) {
        Write-MsixLog Info "DryRun: would run $($stages.Count) stages."
        return [pscustomobject]@{
            PackagePath = $PackagePath
            Stages      = $stages.Name
            DryRun      = $true
        }
    }

    foreach ($s in $stages) {
        Write-MsixLog Info "==> $($s.Name)"
        & $s.Action
    }

    # Sign once at the end
    if (-not $stages -or -not $stages.Count) {
        Write-MsixLog Info 'No stages selected; nothing to do.'
        return
    }
    Write-MsixLog Info '==> Sign'
    Invoke-MsixSigning -PackagePath $current -Pfx $Pfx -PfxPassword $PfxPassword

    return [pscustomobject]@{
        PackagePath = $current
        Stages      = $stages.Name
        DryRun      = $false
    }
}
#endregion

#region Static analysis adapter --------------------------------------------

function Get-MsixHeuristicFindings {
    <#
    .SYNOPSIS
        Runs every read-only TMEditX-style analyzer against a package and
        returns merged findings. Used by Get-MsixStaticAnalysis to expand the
        report.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $out = New-Object System.Collections.Generic.List[object]

    # Uninstaller artefacts
    foreach ($u in Get-MsixUninstallerCandidates -PackagePath $PackagePath) {
        $out.Add([pscustomobject]@{
            Severity = 'Warning'
            Category = 'UninstallerArtifact'
            Symptom  = "Looks like a leftover installer artefact: $($u.Name)"
            Recommendation = "Remove-MsixUninstallerArtifacts -PackagePath '$PackagePath'"
            Evidence = $u.Path
            AppId    = $null
        })
    }

    # Run keys
    foreach ($r in Get-MsixRunKeyEntries -PackagePath $PackagePath) {
        $out.Add([pscustomobject]@{
            Severity = 'Info'
            Category = 'RunKey'
            Symptom  = "Package's $($r.Hive) ships an autostart Run entry."
            Recommendation = "Use a PSF startScript or an HKCU Run entry instead — packaged HKLM Run keys do not fire."
            Evidence = $r.Match
            AppId    = $null
        })
    }

    # Alias suggestions
    foreach ($a in Get-MsixAliasCandidates -PackagePath $PackagePath) {
        if ($a.AlreadyHasAlias) { continue }
        $out.Add([pscustomobject]@{
            Severity = 'Info'
            Category = 'AppExecutionAlias'
            Symptom  = "$($a.AppId) has no AppExecutionAlias."
            Recommendation = "Add-MsixAlias -PackagePath '$PackagePath' -AppIds '$($a.AppId)' (suggested alias: $($a.SuggestAlias))"
            Evidence = $a.Executable
            AppId    = $a.AppId
        })
    }

    # VC runtime missing
    try {
        $vc = Get-MsixVcRuntimeReferences -PackagePath $PackagePath
        if ($vc.Missing) {
            $out.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'VcRuntime'
                Symptom  = "References VC runtime DLLs that are not bundled: $($vc.Missing -join ', ')"
                Recommendation = "Add-MsixVcRuntimeBundle -PackagePath '$PackagePath' -SourceFolder <vs-redist-folder>"
                Evidence = $vc.Missing -join ', '
                AppId    = $null
            })
        }
    } catch {}

    return $out
}
#endregion
