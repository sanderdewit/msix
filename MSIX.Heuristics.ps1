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
    # rescap — <rescap:Capability>
    'runFullTrust'                   = 'rescap'
    'allowElevation'                 = 'rescap'
    'unvirtualizedResources'         = 'rescap'
    'broadFileSystemAccess'          = 'rescap'
    'extendedExecutionUnconstrained' = 'rescap'
    # standard — plain <Capability> (schema enum: only these 5)
    'internetClient'                 = 'standard'
    'internetClientServer'           = 'standard'
    'privateNetworkClientServer'     = 'standard'
    'codeGeneration'                 = 'standard'
    'allJoyn'                        = 'standard'
    # uap — <uap:Capability>
    'documentsLibrary'               = 'uap'
    'picturesLibrary'                = 'uap'
    'videosLibrary'                  = 'uap'
    'musicLibrary'                   = 'uap'
    'removableStorage'               = 'uap'
    'enterpriseAuthentication'       = 'uap'
    'sharedUserCertificates'         = 'uap'
    'userAccountInformation'         = 'uap'
    'objects3D'                      = 'uap'
    'voipCall'                       = 'uap'
    'chat'                           = 'uap'
    'remoteSystem'                   = 'uap'
}

function Get-MsixKnownCapability {
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
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $null = Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"

        $caps = $manifest.Package.Capabilities
        if (-not $caps) {
            $caps = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
            $null = $manifest.Package.AppendChild($caps)
        }

        $rescapUri = Get-MsixManifestNamespaceUri 'rescap'
        $uapUri    = Get-MsixManifestNamespaceUri 'uap'
        $changed = $false

        foreach ($name in $Names) {
            $ns = $script:KnownCapabilities[$name]   # 'rescap' | 'uap' | 'standard' | $null
            # Idempotency: match by LocalName + Name attribute regardless of prefix
            $existing = $caps.ChildNodes | Where-Object {
                ($_.LocalName -eq 'Capability') -and ($_.'Name' -eq $name)
            }
            if ($existing) {
                Write-MsixLog Info "Capability already present: $name"
                continue
            }
            if ($ns -eq 'rescap') {
                Add-MsixManifestNamespace $manifest 'rescap'
                $node = $manifest.CreateElement('rescap:Capability', $rescapUri)
            } elseif ($ns -eq 'uap') {
                Add-MsixManifestNamespace $manifest 'uap'
                $node = $manifest.CreateElement('uap:Capability', $uapUri)
            } else {
                # 'standard' or unknown — plain <Capability>; warn if not in the known-good list
                $validStandard = @('internetClient','internetClientServer','privateNetworkClientServer','allJoyn','codeGeneration')
                if ($name -notin $validStandard) {
                    Write-Warning "Capability '$name' is not in the known-capabilities table. Adding as plain <Capability> — this may fail manifest validation. Run Get-MsixKnownCapability to see the supported list."
                }
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
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
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

function Get-MsixUninstallerCandidate {
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
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
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


function Get-MsixUninstallRegistryEntry {
    <#
    .SYNOPSIS
        Reads the package's virtualized HKLM hive (Registry.dat) and returns
        the Uninstall\* subkeys baked in by the original installer. These are
        leftover and don't function inside an MSIX container.

    .DESCRIPTION
        Loads Registry.dat as a temporary hive (HKLM\TempMsixHive_*), walks
        SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall and the WOW6432Node
        equivalent, captures DisplayName / DisplayVersion / Publisher /
        UninstallString for each, and unloads.

        Requires admin rights (reg.exe load). Returns $null and logs a warning
        if not elevated.

    .PARAMETER PackagePath
        .msix file (read-only).
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-uninreg"

    if (-not (_MsixIsAdmin)) {
        Write-MsixLog Warning 'Get-MsixUninstallRegistryEntry: not elevated — string scan only (no value details).'
        try {
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
            Assert-MsixProcessSuccess $r 'MakeAppx unpack'
            $datPath = Join-Path $workspace 'Registry.dat'
            if (-not (Test-Path $datPath)) { return @() }
            $bytes = [IO.File]::ReadAllBytes($datPath)
            $textU = [System.Text.Encoding]::Unicode.GetString($bytes)
            $textA = [System.Text.Encoding]::ASCII.GetString($bytes)
            $uninstSuffix = 'CurrentVersion\Uninstall\'
            $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $results = @()
            foreach ($encoding in @($textU, $textA)) {
                $m = [regex]::Matches($encoding, [regex]::Escape($uninstSuffix) + '([^\x00\x01\x02\\]+)', 'IgnoreCase')
                foreach ($mm in $m) {
                    $keyName = $mm.Groups[1].Value.Trim()
                    if ($keyName.Length -gt 1 -and $keyName.Length -lt 200 -and $seen.Add($keyName)) {
                        $results += [pscustomobject]@{
                            KeyName         = $keyName
                            DisplayName     = $keyName
                            DisplayVersion  = $null
                            Publisher       = $null
                            UninstallString = $null
                            FullPath        = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$keyName"
                        }
                    }
                }
            }
            return $results
        } finally {
            Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not (Test-Path $datPath)) {
            Write-MsixLog Info 'No Registry.dat in package.'
            return @()
        }

        $hiveName = "TempMsixHive_$([guid]::NewGuid().ToString('N').Substring(0,8))"
        $entries  = @()
        $hiveLoaded = $false
        try {
            $null = & reg.exe load "HKLM\$hiveName" "$datPath" 2>&1
            if ($LASTEXITCODE -ne 0) {
                Write-MsixLog Warning "reg.exe load failed (exit $LASTEXITCODE)."
                return @()
            }
            $hiveLoaded = $true

            foreach ($branch in @(
                "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
            )) {
                if (-not (Test-Path $branch)) { continue }
                Get-ChildItem $branch -ErrorAction SilentlyContinue | ForEach-Object {
                    $values = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                    $entries += [pscustomobject]@{
                        KeyName         = $_.PSChildName
                        DisplayName     = $values.DisplayName
                        DisplayVersion  = $values.DisplayVersion
                        Publisher       = $values.Publisher
                        UninstallString = $values.UninstallString
                        FullPath        = $_.PSPath -replace [regex]::Escape("HKLM:\$hiveName\REGISTRY\MACHINE\"), 'HKLM:\'
                    }
                }
            }
        } finally {
            # Always release the hive — even when an exception interrupted the
            # walk above. Leaving a TempMsixHive_* loaded leaks an HKLM key and
            # blocks the on-disk Registry.dat from being deleted.
            if ($hiveLoaded) {
                [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                & reg.exe unload "HKLM\$hiveName" 2>&1 | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-MsixLog Warning "Failed to unload hive 'HKLM\$hiveName' (exit $LASTEXITCODE) — may need manual: reg.exe unload HKLM\$hiveName"
                }
            }
        }
        return $entries
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


function _MsixIsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Remove-MsixUninstallerArtifact {
    <#
    .SYNOPSIS
        Strips uninstaller-looking files from inside the package AND removes
        their Uninstall\<key> registry entries from Registry.dat (the package's
        virtualized HKLM hive). Repacks + re-signs unless -SkipSigning / -NoSign.

    .PARAMETER PathPatterns
        Filename regex patterns. Defaults to a sensible uninstaller list.

    .PARAMETER UninstallKeyFilter
        Regex matched against `DisplayName` of each Uninstall subkey to decide
        whether to delete it. Default `.*` (every entry — they're all leftover
        from the original installer; MSIX doesn't use them).

    .PARAMETER KeepRegistry
        Skip the Registry.dat cleanup; only strip the .exe files.

    .PARAMETER SkipSigning / NoSign
        Don't sign the repacked .msix. -NoSign is an alias for -SkipSigning.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [string[]]$PathPatterns,
        [string]$UninstallKeyFilter = '.*',
        [switch]$KeepRegistry,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
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
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        # ── Strip files ────────────────────────────────────────────────────
        $removedFiles = @()
        Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $name = $_.Name
                ($PathPatterns | Where-Object { $name -match $_ }).Count -gt 0
            } |
            ForEach-Object {
                if ($PSCmdlet.ShouldProcess($_.FullName, 'Remove uninstaller artefact')) {
                    Remove-Item $_.FullName -Force
                    $removedFiles += $_.FullName.Substring($workspace.Length + 1)
                }
            }

        # ── Strip Registry.dat Uninstall\* entries ────────────────────────
        $removedKeys = @()
        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not $KeepRegistry -and (Test-Path $datPath)) {
            if (-not (_MsixIsAdmin)) {
                Write-MsixLog Warning 'Skipping Registry.dat cleanup (not elevated). Re-run as admin or pass -KeepRegistry.'
            } else {
                $hiveName = "TempMsixHive_$([guid]::NewGuid().ToString('N').Substring(0,8))"
                try {
                    $null = & reg.exe load "HKLM\$hiveName" "$datPath" 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Write-MsixLog Warning "reg.exe load failed (exit $LASTEXITCODE); skipping registry cleanup."
                    } else {
                        foreach ($branch in @(
                            "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                            "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                        )) {
                            if (-not (Test-Path $branch)) { continue }
                            Get-ChildItem $branch -ErrorAction SilentlyContinue | ForEach-Object {
                                $vals = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
                                $name = $vals.DisplayName
                                if (-not $name -or ($name -match $UninstallKeyFilter)) {
                                    if ($PSCmdlet.ShouldProcess($_.PSPath, "Remove Uninstall key '$name'")) {
                                        Remove-Item $_.PSPath -Recurse -Force -ErrorAction SilentlyContinue
                                        $removedKeys += $name
                                    }
                                }
                            }
                        }
                    }
                } finally {
                    [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                    Start-Sleep -Milliseconds 500
                    $null = & reg.exe unload "HKLM\$hiveName" 2>&1
                    if ($LASTEXITCODE -ne 0) {
                        Write-MsixLog Warning "reg.exe unload failed; the in-package Registry.dat may have leaked handles."
                    }
                }
            }
        }

        if (-not $removedFiles -and -not $removedKeys) {
            Write-MsixLog Info 'No uninstaller artefacts found.'
            return
        }
        if ($removedFiles) { Write-MsixLog Info "Files removed:    $($removedFiles -join ', ')" }
        if ($removedKeys)  { Write-MsixLog Info "Reg keys removed: $($removedKeys -join ', ')" }

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        if (-not $SkipSigning) {
            Invoke-MsixSigning -PackagePath $target -Pfx $Pfx -PfxPassword $PfxPassword
        }
        return [pscustomobject]@{
            FilesRemoved = $removedFiles
            KeysRemoved  = $removedKeys
            Output       = $target
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Run-keys (HKLM\Run autostart) ---------------------------------------

function Get-MsixRunKeyEntry {
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
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
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
            } catch { Write-MsixLog Debug "Run-key scan failed for $dat`: $_" }
        }
        return $hits | Sort-Object Hive,Match -Unique
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Shell context-menu entries -------------------------------------------

function _MsixAbsoluteToVfsRelativeDirect {
    <#
    .SYNOPSIS
        Translates an absolute DLL path (from Registry.dat) to a VFS-relative
        path within an already-unpacked MSIX workspace.
        Returns $null if the file cannot be mapped / does not exist in the package.
    #>
    param([string]$AbsPath, [string]$WorkspacePath)
    if (-not $AbsPath) { return $null }
    $mappings = @(
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('ProgramFiles');           Vfs = 'VFS\ProgramFilesX64' }
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('ProgramFilesX86');        Vfs = 'VFS\ProgramFiles(x86)' }
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('System');                 Vfs = 'VFS\SystemX64' }
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('Windows');                Vfs = 'VFS\Windows' }
        [pscustomobject]@{ Abs = [System.Environment]::GetFolderPath('CommonApplicationData');  Vfs = 'VFS\ProgramData' }
    )
    foreach ($m in $mappings) {
        if ($AbsPath.StartsWith($m.Abs, [System.StringComparison]::OrdinalIgnoreCase)) {
            $rel    = $AbsPath.Substring($m.Abs.Length).TrimStart('\')
            $vfsRel = "$($m.Vfs)\$rel"
            if (Test-Path (Join-Path $WorkspacePath $vfsRel)) { return $vfsRel }
        }
    }
    return $null
}


function _MsixRegPathToVfsRelative {
    <#
    .SYNOPSIS
        Translates an MSIX folder-variable DLL path (e.g. [{ProgramFilesX64}]\app\foo.dll)
        stored in Registry.dat to a VFS-relative path within an already-unpacked workspace.
        Falls through to _MsixAbsoluteToVfsRelativeDirect for plain absolute paths.
        Returns $null if the path cannot be mapped or the file is not present in the package.
    #>
    param([string]$RegPath, [string]$WorkspacePath)
    if (-not $RegPath) { return $null }

    # Folder-variable format: [{VarName}]\rest\of\path
    $varMappings = @(
        [pscustomobject]@{ Var = 'ProgramFilesX64';  Vfs = 'VFS\ProgramFilesX64' }
        [pscustomobject]@{ Var = 'ProgramFilesX86';  Vfs = 'VFS\ProgramFiles(x86)' }
        [pscustomobject]@{ Var = 'ProgramFiles6432'; Vfs = 'VFS\ProgramFilesX64' }
        [pscustomobject]@{ Var = 'System';           Vfs = 'VFS\SystemX64' }
        [pscustomobject]@{ Var = 'SystemX86';        Vfs = 'VFS\System' }
        [pscustomobject]@{ Var = 'Windows';          Vfs = 'VFS\Windows' }
        [pscustomobject]@{ Var = 'CommonAppData';    Vfs = 'VFS\ProgramData' }
        [pscustomobject]@{ Var = 'AppData';          Vfs = 'VFS\AppData\Roaming' }
        [pscustomobject]@{ Var = 'LocalAppData';     Vfs = 'VFS\AppData\Local' }
    )
    foreach ($m in $varMappings) {
        if ($RegPath -match ('^\[\{' + [regex]::Escape($m.Var) + '\}\](.*)$')) {
            $rel    = $Matches[1].TrimStart('\')
            $vfsRel = "$($m.Vfs)\$rel"
            if (Test-Path (Join-Path $WorkspacePath $vfsRel)) { return $vfsRel }
            # Return the mapping even if the file isn't present — caller can use for manifest
            return $vfsRel
        }
    }

    # Plain absolute path fallback
    return _MsixAbsoluteToVfsRelativeDirect -AbsPath $RegPath -WorkspacePath $WorkspacePath
}


function Get-MsixShellContextMenuEntry {
    <#
    .SYNOPSIS
        Scans the package's Registry.dat for shell verbs (Classes\*\shell\…) and
        shellex COM handlers (Classes\*\shellex\ContextMenuHandlers\…) that are
        invisible in File Explorer when outside the MSIX container.

    .DESCRIPTION
        When elevated, loads the hive via reg.exe and extracts full key paths,
        CLSIDs, absolute DLL paths, and package-relative VFS paths.
        Without elevation, falls back to a Unicode string scan (names only;
        no CLSIDs or command values).

        Returned objects have these properties:
          Type         'ShellVerb' or 'ShellExt'
          Target       '*', 'Directory', 'Directory\Background', …
          VerbName     (ShellVerb) the verb label, e.g. 'Open with Notepad++'
          HandlerName  (ShellExt)  handler key name, often same as display name
          Command      (ShellVerb) the command string if elevated
          Clsid        (ShellExt)  GUID string e.g. '{AAAA-...}' if elevated
          DllPath      (ShellExt)  absolute InProcServer32 path if elevated
          VfsDllPath   (ShellExt)  package-relative VFS path if DLL found in pkg

    .PARAMETER PackagePath
        .msix file to inspect.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-shellctx"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not (Test-Path $datPath)) { return @() }

        $results = [System.Collections.Generic.List[object]]::new()

        if (_MsixIsAdmin) {
            $hiveName = "TempMsixHive_$([guid]::NewGuid().ToString('N').Substring(0,8))"
            try {
                $null = & reg.exe load "HKLM\$hiveName" "$datPath" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    foreach ($target in @('\*', 'Directory', 'Directory\Background', 'AllFilesystemObjects')) {
                        $tgtClean = $target.TrimStart('\')

                        # Simple shell verbs.
                        # IMPORTANT: Use -LiteralPath everywhere — the target may be '*' which
                        # PowerShell's registry provider treats as a wildcard without -LiteralPath,
                        # causing Get-ChildItem to return the 'shell' key objects themselves
                        # (PSChildName='shell') instead of their verb children.
                        $shellPath = "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\Classes\$target\shell"
                        if (Test-Path -LiteralPath $shellPath) {
                            foreach ($verbKey in Get-ChildItem -LiteralPath $shellPath -ErrorAction SilentlyContinue) {
                                # A verb key that carries ExplorerCommandHandler is a COM-delegating verb
                                # (IExplorerCommand). It must be declared as a FileExplorerContextMenus
                                # extension (desktop4/desktop5), NOT as a uap3:SupportedVerb.
                                $verbProps = Get-ItemProperty -LiteralPath $verbKey.PSPath -ErrorAction SilentlyContinue
                                $ech = $verbProps.ExplorerCommandHandler
                                if ($ech) {
                                    # Normalise CLSID format
                                    if ($ech -notmatch '^\{') { $ech = "{$ech}" }
                                    $dll    = $null
                                    $vfsDll = $null
                                    if ($ech -match '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
                                        foreach ($clsidBranch in @(
                                            "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID\$ech\InProcServer32",
                                            "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\$ech\InProcServer32"
                                        )) {
                                            if (Test-Path -LiteralPath $clsidBranch) {
                                                $dll = (Get-ItemProperty -LiteralPath $clsidBranch -ErrorAction SilentlyContinue).'(default)'
                                                if ($dll) { break }
                                            }
                                        }
                                        if ($dll) {
                                            $vfsDll = _MsixRegPathToVfsRelative -RegPath $dll -WorkspacePath $workspace
                                        }
                                    }
                                    $results.Add([pscustomobject]@{
                                        Type        = 'ShellExt'
                                        Target      = $tgtClean
                                        HandlerName = $verbKey.PSChildName
                                        Command     = $null
                                        Clsid       = $ech
                                        DllPath     = $dll
                                        VfsDllPath  = $vfsDll
                                    })
                                } else {
                                    # Standard shell verb with a command subkey
                                    $cmdPath = Join-Path $verbKey.PSPath 'command'
                                    $cmd     = if (Test-Path -LiteralPath $cmdPath) {
                                        (Get-ItemProperty -LiteralPath $cmdPath -ErrorAction SilentlyContinue).'(default)'
                                    } else { $null }
                                    $results.Add([pscustomobject]@{
                                        Type       = 'ShellVerb'
                                        Target     = $tgtClean
                                        VerbName   = $verbKey.PSChildName
                                        Command    = $cmd
                                        Clsid      = $null
                                        DllPath    = $null
                                        VfsDllPath = $null
                                    })
                                }
                            }
                        }

                        # shellex COM context-menu handlers
                        $shPath = "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\Classes\$target\shellex\ContextMenuHandlers"
                        if (Test-Path -LiteralPath $shPath) {
                            foreach ($hKey in Get-ChildItem -LiteralPath $shPath -ErrorAction SilentlyContinue) {
                                $clsid = (Get-ItemProperty -LiteralPath $hKey.PSPath -ErrorAction SilentlyContinue).'(default)'
                                if ($clsid -and $clsid -notmatch '^\{') { $clsid = "{$clsid}" }
                                $dll    = $null
                                $vfsDll = $null
                                if ($clsid -match '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') {
                                    $ipPath = "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID\$clsid\InProcServer32"
                                    if (Test-Path -LiteralPath $ipPath) {
                                        $dll = (Get-ItemProperty -LiteralPath $ipPath -ErrorAction SilentlyContinue).'(default)'
                                    }
                                    # Also check 32-bit CLSID branch
                                    if (-not $dll) {
                                        $ip32 = "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID\$clsid\InProcServer32"
                                        if (Test-Path -LiteralPath $ip32) {
                                            $dll = (Get-ItemProperty -LiteralPath $ip32 -ErrorAction SilentlyContinue).'(default)'
                                        }
                                    }
                                    if ($dll) {
                                        $vfsDll = _MsixRegPathToVfsRelative -RegPath $dll -WorkspacePath $workspace
                                    }
                                }
                                $results.Add([pscustomobject]@{
                                    Type        = 'ShellExt'
                                    Target      = $tgtClean
                                    HandlerName = $hKey.PSChildName
                                    Command     = $null
                                    Clsid       = $clsid
                                    DllPath     = $dll
                                    VfsDllPath  = $vfsDll
                                })
                            }
                        }
                    }
                }
            } finally {
                [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                $null = & reg.exe unload "HKLM\$hiveName" 2>&1
            }
        } else {
            Write-MsixLog Warning 'Get-MsixShellContextMenuEntry: not elevated — shellex handler names detected via string scan; shell verb detection skipped (run as administrator for full results including verb names and CLSIDs).'
            $bytes = [IO.File]::ReadAllBytes($datPath)
            $text  = [System.Text.Encoding]::Unicode.GetString($bytes)

            # shellex\ContextMenuHandlers\<name>  — reliable enough without elevation
            # (the handler key name directly follows the fixed path ContextMenuHandlers\)
            foreach ($m in [regex]::Matches($text, 'Classes\\(\*|Directory(?:\\Background)?|AllFilesystemObjects)\\shellex\\ContextMenuHandlers\\([^\x00\\]{2,64})', 'IgnoreCase')) {
                $tgt  = $m.Groups[1].Value.Trim("`0")
                $name = $m.Groups[2].Value.Trim("`0")
                if ($tgt -and $name) {
                    $results.Add([pscustomobject]@{
                        Type        = 'ShellExt'
                        Target      = $tgt
                        HandlerName = $name
                        Command     = $null
                        Clsid       = $null
                        DllPath     = $null
                        VfsDllPath  = $null
                    })
                }
            }

            # Shell verb detection is intentionally skipped in non-elevated mode.
            # Registry.dat uses the REGF binary format where key names are stored
            # as individual NK records — not as contiguous full-path strings.
            # A naive regex scan matches the intermediate 'shell' key name itself,
            # producing a false-positive entry with VerbName='shell'.
            # Run as administrator to get accurate verb names via reg.exe hive load.
        }

        # Deduplicate
        $seen = @{}
        return @($results | Where-Object {
            $key = "$($_.Type)|$($_.Target)|$(if ($_.Type -eq 'ShellVerb') { $_.VerbName } else { $_.HandlerName })"
            if (-not $seen[$key]) { $seen[$key] = $true; $true } else { $false }
        })
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region COM server entries ---------------------------------------------------

function Get-MsixComServerEntry {
    <#
    .SYNOPSIS
        Scans the package's Registry.dat for COM server registrations
        (CLSID\*\InProcServer32 and CLSID\*\LocalServer32) that may need to be
        declared in the manifest via com:Extension (windows.comServer).

    .DESCRIPTION
        When elevated, loads the hive via reg.exe for full extraction: CLSIDs,
        server type, DLL path, VFS-relative path (if the DLL lives in the package),
        and ThreadingModel. Non-elevated: Unicode string scan (CLSIDs only).

        Returned objects:
          Clsid          '{XXXXXXXX-...}'
          ServerType     'InProc' | 'LocalServer' | 'Unknown'
          DllPath        absolute InProcServer32 / LocalServer32 path (elevated)
          VfsDllPath     package-relative VFS path if the DLL is in the package
          ThreadingModel e.g. 'Apartment' (InProc, elevated only)
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-comsrv"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not (Test-Path $datPath)) { return @() }

        $results = [System.Collections.Generic.List[object]]::new()

        if (_MsixIsAdmin) {
            $hiveName = "TempMsixHive_$([guid]::NewGuid().ToString('N').Substring(0,8))"
            try {
                $null = & reg.exe load "HKLM\$hiveName" "$datPath" 2>&1
                if ($LASTEXITCODE -eq 0) {
                    foreach ($branch in @(
                        "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID",
                        "HKLM:\$hiveName\REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID"
                    )) {
                        if (-not (Test-Path $branch)) { continue }
                        foreach ($clsidKey in Get-ChildItem $branch -ErrorAction SilentlyContinue) {
                            $clsid = $clsidKey.PSChildName
                            if ($clsid -notmatch '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$') { continue }

                            $ipPath = Join-Path $clsidKey.PSPath 'InProcServer32'
                            if (Test-Path $ipPath) {
                                $vals   = Get-ItemProperty $ipPath -ErrorAction SilentlyContinue
                                $dll    = $vals.'(default)'
                                $thread = $vals.ThreadingModel
                                $vfsDll = if ($dll) { _MsixAbsoluteToVfsRelativeDirect -AbsPath $dll -WorkspacePath $workspace } else { $null }
                                $results.Add([pscustomobject]@{
                                    Clsid          = $clsid
                                    ServerType     = 'InProc'
                                    DllPath        = $dll
                                    VfsDllPath     = $vfsDll
                                    ThreadingModel = if ($thread) { $thread } else { 'Apartment' }
                                })
                            }

                            $lsPath = Join-Path $clsidKey.PSPath 'LocalServer32'
                            if (Test-Path $lsPath) {
                                $cmd = (Get-ItemProperty $lsPath -ErrorAction SilentlyContinue).'(default)'
                                $results.Add([pscustomobject]@{
                                    Clsid          = $clsid
                                    ServerType     = 'LocalServer'
                                    DllPath        = $cmd
                                    VfsDllPath     = $null    # EXE, not DLL-path based
                                    ThreadingModel = $null
                                })
                            }
                        }
                    }
                }
            } finally {
                [gc]::Collect(); [gc]::WaitForPendingFinalizers()
                $null = & reg.exe unload "HKLM\$hiveName" 2>&1
            }
        } else {
            Write-MsixLog Warning 'Get-MsixComServerEntry: not elevated — CLSID string scan only (no DLL paths or threading model).'
            $bytes = [IO.File]::ReadAllBytes($datPath)
            $text  = [System.Text.Encoding]::Unicode.GetString($bytes)
            foreach ($m in [regex]::Matches($text, '\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}')) {
                $results.Add([pscustomobject]@{
                    Clsid          = $m.Value
                    ServerType     = 'Unknown'
                    DllPath        = $null
                    VfsDllPath     = $null
                    ThreadingModel = $null
                })
            }
        }

        # Deduplicate by CLSID + ServerType
        $seen = @{}
        return @($results | Where-Object {
            $key = "$($_.Clsid)|$($_.ServerType)"
            if (-not $seen[$key]) { $seen[$key] = $true; $true } else { $false }
        })
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
#endregion

#region Application execution alias auto-suggest ---------------------------

function Get-MsixAliasCandidate {
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
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
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
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )
    if (-not (Test-Path $ImagePath)) { throw "Splash image not found: $ImagePath" }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
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
        $cfg = Get-Content $cfgPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        foreach ($app in @($cfg.applications)) {
            if ($app.id -ne $AppId) { continue }
            if (-not $app.startScript) {
                $app | Add-Member -NotePropertyName startScript -NotePropertyValue ([pscustomobject]@{}) -Force
            }
            $app.startScript | Add-Member -NotePropertyName splashImage -NotePropertyValue $imageLeaf -Force
        }
        $cfg | ConvertTo-Json -Depth 15 | Set-Content $cfgPath -Encoding utf8

        $target = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
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
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $null = Test-MsixManifest "$workspace\AppxManifest.xml"
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
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
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
        against Get-MsixKnownCapability).

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
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,

        # PrePsf stage
        [switch]$RemoveUninstallers,
        [switch]$RemoveDesktopShortcuts,
        [ValidateSet('Major','Minor','Build','Revision')]
        [string]$VersionBumpComponent,

        # Recommended stage
        [string[]]$Capabilities,
        [switch]$AddFontExtension,
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
        [SecureString]$PfxPassword
    )
    $null = $PsfWorkingDirectory, $PsfAdditionalFiles  # referenced in closure

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
            Remove-MsixUninstallerArtifact -PackagePath $current -SkipSigning
        }
    }
    if ($RemoveDesktopShortcuts) {
        _Stage 'PrePsf:RemoveDesktopShortcuts' {
            Remove-MsixDesktopShortcut -PackagePath $current -SkipSigning
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
    if ($AddFontExtension) {
        _Stage 'Recommended:AddFontExtension' {
            $fonts = Get-MsixFontCandidate -PackagePath $current
            if ($fonts) {
                Add-MsixFontExtension -PackagePath $current -FontPaths @($fonts | Select-Object -ExpandProperty Path) -SkipSigning
            } else {
                Write-MsixLog Info 'AddFontExtension: no font files found in package.'
            }
        }
    }
    if ($PsfFixups -or $PsfAppOptions) {
        _Stage 'Recommended:InjectPsf' {
            $psfArgs = @{
                PackagePath = $current
                Fixups      = $PsfFixups
                SkipSigning = $true
            }
            if ($PsfAppOptions)         { $psfArgs['AppOptions']        = $PsfAppOptions }
            if ($PsfWorkingDirectory)   { $psfArgs['WorkingDirectory']  = $PsfWorkingDirectory }
            if ($PsfAdditionalFiles)    { $psfArgs['AdditionalFiles']   = $PsfAdditionalFiles }
            Add-MsixPsfV2 @psfArgs
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

    if ($PSCmdlet.ShouldProcess($current, "Apply $($stages.Count) auto-fix stages")) {
        foreach ($s in $stages) {
            Write-MsixLog Info "==> $($s.Name)"
            & $s.Action
        }
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


function Invoke-MsixAutoFixFromAnalysis {
    <#
    .SYNOPSIS
        Takes the report produced by Invoke-MsixInvestigation /
        Get-MsixCompatibilityReport and translates each finding into the
        right fixer cmdlet, then runs them sequentially with one signing
        pass at the end. The connect-the-dots layer between analysis and
        remediation.

    .DESCRIPTION
        Maps Findings.Category to a concrete cmdlet:

          UninstallerArtifact                 -> Remove-MsixUninstallerArtifact
          VcRuntime                            -> Add-MsixVcRuntimeBundle (needs -VcRuntimeSourceFolder)
          ManifestFix:FileSystemWriteVirt..    -> Set-MsixFileSystemWriteVirtualization
          ManifestFix:RegistryWriteVirt..      -> Set-MsixRegistryWriteVirtualization
          ManifestFix:StartupTask              -> Add-MsixStartupTask  (needs -StartupTaskAppId / -StartupTaskName)
          ManifestFix:LoaderSearchPathOverride -> Add-MsixLoaderSearchPathOverride (needs -LoaderPaths)
          FileRedirectionFixup                 -> Add-MsixPsfV2 with the SuggestedFixups already in the report

        Categories that always need extra inputs (VcRuntime, StartupTask,
        LoaderSearchPathOverride) are skipped with a warning unless the
        relevant -* parameter is supplied.

        -DryRun lists the planned fixes without doing anything.

    .PARAMETER Report
        Output of Invoke-MsixInvestigation or Get-MsixCompatibilityReport.

    .PARAMETER PackagePath
        Override (default: $Report.PackagePath).

    .PARAMETER PreferManifestOverPsf
        When both a PSF and a manifest fix are suggested for the same symptom,
        pick the manifest one (modern Windows builds only).
        Default: $true.

    .PARAMETER VcRuntimeSourceFolder
        VS Redist folder; required when a VcRuntime finding is in the report.

    .PARAMETER StartupTaskAppId / StartupTaskName
        Required when a ManifestFix:StartupTask finding is in the report.

    .PARAMETER LoaderPaths
        Required when a ManifestFix:LoaderSearchPathOverride finding is in the report.

    .PARAMETER DryRun
        Print the plan and return without mutating.

    .PARAMETER OutputPath / Pfx / PfxPassword / SkipSigning (alias NoSign)
        Forwarded to the underlying fixers. Signing only happens once at the end.

    .EXAMPLE
        $report = Invoke-MsixInvestigation -PackagePath app.msix
        Invoke-MsixAutoFixFromAnalysis -Report $report `
            -VcRuntimeSourceFolder 'C:\…\VC143.CRT' `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Report,
        [string]$PackagePath,
        [bool]$PreferManifestOverPsf = $true,
        [string]$VcRuntimeSourceFolder,
        [string]$StartupTaskAppId,
        [string]$StartupTaskName,
        [string[]]$LoaderPaths,
        [switch]$DryRun,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not $PackagePath) { $PackagePath = $Report.PackagePath }
    if (-not $PackagePath) { throw 'PackagePath could not be inferred from the report.' }

    # Categorise the findings into a stable plan
    $plan = New-Object System.Collections.Generic.List[object]

    $byCat = @{}
    foreach ($f in @($Report.Findings)) {
        if ($f -and $f.Category) { $byCat[$f.Category] = $true }
    }

    # Stage 1 — strip uninstaller artefacts (files + registry)
    if ($byCat.ContainsKey('UninstallerArtifact') -or $byCat.ContainsKey('UninstallRegistry')) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RemoveUninstallers'
            Reason = 'Findings include uninstaller-looking files and/or leftover Uninstall registry keys'
            Action = { Remove-MsixUninstallerArtifact -PackagePath $current -SkipSigning }
        })
    }

    # Stage 2 — manifest-only virtualization (preferred over PSF when matching)
    $hasFsManifestFix  = $byCat.ContainsKey('ManifestFix:FileSystemWriteVirtualization')
    $hasRegManifestFix = $byCat.ContainsKey('ManifestFix:RegistryWriteVirtualization')
    $hasStartupFix     = $byCat.ContainsKey('ManifestFix:StartupTask')
    $hasLoaderFix      = $byCat.ContainsKey('ManifestFix:LoaderSearchPathOverride')

    if ($hasFsManifestFix -and $PreferManifestOverPsf) {
        $plan.Add([pscustomobject]@{
            Stage  = 'FileSystemWriteVirtualization'
            Reason = 'Package writes to install dir; manifest fix is simpler than PSF'
            Action = { Set-MsixFileSystemWriteVirtualization -PackagePath $current -SkipSigning }
        })
    }
    if ($hasRegManifestFix -and $PreferManifestOverPsf) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RegistryWriteVirtualization'
            Reason = 'Package writes to HKLM; manifest fix is simpler than RegLegacy Hklm2Hkcu'
            Action = { Set-MsixRegistryWriteVirtualization -PackagePath $current -SkipSigning }
        })
    }
    if ($hasStartupFix) {
        if ($StartupTaskAppId -and $StartupTaskName) {
            $plan.Add([pscustomobject]@{
                Stage  = 'StartupTask'
                Reason = 'Replace HKLM\Run autostart with windows.startupTask'
                Action = {
                    Add-MsixStartupTask -PackagePath $current `
                        -AppId $StartupTaskAppId -TaskId "$StartupTaskAppId-AutoStart" `
                        -DisplayName $StartupTaskName -Enabled $true -SkipSigning
                }
            })
        } else {
            Write-MsixLog Warning 'Skipping StartupTask: -StartupTaskAppId and -StartupTaskName are required.'
        }
    }
    if ($hasLoaderFix) {
        if ($LoaderPaths) {
            $plan.Add([pscustomobject]@{
                Stage  = 'LoaderSearchPathOverride'
                Reason = 'Replace DLL load failures with manifest declaration'
                Action = { Add-MsixLoaderSearchPathOverride -PackagePath $current -Paths $LoaderPaths -SkipSigning }
            })
        } else {
            Write-MsixLog Warning 'Skipping LoaderSearchPathOverride: -LoaderPaths is required.'
        }
    }

    # Stage 2b — remove desktop shortcuts
    if ($byCat.ContainsKey('DesktopShortcuts')) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RemoveDesktopShortcuts'
            Reason = 'Package ships .lnk files under VFS desktop folders'
            Action = { Remove-MsixDesktopShortcut -PackagePath $current -SkipSigning }
        })
    }

    # Stage 2c — register fonts via uap4:SharedFonts
    if ($byCat.ContainsKey('ManifestFix:SharedFonts')) {
        $plan.Add([pscustomobject]@{
            Stage  = 'AddFontExtension'
            Reason = 'Package ships font files not registered via uap4:SharedFonts'
            Action = {
                $fonts = Get-MsixFontCandidate -PackagePath $current
                if ($fonts) {
                    $fontPaths = @($fonts | Select-Object -ExpandProperty Path)
                    Add-MsixFontExtension -PackagePath $current -FontPaths $fontPaths -SkipSigning
                }
            }
        })
    }

    # Stage 2d — add capability hints
    $capHintFindings = @($Report.Findings | Where-Object Category -eq 'CapabilityHints')
    if ($capHintFindings) {
        $capHintNames = @($capHintFindings.Evidence -split ',\s*' | Where-Object { $_ } | Sort-Object -Unique)
        if ($capHintNames) {
            $plan.Add([pscustomobject]@{
                Stage  = 'AddCapabilityHints'
                Reason = "PE-import hints suggest capabilities: $($capHintNames -join ', ')"
                Action = { Add-MsixCapability -PackagePath $current -Names $capHintNames -SkipSigning }
            })
        }
    }

    # Stage 2e — plain command-based shell verbs (HKCR\*\shell\<verb>\command)
    # These verbs have no CLSID, so desktop9:fileExplorerClassicContextMenuHandler
    # cannot be applied directly. The correct fix is to wrap the command as a COM
    # surrogate server (IContextMenu), register it via Add-MsixLegacyContextMenu, and
    # update the CLSID references in Registry.dat — a manual operation.
    # ExplorerCommandHandler verbs (which DO have a CLSID) are already classified as
    # ShellExt during detection and handled by stage 2g below.
    if ($byCat.ContainsKey('ShellVerb')) {
        $shellVerbFinding = @($Report.Findings | Where-Object Category -eq 'ShellVerb') | Select-Object -First 1
        $verbNames = ($shellVerbFinding.ShellEntries | ForEach-Object { $_.VerbName } | Where-Object { $_ }) -join ', '
        Write-MsixLog Info "ShellVerb: $($shellVerbFinding.ShellEntries.Count) plain command shell verb(s) detected ($verbNames). Cannot be auto-fixed — desktop9:fileExplorerClassicContextMenuHandler requires a COM CLSID. Convert to a COM surrogate server and use Add-MsixLegacyContextMenu."
    }

    # Stage 2g — COM shellex context menu (desktop9 surrogate-server pattern)
    if ($byCat.ContainsKey('ShellExt')) {
        $shellExtFinding = @($Report.Findings | Where-Object Category -eq 'ShellExt') | Select-Object -First 1
        $autoFixable     = @($shellExtFinding.ShellEntries | Where-Object { $_.Clsid -and $_.VfsDllPath })
        if ($autoFixable) {
            $capturedShellEntries = $autoFixable   # capture for closure
            $plan.Add([pscustomobject]@{
                Stage  = 'AddLegacyContextMenu'
                Reason = "Register $($capturedShellEntries.Count) shellex COM handler(s) via desktop9 surrogate-server"
                Action = {
                    foreach ($entry in $capturedShellEntries) {
                        $ft = @(if ($entry.Target -eq '*') { '*' } else { $entry.Target })
                        Add-MsixLegacyContextMenu -PackagePath $current `
                            -ShellExtDll $entry.VfsDllPath `
                            -Clsid $entry.Clsid `
                            -DisplayName $entry.HandlerName `
                            -FileTypes $ft `
                            -SkipSigning
                    }
                }
            })
        } else {
            Write-MsixLog Info "ShellExt: CLSID/VFS DLL path not resolved — run elevated for full detection, then call Add-MsixLegacyContextMenu manually."
        }
    }

    # Stage 2h — COM InProcessServer declaration (com:Extension, windows.comServer)
    if ($byCat.ContainsKey('ComServer')) {
        $comFinding = @($Report.Findings | Where-Object Category -eq 'ComServer') | Select-Object -First 1
        # Entries that have a VFS DLL path (package-bundled, auto-fixable)
        # and are not already handled by the ShellExt stage (SurrogateServer)
        $shellExtClsids = @()
        if ($byCat.ContainsKey('ShellExt')) {
            $seF = @($Report.Findings | Where-Object Category -eq 'ShellExt') | Select-Object -First 1
            $shellExtClsids = @($seF.ShellEntries.Clsid | Where-Object { $_ })
        }
        $autoComServers = @($comFinding.ComEntries | Where-Object {
            $_.VfsDllPath -and $_.Clsid -notin $shellExtClsids
        })
        if ($autoComServers) {
            $capturedComServers = $autoComServers
            $plan.Add([pscustomobject]@{
                Stage  = 'AddComServer'
                Reason = "Declare $($capturedComServers.Count) bundled COM InProcessServer(s) in the manifest"
                Action = {
                    $serverSpecs = @($capturedComServers | ForEach-Object {
                        @{ Clsid = $_.Clsid; VfsDllPath = $_.VfsDllPath; ThreadingModel = $_.ThreadingModel }
                    })
                    Add-MsixComServerExtension -PackagePath $current -Servers $serverSpecs -SkipSigning
                }
            })
        } else {
            Write-MsixLog Info "ComServer: no auto-fixable InProc servers (run elevated for DLL path resolution)."
        }
    }

    # Stage 3 — VC runtime bundle
    if ($byCat.ContainsKey('VcRuntime')) {
        if ($VcRuntimeSourceFolder) {
            $plan.Add([pscustomobject]@{
                Stage  = 'BundleVcRuntimes'
                Reason = 'Package references VC runtime DLLs that are not bundled'
                Action = { Add-MsixVcRuntimeBundle -PackagePath $current -SourceFolder $VcRuntimeSourceFolder -SkipSigning }
            })
        } else {
            Write-MsixLog Warning 'Skipping VcRuntime bundle: -VcRuntimeSourceFolder is required.'
        }
    }

    # Stage 4 — PSF fixups (only those NOT already covered by a manifest fix)
    if ($Report.SuggestedFixups -and $Report.SuggestedFixups.Count -gt 0) {
        $skipPsfFs  = $hasFsManifestFix  -and $PreferManifestOverPsf
        $skipPsfReg = $hasRegManifestFix -and $PreferManifestOverPsf
        $kept = @($Report.SuggestedFixups | Where-Object {
            -not (
                ($skipPsfFs  -and $_.dll -in 'FileRedirectionFixup.dll','MFRFixup.dll') -or
                ($skipPsfReg -and $_.dll -eq 'RegLegacyFixups.dll')
            )
        })
        if ($kept.Count -gt 0) {
            $plan.Add([pscustomobject]@{
                Stage  = 'InjectPsf'
                Reason = "Apply $($kept.Count) PSF fixup(s) from analysis"
                Action = { Add-MsixPsfV2 -PackagePath $current -Fixups $kept -SkipSigning }
            })
        }
    }

    if (-not $plan -or -not $plan.Count) {
        Write-MsixLog Info 'Nothing actionable in the report. Either no findings or all need manual parameters.'
        return [pscustomobject]@{
            PackagePath = $PackagePath
            Plan        = @()
            DryRun      = [bool]$DryRun
        }
    }

    # Emit the plan
    Write-MsixLog Info '─── AutoFix plan ───'
    foreach ($p in $plan) {
        Write-MsixLog Info "  $($p.Stage)  ($($p.Reason))"
    }

    if ($DryRun) {
        return [pscustomobject]@{
            PackagePath = $PackagePath
            Plan        = $plan
            DryRun      = $true
        }
    }

    # Stage execution — write to OutputPath if asked, otherwise overwrite in-place
    $current = $PackagePath
    if ($OutputPath -and ($OutputPath -ne $PackagePath)) {
        Copy-Item $PackagePath $OutputPath -Force
        $current = $OutputPath
    }

    foreach ($p in $plan) {
        Write-MsixLog Info "==> $($p.Stage)"
        & $p.Action
    }

    if (-not $SkipSigning) {
        Write-MsixLog Info '==> Sign'
        Invoke-MsixSigning -PackagePath $current -Pfx $Pfx -PfxPassword $PfxPassword
    } else {
        Write-MsixLog Info 'NoSign requested; package left unsigned.'
    }

    return [pscustomobject]@{
        PackagePath = $current
        Plan        = $plan
        DryRun      = $false
    }
}
#endregion

#region Static analysis adapter --------------------------------------------

function Get-MsixHeuristicFinding {
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
    foreach ($u in Get-MsixUninstallerCandidate -PackagePath $PackagePath) {
        $out.Add([pscustomobject]@{
            Severity = 'Warning'
            Category = 'UninstallerArtifact'
            Symptom  = "Looks like a leftover installer artefact: $($u.Name)"
            Recommendation = "Remove-MsixUninstallerArtifact -PackagePath '$PackagePath'"
            Evidence = $u.Path
            AppId    = $null
        })
    }

    # Run keys
    foreach ($r in Get-MsixRunKeyEntry -PackagePath $PackagePath) {
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
    foreach ($a in Get-MsixAliasCandidate -PackagePath $PackagePath) {
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
        $vc = Get-MsixVcRuntimeReference -PackagePath $PackagePath
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
    } catch { Write-MsixLog Debug "VC runtime heuristic skipped: $_" }

    # ── Fonts inside the package (suggest uap4:SharedFonts) ────────────────
    try {
        $fonts = Get-MsixFontCandidate -PackagePath $PackagePath
        if ($fonts) {
            $out.Add([pscustomobject]@{
                Severity = 'Info'
                Category = 'ManifestFix:SharedFonts'
                Symptom  = "Package ships $($fonts.Count) font file(s) but doesn't register them via uap4:SharedFonts."
                Recommendation = "Add-MsixFontExtension -PackagePath '$PackagePath' -FontPaths (Get-MsixFontCandidate -PackagePath '$PackagePath' | Select-Object -ExpandProperty Path)"
                Evidence = ($fonts | Select-Object -First 5 -ExpandProperty Name) -join ', '
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Font heuristic skipped: $_" }

    # ── Desktop shortcuts inside the package (suggest removal) ──────────────
    try {
        $sc = Get-MsixDesktopShortcutCandidate -PackagePath $PackagePath
        if ($sc) {
            $out.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'DesktopShortcuts'
                Symptom  = "Package ships $($sc.Count) .lnk file(s) under VFS\Common Desktop / VFS\Desktop."
                Recommendation = "Remove-MsixDesktopShortcut -PackagePath '$PackagePath'"
                Evidence = ($sc | Select-Object -First 3 -ExpandProperty Name) -join ', '
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Desktop shortcut heuristic skipped: $_" }

    # ── Capability hints from PE imports (suggest Add-MsixCapability) ───────
    try {
        $caps = Get-MsixCapabilityHint -PackagePath $PackagePath
        if ($caps) {
            $out.Add([pscustomobject]@{
                Severity = 'Info'
                Category = 'CapabilityHints'
                Symptom  = "PE imports suggest the app may need: $($caps -join ', ')"
                Recommendation = "Add-MsixCapability -PackagePath '$PackagePath' -Names $($caps -join ',')  (validate with Application Capability Profiler first)"
                Evidence = $caps -join ', '
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Capability hints heuristic skipped: $_" }

    # ── Uninstall registry leftovers ────────────────────────────────────────
    try {
        $uninst = Get-MsixUninstallRegistryEntry -PackagePath $PackagePath
        if ($uninst) {
            $out.Add([pscustomobject]@{
                Severity = 'Warning'
                Category = 'UninstallRegistry'
                Symptom  = "Package's Registry.dat has $($uninst.Count) Uninstall\* leftover key(s)."
                Recommendation = "Remove-MsixUninstallerArtifact -PackagePath '$PackagePath'  (run elevated to also strip the registry entries)"
                Evidence = ($uninst | Select-Object -First 3 -ExpandProperty DisplayName) -join ', '
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Uninstall registry heuristic skipped: $_" }

    # ── Shell context-menu entries invisible outside the MSIX container ───────
    try {
        $shellMenus    = Get-MsixShellContextMenuEntry -PackagePath $PackagePath
        $verbEntries   = @($shellMenus | Where-Object Type -eq 'ShellVerb')
        $shellextEntries = @($shellMenus | Where-Object Type -eq 'ShellExt')

        if ($verbEntries) {
            $out.Add([pscustomobject]@{
                Severity       = 'Warning'
                Category       = 'ShellVerb'
                Symptom        = "Registry.dat declares $($verbEntries.Count) shell verb(s) ($($verbEntries.VerbName -join ', ')) that are invisible in File Explorer outside the MSIX container."
                Recommendation = "Plain command shell verbs require a COM surrogate to surface in File Explorer under MSIX. Convert the command to a COM in-process server, then call: Add-MsixLegacyContextMenu -PackagePath '$PackagePath' -ShellExtDll <VFS-dll> -Clsid <new-guid> -DisplayName '<verb>' -FileTypes '*'  (desktop9:fileExplorerClassicContextMenuHandler). Note: Add-MsixShellVerbExtension generates uap3:SupportedVerbs which is for Open-With file-type associations, NOT for context menu entries."
                Evidence       = ($verbEntries | ForEach-Object { "$($_.Target)\shell\$($_.VerbName)" }) -join '; '
                AppId          = $null
                ShellEntries   = $verbEntries
            })
        }

        if ($shellextEntries) {
            $out.Add([pscustomobject]@{
                Severity       = 'Error'
                Category       = 'ShellExt'
                Symptom        = "Registry.dat declares $($shellextEntries.Count) in-process shell handler(s) ($($shellextEntries.HandlerName -join ', ')) that will not load under MSIX. Includes both shellex\ContextMenuHandlers and shell verb keys with ExplorerCommandHandler (COM-delegating verbs)."
                Recommendation = "Add-MsixLegacyContextMenu -PackagePath '$PackagePath' -ShellExtDll <VFS-relative-dll> -Clsid <clsid> -DisplayName <name>  (Win11 21H2+: desktop9:fileExplorerClassicContextMenuHandler + com:SurrogateServer)"
                Evidence       = ($shellextEntries | ForEach-Object {
                    $regPath = if ($_.Clsid -and ($_.DllPath -or $_.VfsDllPath)) {
                        # ExplorerCommandHandler verb or shellex entry with resolved CLSID
                        "$($_.Target)\shell\$($_.HandlerName) [ExplorerCommandHandler=$($_.Clsid)]$(if ($_.VfsDllPath) { " -> $($_.VfsDllPath)" })"
                    } else {
                        "$($_.Target)\shellex\ContextMenuHandlers\$($_.HandlerName)$(if ($_.Clsid) { " [$($_.Clsid)]" })"
                    }
                    $regPath
                }) -join '; '
                AppId          = $null
                ShellEntries   = $shellextEntries
            })
        }
    } catch {
        Write-MsixLog Debug "Shell context-menu heuristic failed: $_"
    }

    # ── COM server registrations in Registry.dat ──────────────────────────────
    try {
        $comEntries = Get-MsixComServerEntry -PackagePath $PackagePath
        # Only surface InProc servers with a resolvable VFS DLL (package-bundled);
        # LocalServer and Unknown-type entries can't be auto-fixed and produce noise.
        $inprocPkg  = @($comEntries | Where-Object { $_.ServerType -eq 'InProc' -and $_.VfsDllPath })
        if ($inprocPkg) {
            $out.Add([pscustomobject]@{
                Severity       = 'Info'
                Category       = 'ComServer'
                Symptom        = "Registry.dat registers $($inprocPkg.Count) in-process COM server(s) with DLLs inside the package. External COM clients cannot activate them without a com:Extension declaration in the manifest."
                Recommendation = "Add-MsixComServerExtension -PackagePath '$PackagePath' -Servers @($($inprocPkg | ForEach-Object { "@{ Clsid='$($_.Clsid)'; VfsDllPath='$($_.VfsDllPath)'; ThreadingModel='$($_.ThreadingModel)' }" } | Select-Object -First 2 | Join-String -Separator ', '))"
                Evidence       = ($inprocPkg | ForEach-Object { "$($_.Clsid) → $($_.VfsDllPath)" }) -join '; '
                AppId          = $null
                ComEntries     = $inprocPkg
            })
        }
    } catch {
        Write-MsixLog Debug "COM server heuristic failed: $_"
    }

    # ── Nested installer packages inside the package ─────────────────────────
    try {
        $nested = @(Get-MsixNestedPackageCandidate -PackagePath $PackagePath)
        if ($nested) {
            $out.Add([pscustomobject]@{
                Severity       = 'Warning'
                Category       = 'NestedPackage'
                Symptom        = "Package contains $($nested.Count) nested installer package(s) that cannot be installed from within the MSIX container."
                Recommendation = 'Remove these files and deploy the nested packages separately (Intune / SCCM staging, or a startScript wrapper that calls winget / msiexec on a staged copy).'
                Evidence       = ($nested | Select-Object -First 3 -ExpandProperty Name) -join ', '
                AppId          = $null
            })
        }
    } catch {
        Write-MsixLog Debug "Nested package heuristic failed: $_"
    }

    # ── Manifest-level findings (alternatives to PSF) ───────────────────────
    try {
        $toolsRoot = Get-MsixToolsRoot
        $fileinfo  = Get-Item $PackagePath
        $tmp = New-MsixWorkspace "$($fileinfo.BaseName)-mfheur"
        try {
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $tmp, '/o')
            if ($r.ExitCode -eq 0) {
                [xml]$mf = Get-MsixManifest "$tmp\AppxManifest.xml"
                $exts    = @($mf.Package.Extensions.Extension)
                $appExts = @($mf.Package.Applications.Application.Extensions.Extension)

                # FileSystem/RegistryWriteVirtualization live in <Properties> (desktop6 namespace),
                # NOT in <Extensions>. Check for the flag element by local name + namespace-uri.
                $d6Uri      = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/6'
                $hasFsVirt  = [bool]($mf.Package.Properties.SelectSingleNode(
                    "*[local-name()='FileSystemWriteVirtualization' and namespace-uri()='$d6Uri']"))
                $hasRegVirt = [bool]($mf.Package.Properties.SelectSingleNode(
                    "*[local-name()='RegistryWriteVirtualization' and namespace-uri()='$d6Uri']"))
                $hasInstVirt = ($exts.Category -contains 'windows.installedLocationVirtualization')
                # LoaderSearchPathOverride can be at Package-level OR Application-level
                # (the function was moved to Application-level; check both for idempotency).
                $hasLoaderOv = $false
                foreach ($e in (@($exts) + @($appExts))) {
                    if ($e.SelectSingleNode('*[local-name()="LoaderSearchPathOverride"]')) {
                        $hasLoaderOv = $true; break
                    }
                }

                # If we already detected write-permission risk via static or
                # trace findings AND the package isn't using the manifest fix,
                # surface that as a more lightweight alternative to PSF.
                $needsWriteFix = $out | Where-Object Category -in 'FileRedirectionFixup','UninstallerArtifact'
                if ($needsWriteFix -and -not $hasFsVirt -and -not $hasInstVirt) {
                    $out.Add([pscustomobject]@{
                        Severity = 'Info'
                        Category = 'ManifestFix:FileSystemWriteVirtualization'
                        Symptom  = 'Package writes to its install location but no manifest virtualization extension is set.'
                        Recommendation = "Set-MsixFileSystemWriteVirtualization -PackagePath '$PackagePath'  (Win10 19041+; alternative to PSF FileRedirectionFixup for the broad case)"
                        Evidence = 'No desktop6:FileSystemWriteVirtualization in <Properties>'
                        AppId    = $null
                    })
                }

                $needsRegFix = $out | Where-Object Category -eq 'RegLegacyFixups'
                if ($needsRegFix -and -not $hasRegVirt) {
                    $out.Add([pscustomobject]@{
                        Severity = 'Info'
                        Category = 'ManifestFix:RegistryWriteVirtualization'
                        Symptom  = 'Package writes to HKLM but no manifest registry virtualization is set.'
                        Recommendation = "Set-MsixRegistryWriteVirtualization -PackagePath '$PackagePath'  (Win10 19041+; alternative to RegLegacy Hklm2Hkcu)"
                        Evidence = 'No desktop6:RegistryWriteVirtualization in <Properties>'
                        AppId    = $null
                    })
                }

                # HKLM Run keys but no startupTask extension
                $hasStartupTask = $false
                foreach ($e in $appExts) {
                    if ($e.Category -eq 'windows.startupTask') { $hasStartupTask = $true; break }
                }
                $hasRunKeys = $out | Where-Object Category -eq 'RunKey'
                if ($hasRunKeys -and -not $hasStartupTask) {
                    $out.Add([pscustomobject]@{
                        Severity = 'Info'
                        Category = 'ManifestFix:StartupTask'
                        Symptom  = 'Package contains autostart Run keys but declares no windows.startupTask.'
                        Recommendation = "Add-MsixStartupTask -PackagePath '$PackagePath' -AppId <app> -TaskId <id> -DisplayName <name>"
                        Evidence = 'Run-key entries in Registry.dat / User.dat'
                        AppId    = $null
                    })
                }

                # DLL load failures suggest LoaderSearchPathOverride
                $dllFindings = $out | Where-Object Category -eq 'DynamicLibraryFixup'
                if ($dllFindings -and -not $hasLoaderOv) {
                    $out.Add([pscustomobject]@{
                        Severity = 'Info'
                        Category = 'ManifestFix:LoaderSearchPathOverride'
                        Symptom  = 'DLL load failures reported but no uap6:LoaderSearchPathOverride is set.'
                        Recommendation = "Add-MsixLoaderSearchPathOverride -PackagePath '$PackagePath' -Paths 'VFS/ProgramFilesX64/<App>/lib'  (manifest alternative to DynamicLibraryFixup)"
                        Evidence = 'LoadLibrary failure(s) in trace output'
                        AppId    = $null
                    })
                }

                # Suppress ShellExt finding if the manifest already declares desktop9 COM handlers.
                # desktop9 extensions are at Application-level ($appExts); check both levels for safety.
                $hasLegacyCtxMenu = (@($exts) + @($appExts)) | Where-Object {
                    $_.Category -in @('windows.fileExplorerClassicContextMenuHandler','windows.fileExplorerClassicDragDropContextMenuHandler')
                }
                if ($hasLegacyCtxMenu) {
                    $toRemove = @($out | Where-Object Category -eq 'ShellExt')
                    foreach ($rem in $toRemove) { [void]$out.Remove($rem) }
                }

                # Suppress ShellVerb finding if the manifest already declares FTA or IExplorerCommand menus
                $hasFta            = $appExts | Where-Object { $_.Category -eq 'windows.fileTypeAssociation' }
                $hasModernCtxMenu  = $appExts | Where-Object { $_.Category -eq 'windows.fileExplorerContextMenus' }
                if ($hasFta -or $hasModernCtxMenu) {
                    $toRemove = @($out | Where-Object Category -eq 'ShellVerb')
                    foreach ($rem in $toRemove) { [void]$out.Remove($rem) }
                }

                # Suppress ComServer finding if all CLSIDs are already declared in the manifest
                $comFinding = @($out | Where-Object Category -eq 'ComServer')
                if ($comFinding) {
                    $declaredClsids = @($mf.SelectNodes("//*[local-name()='Class']/@Id") | ForEach-Object { $_.Value })
                    $stillMissing   = @($comFinding[0].ComEntries | Where-Object { $_.Clsid -notin $declaredClsids })
                    if (-not $stillMissing) {
                        [void]$out.Remove($comFinding[0])
                    } elseif ($stillMissing.Count -lt $comFinding[0].ComEntries.Count) {
                        # Partial: update the finding to only the missing ones
                        $comFinding[0].ComEntries = $stillMissing
                    }
                }
            }
        } finally {
            Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Write-MsixLog Debug "Manifest-fix heuristic failed: $_"
    }

    return $out
}
#endregion


# Backward-compatible plural aliases
Set-Alias Get-MsixKnownCapabilities Get-MsixKnownCapability
Set-Alias Get-MsixUninstallerCandidates Get-MsixUninstallerCandidate
Set-Alias Get-MsixUninstallRegistryEntries Get-MsixUninstallRegistryEntry
Set-Alias Remove-MsixUninstallerArtifacts Remove-MsixUninstallerArtifact
Set-Alias Get-MsixRunKeyEntries Get-MsixRunKeyEntry
Set-Alias Get-MsixShellContextMenuEntries Get-MsixShellContextMenuEntry
Set-Alias Get-MsixComServerEntries Get-MsixComServerEntry
Set-Alias Get-MsixAliasCandidates Get-MsixAliasCandidate
Set-Alias Get-MsixHeuristicFindings Get-MsixHeuristicFinding
