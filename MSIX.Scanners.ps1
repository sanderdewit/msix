# =============================================================================
# MSIX scanners (split from MSIX.Heuristics.ps1 in issue #38)
# -----------------------------------------------------------------------------
# Read-only inspectors that produce findings -- Get-Msix*Candidate / *Entry /
# *Hint / HeuristicFinding. None of these mutate the package.
# Mutator counterparts live in MSIX.PackageMutators.ps1; the auto-fix
# orchestrators in MSIX.AutoFix.ps1.
# =============================================================================


# ---------------------------------------------------------------------------
# Uninstaller / updater / desktop-shortcut scanners
# ---------------------------------------------------------------------------

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

        Detection-only — pair with Remove-MsixUninstallerArtifact to strip
        the matched files and the matching Uninstall\* registry leftovers.
        Feeds the `UninstallerArtifact` finding in Get-MsixHeuristicFinding.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # List uninstaller leftovers, then remove them in a follow-up call
        Get-MsixUninstallerCandidate -PackagePath app.msix
        Remove-MsixUninstallerArtifact -PackagePath app.msix -SkipSigning

    .OUTPUTS
        [pscustomobject] one per match: Name, Path (package-relative), SizeBytes.
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


function Get-MsixUpdaterCandidate {
    <#
    .SYNOPSIS
        Lists files inside the package that look like auto-updater binaries or
        scheduled-task artefacts. Auto-updaters typically fail (or worse,
        damage the install) inside the MSIX container and should be removed
        before publishing.

    .DESCRIPTION
        Pattern matches against well-known auto-updater filename shapes
        (Updater.exe, *UpdateSvc*.exe, *Sparkle*.dll, *Squirrel*.exe,
        GoogleUpdate*.exe, MicrosoftEdgeUpdate*.exe, omaha*.exe,
        *AutoUpdater*.exe, *MaintenanceService*.exe) and flags any *.xml
        shipped under a Tasks\ or VFS\Windows\Tasks\ folder as scheduled-task
        artefacts.

        Detection-only — pair with Remove-MsixUpdaterArtifact to strip the
        matched files. Feeds the `UpdaterArtifact` finding in
        Get-MsixHeuristicFinding.

        False-positive guard: filenames also matching PSF helpers, MSVC /
        UCRT redistributables, or the MSIX runtime itself are skipped.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # List updater leftovers, then remove them in a follow-up call
        Get-MsixUpdaterCandidate -PackagePath app.msix
        Remove-MsixUpdaterArtifact -PackagePath app.msix -SkipSigning

    .OUTPUTS
        [pscustomobject] one per match: RelativePath, LeafName, Kind
        ('Binary' or 'ScheduledTask'), Reason.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackagePath)

    $patterns = @(
        '^.*updater?\.exe$',
        '^.*updatesvc.*\.exe$',
        '^.*sparkle.*\.(dll|exe)$',
        '^.*squirrel.*\.exe$',
        '^GoogleUpdate.*\.exe$',
        '^MicrosoftEdgeUpdate.*\.exe$',
        '^omaha.*\.exe$',
        '^.*autoupdater?.*\.exe$',
        '^.*maintenanceservice.*\.exe$',
        '^.*winsparkle.*\.(dll|exe)$'
    )
    $excludePatterns = @('^psf', '^msvc', '^vcruntime', '^api-ms-win-', '^msix')

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-upd"
    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Get-ChildItem $workspace -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                $leaf = $_.Name
                $rel  = $_.FullName.Substring($workspace.Length + 1)

                # False-positive guard
                $skip = $false
                foreach ($ex in $excludePatterns) {
                    if ($leaf -match $ex) { $skip = $true; break }
                }
                if ($skip) { return }

                # Binary signal
                $matched = $null
                foreach ($p in $patterns) {
                    if ($leaf -match $p) { $matched = $p; break }
                }
                if ($matched) {
                    [pscustomobject]@{
                        RelativePath = $rel
                        LeafName     = $leaf
                        Kind         = 'Binary'
                        Reason       = "Matches updater binary pattern: $matched"
                    }
                    return
                }

                # Scheduled-task XML signal
                if ($leaf -match '\.xml$') {
                    $relLower = $rel.ToLowerInvariant()
                    if ($relLower -match '(^|\\)tasks\\' -or $relLower -match '\\vfs\\windows\\tasks\\') {
                        [pscustomobject]@{
                            RelativePath = $rel
                            LeafName     = $leaf
                            Kind         = 'ScheduledTask'
                            Reason       = 'Scheduled task XML under Tasks/'
                        }
                    }
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
        Parses Registry.dat in-memory via offreg.dll (Offline Registry API).
        Walks SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall and the
        WOW6432Node equivalent, captures DisplayName / DisplayVersion /
        Publisher / UninstallString for each entry.

        Works WITHOUT elevation. The original implementation used reg.exe load
        which requires SeBackupPrivilege + SeRestorePrivilege regardless of
        mount point (HKLM, HKU, HKCU). offreg.dll parses the hive from disk
        without mounting it into the live registry, so no privileges are needed.

    .PARAMETER PackagePath
        .msix file (read-only).

    .EXAMPLE
        # Surface leftover uninstall registry entries (no elevation required)
        Get-MsixUninstallRegistryEntry -PackagePath app.msix |
            Select-Object DisplayName, Publisher, UninstallString

    .OUTPUTS
        [pscustomobject[]] each with KeyName, DisplayName, DisplayVersion,
        Publisher, UninstallString, FullPath. Returns an empty array when
        Registry.dat has no Uninstall\* subkeys.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory)][string]$PackagePath)

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace "$($fileinfo.BaseName)-uninreg"

    try {
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $datPath = Join-Path $workspace 'Registry.dat'
        if (-not (Test-Path $datPath)) {
            Write-MsixLog Info 'No Registry.dat in package.'
            return @()
        }

        $hive = _MsixOpenOfflineHive -Path $datPath
        try {
            $entries = [System.Collections.Generic.List[object]]::new()
            foreach ($branch in @(
                'REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                'REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
            )) {
                $branchKey = _MsixOfflineOpenKey -Parent $hive -SubKey $branch
                if ($branchKey -eq [IntPtr]::Zero) { continue }
                try {
                    foreach ($child in (_MsixOfflineEnumSubKeys -Key $branchKey)) {
                        $entries.Add([pscustomobject]@{
                            KeyName         = $child
                            DisplayName     = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$child" -Name 'DisplayName'
                            DisplayVersion  = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$child" -Name 'DisplayVersion'
                            Publisher       = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$child" -Name 'Publisher'
                            UninstallString = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$child" -Name 'UninstallString'
                            FullPath        = "HKLM:\$($branch -replace 'REGISTRY\\MACHINE\\', '')\$child"
                        })
                    }
                } finally {
                    _MsixOfflineCloseKey -Key $branchKey
                }
            }
            return $entries.ToArray()
        } finally {
            _MsixCloseOfflineHive -Hive $hive
        }
    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


#region Run-keys (HKLM\Run autostart) ---------------------------------------

function Get-MsixRunKeyEntry {
    <#
    .SYNOPSIS
        Lists the HKLM/HKCU \…\Run\* entries declared by the package — usually
        baked in by the original installer. These don't fire under MSIX and
        admins typically remove them or replace with a startScript.

    .DESCRIPTION
        Inspects User.dat and Registry.dat hives shipped in VFS\… for
        Software\Microsoft\Windows\CurrentVersion\Run\* values via a Unicode
        string scan (best effort — works without elevation). Feeds the
        `RunKey` finding in Get-MsixHeuristicFinding, which in turn drives the
        `ManifestFix:StartupTask` recommendation when the package has no
        windows.startupTask extension declared.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # Find Run-key autostart leftovers
        Get-MsixRunKeyEntry -PackagePath app.msix

    .OUTPUTS
        [pscustomobject[]] each with Hive ('Registry.dat' or 'User.dat') and
        Match (the matched Run-key path).
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
        Loads Registry.dat via reg.exe into a temporary HKCU hive (no
        elevation required) and extracts full key paths, CLSIDs, absolute
        DLL paths, and package-relative VFS paths.

        Returned objects have these properties:
          Type         'ShellVerb' or 'ShellExt'
          Target       '*', 'Directory', 'Directory\Background', …
          VerbName     (ShellVerb) the verb label, e.g. 'Open with Notepad++'
          HandlerName  (ShellExt)  handler key name, often same as display name
          Command      (ShellVerb) the command string
          Clsid        (ShellExt)  GUID string e.g. '{AAAA-...}'
          DllPath      (ShellExt)  absolute InProcServer32 path
          VfsDllPath   (ShellExt)  package-relative VFS path if DLL found in pkg

        Uses offreg.dll (Offline Registry API) to parse Registry.dat in memory.
        No elevation required.

        Surfaces `ShellVerb` and `ShellExt` findings via Get-MsixHeuristicFinding;
        ShellExt entries with a resolved Clsid + VfsDllPath are auto-fixable
        through the `AddLegacyContextMenu` stage of Invoke-MsixAutoFixFromAnalysis.

    .PARAMETER PackagePath
        .msix file to inspect.

    .EXAMPLE
        # Surface all shell verbs and shellex handlers (no elevation required)
        Get-MsixShellContextMenuEntry -PackagePath app.msix |
            Format-Table Type, Target, VerbName, HandlerName, Clsid, VfsDllPath

    .OUTPUTS
        [pscustomobject[]] with Type, Target, VerbName/HandlerName, Command,
        Clsid, DllPath, VfsDllPath as documented above.
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
        $clsidGuidRegex = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'

        $hive = _MsixOpenOfflineHive -Path $datPath
        try {
            # Helper: read the InProcServer32 default value from either the
            # 64-bit Classes\CLSID branch or the WOW6432Node fallback.
            function _resolveClsidDll([IntPtr]$h, [string]$clsid) {
                foreach ($prefix in @(
                    'REGISTRY\MACHINE\SOFTWARE\Classes\CLSID',
                    'REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID'
                )) {
                    $v = _MsixOfflineGetValue -Parent $h -SubKey "$prefix\$clsid\InProcServer32" -Name ''
                    if ($v) { return $v }
                }
                return $null
            }

            foreach ($target in @('*', 'Directory', 'Directory\Background', 'AllFilesystemObjects')) {
                $tgtClean = $target

                # ── Shell verbs: Classes\<target>\shell\<verb>
                $shellPath = "REGISTRY\MACHINE\SOFTWARE\Classes\$target\shell"
                $shellKey  = _MsixOfflineOpenKey -Parent $hive -SubKey $shellPath
                if ($shellKey -ne [IntPtr]::Zero) {
                    try {
                        foreach ($verbName in (_MsixOfflineEnumSubKeys -Key $shellKey)) {
                            $verbPath = "$shellPath\$verbName"
                            $ech = _MsixOfflineGetValue -Parent $hive -SubKey $verbPath -Name 'ExplorerCommandHandler'
                            if ($ech) {
                                if ($ech -notmatch '^\{') { $ech = "{$ech}" }
                                $dll = $null; $vfsDll = $null
                                if ($ech -match $clsidGuidRegex) {
                                    $dll = _resolveClsidDll $hive $ech
                                    if ($dll) { $vfsDll = _MsixRegPathToVfsRelative -RegPath $dll -WorkspacePath $workspace }
                                }
                                $results.Add([pscustomobject]@{
                                    Type        = 'ShellExt'
                                    Target      = $tgtClean
                                    HandlerName = $verbName
                                    Command     = $null
                                    Clsid       = $ech
                                    DllPath     = $dll
                                    VfsDllPath  = $vfsDll
                                })
                            } else {
                                $cmd = _MsixOfflineGetValue -Parent $hive -SubKey "$verbPath\command" -Name ''
                                $results.Add([pscustomobject]@{
                                    Type       = 'ShellVerb'
                                    Target     = $tgtClean
                                    VerbName   = $verbName
                                    Command    = $cmd
                                    Clsid      = $null
                                    DllPath    = $null
                                    VfsDllPath = $null
                                })
                            }
                        }
                    } finally {
                        _MsixOfflineCloseKey -Key $shellKey
                    }
                }

                # ── shellex COM handlers: Classes\<target>\shellex\ContextMenuHandlers\<name>
                $shexPath = "REGISTRY\MACHINE\SOFTWARE\Classes\$target\shellex\ContextMenuHandlers"
                $shexKey  = _MsixOfflineOpenKey -Parent $hive -SubKey $shexPath
                if ($shexKey -ne [IntPtr]::Zero) {
                    try {
                        foreach ($handlerName in (_MsixOfflineEnumSubKeys -Key $shexKey)) {
                            $clsid = _MsixOfflineGetValue -Parent $hive -SubKey "$shexPath\$handlerName" -Name ''
                            if ($clsid -and $clsid -notmatch '^\{') { $clsid = "{$clsid}" }
                            $dll = $null; $vfsDll = $null
                            if ($clsid -and $clsid -match $clsidGuidRegex) {
                                $dll = _resolveClsidDll $hive $clsid
                                if ($dll) { $vfsDll = _MsixRegPathToVfsRelative -RegPath $dll -WorkspacePath $workspace }
                            }
                            $results.Add([pscustomobject]@{
                                Type        = 'ShellExt'
                                Target      = $tgtClean
                                HandlerName = $handlerName
                                Command     = $null
                                Clsid       = $clsid
                                DllPath     = $dll
                                VfsDllPath  = $vfsDll
                            })
                        }
                    } finally {
                        _MsixOfflineCloseKey -Key $shexKey
                    }
                }
            }
        } finally {
            _MsixCloseOfflineHive -Hive $hive
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
        and ThreadingModel. Works without elevation: hive is mounted under HKCU.

        Returned objects:
          Clsid          '{XXXXXXXX-...}'
          ServerType     'InProc' | 'LocalServer' | 'Unknown'
          DllPath        absolute InProcServer32 / LocalServer32 path (elevated)
          VfsDllPath     package-relative VFS path if the DLL is in the package
          ThreadingModel e.g. 'Apartment' (InProc, elevated only)

        Surfaces the `ComServer` finding in Get-MsixHeuristicFinding. Entries
        with a resolved VfsDllPath feed the `AddComServer` stage of
        Invoke-MsixAutoFixFromAnalysis, which calls Add-MsixComServerExtension.

    .PARAMETER PackagePath
        .msix file to inspect.

    .EXAMPLE
        # Find COM servers registered in the package's Registry.dat
        Get-MsixComServerEntry -PackagePath app.msix |
            Where-Object ServerType -eq 'InProc'

    .OUTPUTS
        [pscustomobject[]] with Clsid, ServerType, DllPath, VfsDllPath,
        ThreadingModel as documented above.
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
        $clsidGuidRegex = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'

        $hive = _MsixOpenOfflineHive -Path $datPath
        try {
            foreach ($branch in @(
                'REGISTRY\MACHINE\SOFTWARE\Classes\CLSID',
                'REGISTRY\MACHINE\SOFTWARE\WOW6432Node\Classes\CLSID'
            )) {
                $branchKey = _MsixOfflineOpenKey -Parent $hive -SubKey $branch
                if ($branchKey -eq [IntPtr]::Zero) { continue }
                try {
                    foreach ($clsid in (_MsixOfflineEnumSubKeys -Key $branchKey)) {
                        if ($clsid -notmatch $clsidGuidRegex) { continue }

                        # InProcServer32 (DLL)
                        $ipBase = "$branch\$clsid\InProcServer32"
                        $dll    = _MsixOfflineGetValue -Parent $hive -SubKey $ipBase -Name ''
                        if ($dll) {
                            $thread = _MsixOfflineGetValue -Parent $hive -SubKey $ipBase -Name 'ThreadingModel'
                            $vfsDll = _MsixAbsoluteToVfsRelativeDirect -AbsPath $dll -WorkspacePath $workspace
                            $results.Add([pscustomobject]@{
                                Clsid          = $clsid
                                ServerType     = 'InProc'
                                DllPath        = $dll
                                VfsDllPath     = $vfsDll
                                ThreadingModel = if ($thread) { $thread } else { 'Apartment' }
                            })
                        }

                        # LocalServer32 (EXE)
                        $lsCmd = _MsixOfflineGetValue -Parent $hive -SubKey "$branch\$clsid\LocalServer32" -Name ''
                        if ($lsCmd) {
                            $results.Add([pscustomobject]@{
                                Clsid          = $clsid
                                ServerType     = 'LocalServer'
                                DllPath        = $lsCmd
                                VfsDllPath     = $null
                                ThreadingModel = $null
                            })
                        }
                    }
                } finally {
                    _MsixOfflineCloseKey -Key $branchKey
                }
            }
        } finally {
            _MsixCloseOfflineHive -Hive $hive
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

        Feeds the `AppExecutionAlias` finding in Get-MsixHeuristicFinding.
        Pass the AppId values to Add-MsixAlias to register the suggestions.

    .PARAMETER PackagePath
        .msix to scan (read-only).

    .EXAMPLE
        # Surface alias candidates and add the first one with Add-MsixAlias
        $cands = Get-MsixAliasCandidate -PackagePath app.msix |
            Where-Object { -not $_.AlreadyHasAlias }
        Add-MsixAlias -PackagePath app.msix `
            -AppIds $cands.AppId -SkipSigning

    .OUTPUTS
        [pscustomobject[]] each with AppId, Executable, SuggestAlias,
        AlreadyHasAlias.
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

    # Auto-updater artefacts (binaries + scheduled-task XMLs)
    try {
        foreach ($u in Get-MsixUpdaterCandidate -PackagePath $PackagePath) {
            $out.Add([pscustomobject]@{
                Severity = 'Info'
                Category = 'UpdaterArtifact'
                Symptom  = "Auto-updater detected: $($u.LeafName) ($($u.Kind))"
                Recommendation = "Remove-MsixUpdaterArtifact -PackagePath '$PackagePath'"
                Evidence = $u.RelativePath
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Updater heuristic skipped: $_" }

    # Plugin / extension-point directories. Default fix path is
    # selective FileSystemWriteVirtualization (Win10 19041+); operators on
    # older fleets can opt into PSF FileRedirection via -LegacyPluginFix on
    # Invoke-MsixAutoFixFromAnalysis.
    try {
        foreach ($p in Get-MsixPluginExtensionPoint -PackagePath $PackagePath) {
            $out.Add([pscustomobject]@{
                Severity = 'Info'
                Category = 'PluginDirectory'
                Symptom  = "Likely runtime extension folder: $($p.Name) ($($p.FileCount) entries)"
                Recommendation = "Set-MsixFileSystemWriteVirtualization -PackagePath '$PackagePath' -ExcludedDirectories @('$($p.RelativePath -replace '\\','/')')  (modern: desktop6+virtualization carve-out)  OR  Add-MsixPsfV2 -Fixups (New-MsixPsfFileRedirectionConfig -Base '$($p.RelativePath -replace '\\','/')' -Patterns '.*')  (legacy: PSF route)"
                Evidence = $p.RelativePath
                AppId    = $null
            })
        }
    } catch { Write-MsixLog Debug "Plugin extension-point heuristic skipped: $_" }

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
                Recommendation = "Remove-MsixUninstallerArtifact -PackagePath '$PackagePath'  (strips Uninstall\* keys from Registry.dat via offreg; no elevation required)"
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


# ---------------------------------------------------------------------------
# Plural-noun back-compat aliases (issue #38: preserved across the heuristics
# file split — every alias defined in the pre-split MSIX.Heuristics.ps1 still
# resolves to the same singular cmdlet).
# ---------------------------------------------------------------------------
Set-Alias Get-MsixUninstallerCandidates    Get-MsixUninstallerCandidate
Set-Alias Get-MsixUninstallRegistryEntries Get-MsixUninstallRegistryEntry
Set-Alias Get-MsixUpdaterCandidates        Get-MsixUpdaterCandidate
Set-Alias Get-MsixRunKeyEntries            Get-MsixRunKeyEntry
Set-Alias Get-MsixShellContextMenuEntries  Get-MsixShellContextMenuEntry
Set-Alias Get-MsixComServerEntries         Get-MsixComServerEntry
Set-Alias Get-MsixAliasCandidates          Get-MsixAliasCandidate
Set-Alias Get-MsixHeuristicFindings        Get-MsixHeuristicFinding
