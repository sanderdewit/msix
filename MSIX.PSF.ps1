# Registry of known fixups: name -> { Dll (generic), HasBitSuffix }
# Bit-suffixed DLLs are stored as FileRedirectionFixup32.dll / 64.dll on disk
# but referenced as FileRedirectionFixup.dll inside the package/config.json.
$script:PsfFixupRegistry = [ordered]@{
    FileRedirectionFixup = @{ HasBitSuffix = $true  }
    MFRFixup             = @{ HasBitSuffix = $true  }   # TMurgent fork only
    RegLegacyFixups      = @{ HasBitSuffix = $true  }
    EnvVarFixup          = @{ HasBitSuffix = $true  }
    DynamicLibraryFixup  = @{ HasBitSuffix = $true  }
    TraceFixup           = @{ HasBitSuffix = $true  }
    WaitForDebuggerFixup = @{ HasBitSuffix = $true  }
    KernelTraceControl   = @{ HasBitSuffix = $false }
}

#region --- Config builders -------------------------------------------------

function New-MsixPsfFileRedirectionConfig {
    <#
    .SYNOPSIS
        Builds a FileRedirectionFixup config hashtable for use with Add-MsixPsfV2.

    .DESCRIPTION
        Redirects file I/O matching one or more regex patterns under -Base
        into a writable, per-user location at runtime. Use this when an app
        writes log files, temp data, or settings to a folder that MSIX
        containerises as read-only.

    .PARAMETER Base
        Folder (relative to the chosen path type) whose contents are subject
        to redirection. Use 'logs' for VFS\ProgramFilesX64\<App>\logs etc.

    .PARAMETER Patterns
        One or more regex strings matched against filenames in -Base.

    .PARAMETER PathType
        How -Base is anchored: packageRelative (default), packageDriveRelative,
        or knownFolderRelative.

    .OUTPUTS
        [hashtable] suitable for Add-MsixPsfV2 -Fixups.

    .EXAMPLE
        # Chain into Add-MsixPsfV2
        $fixup = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log','.*\.tmp'
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($fixup) `
            -Pfx cert.pfx -PfxPassword $pw
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [string]$Base,
        [Parameter(Mandatory)]
        [string[]]$Patterns,
        [ValidateSet('packageRelative', 'packageDriveRelative', 'knownFolderRelative')]
        [string]$PathType = 'packageRelative'
    )
    return @{
        dll    = 'FileRedirectionFixup.dll'
        config = @{
            redirectedPaths = @{
                $PathType = @(@{ base = $Base; patterns = [array]$Patterns })
            }
        }
    }
}

function New-MsixPsfRegLegacyConfig {
    <#
    .SYNOPSIS
        Builds a RegLegacyFixups config hashtable. Supports all four types
        documented by the TMurgent PSF fork:

          - ModifyKeyAccess   downgrade FULL/RW masks (default)
          - FakeDelete        deny "key not found" for legacy uninstallers
          - DeletionMarker    suppress reads of explicitly-deleted keys
          - Hklm2Hkcu         redirect HKLM writes to HKCU (per-user)

    .PARAMETER Hive
        Registry hive the rule applies to: HKCU or HKLM.

    .PARAMETER Patterns
        Key-path regex patterns (relative to -Hive) the rule matches.

    .PARAMETER Type
        Behaviour: ModifyKeyAccess (default), FakeDelete, DeletionMarker,
        or Hklm2Hkcu.

    .PARAMETER Access
        Required when -Type is ModifyKeyAccess. Downgrade mapping like
        Full2MaxAllowed, Full2RW, Full2R, RW2R, RW2MaxAllowed, or
        NotAllowed.

    .OUTPUTS
        [hashtable] suitable for Add-MsixPsfV2 -Fixups.

    .EXAMPLE
        # Modify access mask
        New-MsixPsfRegLegacyConfig -Type ModifyKeyAccess -Hive HKCU `
            -Access Full2MaxAllowed -Patterns 'SOFTWARE\App\*'

    .EXAMPLE
        # Pretend the key doesn't exist (legacy uninstaller probes)
        New-MsixPsfRegLegacyConfig -Type FakeDelete -Hive HKLM `
            -Patterns 'SOFTWARE\App\Uninstall'

    .EXAMPLE
        # Send legacy HKLM writes to HKCU instead, then chain into Add-MsixPsfV2
        $fixup = New-MsixPsfRegLegacyConfig -Type Hklm2Hkcu -Hive HKLM `
            -Patterns 'SOFTWARE\App\*'
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($fixup) `
            -Pfx cert.pfx -PfxPassword $pw
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('HKCU', 'HKLM')]
        [string]$Hive,
        [Parameter(Mandatory)]
        [string[]]$Patterns,
        [ValidateSet('ModifyKeyAccess', 'FakeDelete', 'DeletionMarker', 'Hklm2Hkcu')]
        [string]$Type = 'ModifyKeyAccess',
        # Required only for ModifyKeyAccess
        [ValidateSet('Full2RW','Full2R','Full2MaxAllowed','RW2R','RW2MaxAllowed','NotAllowed')]
        [string]$Access
    )

    if ($Type -eq 'ModifyKeyAccess' -and -not $Access) {
        throw '-Access is required when -Type ModifyKeyAccess. Try Full2MaxAllowed.'
    }

    $remediation = [ordered]@{
        hive     = $Hive
        patterns = [array]$Patterns
    }
    if ($Type -eq 'ModifyKeyAccess') {
        $remediation['access'] = $Access
    }

    return @{
        dll    = 'RegLegacyFixups.dll'
        config = @{
            type        = $Type
            remediation = @($remediation)
        }
    }
}

function New-MsixPsfEnvVarConfig {
    <#
    .SYNOPSIS
        Builds an EnvVarFixup config hashtable for use with Add-MsixPsfV2.

    .DESCRIPTION
        Injects environment variables into the target process at startup
        without modifying the user or machine environment. Use for apps that
        need a configuration var set inside the package container only.

    .PARAMETER Variables
        Hashtable of name/value pairs to set for the target process.

    .OUTPUTS
        [hashtable] suitable for Add-MsixPsfV2 -Fixups.

    .EXAMPLE
        $env = New-MsixPsfEnvVarConfig -Variables @{ MY_VAR = 'value'; ANOTHER = 'val2' }
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($env) `
            -Pfx cert.pfx -PfxPassword $pw
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Variables
    )
    return @{
        dll    = 'EnvVarFixup.dll'
        config = @{ envVars = $Variables }
    }
}

function New-MsixPsfDynamicLibraryConfig {
    <#
    .SYNOPSIS
        Builds a DynamicLibraryFixup config hashtable. Maps DLL imports to
        package-relative replacement DLLs at runtime.

    .DESCRIPTION
        Use when an app imports a DLL by name and the OS loader can't find it
        (because it's vendored at a non-standard relative path). Each entry
        names a DLL and where the runtime should redirect to.

        For the "just add a search path" case, prefer the manifest-only fix:
        Add-MsixLoaderSearchPathOverride.

    .PARAMETER Mappings
        Array of hashtables: @{ name='foo.dll'; filepath='VFS/ProgramFilesX64/App/lib/foo.dll' }

    .EXAMPLE
        $dyn = New-MsixPsfDynamicLibraryConfig -Mappings @(
            @{ name='liba.dll'; filepath='VFS/ProgramFilesX64/App/lib/liba.dll' }
            @{ name='libb.dll'; filepath='VFS/ProgramFilesX64/App/lib/libb.dll' }
        )
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($dyn) -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [hashtable[]]$Mappings
    )
    foreach ($m in $Mappings) {
        if (-not $m.name)     { throw "Each mapping needs 'name'." }
        if (-not $m.filepath) { throw "Each mapping needs 'filepath'." }
    }
    return @{
        dll    = 'DynamicLibraryFixup.dll'
        config = @{
            relativePaths = @($Mappings | ForEach-Object {
                [ordered]@{ name = $_.name; filepath = $_.filepath }
            })
        }
    }
}


function New-MsixPsfWaitForDebuggerConfig {
    <#
    .SYNOPSIS
        Builds a WaitForDebuggerFixup config hashtable.

    .DESCRIPTION
        At process startup the fixup blocks until a debugger attaches —
        invaluable when investigating apps that crash before you can attach.

        Strip this fixup before shipping a production package; it's a
        diagnostic helper only.

    .PARAMETER Processes
        Optional array of process names (without .exe) the fixup should block
        on. If omitted, the fixup applies to whatever process loads it.

    .EXAMPLE
        $wait = New-MsixPsfWaitForDebuggerConfig
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($wait) -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [string[]]$Processes
    )
    $cfg = @{}
    if ($Processes) {
        $cfg['processes'] = @($Processes | ForEach-Object { @{ executable = $_ } })
    }
    return @{
        dll    = 'WaitForDebuggerFixup.dll'
        config = $cfg
    }
}


function New-MsixPsfArgument {
    <#
    .SYNOPSIS
        Returns a hashtable describing per-application command-line arguments
        and (optionally) a working directory. Pass to Add-MsixPsfV2 -AppOptions.

        Maps to the top-level `applications[].arguments` field documented at
        https://learn.microsoft.com/en-us/windows/msix/psf/psf-launch-apps-with-parameters

    .PARAMETER AppId
        Application Id (as in AppxManifest.xml) the arguments apply to.

    .PARAMETER Arguments
        Command-line argument string passed to the application.

    .PARAMETER WorkingDirectory
        Optional package-relative working directory.

    .OUTPUTS
        [hashtable] suitable for Add-MsixPsfV2 -AppOptions.

    .EXAMPLE
        # Pass through to Add-MsixPsfV2 via -AppOptions
        $opt   = New-MsixPsfArgument -AppId 'App' -Arguments '/bootfromsettingshortcut'
        $fixup = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($fixup) `
            -AppOptions @($opt) -Pfx cert.pfx -PfxPassword $pw
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,
        [string]$Arguments,
        [string]$WorkingDirectory
    )
    $h = @{ id = $AppId }
    if ($Arguments)        { $h['arguments']        = $Arguments }
    if ($WorkingDirectory) { $h['workingDirectory'] = $WorkingDirectory }
    return $h
}

function New-MsixPsfStartScriptConfig {
    <#
    .SYNOPSIS
        Builds a PSF startScript / endScript block (per-application).

    .DESCRIPTION
        Used by PSFLauncher to run a PowerShell script before (startScript) or
        after (endScript) the target application. Requires StartingScriptWrapper.ps1
        from PSFBinaries.zip alongside the script in the package.

        See https://learn.microsoft.com/en-us/windows/msix/psf/create-shortcut-with-script-package-support-framework

    .PARAMETER AppId
        Application Id this script attaches to.

    .PARAMETER ScriptPath
        Package-relative path to the .ps1 script (e.g. "ContosoExpenses\createshortcut.ps1").

    .PARAMETER ScriptArguments
        Optional argument string passed to the script.

    .PARAMETER RunInVirtualEnvironment
        If true, the script runs inside the package container; otherwise on the host.

    .PARAMETER RunOnce
        If true, the script runs only the first time the application is launched.

    .PARAMETER ShowWindow
        If true, the PowerShell host window is visible.

    .PARAMETER WaitForScriptToFinish
        If true, the application start blocks until the script exits.

    .PARAMETER StopOnScriptError
        If true, application launch is aborted when the script returns non-zero.

    .PARAMETER Timeout
        Seconds to wait for the script before giving up. 0 = no timeout.

    .PARAMETER EndScript
        If specified, returned as endScript instead of startScript.

    .OUTPUTS
        [hashtable] suitable for Add-MsixPsfV2 -AppOptions.

    .EXAMPLE
        # Pre-launch shortcut creation, blocking until finished
        $opt = New-MsixPsfStartScriptConfig -AppId 'App' `
            -ScriptPath 'createshortcut.ps1' -RunOnce -WaitForScriptToFinish
        Add-MsixPsfV2 -PackagePath app.msix `
            -Fixups @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' ) `
            -AppOptions @($opt) `
            -AdditionalFiles @('C:\src\createshortcut.ps1') `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Post-exit cleanup
        New-MsixPsfStartScriptConfig -AppId 'App' -ScriptPath 'cleanup.ps1' -EndScript
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [string]$AppId,
        [Parameter(Mandatory)]
        [string]$ScriptPath,
        [string]$ScriptArguments,
        [switch]$RunInVirtualEnvironment,
        [switch]$RunOnce,
        [switch]$ShowWindow,
        [switch]$WaitForScriptToFinish,
        [switch]$StopOnScriptError,
        [int]$Timeout = 0,
        [switch]$EndScript
    )
    $script = [ordered]@{
        scriptPath              = $ScriptPath
        runInVirtualEnvironment = [bool]$RunInVirtualEnvironment
        runOnce                 = [bool]$RunOnce
        showWindow              = [bool]$ShowWindow
        waitForScriptToFinish   = [bool]$WaitForScriptToFinish
        stopOnScriptError       = [bool]$StopOnScriptError
    }
    if ($ScriptArguments) { $script['scriptArguments'] = $ScriptArguments }
    if ($Timeout -gt 0)   { $script['timeout']         = $Timeout }

    return @{
        appId  = $AppId
        kind   = if ($EndScript) { 'endScript' } else { 'startScript' }
        block  = $script
    }
}

function New-MsixPsfTraceConfig {
    <#
    .SYNOPSIS
        Builds a TraceFixup config hashtable for use with Add-MsixPsfV2.

    .DESCRIPTION
        TraceFixup logs filesystem and registry calls made by the target
        process, classified by failure mode. Pair with DebugView (or
        equivalent) to capture the trace stream while reproducing an issue.

    .PARAMETER FilesystemLevel
        How much filesystem activity to log: allFailures,
        unexpectedFailures (default), or ignore.

    .PARAMETER RegistryLevel
        How much registry activity to log: allFailures, unexpectedFailures,
        or ignore (default).

    .OUTPUTS
        [hashtable] suitable for Add-MsixPsfV2 -Fixups.

    .EXAMPLE
        $trace = New-MsixPsfTraceConfig -FilesystemLevel allFailures
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($trace) `
            -Pfx cert.pfx -PfxPassword $pw
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [ValidateSet('allFailures', 'unexpectedFailures', 'ignore')]
        [string]$FilesystemLevel = 'unexpectedFailures',
        [ValidateSet('allFailures', 'unexpectedFailures', 'ignore')]
        [string]$RegistryLevel   = 'ignore'
    )
    return @{
        dll    = 'TraceFixup.dll'
        config = @{
            traceLevels = @{
                filesystem = $FilesystemLevel
                registry   = $RegistryLevel
            }
        }
    }
}

#endregion

#region --- Config.json generation -----------------------------------------

function New-MsixPsfConfig {
    <#
    .SYNOPSIS
        Generates a complete PSF config.json string from a manifest, fixups, and
        optional per-application options (arguments, workingDirectory, startScript,
        endScript).
    .PARAMETER AppOptions
        Hashtables produced by New-MsixPsfArgument and New-MsixPsfStartScriptConfig.
        Each is merged into the matching application entry by AppId.
    .OUTPUTS
        [string] JSON
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [xml]$Manifest,
        [Parameter(Mandatory)]
        [hashtable[]]$Fixups,
        [string]$WorkingDirectory,
        [hashtable[]]$AppOptions
    )

    $apps = @($Manifest.Package.Applications.Application)

    # Index AppOptions by app id and kind so we can merge into entries
    $argsById   = @{}
    $startById  = @{}
    $endById    = @{}
    foreach ($opt in @($AppOptions)) {
        if (-not $opt) { continue }
        if ($opt.kind -eq 'startScript') { $startById[$opt.appId] = $opt.block; continue }
        if ($opt.kind -eq 'endScript')   { $endById[$opt.appId]   = $opt.block; continue }
        # Otherwise treat as arguments hashtable from New-MsixPsfArgument
        if ($opt.id) { $argsById[$opt.id] = $opt }
    }

    $appEntries = foreach ($app in $apps) {
        $entry = [ordered]@{
            id         = $app.Id
            executable = $app.GetAttribute('Executable').Replace('\', '/')
        }
        if ($WorkingDirectory) { $entry['workingDirectory'] = $WorkingDirectory }

        if ($argsById.ContainsKey($app.Id)) {
            $a = $argsById[$app.Id]
            if ($a.arguments)        { $entry['arguments']        = $a.arguments }
            if ($a.workingDirectory) { $entry['workingDirectory'] = $a.workingDirectory }
        }
        if ($startById.ContainsKey($app.Id)) { $entry['startScript'] = $startById[$app.Id] }
        if ($endById.ContainsKey($app.Id))   { $entry['endScript']   = $endById[$app.Id] }
        $entry
    }

    # One process block per application, all sharing the same fixup set
    $processEntries = foreach ($app in $apps) {
        $exeName = $app.GetAttribute('Executable').Split('\')[-1] -replace '\.exe$', ''
        [ordered]@{
            executable = $exeName
            fixups     = [array]$Fixups
        }
    }

    return [ordered]@{
        applications = [array]$appEntries
        processes    = [array]$processEntries
    } | ConvertTo-Json -Depth 15
}

#endregion

#region --- PSF injection ---------------------------------------------------

function Add-MsixPsfV2 {
    <#
    .SYNOPSIS
        Injects the Package Support Framework into an MSIX package.

    .DESCRIPTION
        Unpacks the MSIX to an isolated workspace, copies PSF runtime files,
        generates a valid config.json, updates the AppxManifest to point each
        Application at the correct PsfLauncher, repacks, and re-signs.

    .PARAMETER PackagePath
        Path to the .msix file to modify (modified in-place).

    .PARAMETER Fixups
        One or more fixup config hashtables from New-MsixPsf*Config helpers.

    .PARAMETER PsfSourcePath
        Override the folder containing PSF binaries (PsfLauncher*.exe, etc.).
        Defaults to the 'psf' subfolder under the module tools root.

    .PARAMETER WorkingDirectory
        Optional package-relative working directory written to config.json.

    .PARAMETER AppOptions
        Hashtables produced by New-MsixPsfArgument or
        New-MsixPsfStartScriptConfig. Merged into the matching application
        entry in config.json by AppId.

    .PARAMETER AdditionalFiles
        Extra files to copy into the package's app folder before repack
        (e.g. a .ps1 referenced by a startScript, a .lnk, icon files).

    .PARAMETER OutputPath
        Write the repacked package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Skip the final signing step. Use when chaining multiple PSF /
        manifest mutations and signing only at the very end with
        Invoke-MsixSigning. Alias: -NoSign.

    .PARAMETER Pfx
        Path to PFX certificate for signing. Omit to use the machine store.

    .PARAMETER PfxPassword
        SecureString password for the PFX file (required when -Pfx is
        specified).

    .PARAMETER UnsignedOutputPath
        If signing fails, preserve the unsigned scratch package at this path
        for inspection. The user's -PackagePath is left byte-equal to before
        the call in this scenario.

    .EXAMPLE
        # File-redirection fixup: redirect log writes to a package-relative folder
        $fixup = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($fixup) `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Chain multiple typed builders, stack fixups, sign once at the end
        $fr   = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'
        $env  = New-MsixPsfEnvVarConfig -Variables @{ MY_VAR = 'value' }
        $wait = New-MsixPsfWaitForDebuggerConfig
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($fr, $env, $wait) `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Start-script flow: copy the script in via -AdditionalFiles and
        # bind it through New-MsixPsfStartScriptConfig
        $script = New-MsixPsfStartScriptConfig -AppId 'App' `
            -ScriptPath 'createshortcut.ps1' -RunOnce -WaitForScriptToFinish
        $fixup  = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($fixup) `
            -AppOptions @($script) `
            -AdditionalFiles @('C:\src\createshortcut.ps1') `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Stage 1 of a chained mutation: skip signing now, sign at the end
        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($fixup) -SkipSigning
        # ... more manifest edits ...
        Invoke-MsixSigning -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw

    .NOTES
        Idempotent: re-running with the same fixup set merges new fixups
        into the existing config.json by DLL name rather than rewriting
        applications[] to reference PsfLauncher recursively.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [hashtable[]]$Fixups,
        [string]$PsfSourcePath,
        [string]$WorkingDirectory,
        [hashtable[]]$AppOptions,
        [string[]]$AdditionalFiles,        # extra files to copy into the package (e.g. a startScript .ps1)
        # Output path for dry-run mode. If set, the modified package is written
        # there instead of overwriting -PackagePath. Useful for staged pipelines.
        [string]$OutputPath,
        # If $true, the repacked output is NOT signed. Use this when chaining
        # multiple PSF / manifest mutations and signing only at the very end.
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $toolsRoot = Get-MsixToolsRoot
    if (-not $PsfSourcePath) { $PsfSourcePath = Join-Path $toolsRoot 'psf' }

    $fileinfo = Get-Item -LiteralPath $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName

    try {
        Write-MsixLog Info "Unpacking: $($fileinfo.FullName)"
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        $null = Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"
        $apps = @(Get-MsixManifestApplication $manifest)

        # Determine bitness from first app's executable path
        $firstExe  = $apps[0].GetAttribute('Executable')
        if (-not $firstExe) {
            # Fallback: scan workspace for the first .exe that isn't a PSF launcher
            $firstExe = Get-ChildItem -LiteralPath $workspace -Recurse -Filter '*.exe' -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -notmatch '^Psf' } |
                        Select-Object -First 1 |
                        ForEach-Object { $_.FullName.Substring($workspace.Length + 1) }
            Write-MsixLog Warning "Application Executable attribute was empty; resolved via scan: $firstExe"
        }
        $is64      = $firstExe -match 'x64|ProgramFilesX64'
        $bitSuffix = if ($is64) { '64' } else { '32' }

        # Resolve the subfolder that contains the first app's executable
        $relDir    = if ($firstExe -and $firstExe.Contains('\')) { $firstExe.Substring(0, $firstExe.LastIndexOf('\')) } else { '' }
        $appFolder = if ($relDir) { Join-Path $workspace $relDir } else { $workspace }

        # --- config.json (placed alongside the app executable) ---
        $configPath = Join-Path $appFolder 'config.json'

        # Detect re-injection: manifest already points to a PsfLauncher, which means
        # a previous Add-MsixPsfV2 run already set up the launcher → real executable
        # mapping. Re-generating config from the manifest would make applications[] and
        # processes[] reference PsfLauncher instead of the original exe. Merge instead.
        $psfLauncherRx = [regex]'[/\\]PsfLauncher\d+(?:_\d+)?\.exe$'
        $isPsfPresent  = $apps | Where-Object { $psfLauncherRx.IsMatch($_.GetAttribute('Executable')) } |
                         Select-Object -First 1

        if ($isPsfPresent -and (Test-Path -LiteralPath $configPath)) {
            # Merge mode: read existing config, append new fixups to each process entry
            $existingCfg  = Get-Content -LiteralPath $configPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            $existingApps = @($existingCfg.applications)

            # Build a map of process entries keyed by executable name
            $procMap = [ordered]@{}
            foreach ($p in @($existingCfg.processes)) {
                $procFixups = [System.Collections.Generic.List[object]]::new()
                foreach ($fixup in @($p.fixups)) {
                    $procFixups.Add($fixup)
                }
                $procMap[$p.executable] = $procFixups
            }

            # For each application in the existing config, ensure a process entry exists
            # and append any new fixups that are not already present (deduplicate by dll name)
            foreach ($appEntry in $existingApps) {
                $exeName = ($appEntry.executable -split '[/\\]')[-1] -replace '\.exe$', ''
                if (-not $procMap.ContainsKey($exeName)) {
                    $procMap[$exeName] = [System.Collections.Generic.List[object]]::new()
                }
                $existingDlls = @($procMap[$exeName] | ForEach-Object { $_.dll })
                foreach ($fixup in $Fixups) {
                    if ($fixup.dll -notin $existingDlls) {
                        $procMap[$exeName].Add($fixup)
                    }
                }
            }

            $mergedProcs = @($procMap.GetEnumerator() | ForEach-Object {
                [ordered]@{ executable = $_.Key; fixups = [array]$_.Value }
            })

            $mergedJson = [ordered]@{
                applications = $existingApps
                processes    = $mergedProcs
            } | ConvertTo-Json -Depth 15

            if ($PSCmdlet.ShouldProcess($configPath, 'Merge PSF config.json')) {
                $mergedJson | Out-File $configPath -Encoding utf8 -Force
                Write-MsixLog Info "PSF config merged (fixup(s) added to existing config): $configPath"
            }
        } else {
            # Fresh injection: generate config.json from manifest
            $psfJson = New-MsixPsfConfig -Manifest $manifest `
                                          -Fixups $Fixups `
                                          -WorkingDirectory $WorkingDirectory `
                                          -AppOptions $AppOptions

            if ($PSCmdlet.ShouldProcess($configPath, 'Write PSF config.json')) {
                $psfJson | Out-File $configPath -Encoding utf8 -Force
                Write-MsixLog Info "PSF config written: $configPath"
            }
        }

        Test-MsixPsfConfig $configPath

        # --- Copy PSF runtime binaries ---
        $runtimeFiles = @(
            "PsfLauncher$bitSuffix.exe",
            "PsfRuntime$bitSuffix.dll",
            "PsfRunDll$bitSuffix.exe"
        )
        foreach ($f in $runtimeFiles) {
            $src = Join-Path $PsfSourcePath $f
            if (Test-Path -LiteralPath $src) {
                if ($PSCmdlet.ShouldProcess($src, "Copy PSF runtime")) {
                    Copy-Item -LiteralPath $src -Destination $appFolder -Force
                    Write-MsixLog Debug "Copied: $f"
                }
            } else {
                Write-MsixLog Warning "PSF runtime not found: $src"
            }
        }

        # --- Copy fixup DLLs (strip bit suffix for package naming) ---
        foreach ($fixup in $Fixups) {
            $dllName = $fixup.dll                           # e.g. FileRedirectionFixup.dll
            $dllBase = $dllName -replace '\.dll$', ''      # e.g. FileRedirectionFixup
            $meta    = $script:PsfFixupRegistry[$dllBase]

            if ($meta -and $meta.HasBitSuffix) {
                $src = Join-Path $PsfSourcePath "${dllBase}${bitSuffix}.dll"
            } else {
                $src = Join-Path $PsfSourcePath $dllName
            }

            if (Test-Path -LiteralPath $src) {
                if ($PSCmdlet.ShouldProcess($src, "Copy fixup DLL")) {
                    Copy-Item -LiteralPath $src -Destination (Join-Path $appFolder $dllName) -Force
                    Write-MsixLog Debug "Fixup copied: $dllName"
                }
            } else {
                Write-MsixLog Warning "Fixup DLL not found: $src"
            }
        }

        # --- Optional extra files (e.g. start scripts, .lnk, icons) ---
        if ($AdditionalFiles) {
            foreach ($extra in $AdditionalFiles) {
                if (Test-Path -LiteralPath $extra) {
                    Copy-Item -LiteralPath $extra -Destination $appFolder -Force
                    Write-MsixLog Debug "Extra file copied: $extra"
                } else {
                    Write-MsixLog Warning "Additional file not found: $extra"
                }
            }
        }

        # Always ship StartingScriptWrapper.ps1 if any app uses startScript/endScript
        $needsWrapper = @($AppOptions) | Where-Object { $_.kind -in 'startScript','endScript' }
        if ($needsWrapper) {
            $wrapper = Join-Path $PsfSourcePath 'StartingScriptWrapper.ps1'
            if (Test-Path -LiteralPath $wrapper) {
                Copy-Item -LiteralPath $wrapper -Destination $appFolder -Force
                Write-MsixLog Debug "StartingScriptWrapper.ps1 copied"
            } else {
                Write-MsixLog Warning "StartingScriptWrapper.ps1 not found in $PsfSourcePath"
            }
        }

        # --- Update manifest: point each Application at PsfLauncher ---
        # Skip when PSF is already present — launcher is already wired in the manifest.
        if ($isPsfPresent) {
            Write-MsixLog Info 'PSF already present; skipping manifest launcher update.'
        } else {
            $i = 0
            foreach ($app in $apps) {
                $i++
                # App 1 → PsfLauncher64.exe, App 2+ → PsfLauncher64_2.exe, etc.
                if ($i -eq 1) {
                    $launcherName = "PsfLauncher$bitSuffix.exe"
                } else {
                    $launcherName = "PsfLauncher${bitSuffix}_$i.exe"
                    Copy-Item (Join-Path $PsfSourcePath "PsfLauncher$bitSuffix.exe") `
                              (Join-Path $appFolder $launcherName) -Force
                }

                $oldExe  = $app.GetAttribute('Executable')
                $oldLeaf = $oldExe.Split('\')[-1]
                $newExe  = $oldExe -replace [regex]::Escape($oldLeaf), $launcherName
                $app.SetAttribute('Executable', $newExe)

                # Note: we intentionally do NOT touch any existing
                # windows.appExecutionAlias extension here. The alias
                # inherits its launch target from the parent Application's
                # Executable attribute when the Extension itself omits
                # Executable/EntryPoint. Setting Executable on the alias
                # Extension without also setting EntryPoint is a schema
                # violation ("The attribute EntryPoint must be specified
                # if the attribute Executable on the Extension element is
                # specified"). An earlier sync block set only Executable
                # and produced exactly that MakeAppx error every time PSF
                # ran on a package that already had an alias declared
                # (e.g. one added by Invoke-MsixAutoFixFromAnalysis's
                # AppExecutionAlias stage).
            }

            if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save updated manifest')) {
                Save-MsixManifest $manifest "$workspace\AppxManifest.xml"
            }
        }

        # --- Atomic repack-sign-move (issue #40) ---
        # Pack to a scratch path, sign at scratch, Move-Item to the target
        # only on success. A signing failure must NEVER leave the user with
        # an unsigned modified copy of their signed package.
        $repackTarget = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $scratch      = Join-Path $env:TEMP ("msix-psfv2-{0}{1}" -f ([guid]::NewGuid().ToString('N').Substring(0,8)), ([System.IO.Path]::GetExtension($repackTarget)))
        Write-MsixLog Info "Repacking (via scratch): $repackTarget"
        $packOk = $false
        try {
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $scratch, '/d', $workspace, '/o')
            Assert-MsixProcessSuccess $r 'MakeAppx pack'
            $packOk = $true
            if ($SkipSigning) {
                Write-MsixLog Info "Skipping signing (use Invoke-MsixSigning later, or chain another PSF call)."
            } else {
                Invoke-MsixSigning -PackagePath $scratch -Pfx $Pfx -PfxPassword $PfxPassword
            }
            Move-Item -LiteralPath $scratch -Destination $repackTarget -Force
        } catch {
            if ($packOk -and $UnsignedOutputPath) {
                Copy-Item -LiteralPath $scratch -Destination $UnsignedOutputPath -Force -ErrorAction SilentlyContinue
                Write-MsixLog Warning "Signing failed. Unsigned package preserved at: $UnsignedOutputPath"
            }
            throw
        } finally {
            if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue }
        }

    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}

#endregion



# Backward-compatible plural aliases
Set-Alias New-MsixPsfArguments New-MsixPsfArgument
