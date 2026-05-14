# =============================================================================
# Debug & Sandbox helpers
# -----------------------------------------------------------------------------
# Goal: an admin downloads / receives a possibly-broken .msix, drops it in a
# folder, and runs ONE command. The module then:
#
#   1. Runs static analysis on the package
#   2. Spits out a numbered list of exact PowerShell commands to fix it
#   3. Optionally launches Process Monitor + DebugView, ready to capture
#   4. Optionally spins up a Windows Sandbox configured to load this module,
#      install the package, and start the debug session inside it
# =============================================================================

function Resolve-MsixDebugViewPath {
    if ($env:MSIX_DEBUGVIEW_PATH -and (Test-Path $env:MSIX_DEBUGVIEW_PATH)) {
        return (Resolve-Path $env:MSIX_DEBUGVIEW_PATH).Path
    }
    $cmd = Get-Command Dbgview.exe, Dbgview64.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { return $cmd.Source }
    foreach ($p in @(
        (Join-Path (Get-MsixToolsRoot) 'procmon\Dbgview.exe'),
        "${env:ProgramFiles}\SysInternals\Dbgview.exe",
        "${env:ProgramFiles}\SysInternalsSuite\Dbgview.exe"
    )) {
        if (Test-Path $p) { return $p }
    }
    return $null
}


function Get-MsixDebugRecommendation {
    <#
    .SYNOPSIS
        Converts a compatibility report's findings into a numbered list of
        copy-paste-ready PowerShell commands.

    .DESCRIPTION
        Each command is annotated with:
          - what symptom it addresses
          - which AppId it applies to (if known)
          - why this fix is recommended

    .PARAMETER Report
        Output of Get-MsixCompatibilityReport / Invoke-MsixInvestigation.

    .PARAMETER PackagePath
        Used in the generated commands. Defaults to $Report.PackagePath.

    .PARAMETER Pfx / PfxPassword
        Substituted into signing parts of the recommended commands.

    .OUTPUTS
        [string[]] — one entry per recommendation, formatted for printing
                    or piping into a .ps1 file.
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '')]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        $Report,
        [string]$PackagePath,
        [string]$Pfx          = '<path-to-cert.pfx>',
        [string]$PfxPassword  = '<pfx-password>'
    )

    if (-not $PackagePath) { $PackagePath = $Report.PackagePath }
    $lines = New-Object System.Collections.Generic.List[string]
    $i = 0

    foreach ($f in @($Report.Findings)) {
        $i++
        $header = "# [$i] [$($f.Severity)] $($f.Category) — $($f.Symptom)"
        if ($f.AppId)    { $header += "  (App: $($f.AppId))" }
        if ($f.Evidence) { $header += "  Evidence: $($f.Evidence)" }
        $lines.Add($header)

        switch ($f.Category) {
            'WorkingDirectory' {
                $wd = if ($f.Recommendation -match "workingDirectory='([^']+)'") { $matches[1] } else { 'VFS/ProgramFilesX64/<App>/' }
                $lines.Add("Add-MsixPsfV2 -PackagePath '$PackagePath' ``")
                $lines.Add("    -Fixups            @() ``")
                $lines.Add("    -WorkingDirectory '$wd' ``")
                $lines.Add("    -Pfx '$Pfx' -PfxPassword '$PfxPassword'")
            }
            'FileRedirectionFixup' {
                $base = if ($f.Recommendation -match "-Base '([^']+)'") { $matches[1] } else { 'VFS/ProgramFilesX64/<App>/' }
                $lines.Add("# Manifest alternative (Win11+, no PSF overhead): Set-MsixFileSystemWriteVirtualization -PackagePath '$PackagePath' -Pfx '$Pfx' -PfxPassword '$PfxPassword'")
                $lines.Add("Add-MsixPsfV2 -PackagePath '$PackagePath' ``")
                $lines.Add("    -Fixups @( New-MsixPsfFileRedirectionConfig -Base '$base' -Patterns '.*\.log','.*\.tmp','.*\.cache' ) ``")
                $lines.Add("    -Pfx '$Pfx' -PfxPassword '$PfxPassword'")
            }
            'RegLegacyFixups' {
                $lines.Add("# Manifest alternative (Win11+, no PSF overhead): Set-MsixRegistryWriteVirtualization -PackagePath '$PackagePath' -Pfx '$Pfx' -PfxPassword '$PfxPassword'")
                $lines.Add("Add-MsixPsfV2 -PackagePath '$PackagePath' ``")
                $lines.Add("    -Fixups @( New-MsixPsfRegLegacyConfig -Hive HKLM -Access Full2MaxAllowed -Patterns 'SOFTWARE\\<Vendor>\\*' ) ``")
                $lines.Add("    -Pfx '$Pfx' -PfxPassword '$PfxPassword'")
            }
            'MultiApp' {
                $lines.Add("# Multi-app package: ensure every Application id appears in config.json applications[].")
                $lines.Add("# Add-MsixPsfV2 already iterates and creates PsfLauncher{n}.exe per app.")
            }
            'PSF' {
                $lines.Add("# Inspect existing config.json before adding more fixups:")
                $lines.Add("Get-MsixManifest '$PackagePath' | Select-Xml '//Application' | ForEach-Object { `$_.Node.Executable }")
            }
            default {
                $lines.Add("# (manual review) $($f.Recommendation)")
            }
        }
        $lines.Add('')
    }

    if ($i -eq 0) {
        $lines.Add('# No issues detected. Package looks ready to deploy.')
    }
    return ,$lines.ToArray()
}


function Start-MsixDebugSession {
    <#
    .SYNOPSIS
        One-call setup of a debugging session for a problematic MSIX package.

    .DESCRIPTION
        Performs the operator workflow that the MS Learn docs describe manually:

        1. Runs static analysis on the package and prints a numbered list of
           recommended PowerShell commands.
        2. Optionally launches Process Monitor (filtered for the package's
           executable) and DebugView.
        3. Optionally installs the package (-Install) and runs it inside
           Invoke-CommandInDesktopPackage.
        4. Returns the report so it can be saved or further processed.

        Designed to be the first thing an admin runs inside a Windows Sandbox
        after copying the .msix in.

    .PARAMETER PackagePath
        .msix file under investigation.

    .PARAMETER Install
        Install (or re-install) the package via Add-AppPackage before debugging.

    .PARAMETER LaunchProcMon / LaunchDebugView
        Open the corresponding Sysinternals tool. Auto-installs Procmon if missing.

    .PARAMETER ProcessName
        Filters Procmon to a specific image name (improves signal-to-noise).

    .PARAMETER OutputDirectory
        Where to write the report.txt + recommended-commands.ps1 file.
        Defaults to a "msix-debug-<pkg>" folder on the desktop.

    .EXAMPLE
        Start-MsixDebugSession -PackagePath C:\Drop\app.msix -Install -LaunchProcMon -LaunchDebugView
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [switch]$Install,
        [switch]$LaunchProcMon,
        [switch]$LaunchDebugView,
        [string]$ProcessName,
        [string]$OutputDirectory
    )

    if (-not $PSCmdlet.ShouldProcess($PackagePath, 'Start MSIX Debug Session')) { return }

    $null = $ProcessName  # forwarded to Process Monitor filter when -LaunchProcMon is used
    $fileinfo = Get-Item $PackagePath
    if (-not $OutputDirectory) {
        $OutputDirectory = Join-Path ([Environment]::GetFolderPath('Desktop')) "msix-debug-$($fileinfo.BaseName)"
    }
    New-Item $OutputDirectory -ItemType Directory -Force | Out-Null

    Write-MsixLog Info "=== MSIX Debug Session: $($fileinfo.Name) ==="
    Write-MsixLog Info "Output: $OutputDirectory"

    # 1) Analysis
    $report  = Invoke-MsixInvestigation -PackagePath $PackagePath
    $commands = Get-MsixDebugRecommendation -Report $report -PackagePath $PackagePath

    $report   | Format-List | Out-File (Join-Path $OutputDirectory 'report.txt')
    $commands | Out-File    (Join-Path $OutputDirectory 'recommended-commands.ps1') -Encoding utf8

    Write-Information ''
    Write-Information '────────────────────────────────────────────────────────────────────'
    Write-Information ' RECOMMENDED COMMANDS (also saved to recommended-commands.ps1)'
    Write-Information '────────────────────────────────────────────────────────────────────'
    $commands | ForEach-Object { Write-Information $_ }
    Write-Information '────────────────────────────────────────────────────────────────────'
    Write-Information ''

    # 2) Install
    if ($Install) {
        Write-MsixLog Info "Installing package…"
        Add-AppPackage -Path $fileinfo.FullName -ForceApplicationShutdown -ErrorAction Stop
    }

    # 3) Procmon
    if ($LaunchProcMon) {
        $procmon = Resolve-MsixProcMonPath
        if (-not $procmon) {
            Write-MsixLog Info "Process Monitor not found; downloading."
            Install-MsixProcMon | Out-Null
            $procmon = Resolve-MsixProcMonPath
        }
        if ($procmon) {
            $pmlPath = Join-Path $OutputDirectory 'capture.pml'
            $pmArgs  = @('/AcceptEula', '/Quiet', '/Minimized', '/BackingFile', "`"$pmlPath`"")
            Start-Process $procmon -ArgumentList $pmArgs
            Write-MsixLog Info "Process Monitor capturing to $pmlPath"
            Write-Information "  Stop later with: Start-Process '$procmon' -ArgumentList '/Terminate'"
        }
    }

    # 4) DebugView
    if ($LaunchDebugView) {
        $dv = Resolve-MsixDebugViewPath
        if ($dv) {
            Start-Process $dv
            Write-MsixLog Info "DebugView launched: $dv"
        } else {
            Write-MsixLog Warning 'DebugView not found. Download from https://learn.microsoft.com/sysinternals/downloads/debugview and set $env:MSIX_DEBUGVIEW_PATH.'
        }
    }

    return [pscustomobject]@{
        Report           = $report
        OutputDirectory  = $OutputDirectory
        RecommendedFile  = Join-Path $OutputDirectory 'recommended-commands.ps1'
    }
}


function New-MsixSandboxConfig {
    <#
    .SYNOPSIS
        Generates a Windows Sandbox (.wsb) configuration that maps a folder
        containing this module + a target .msix into the sandbox, and runs
        Start-MsixDebugSession on first login.

    .DESCRIPTION
        The resulting workflow:

          1. Operator places the .msix to debug into <DropFolder>.
          2. Operator runs:
                $cfg = New-MsixSandboxConfig -DropFolder C:\debug-msix -PackageName app.msix
                Start-Process $cfg
          3. Windows Sandbox boots, the bootstrap script imports this module
             from the mapped folder and invokes Start-MsixDebugSession with
             -Install -LaunchProcMon -LaunchDebugView.

        The sandbox keeps the host clean and provides a disposable env per run.

    .PARAMETER DropFolder
        Host folder containing the .msix to debug. Mapped read-write in the
        sandbox so analysis output / captured PML can be retrieved.

    .PARAMETER PackageName
        Filename inside DropFolder (e.g. 'broken.msix').

    .PARAMETER ModulePath
        Path to this module on the host. Defaults to the running module folder.

    .PARAMETER OutputPath
        Where to write the .wsb file. Defaults to "$DropFolder\msix-debug.wsb".

    .PARAMETER vGPU / Networking
        Enable/disable the sandbox features. Both default to enabled.

    .EXAMPLE
        $wsb = New-MsixSandboxConfig -DropFolder C:\drop -PackageName broken.msix
        Start-Process $wsb     # boots Windows Sandbox
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [string]$DropFolder,
        [Parameter(Mandatory)]
        [string]$PackageName,
        [string]$ModulePath,
        [string]$OutputPath,
        [bool]$vGPU = $true,
        [bool]$Networking = $true
    )

    if (-not (Test-Path $DropFolder)) { throw "DropFolder not found: $DropFolder" }
    $msix = Join-Path $DropFolder $PackageName
    if (-not (Test-Path $msix)) { throw "Package not in drop folder: $msix" }

    if (-not $ModulePath) {
        $ModulePath = $PSScriptRoot
    }
    if (-not $OutputPath) {
        $OutputPath = Join-Path $DropFolder 'msix-debug.wsb'
    }

    # Bootstrap script: written into the drop folder so the sandbox can run it
    $bootstrap = Join-Path $DropFolder 'sandbox-bootstrap.ps1'
    @"
# Auto-generated by New-MsixSandboxConfig
`$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy -Scope Process Bypass -Force
Import-Module 'C:\msix-module\MSIX.psm1' -Force
Initialize-MsixToolchain | Out-Null
Start-MsixDebugSession ``
    -PackagePath     'C:\msix-drop\$PackageName' ``
    -Install         ``
    -LaunchProcMon   ``
    -LaunchDebugView ``
    -OutputDirectory 'C:\msix-drop\debug-output'
Read-Host 'Press Enter to close the sandbox session'
"@ | Set-Content -Path $bootstrap -Encoding utf8

    # Wrapper .cmd because LogonCommand wants a single argv
    $cmdWrap = Join-Path $DropFolder 'sandbox-bootstrap.cmd'
    "powershell.exe -NoExit -ExecutionPolicy Bypass -File ""C:\msix-drop\sandbox-bootstrap.ps1""" |
        Set-Content -Path $cmdWrap -Encoding ascii

    $vgpuTxt = if ($vGPU)       { 'Enable' } else { 'Disable' }
    $netTxt  = if ($Networking) { 'Default' } else { 'Disable' }

    $wsb = @"
<Configuration>
  <VGpu>$vgpuTxt</VGpu>
  <Networking>$netTxt</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>$DropFolder</HostFolder>
      <SandboxFolder>C:\msix-drop</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>$ModulePath</HostFolder>
      <SandboxFolder>C:\msix-module</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\msix-drop\sandbox-bootstrap.cmd</Command>
  </LogonCommand>
</Configuration>
"@
    Set-Content -Path $OutputPath -Value $wsb -Encoding utf8
    Write-MsixLog Info "Sandbox config: $OutputPath"
    Write-MsixLog Info "Bootstrap:      $bootstrap"

    return $OutputPath
}


function Start-MsixSandbox {
    <#
    .SYNOPSIS
        Generates a sandbox config (if not provided) and launches Windows Sandbox.

    .PARAMETER DropFolder / PackageName
        Forwarded to New-MsixSandboxConfig if -ConfigPath isn't given.

    .PARAMETER ConfigPath
        Use an existing .wsb file instead of generating one.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$DropFolder,
        [string]$PackageName,
        [string]$ConfigPath
    )

    if (-not (Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue)) {
        throw 'Windows Sandbox not installed. Enable the optional feature: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All'
    }

    if (-not $ConfigPath) {
        if (-not $DropFolder -or -not $PackageName) {
            throw '-DropFolder and -PackageName are required if -ConfigPath is not given.'
        }
        $ConfigPath = New-MsixSandboxConfig -DropFolder $DropFolder -PackageName $PackageName
    }

    if (-not $PSCmdlet.ShouldProcess($ConfigPath, 'Launch Windows Sandbox')) { return }
    Write-MsixLog Info "Launching Windows Sandbox with $ConfigPath"
    Start-Process -FilePath 'WindowsSandbox.exe' -ArgumentList "`"$ConfigPath`""
}


# Backward-compatible plural aliases
Set-Alias Get-MsixDebugRecommendations Get-MsixDebugRecommendation
