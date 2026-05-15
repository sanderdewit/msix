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

    $toolsRoot = Get-MsixToolsRoot
    foreach ($p in @(
        (Join-Path $toolsRoot 'debugview\Dbgview64.exe'),
        (Join-Path $toolsRoot 'debugview\Dbgview.exe'),
        (Join-Path $toolsRoot 'procmon\Dbgview64.exe'),
        (Join-Path $toolsRoot 'procmon\Dbgview.exe'),
        "${env:ProgramFiles}\SysInternals\Dbgview64.exe",
        "${env:ProgramFiles}\SysInternals\Dbgview.exe",
        "${env:ProgramFiles}\SysInternalsSuite\Dbgview64.exe",
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
        Where to write report.html + report.json + recommended-commands.ps1.
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

    # Structured output -- both JSON (programmable) and HTML (human-readable).
    # The old report.txt rendered nested objects as @{Foo=...; Bar=...} which
    # was unreadable; ConvertTo-MsixReportHtml fans the Findings array into a
    # real <table> and embeds the recommended commands as a code block.
    $jsonPath = Join-Path $OutputDirectory 'report.json'
    $htmlPath = Join-Path $OutputDirectory 'report.html'
    $cmdsPath = Join-Path $OutputDirectory 'recommended-commands.ps1'

    $report   | ConvertTo-Json -Depth 12 | Set-Content -Path $jsonPath -Encoding utf8
    $commands | Set-Content       -Path $cmdsPath -Encoding utf8
    ConvertTo-MsixReportHtml -Report $report -Commands $commands -PackagePath $PackagePath |
        Set-Content -Path $htmlPath -Encoding utf8

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

    # 4) DebugView -- auto-install on miss (mirrors the Procmon path above)
    if ($LaunchDebugView) {
        $dv = Resolve-MsixDebugViewPath
        if (-not $dv) {
            Write-MsixLog Info 'DebugView not found; downloading from Sysinternals.'
            try {
                Install-MsixDebugView | Out-Null
                $dv = Resolve-MsixDebugViewPath
            } catch {
                Write-MsixLog Warning "DebugView install failed: $($_.Exception.Message)"
            }
        }
        if ($dv) {
            Start-Process $dv
            Write-MsixLog Info "DebugView launched: $dv"
        } else {
            Write-MsixLog Warning 'DebugView not found. Run Install-MsixDebugView or set $env:MSIX_DEBUGVIEW_PATH manually.'
        }
    }

    return [pscustomobject]@{
        Report           = $report
        OutputDirectory  = $OutputDirectory
        ReportHtml       = $htmlPath
        ReportJson       = $jsonPath
        RecommendedFile  = $cmdsPath
    }
}


function ConvertTo-MsixReportHtml {
    <#
    .SYNOPSIS
        Renders a compatibility report into a standalone HTML page with
        sortable tables for Findings, embedded RecommendedCommands as a code
        block, and links back to the package + raw JSON.

    .DESCRIPTION
        Self-contained HTML (inline CSS, no external dependencies) so the
        operator can copy it out of the sandbox / debug folder and open it
        anywhere.

    .PARAMETER Report
        Output of Invoke-MsixInvestigation / Get-MsixCompatibilityReport.

    .PARAMETER Commands
        Output of Get-MsixDebugRecommendation (string array).

    .PARAMETER PackagePath
        Original .msix path; included in the header.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Report,
        [string[]]$Commands,
        [string]$PackagePath
    )

    function _Esc([string]$s) {
        if ($null -eq $s) { return '' }
        ($s -replace '&','&amp;') -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<!doctype html><html lang="en"><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>MSIX Debug Report -- $(_Esc (Split-Path $PackagePath -Leaf))</title>")
    [void]$sb.AppendLine(@'
<style>
:root { color-scheme: light dark; }
body { font: 14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
       margin: 2em auto; max-width: 1100px; padding: 0 1em; }
h1 { border-bottom: 2px solid #888; padding-bottom: .25em; }
h2 { margin-top: 2em; }
table { border-collapse: collapse; width: 100%; margin: .5em 0 1.5em; }
th, td { border: 1px solid #888; padding: .35em .6em; text-align: left;
         vertical-align: top; }
th { background: #eee; }
@media (prefers-color-scheme: dark) {
  th { background: #333; }
  body { background: #1e1e1e; color: #ddd; }
  td, th { border-color: #555; }
}
.sev-Error    { color: #b00020; font-weight: 600; }
.sev-Warning  { color: #b25e00; font-weight: 600; }
.sev-Info     { color: #555; }
pre { background: #111; color: #eee; padding: 1em; border-radius: 6px;
      overflow-x: auto; white-space: pre-wrap; }
code { font: 13px/1.4 Consolas, Menlo, monospace; }
.meta { color: #666; font-size: 12px; }
.kv { display: grid; grid-template-columns: 9em 1fr; gap: .25em 1em; }
</style>
'@)
    [void]$sb.AppendLine('</head><body>')

    [void]$sb.AppendLine("<h1>MSIX Debug Report</h1>")
    [void]$sb.AppendLine('<div class="meta">')
    [void]$sb.AppendLine("Package: <code>$(_Esc $PackagePath)</code><br>")
    [void]$sb.AppendLine("Generated: $(_Esc ([DateTime]::Now.ToString('o')))<br>")
    [void]$sb.AppendLine('</div>')

    # --- Findings ---
    $findings = @($Report.Findings)
    [void]$sb.AppendLine("<h2>Findings ($($findings.Count))</h2>")
    if ($findings) {
        [void]$sb.AppendLine('<table><tr><th>#</th><th>Severity</th><th>Category</th><th>AppId</th><th>Symptom</th><th>Recommendation</th><th>Evidence</th></tr>')
        $i = 0
        foreach ($f in $findings) {
            $i++
            $sev = _Esc $f.Severity
            [void]$sb.AppendLine("<tr><td>$i</td><td class=""sev-$sev"">$sev</td><td>$(_Esc $f.Category)</td><td>$(_Esc $f.AppId)</td><td>$(_Esc $f.Symptom)</td><td>$(_Esc $f.Recommendation)</td><td>$(_Esc $f.Evidence)</td></tr>")
        }
        [void]$sb.AppendLine('</table>')
    } else {
        [void]$sb.AppendLine('<p><em>No findings — package looks ready to deploy.</em></p>')
    }

    # --- Recommended commands ---
    if ($Commands -and $Commands.Count -gt 0) {
        [void]$sb.AppendLine('<h2>Recommended commands</h2>')
        [void]$sb.AppendLine('<p>Copy-paste these into PowerShell, or use the bundled <code>recommended-commands.ps1</code>.</p>')
        [void]$sb.AppendLine('<pre><code>')
        foreach ($c in $Commands) { [void]$sb.AppendLine((_Esc $c)) }
        [void]$sb.AppendLine('</code></pre>')
    }

    # --- Suggested fixups (raw) ---
    if ($Report.SuggestedFixups) {
        [void]$sb.AppendLine('<h2>Suggested fixups (raw)</h2>')
        [void]$sb.AppendLine('<pre><code>')
        [void]$sb.AppendLine((_Esc ($Report.SuggestedFixups | ConvertTo-Json -Depth 10)))
        [void]$sb.AppendLine('</code></pre>')
    }

    # --- ProcMon log path ---
    if ($Report.ProcMonLog) {
        [void]$sb.AppendLine('<h2>Process Monitor capture</h2>')
        [void]$sb.AppendLine("<p><code>$(_Esc $Report.ProcMonLog)</code></p>")
    }

    [void]$sb.AppendLine('<p class="meta">Full structured data: <code>report.json</code></p>')
    [void]$sb.AppendLine('</body></html>')
    return $sb.ToString()
}


function New-MsixSandboxConfig {
    <#
    .SYNOPSIS
        Generates a Windows Sandbox (.wsb) configuration that maps the module
        + target .msix into the sandbox, installs the Windows App Runtime +
        DesktopAppInstaller (which the default sandbox image lacks), optionally
        trusts a self-signed certificate, then runs Start-MsixDebugSession.

    .DESCRIPTION
        Workflow:

          1. Operator drops the .msix in <DropFolder>.
          2. Operator runs:
                Start-MsixSandbox -DropFolder C:\drop -PackageName broken.msix
          3. The sandbox bootstrap script:
               a. Installs WindowsAppRuntimeInstall-x64.exe (silent)
               b. Adds Microsoft.DesktopAppInstaller.msixbundle
               c. (optional) Imports the self-signed cert into LocalMachine\Root
                  + TrustedPeople so the package will install
               d. Imports this module and runs Start-MsixDebugSession

        The .wsb maps an extra read-only folder (`runtime`) that contains the
        AppRuntime cache (see Initialize-MsixToolchain), and optionally a
        certificate file.

    .PARAMETER DropFolder
        Host folder containing the .msix to debug. Mapped read-write.

    .PARAMETER PackageName
        Filename inside DropFolder.

    .PARAMETER ModulePath
        Module folder on the host. Defaults to the running module folder.

    .PARAMETER RuntimePath
        Folder containing DesktopAppInstaller msixbundle + WindowsAppRuntime
        installer (cached by Install-MsixAppRuntime). Defaults to
        $ToolsRoot\runtime; auto-populated if missing.

    .PARAMETER CertPath
        Optional path to a .cer file (public part of a self-signed cert) that
        the bootstrap should trust before installing the package.

    .PARAMETER OutputPath
        Where to write the .wsb. Defaults to "$DropFolder\msix-debug.wsb".

    .PARAMETER vGPU / Networking
        Sandbox features.

    .EXAMPLE
        # The package was signed with a self-signed cert (cert.cer next to .msix)
        $wsb = New-MsixSandboxConfig -DropFolder C:\drop -PackageName broken.msix `
                                     -CertPath C:\drop\debug-cert.cer
        Start-Process $wsb
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [string]$DropFolder,
        [Parameter(Mandatory)]
        [string]$PackageName,
        [string]$ModulePath,
        [string]$RuntimePath,
        [string]$CertPath,
        [string]$OutputPath,
        [bool]$vGPU = $true,
        [bool]$Networking = $true
    )

    if (-not (Test-Path $DropFolder)) { throw "DropFolder not found: $DropFolder" }
    $msix = Join-Path $DropFolder $PackageName
    if (-not (Test-Path $msix)) { throw "Package not in drop folder: $msix" }

    if (-not $ModulePath)  { $ModulePath  = $PSScriptRoot }
    if (-not $RuntimePath) {
        # Auto-cache runtime installers if not provided
        $runtimeResult = Update-MsixAppRuntime
        $RuntimePath   = $runtimeResult.Path
    }
    if (-not (Test-Path $RuntimePath)) {
        throw "RuntimePath not found: $RuntimePath. Run Install-MsixAppRuntime first."
    }

    # ── Pre-flight: discover what WindowsAppRuntime channels the package
    #    actually declares as dependencies, and ensure they are cached.
    #    Otherwise the sandbox install fails with HRESULT 0x80073CF3.
    try {
        $required = @(Get-MsixRequiredAppRuntimeChannel -PackagePath $msix)
        if ($required) {
            Write-MsixLog Info "Package requires WindowsAppRuntime channels: $($required -join ', ')"
            $missing = $required | Where-Object {
                -not (Test-Path (Join-Path $RuntimePath "WindowsAppRuntimeInstall-x64-$_.exe"))
            }
            if ($missing) {
                Write-MsixLog Info "Caching missing channels: $($missing -join ', ')"
                Install-MsixAppRuntime -Destination $RuntimePath -Channels $missing | Out-Null
            }
        }
    } catch {
        Write-MsixLog Warning "Could not pre-detect WindowsAppRuntime dependencies: $($_.Exception.Message)"
    }
    if ($CertPath -and -not (Test-Path $CertPath)) {
        throw "CertPath not found: $CertPath"
    }

    if (-not $OutputPath) {
        $OutputPath = Join-Path $DropFolder 'msix-debug.wsb'
    }

    # Cert handling: if specified, copy into drop folder so the sandbox sees it
    $certFileInSandbox = ''
    if ($CertPath) {
        $certLeaf = Split-Path $CertPath -Leaf
        $certTarget = Join-Path $DropFolder $certLeaf
        if ((Resolve-Path $CertPath).Path -ne (Resolve-Path $certTarget -ErrorAction SilentlyContinue).Path) {
            Copy-Item $CertPath $certTarget -Force
        }
        $certFileInSandbox = "C:\msix-drop\$certLeaf"
    }

    # Bootstrap script (PowerShell, runs inside sandbox)
    $bootstrap = Join-Path $DropFolder 'sandbox-bootstrap.ps1'
    $certBlock = if ($certFileInSandbox) { @"

# 3. Trust the self-signed signing certificate so the package will install
Write-Host '==> Trusting signing certificate' -ForegroundColor Cyan
Import-Certificate -FilePath '$certFileInSandbox' -CertStoreLocation 'Cert:\LocalMachine\Root'        | Out-Null
Import-Certificate -FilePath '$certFileInSandbox' -CertStoreLocation 'Cert:\LocalMachine\TrustedPeople' | Out-Null
"@ } else { '' }

    @"
# Auto-generated by New-MsixSandboxConfig
`$ErrorActionPreference = 'Stop'
Set-ExecutionPolicy -Scope Process Bypass -Force

# 1. Install every WindowsAppRuntime channel we cached. The package may
#    pin a specific channel (e.g. Notepad 8.9.x pins 1.4); installing
#    only the latest fails with HRESULT 0x80073CF3 because the runtime
#    versions are SIDE-BY-SIDE -- newer doesn't satisfy older deps.
Write-Host '==> Installing all WindowsAppRuntime channels' -ForegroundColor Cyan
Get-ChildItem 'C:\msix-runtime\WindowsAppRuntimeInstall-x64*.exe' -File |
    Sort-Object Name |
    ForEach-Object {
        Write-Host "    - `$(`$_.Name)" -ForegroundColor DarkGray
        `$proc = Start-Process -FilePath `$_.FullName -ArgumentList '--silent' ``
                              -Wait -PassThru
        if (`$proc.ExitCode -ne 0) {
            Write-Warning "Runtime installer `$(`$_.Name) exited with `$(`$proc.ExitCode)"
        }
    }

# 2. Install DesktopAppInstaller msixbundle (provides the AppInstaller UI
#    handler + winget; required for .msix double-click installs to work
#    in default Win11 Sandbox, which doesn't ship it).
Write-Host '==> Installing DesktopAppInstaller' -ForegroundColor Cyan
try {
    Add-AppPackage -Path 'C:\msix-runtime\Microsoft.DesktopAppInstaller.msixbundle' ``
                   -ForceApplicationShutdown -ErrorAction Stop
} catch {
    Write-Warning "DesktopAppInstaller install failed: `$(`$_.Exception.Message)"
    Write-Warning 'Continuing anyway -- Add-AppPackage of the target .msix may still work.'
}
$certBlock

# 4. Load module and run the debug session
Write-Host '==> Loading MSIX module and starting debug session' -ForegroundColor Cyan
Import-Module 'C:\msix-module\MSIX.psm1' -Force
# Skip everything that needs network; the host already pre-cached anything
# the sandbox needs in C:\msix-runtime.
Initialize-MsixToolchain -Skip Sdk,Psf,Procmon,DebugView,MsixMgr,Runtime | Out-Null

Start-MsixDebugSession ``
    -PackagePath     'C:\msix-drop\$PackageName' ``
    -Install         ``
    -LaunchProcMon   ``
    -LaunchDebugView ``
    -OutputDirectory 'C:\msix-drop\debug-output'

Read-Host 'Press Enter to close the sandbox session'
"@ | Set-Content -Path $bootstrap -Encoding utf8

    # .cmd wrapper because LogonCommand wants a single argv
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
    <MappedFolder>
      <HostFolder>$RuntimePath</HostFolder>
      <SandboxFolder>C:\msix-runtime</SandboxFolder>
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

    .DESCRIPTION
        When -AutoSign is set and the package is unsigned (or its signature
        chain won't validate inside a fresh sandbox), the function:

          1. Generates a self-signed certificate with the manifest's Publisher
             as the subject.
          2. Re-signs the .msix with it.
          3. Exports the public .cer.
          4. Passes the .cer to New-MsixSandboxConfig so the bootstrap installs
             it into LocalMachine\Root + TrustedPeople before installing the
             package.

    .PARAMETER DropFolder / PackageName
        Forwarded to New-MsixSandboxConfig if -ConfigPath isn't given.

    .PARAMETER ConfigPath
        Use an existing .wsb file instead of generating one.

    .PARAMETER AutoSign
        If the package isn't signed (or the signature chain won't validate),
        auto-generate a self-signed cert that matches the manifest Publisher
        and use it to sign the package + trust it in the sandbox.

    .PARAMETER CertPath
        Bring your own .cer file to trust in the sandbox (instead of
        -AutoSign generating one).

    .EXAMPLE
        # Fast path: auto-sign and run
        Start-MsixSandbox -DropFolder C:\drop -PackageName broken.msix -AutoSign
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$DropFolder,
        [string]$PackageName,
        [string]$ConfigPath,
        [switch]$AutoSign,
        [string]$CertPath
    )

    if (-not (Get-Command WindowsSandbox.exe -ErrorAction SilentlyContinue)) {
        throw 'Windows Sandbox not installed. Enable the optional feature: Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All'
    }

    if (-not $ConfigPath) {
        if (-not $DropFolder -or -not $PackageName) {
            throw '-DropFolder and -PackageName are required if -ConfigPath is not given.'
        }

        $effectiveCertPath = $CertPath

        if ($AutoSign -and -not $effectiveCertPath) {
            $msix = Join-Path $DropFolder $PackageName
            $needsSelfSign = (Test-MsixSignature -PackagePath $msix).NeedsSelfSign
            if ($needsSelfSign) {
                Write-MsixLog Info 'Package signature missing/invalid; generating self-signed cert and re-signing.'
                $signed = Invoke-MsixSelfSignAndDebug -PackagePath $msix
                $effectiveCertPath = $signed.CertPath
            } else {
                Write-MsixLog Info 'Package signature is valid; skipping self-sign.'
            }
        }

        $cfgArgs = @{
            DropFolder  = $DropFolder
            PackageName = $PackageName
        }
        if ($effectiveCertPath) { $cfgArgs['CertPath'] = $effectiveCertPath }
        $ConfigPath = New-MsixSandboxConfig @cfgArgs
    }

    if (-not $PSCmdlet.ShouldProcess($ConfigPath, 'Launch Windows Sandbox')) { return }
    Write-MsixLog Info "Launching Windows Sandbox with $ConfigPath"
    Start-Process -FilePath 'WindowsSandbox.exe' -ArgumentList "`"$ConfigPath`""
}


# Backward-compatible plural aliases
Set-Alias Get-MsixDebugRecommendations Get-MsixDebugRecommendation
