# MSIX PowerShell Module — v0.9.0

Enterprise-grade MSIX packaging automation. PSF (TMurgent) injection with the
full RegLegacy + MFR fixup palette, context menus, signing, CI/CD pipeline,
automated compatibility investigation (static + procmon + DebugView trace
parsing + TMEditX-style heuristics), sandbox debug helper, App Attach VHDX/CIM
generator (msixmgr auto-update), Win32 App Isolation, AppData / orphan
helpers, accelerator import, current limitations knowledge base, PSADT-style
standard scripts, VC++ runtime bundling, package compare, and a Pester test
suite.

---

## Why this module

Microsoft's MSIX docs describe a manual workflow for every common conversion
problem: download Procmon, set filters, run the app, eyeball the failures,
hand-edit `config.json`, copy DLLs, repack, sign. This module collapses that
into a small set of idempotent functions you can run from a CI pipeline,
script, sandbox, or PowerShell session.

References this module automates:

- [Package Support Framework overview](https://learn.microsoft.com/windows/msix/psf/package-support-framework)
- [PSF — Working Directory fixup](https://learn.microsoft.com/windows/msix/psf/psf-current-working-directory)
- [PSF — Filesystem Write Permission](https://learn.microsoft.com/windows/msix/psf/psf-filesystem-writepermission)
- [PSF — Launching apps with parameters](https://learn.microsoft.com/windows/msix/psf/psf-launch-apps-with-parameters)
- [PSF — Run scripts to create shortcuts](https://learn.microsoft.com/windows/msix/psf/create-shortcut-with-script-package-support-framework)
- [PSF integration with MPT](https://learn.microsoft.com/windows/msix/psf/psf-integration-with-mpt)
- [Accelerators](https://learn.microsoft.com/windows/msix/toolkit/accelerators)
- [Troubleshoot MSIX containers](https://learn.microsoft.com/windows/msix/manage/troubleshoot-msix-container)
- [Desktop-to-UWP known issues](https://learn.microsoft.com/windows/msix/desktop/desktop-to-uwp-known-issues)
- [Support legacy context menus](https://learn.microsoft.com/windows/msix/packaging-tool/support-legacy-context-menus)
- [Win32 app isolation](https://learn.microsoft.com/windows/win32/secauthz/app-isolation-overview)
- [Know your installer](https://learn.microsoft.com/windows/msix/packaging-tool/know-your-installer)
- [TMurgent PSF fork](https://github.com/TimMangan/MSIX-PackageSupportFramework)

---

## Quick start

> The Windows installed `MSIX` module conflicts with this one's name. Until a
> new gallery version is published, **import by full path**.

```powershell
Import-Module 'C:\temp\msix\MSIX\MSIX.psm1' -Force

# One-time toolchain setup: PSF (TMurgent) + Process Monitor + msixmgr
Initialize-MsixToolchain
```

`Initialize-MsixToolchain` populates the module tools root with:

- TMurgent PSF release (PsfLauncher / PsfRuntime / MFRFixup / StartingScriptWrapper.ps1)
- Sysinternals Process Monitor
- Microsoft msixmgr (App Attach VHDX/CIM generator)

Skip individual components with `-Skip Procmon,MsixMgr`.

---

## Architecture

```
MSIX\
├── MSIX.psd1                Manifest
├── MSIX.psm1                Root module
├── MSIX.Logging.ps1         Write-MsixLog + level/file controls
├── MSIX.Core.ps1            Workspace, process runner, tools auto-detect
├── MSIX.Validation.ps1      Manifest / config / process validators
├── MSIX.Manifest.ps1        XML helpers + namespace registry
├── MSIX.PSF.ps1             Fixup builders + Add-MsixPsfV2 injection engine
├── MSIX.PsfBinaries.ps1     TMurgent PSF + Procmon downloaders
├── MSIX.Signing.ps1         Invoke-MsixSigning (signtool wrapper)
├── MSIX.ContextMenu.ps1     desktop9 (legacy) + desktop4 (modern)
├── MSIX.Pipeline.ps1        Invoke-MsixPipeline — sign-once orchestrator
├── MSIX.Investigation.ps1   Static + procmon analysis + recommendations
├── MSIX.Debug.ps1           Start-MsixDebugSession + sandbox bootstrap
├── MSIX.AppData.ps1         Container / orphan / merged-fs helpers
├── MSIX.Accelerator.ps1     MS Learn accelerator YAML import + apply
├── MSIX.AppAttach.ps1       VHDX/CIM generator (msixmgr)
├── MSIX.AppIsolation.ps1    Win32 App Isolation (opt-in)
├── MSIX.Limitations.ps1     Limitations knowledge base
├── MSIX.Trace.ps1           DebugView / TraceFixup output parser
├── MSIX.Scripts.ps1         PSADT-flavoured standard scripts + signing
├── MSIX.MFR.ps1             Modern File Redirection (TMurgent fork)
├── MSIX.VcRuntime.ps1       VC++ runtime detection + bundling
├── MSIX.Heuristics.ps1      TMEditX-style auto-fixers + Invoke-MsixAutoFix
├── MSIX.Compare.ps1         Compare-MsixPackage (manifest + file + signing diff)
├── templates/               .ps1.tmpl files for standard scripts
├── MSIX.Tests/              Pester test suite (run with Invoke-MsixTests.ps1)
└── docs/                    Per-fixup reference + limitations + know-your-installer
```

---

## Debug a broken MSIX in a sandbox (one-call workflow)

```powershell
Import-Module 'C:\temp\msix\MSIX\MSIX.psm1' -Force

# 1. From the host: spin up Windows Sandbox with the .msix and the module
$cfg = New-MsixSandboxConfig -DropFolder 'C:\drop' -PackageName 'broken.msix'
Start-MsixSandbox -ConfigPath $cfg

# Inside the sandbox the LogonCommand auto-runs:
#   Initialize-MsixToolchain
#   Start-MsixDebugSession -PackagePath ... -Install -LaunchProcMon -LaunchDebugView
```

What `Start-MsixDebugSession` does, even outside the sandbox:

- Runs `Invoke-MsixInvestigation` (static analysis).
- Prints (and saves to `recommended-commands.ps1`) a numbered list of
  copy-paste-ready PowerShell commands — one per finding — that fix the
  detected symptoms.
- Optionally installs the package, launches Procmon (auto-installing it if
  missing), opens DebugView for the trace stream.

Sample output of `RecommendedCommands` for a real package:

```
# [1] [Warning] WorkingDirectory — Executable depends on companion files in VFS\ProgramFilesX64\App but no workingDirectory set.  (App: App)  Evidence: app.ini, settings.cfg
Add-MsixPsfV2 -PackagePath 'C:\drop\broken.msix' `
    -Fixups            @() `
    -WorkingDirectory 'VFS/ProgramFilesX64/App/' `
    -Pfx '<path-to-cert.pfx>' -PfxPassword '<pfx-password>'

# [2] [Warning] FileRedirectionFixup — Writable-looking files shipped inside the VFS payload.  (App: App)  Evidence: app.log, cache.tmp
Add-MsixPsfV2 -PackagePath 'C:\drop\broken.msix' `
    -Fixups @( New-MsixPsfFileRedirectionConfig -Base 'VFS/ProgramFilesX64/App/' -Patterns '.*\.log','.*\.tmp','.*\.cache' ) `
    -Pfx '<path-to-cert.pfx>' -PfxPassword '<pfx-password>'
```

---

## End-to-end pipeline (sign-once)

`Invoke-MsixPipeline` runs every requested stage — publisher update, App
Isolation capability injection, PSF injection — against the same workspace
and signs only at the very end. Add `-OutputPath` for a non-destructive run.

```powershell
$config = @{
    Publisher = 'CN=Contoso, O=Contoso, C=NL'
    PSF = @{
        Fixups = @(
            New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log','.*\.tmp'
            New-MsixPsfEnvVarConfig -Variables @{ APP_MODE = 'packaged' }
        )
        WorkingDirectory = 'VFS/ProgramFilesX64/Contoso/'
    }
    AppIsolation = @{                                                # opt-in
        Capabilities = 'isolatedWin32-promptForAccess','isolatedWin32-userProfileMinimal'
    }
    Signing = @{ Pfx = 'cert.pfx'; PfxPassword = 'P@ss' }
}
Invoke-MsixPipeline -PackagePath app.msix -OutputPath app-fixed.msix -Config $config
```

---

## Investigation

### Static-only (no install required)

```powershell
$report = Invoke-MsixInvestigation -PackagePath app.msix
$report.Findings            | Format-Table
$report.SuggestedFixups     | ConvertTo-Json -Depth 8
$report.RecommendedCommands | Out-File next-steps.ps1
```

### With Process Monitor

```powershell
Initialize-MsixToolchain   # ensures procmon is on disk

$report = Invoke-MsixInvestigation -PackagePath app.msix -WithProcMon `
    -PackageFamilyName 'Contoso.App_8wekyb3d8bbwe' -AppId 'App' `
    -DurationSeconds 30 -ProcessName 'app.exe'
```

### Trace fixup for live diagnostics

```powershell
Add-MsixDiagnosticTrace -PackagePath app.msix -Pfx cert.pfx -PfxPassword 'P@ss'
# Install, run, view DebugView output (Capture > Capture Global Win32, admin).
# DebugView > File > Save (.log) — feed it back in:

$report = Invoke-MsixInvestigation -PackagePath app.msix -TraceLogPath C:\debug\app.log
$report.Findings            | Format-Table
$report.RecommendedCommands | Out-File next-steps.ps1
```

`Get-MsixTraceFailures` and `ConvertFrom-MsixTraceToFindings` are exposed as
standalone helpers — use them on raw DebugView output you've already captured.

---

## Standard scripts (PSADT-flavoured, parameterised)

Generate signed PowerShell scripts from bundled templates and inject them as
PSF startScripts in one call. Customer-specific values are baked in at
generation time, so the same package can carry per-customer state.

```powershell
Get-MsixStandardScripts          # see catalogue (CreateShortcut, CopyIconToAppData, …)

# 1) Generate + sign a script in isolation
New-MsixStandardScript -Name CreateShortcut `
    -Parameters @{ DisplayName='Contoso'; Target='contoso.exe'; Location='Desktop' } `
    -OutputPath C:\src\createshortcut.ps1 `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# 2) Or, generate + sign + inject into an MSIX in one step
Add-MsixStandardScript -PackagePath app.msix -AppId 'App' `
    -Name CreateShortcut `
    -Parameters @{ DisplayName='Contoso'; Target='contoso.exe' } `
    -RunOnce -WaitForScriptToFinish `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Sign an arbitrary script you wrote yourself
Set-MsixScriptSignature -ScriptPath my-bootstrap.ps1 -Pfx cert.pfx -PfxPassword 'P@ss'
```

Bundled templates (also in [templates/](templates)):

| Template                  | What it does                                                  |
|---------------------------|----------------------------------------------------------------|
| `CreateShortcut`          | Desktop / start-menu .lnk pointing at the alias.              |
| `CopyIconToAppData`       | Copy bundled icons to `%APPDATA%` so .lnks survive updates.   |
| `CleanupOldUserData`      | Idempotent removal of legacy paths / registry keys.            |
| `RegisterFileAssociation` | HKCU FTA registration for one or more extensions.              |
| `CustomerSettingsBootstrap` | Bake per-customer JSON into HKCU on first run.               |

---

## App Attach (VHDX / CIM)

```powershell
# VHDX (auto-sized, NTFS, ACLs applied)
New-MsixAppAttachImage -PackagePath app.msix -OutputPath C:\images\app.vhdx

# CIM (Composite Image, no Hyper-V required)
New-MsixAppAttachImage -PackagePath app.msix -OutputPath C:\images\app.cim -FileType cim

# Multiple packages into one image
New-MsixAppAttachImage -PackagePath @('a.msix','b.msix') -OutputPath bundle.vhdx -SizeGB 4

# Inspect a previously-built image
Test-MsixAppAttachImage -ImagePath C:\images\app.vhdx
```

---

## Win32 App Isolation (opt-in)

Adds `rescap:Capability` entries to the manifest so the app runs inside the
Win32 isolation broker (Win 11 24H2+). **Validate first** — many apps break
under isolation.

```powershell
Get-MsixIsolationCapabilities      # documented isolation capability names

Add-MsixAppIsolation -PackagePath app.msix `
    -Capabilities 'isolatedWin32-promptForAccess', 'isolatedWin32-userProfileMinimal' `
    -Pfx cert.pfx -PfxPassword 'P@ss'

Remove-MsixAppIsolation -PackagePath app.msix -Pfx cert.pfx -PfxPassword 'P@ss'
```

Use [Microsoft's Application Capability Profiler](https://github.com/microsoft/win32-app-isolation/releases)
to discover which capabilities your app actually needs.

---

## PSF — fine-grained injection

```powershell
$opts = @(
    New-MsixPsfArguments -AppId 'App' `
        -Arguments '/bootfromsettingshortcut' `
        -WorkingDirectory 'VFS/ProgramFilesX64/Contoso/'
)
$startScript = New-MsixPsfStartScriptConfig -AppId 'App' `
    -ScriptPath 'createshortcut.ps1' -RunOnce -WaitForScriptToFinish

Add-MsixPsfV2 -PackagePath app.msix `
    -Fixups          @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' ) `
    -AppOptions      @( $opts; $startScript ) `
    -AdditionalFiles 'C:\src\createshortcut.ps1','C:\src\Contoso Expenses.lnk','C:\src\contoso.ico' `
    -OutputPath      'C:\out\app-fixed.msix' `
    -SkipSigning                                       # chain another stage, sign at the end
```

`-AdditionalFiles` are copied into the same folder as the executable; if any
`startScript`/`endScript` is in `-AppOptions`, `StartingScriptWrapper.ps1`
is copied automatically from the PSF tools root.

Per-fixup reference: [docs/fixup-FileRedirection.md](docs/fixup-FileRedirection.md),
[docs/fixup-RegLegacy.md](docs/fixup-RegLegacy.md),
[docs/fixup-EnvVar.md](docs/fixup-EnvVar.md),
[docs/fixup-Trace.md](docs/fixup-Trace.md),
[docs/fixup-WorkingDirectory.md](docs/fixup-WorkingDirectory.md).

---

## Working with packaged AppData

```powershell
Get-MsixContainerAppData -PackageName 'Contoso.App'
# PackageRoot, VirtualLocal, VirtualRoaming, VirtualTemp

Get-MsixOrphanedAppData | Where-Object SizeMB -gt 1
# Common 2023+ scenario: legacy installer wrote to %AppData%\Roaming during conversion

Copy-MsixHostAppDataIntoPackage -SourcePath "$env:APPDATA\ContosoLegacy" -PackageName 'Contoso.App'

Invoke-MsixContainerCommand -PackageName 'Contoso.App' -Command 'cmd.exe'
Invoke-MsixContainerCommand -PackageName 'Contoso.App' -Command 'regedit.exe'

Get-MsixPackageStorageSummary -PackageName 'Contoso.App'
```

---

## Limitations / know-your-installer

```powershell
Get-MsixLimitations                  # full table
Get-MsixLimitations -Severity blocker
Get-MsixLimitations -ExcludeVendor   # only Microsoft-documented entries

Test-MsixAgainstLimitations -PackagePath app.msix
```

See [docs/limitations.md](docs/limitations.md) and
[docs/know-your-installer.md](docs/know-your-installer.md).

---

## Accelerators

```powershell
$accel = Import-MsixAccelerator -Path .\line.yaml
$accel.SuggestedFixups
$accel.AppOptions
$accel.Capabilities; $accel.Dependencies; $accel.ManualNotes

Invoke-MsixAccelerator -PackagePath line.msix -AcceleratorPath line.yaml `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

`Install-Module powershell-yaml` for full YAML support; otherwise a minimal
fallback parser handles top-level scalar keys.

---

## Context menus

```powershell
# Legacy IContextMenu (Win 11 21H2+) — needs com + desktop9 namespaces
Add-MsixLegacyContextMenu -PackagePath app.msix `
    -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
    -Clsid       '{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}' `
    -DisplayName 'My Context Menu' `
    -FileTypes   '*', '.log', 'Directory' `
    -MenuType    ContextMenu `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Modern IExplorerCommand (recommended for new shell extensions)
Add-MsixFileExplorerContextMenu -PackagePath app.msix `
    -AppId     'App' `
    -VerbId    'open' `
    -VerbClsid '{XXXXXXXX-...}' `
    -FileTypes '.txt', '.log'
```

---

## Tools resolution

`Get-MsixToolsRoot` searches in order:

1. `$env:MSIX_TOOLS_PATH` — explicit override (must contain `Tools\MakeAppx.exe`)
2. The module folder itself (if you populate `MSIX\Tools\` and `MSIX\psf\`)
3. The highest-versioned sibling folder (e.g. `..\0.56\`)
4. Windows 10/11 SDK install paths

Set with `Set-MsixToolsRoot -Path C:\path\to\toolsroot` to lock for the session.

`Initialize-MsixToolchain` populates `Tools-root\psf` (TMurgent) and
`Tools-root\procmon` automatically.

---

## CI/CD usage

The whole API is non-interactive. There are no `Read-Host` or `PromptForChoice`
calls anywhere; functions that previously prompted (`Add-MsixAlias`,
`Remove-MsixStartMenuEntry`) take `-AppIds` or `-All` instead.

```powershell
Import-Module .\MSIX\MSIX.psm1 -Force
Initialize-MsixToolchain | Out-Null

$report = Invoke-MsixInvestigation -PackagePath $env:BUILD_OUTPUT
if ($report.Findings | Where-Object Severity -eq 'Error') {
    throw 'Compatibility issues detected; aborting build.'
}
Invoke-MsixPipeline -PackagePath $env:BUILD_OUTPUT -OutputPath $env:BUILD_FIXED -Config @{
    PSF     = @{ Fixups = $report.SuggestedFixups }
    Signing = @{ Pfx = $env:CODE_SIGN_PFX; PfxPassword = $env:CODE_SIGN_PWD }
}
```

---

## TMEditX-style auto-fixers (v0.9)

A curated set of one-shot fixers modelled on Tim Mangan's TMEditX commercial
tool — all opt-in and PowerShell-native. Use `Invoke-MsixAutoFix` to chain
them with a single signing pass at the end.

### Heuristic findings (read-only)

```powershell
$report = Invoke-MsixInvestigation -PackagePath app.msix
# Findings now include uninstaller artefacts, autostart Run keys, missing
# AppExecutionAlias suggestions, and missing VC++ runtimes — surfaced
# automatically alongside the existing static checks.

# Or call them individually:
Get-MsixUninstallerCandidates -PackagePath app.msix
Get-MsixRunKeyEntries         -PackagePath app.msix
Get-MsixAliasCandidates       -PackagePath app.msix
Get-MsixVcRuntimeReferences   -PackagePath app.msix
Get-MsixHeuristicFindings     -PackagePath app.msix    # roll-up
```

### Individual fixers

```powershell
# Strip uninst*/setup* leftovers
Remove-MsixUninstallerArtifacts -PackagePath app.msix -Pfx cert.pfx -PfxPassword 'P@ss'

# Add capabilities (standard or rescap, looked up against catalogue)
Get-MsixKnownCapabilities | Format-Table
Add-MsixCapability -PackagePath app.msix `
    -Names runFullTrust, internetClient, broadFileSystemAccess `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Bundle missing VC++ runtimes (architecture-aware)
Add-MsixVcRuntimeBundle -PackagePath app.msix `
    -SourceFolder 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Redist\MSVC\14.42.34433\x64\Microsoft.VC143.CRT' `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Splash image while a slow startScript runs
Add-MsixSplashScreen -PackagePath app.msix -ImagePath logo.png -AppId 'App' `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Bump the package version
Update-MsixPackageVersion -PackagePath app.msix -Component Build -KeepLastZero $true `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

### One-call orchestrator (sign-once)

```powershell
Invoke-MsixAutoFix -PackagePath app.msix `
    -OutputPath app-fixed.msix `
    -RemoveUninstallers `
    -VersionBumpComponent Build `
    -Capabilities runFullTrust, internetClient `
    -PsfFixups @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' ) `
    -VcRuntimeSourceFolder 'C:\…\VC143.CRT' `
    -SplashImagePath logo.png -SplashAppId 'App' `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Preview which stages would fire, no mutation, no signing:
Invoke-MsixAutoFix -PackagePath app.msix -RemoveUninstallers -DryRun
```

---

## Modern File Redirection (MFR)

`MFRFixup.dll` ships with TMurgent's fork and replaces classic
`FileRedirectionFixup` with finer controls (ILV-aware, COW, Traditional vs
Local known-folder catalogue).

```powershell
Get-MsixMfrKnownFolders                 # all three lists
Get-MsixMfrKnownFolders -Mode Local     # ThisPCDesktopFolder, Personal, …

$rule = New-MsixMfrTraditionalRule `
    -KnownFolder 'ProgramFilesX64' `
    -RelativePath 'Contoso/logs' `
    -Patterns '.*\.log' `
    -Cow enablePe -IlvAware $true

$mfr = New-MsixPsfMfrConfig -TraditionalRules @($rule) -GlobalIlvAware $true
Add-MsixPsfV2 -PackagePath app.msix -Fixups @($mfr) -Pfx cert.pfx -PfxPassword 'P@ss'
```

`MFRFixup` shows up in the PSF binary registry alongside `FileRedirectionFixup`,
so `Add-MsixPsfV2` will copy `MFRFixup32.dll`/`MFRFixup64.dll` into the
package automatically when the fixup config references it.

---

## RegLegacyFixups — full type palette (v0.9)

`New-MsixPsfRegLegacyConfig` now supports all four documented types:

```powershell
# Modify access mask (the v0.6 default)
New-MsixPsfRegLegacyConfig -Type ModifyKeyAccess -Hive HKCU `
    -Access Full2MaxAllowed -Patterns 'SOFTWARE\App\*'

# Pretend a key doesn't exist (legacy uninstaller probes)
New-MsixPsfRegLegacyConfig -Type FakeDelete -Hive HKLM `
    -Patterns 'SOFTWARE\App\Uninstall'

# Suppress reads of explicitly-deleted keys
New-MsixPsfRegLegacyConfig -Type DeletionMarker -Hive HKLM `
    -Patterns 'SOFTWARE\App\Old'

# Redirect HKLM writes to per-user HKCU
New-MsixPsfRegLegacyConfig -Type Hklm2Hkcu -Hive HKLM `
    -Patterns 'SOFTWARE\App\*'
```

---

## Compare two packages

```powershell
$diff = Compare-MsixPackage -LeftPath old.msix -RightPath new.msix
$diff.HasChanges
$diff.ManifestChanges | Format-Table
$diff.FileChanges     | Format-Table
$diff.SigningChanges  | Format-Table
```

Files are compared by SHA-256 hash and size. `[Content_Types]`,
`AppxBlockMap.xml` and `AppxSignature.p7x` are excluded by default
(override with `-ExcludePathPattern @()`).

Useful as a CI gate:
```powershell
if ((Compare-MsixPackage -LeftPath $publishedMsix -RightPath $candidateMsix).HasChanges) {
    throw 'Package contents diverged from the published baseline.'
}
```

---

## Tests

Pester v5 unit tests live under `MSIX.Tests\`. They cover pure functions
(builders, manifest helpers, validation, trace parser, recommendations,
limitations, standard scripts) and intentionally do **not** require the
toolchain (PSF / Procmon / msixmgr) to be installed — so CI runners can
execute them against just PowerShell.

```powershell
# One-time
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser

# Run everything
.\MSIX.Tests\Invoke-MsixTests.ps1

# Run by tag
.\MSIX.Tests\Invoke-MsixTests.ps1 -Tag Builders
.\MSIX.Tests\Invoke-MsixTests.ps1 -Tag Trace,Recommendations
```

NUnit-format results are written to `MSIX.Tests\TestResults.xml`.

---

## Idempotency

All functions are designed to be re-runnable:

- PSF is not re-injected if already present
- Manifest changes are checked before writing (no-op on match)
- Context menu / capability entries are deduplicated
- Signing only occurs when configured and not skipped

---

## License

Same as upstream PSF tooling. PSF binaries fetched at runtime are property of
their respective owners (Microsoft / Tim Mangan).
