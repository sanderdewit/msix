# MSIX PowerShell Module — v0.12.0

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

> The maintainer owns the `MSIX` name on PSGallery. Until v0.12.0 is published
> there, the installed community module may shadow this one — **import by full
> path** to be safe, or uninstall the old version first.

```powershell
Import-Module 'C:\temp\msix\MSIX\MSIX.psm1' -Force

# One-time toolchain setup: SDK tools (MakeAppx + signtool) + PSF (TMurgent)
# + Process Monitor + msixmgr — all from official sources, on-demand.
Initialize-MsixToolchain
```

`Initialize-MsixToolchain` populates the module folder with:

- **Microsoft.Windows.SDK.BuildTools** (signed MakeAppx.exe + signtool.exe
  pulled from NuGet — no Visual Studio / Windows SDK install required)
- TMurgent PSF release (PsfLauncher / PsfRuntime / MFRFixup / StartingScriptWrapper.ps1)
- Sysinternals Process Monitor
- Microsoft msixmgr (App Attach VHDX/CIM generator)

Skip individual components with `-Skip Sdk,Procmon,MsixMgr`. Each piece
also has its own `Install-Msix*` / `Update-Msix*` / `Get-Msix*Version`
trio if you'd rather drive them yourself.

> **Just need MakeAppx + signtool?** `Install-MsixSdkTools` does only that.
> The error you used to get when no toolchain was on disk now points at it.

### Inspect a package without unpacking

```powershell
# Polymorphic: works on .msix, .appx, .msixbundle, .appxbundle, an unpacked
# folder, or an AppxManifest.xml directly.
$m = Get-MsixManifest -Path C:\drop\app.msix
$m.Package.Identity.Name
$m.Package.Applications.Application.Id
```

### Don't sign the output

Every editing cmdlet accepts both `-SkipSigning` and `-NoSign` (alias). Use
either when you're chaining edits and want to sign once at the end, or when
you're staging an unsigned .msix for someone else's signing pipeline.

```powershell
Add-MsixCapability -PackagePath app.msix -Names runFullTrust -NoSign
Set-MsixFileSystemWriteVirtualization -PackagePath app.msix -NoSign
# Sign the final result yourself:
Invoke-MsixSigning -PackagePath app.msix -Pfx cert.pfx -PfxPassword 'P@ss'
```

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
├── MSIX.Heuristics.ps1      TMEditX-style auto-fixers + Invoke-MsixAutoFix(FromAnalysis)
├── MSIX.Detection.ps1       Read-only scanners (fonts, desktop shortcuts, capability hints)
├── MSIX.ManifestExtensions.ps1  Manifest-only fixers (PSF alternatives)
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

## What's new in v0.12.0

| Area | Change |
|---|---|
| **Renamed** | `Invoke-MsixCmd` → `Invoke-MsixCommand` (old name kept as alias) |
| **Renamed** | `Get-PublisherIdFromPublisher` → `Get-MsixPublisherId` (old name kept as alias) |
| **Bug fix** | `Add-MsixAlias` completely rewritten — now correctly wires `uap3:AppExecutionAlias` without invalid attributes |
| **Bug fix** | `Add-MsixPsfV2` startScript wrapper (`StartingScriptWrapper.ps1`) always copied when a startScript/endScript is configured, even without additional files |
| **Bug fix** | `Get-MsixCompatibilityReport` now surfaces registry uninstall keys from `Registry.dat` in addition to file-system artifacts |
| **Bug fix** | Signing failures now throw a terminating error (was `Write-Error`), so `-ErrorAction Stop` and `try/catch` work correctly |
| **Bug fix** | `Add-MsixPsfV2` — `$app.Executable` property access replaced with `GetAttribute`/`SetAttribute` throughout; PowerShell's XML adapter silently creates a child element on write instead of updating the attribute, corrupting the manifest on a second PSF pass |
| **Bug fix** | `Add-MsixPsfV2` — null-safe fallback when `Executable` attribute is missing (scans workspace for first non-PSF `.exe`) |
| **Bug fix** | `Test-MsixManifest` leaked its `$true` return value into the pipeline at every call site; all callers now use `$null = Test-MsixManifest ...` |
| **Bug fix** | `sharedUserCertificates` (and `documentsLibrary`, `picturesLibrary`, etc.) correctly emitted as `<uap:Capability>` — the plain `<Capability>` element only accepts 5 names per schema |
| **Bug fix** | `Invoke-MsixAutoFixFromAnalysis` — null-guard on `$f.Category` prevents crash when non-finding objects flow through the Findings array |
| **Bug fix** | `Add-MsixPsfV2` — `Get-MsixManifestApplications` result now wrapped with `@()` at the call site; PowerShell unrolls a single `XmlElement` from the function pipeline into a scalar, making `$apps[0]` resolve via the XmlNode PS type adapter (child-node indexing) instead of array indexing — causing `InvokeMethodOnNull` on single-application packages |
| **Bug fix** | `Add-MsixShellVerbExtension` — FTA element changed from `uap:FileTypeAssociation` to `uap3:FileTypeAssociation` (substitution-group child of the `uap:Extension` container); this is required to host `uap3:SupportedVerbs`. The Extension wrapper must remain `uap:Extension` — `uap3:Extension` does not support the `windows.fileTypeAssociation` category and causes the same `{shell}Name` schema error. MinBuild bumped to 21301 for `uap3:SupportedVerbs` schema recognition |
| **Bug fix** | `Get-MsixShellContextMenuEntries` elevated path — `Test-Path` / `Get-ChildItem` / `Get-ItemProperty` calls on registry paths containing `*` (for `HKCR\*\shell`) now use `-LiteralPath`; without it PowerShell's registry provider treats `*` as a wildcard, causing `Get-ChildItem` to return the `shell` key objects themselves (PSChildName=`shell`) rather than their verb children, producing a false-positive `VerbName=shell` even in elevated mode |
| **Bug fix** | `Add-MsixShellVerbExtension` — `SetAttribute('Name', $slug -replace …, '')` inside a method-call was parsed as 3 arguments by PowerShell (the `-replace` comma consumed as argument separator), silently calling the `SetAttribute(localName, namespaceURI, value)` overload and producing `xmlns:d6p1="<slug>"` / `d6p1:Name=""` in the manifest (MakeAppx error `{<slug>}Name not defined`); fixed by pre-computing the slug in a separate variable |
| **Bug fix** | `Get-MsixShellContextMenuEntries` elevated path — shell verb keys carrying an `ExplorerCommandHandler` value (COM-delegating verbs) are now classified as `ShellExt` instead of `ShellVerb`; they require `desktop9:fileExplorerClassicContextMenuHandler`, not `uap3:SupportedVerbs`, and their DLL path is resolved from the CLSID's `InProcServer32` via the new `_MsixRegPathToVfsRelative` helper |
| **Bug fix** | `Add-MsixLegacyContextMenu`, `Add-MsixFileExplorerContextMenu`, `Add-MsixComServerExtension` — CLSID format corrected: `com:Class Id` (ST_GUID schema type) must be a bare GUID without braces (e.g. `B298D29A-A6ED-11DE-BA8C-A68E55D89593`), while `desktop9:ExtensionHandler Clsid` and `desktop4:Verb Clsid` (ST_CLSID schema type) must include braces (`{B298D29A-...}`); two separate variables `$ClsidBare` / `$ClsidBraced` now used to satisfy both constraints |
| **Bug fix** | `Add-MsixLegacyContextMenu` — `com:Extension` and `desktop9:Extension` now inserted into the Application's `<Extensions>` child element instead of a separate Package-level `<Extensions>` node; the previous code appended to `$manifest.Package.Extensions`, creating a second `<Extensions>` block that made MakeAppx reject the manifest |
| **Bug fix** | `Add-MsixLegacyContextMenu` — DLL path sanitisation added: if `-ShellExtDll` is passed with an MSIX folder-variable prefix (e.g. `[{ProgramFilesX64}]\App\foo.dll`), it is now normalised to `VFS\ProgramFilesX64\App\foo.dll` before it is written to the `com:Class Path` attribute; previously the raw registry format reached the manifest and caused a validation error |
| **Bug fix** | `Set-MsixFileSystemWriteVirtualization`, `Set-MsixRegistryWriteVirtualization`, `Add-MsixLoaderSearchPathOverride`, `Add-MsixComServerExtension` — extensions are now written into the Application's `<Extensions>` node (Application-level) instead of creating a separate Package-level `<Extensions>` block; an optional `-AppId` parameter has been added to all four functions (defaults to the first Application when omitted) |
| **Bug fix** | `_MsixGetOrCreateApplicationExtensions` — now accepts an optional `$AppId` (defaults to first Application when empty) and uses `SelectSingleNode('*[local-name()="Extensions"]')` instead of the `$app.Extensions` property shorthand to detect the existing Extensions child node reliably regardless of namespace-declaration ordering; all callers updated accordingly |
| **Bug fix** | `Set-MsixFileSystemWriteVirtualization`, `Set-MsixRegistryWriteVirtualization` — completely rewritten to target `<Package><Properties>` instead of `<Extensions>`; the MSIX schema only allows `windows.filesystemwritevirtualization` / `windows.registrywritevirtualization` in Properties (as `desktop6:FileSystemWriteVirtualization` / `desktop6:RegistryWriteVirtualization` elements with value `enabled`/`disabled`), placing them in Application-level or Package-level Extensions is a schema violation; optional excluded paths now use the `virtualization` namespace also in Properties; `-AppId` parameter removed (Properties is package-scope); `rescap:Capability Name="unvirtualizedResources"` is now added automatically (required by the schema — MakeAppx rejects the manifest without it); default action changed from enabled→**disabled** (MSIX enables write virtualization by default; the standard conversion fix is to disable it); `-Disable` switch replaced with `-Enable`; `$ExcludedDirectories` defaults to `$(KnownFolder:LocalAppData)` + `$(KnownFolder:RoamingAppData)` matching the MSIX Packaging Tool reference manifest; excluded dirs are always written alongside the flag (commercial tool does both together) |
| **Bug fix** | `Get-MsixShellContextMenuEntries` — MSIX registry-variable DLL paths (`[{ProgramFilesX64}]\app\foo.dll`, etc.) now resolved correctly via new `_MsixRegPathToVfsRelative` helper; the previous `_MsixAbsoluteToVfsRelativeDirect` only handled plain absolute paths and left `VfsDllPath` null for all packages that store paths in MSIX folder-variable format |
| **Bug fix** | `Invoke-MsixAutoFixFromAnalysis` — `AddShellVerbExtension` autofix stage removed; `uap3:SupportedVerbs` is for Open-With file-type associations, NOT shell context menus. Plain command shell verbs have no CLSID so cannot use `desktop9:fileExplorerClassicContextMenuHandler` without a COM surrogate wrapper — reported as manual-fix required. `ExplorerCommandHandler` verbs (which have a CLSID) are classified as `ShellExt` and auto-fixed via `desktop9` through `AddLegacyContextMenu` |
| **Bug fix** | `Get-MsixShellContextMenuEntries` — non-elevated shell verb scan (`Classes\*\shell\<verb>` string regex) removed; REGF format stores key names as individual NK records so the regex falsely matched the intermediate `shell` key name itself (producing `VerbName=shell`); shell verb detection now requires elevation (shellex handler detection via string scan is retained as it is reliable) |
| **New detection** | `Get-MsixCompatibilityReport` detects three registry-based patterns invisible outside the MSIX container: `ShellVerb` (`Classes\*\shell\<verb>`, Warning), `ShellExt` (`Classes\*\shellex\ContextMenuHandlers\`, Error), `ComServer` (CLSID InProcServer32 with bundled DLL, Info); plus `NestedPackage` (Warning) when `.msix`/`.appx` files are found inside the package |
| **New functions** | `Get-MsixShellContextMenuEntries` — shell verb + shellex scanner with VfsDllPath resolution; `Get-MsixComServerEntries` — COM CLSID registry scanner; `Get-MsixNestedPackageCandidates` — nested package file scanner |
| **New functions** | `Add-MsixShellVerbExtension` — adds Open-With file-type associations via `uap3:FileTypeAssociation + uap3:SupportedVerbs` (for making an app appear in the Windows Open-With dialog for specific extensions — **not** for shell context menu extensions); `Add-MsixComServerExtension` — declares COM `InProcessServer` entries via `com:Extension` (windows.comServer) |
| **Auto-fix (ShellVerb)** | Plain command shell verbs under `HKCR\*\shell\<verb>\command` have no CLSID and cannot be auto-fixed via `desktop9:fileExplorerClassicContextMenuHandler`. Reported as Warning with manual-fix guidance: convert to COM surrogate, then call `Add-MsixLegacyContextMenu` |
| **Auto-fix (ShellExt)** | Stage `AddLegacyContextMenu`: when elevated and DLL resolves to VFS path, calls `Add-MsixLegacyContextMenu` (desktop9 surrogate-server) |
| **Auto-fix (ComServer)** | Stage `AddComServer`: for bundled in-process COM servers (InProcServer32 DLL inside VFS), calls `Add-MsixComServerExtension`; CLSIDs already handled by `AddLegacyContextMenu` (SurrogateServer) are excluded |
| **Manifest cross-check** | Findings suppressed when the manifest already declares the corresponding extension: desktop9 for ShellExt, `windows.fileTypeAssociation`/`windows.fileExplorerContextMenus` for ShellVerb, existing `com:Class` elements for ComServer |
| **New stages** | `Invoke-MsixAutoFix -RemoveDesktopShortcuts` and `-AddFontExtension` |
| **New mappings** | `Invoke-MsixAutoFixFromAnalysis` now handles `DesktopShortcuts`, `ManifestFix:SharedFonts`, `CapabilityHints`, and `UninstallRegistry` findings |
| **New property** | `$report.SuggestedManifestFixes` lists manifest alternatives alongside `SuggestedFixups` |
| **Architecture** | 14 editing cmdlets refactored to the shared `_MsixMutateManifest` helper — no more copy-pasted unpack/repack/sign boilerplate |
| **Logging** | All `Write-Host` calls replaced with `Write-Information` (stream 6) — module output is now CI/pipeline-capturable |
| **PSF builders** | `New-MsixPsfDynamicLibraryConfig`, `New-MsixPsfWaitForDebuggerConfig` |

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

### Additional PSF typed builders

```powershell
# DynamicLibraryFixup — maps DLL names to package-relative paths
$dlf = New-MsixPsfDynamicLibraryConfig -Mappings @(
    @{ name = 'mylib.dll'; filepath = 'VFS/ProgramFilesX64/App/lib/mylib.dll' }
    @{ name = 'util.dll';  filepath = 'VFS/ProgramFilesX64/App/lib/util.dll'  }
)
Add-MsixPsfV2 -PackagePath app.msix -Fixups @($dlf) -Pfx cert.pfx -PfxPassword 'P@ss'

# WaitForDebuggerFixup — halts launch until a debugger attaches (strip before shipping)
$wfd = New-MsixPsfWaitForDebuggerConfig -Processes 'app.exe','worker.exe'
Add-MsixPsfV2 -PackagePath app.msix -Fixups @($wfd) -SkipSigning
```

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

All module logging now uses `Write-Information` (stream 6) instead of
`Write-Host`, so output is fully capturable by CI pipelines and PowerShell
transcripts. Redirect or suppress it with the standard `-InformationAction`
preference:

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
    -RemoveDesktopShortcuts `          # NEW in v0.12
    -AddFontExtension `                # NEW in v0.12 — registers .ttf/.otf/.ttc via uap4
    -VersionBumpComponent Build `
    -Capabilities runFullTrust, internetClient `
    -PsfFixups @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' ) `
    -VcRuntimeSourceFolder 'C:\…\VC143.CRT' `
    -SplashImagePath logo.png -SplashAppId 'App' `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Preview which stages would fire, no mutation, no signing (-WhatIf also supported):
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

## Auto-fix from analysis (one-call)

`Invoke-MsixAutoFixFromAnalysis` is the connect-the-dots layer between
investigation and remediation. Hand it the report from
`Invoke-MsixInvestigation` (or `Get-MsixCompatibilityReport`) and it runs
the right fixer for every finding, signing once at the end.

```powershell
$report = Invoke-MsixInvestigation -PackagePath app.msix
$report.Findings | Format-Table Severity, Category, Symptom

# Apply everything actionable. Some categories need extra inputs:
Invoke-MsixAutoFixFromAnalysis -Report $report `
    -VcRuntimeSourceFolder 'C:\…\VC143.CRT' `
    -StartupTaskAppId 'App' -StartupTaskName 'Contoso' `
    -LoaderPaths 'VFS/ProgramFilesX64/App/lib' `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Preview only, no mutation:
Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
```

| Finding category | Fixer it runs |
|---|---|
| `UninstallerArtifact` / `UninstallRegistry` | `Remove-MsixUninstallerArtifacts` (files + Registry.dat) |
| `DesktopShortcuts` | `Remove-MsixDesktopShortcuts` |
| `ManifestFix:SharedFonts` | `Add-MsixFontExtension` |
| `CapabilityHints` | `Add-MsixCapability` (heuristic from PE imports) |
| `VcRuntime` | `Add-MsixVcRuntimeBundle` (needs `-VcRuntimeSourceFolder`) |
| `ManifestFix:FileSystemWriteVirtualization` | `Set-MsixFileSystemWriteVirtualization` |
| `ManifestFix:RegistryWriteVirtualization` | `Set-MsixRegistryWriteVirtualization` |
| `ManifestFix:StartupTask` | `Add-MsixStartupTask` (needs `-StartupTask*`) |
| `ManifestFix:LoaderSearchPathOverride` | `Add-MsixLoaderSearchPathOverride` (needs `-LoaderPaths`) |
| `FileRedirectionFixup` (PSF) | `Add-MsixPsfV2` (uses `$Report.SuggestedFixups`) |

By default `-PreferManifestOverPsf $true` skips PSF for symptoms already
covered by a manifest fix (no double-fixing).

The report object now also carries a `SuggestedManifestFixes` property that
lists manifest alternatives for PSF findings (e.g. the manifest
`FileSystemWriteVirtualization` alternative for `FileRedirectionFixup`).
Use it to compare approaches before committing:

```powershell
$report = Invoke-MsixInvestigation -PackagePath app.msix
$report.SuggestedFixups         | ConvertTo-Json -Depth 8   # PSF path
$report.SuggestedManifestFixes  | Format-Table               # manifest alternatives
```

---

## Manifest-only fixers (alternatives to PSF)

The AppX manifest schema has matured a lot since PSF was first written.
Several runtime issues that PSF traditionally addressed via DLL injection
can now be fixed by adding the right manifest extension — faster at runtime,
no foreign DLLs in the package, and survives Windows updates more cleanly.

| Cmdlet | Schema | Min OS | Replaces |
|---|---|---|---|
| `Set-MsixFileSystemWriteVirtualization` | desktop6 | 19041 | PSF FileRedirection / MFR (broad case) |
| `Set-MsixRegistryWriteVirtualization`   | desktop6 | 19041 | RegLegacy `Hklm2Hkcu` (broad case) |
| `Set-MsixInstalledLocationVirtualization` | uap10 | 19041 | FRF + explicit update-time policy |
| `Add-MsixLoaderSearchPathOverride` | uap6 | 17134 | DynamicLibraryFixup (simple cases) |
| `Add-MsixFirewallRule` | desktop2 | 15063 | post-install `netsh` / `New-NetFirewallRule` |
| `Add-MsixProtocolHandler` | uap | any | host-side HKCU protocol script |
| `Add-MsixFileTypeAssociation` | uap | any | host-side HKCU FTA script |
| `Add-MsixStartupTask` | uap5 | 15063 | HKLM/HKCU `\Run` keys (which don't fire under MSIX) |

All cmdlets:

- Add the required namespace declaration to the manifest (idempotent)
- Bump `MaxVersionTested` to the documented minimum build automatically
- Repack the package and (unless `-SkipSigning`) re-sign it
- Support `-OutputPath` for non-destructive runs

### Examples

```powershell
# Per-user write redirection — replaces FileRedirectionFixup for the broad case
Set-MsixFileSystemWriteVirtualization -PackagePath app.msix `
    -ExcludedDirectories 'VFS/Common AppData/MyApp/SharedCache' `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Explicit update policy when redirecting writes to the install dir
Set-MsixInstalledLocationVirtualization -PackagePath app.msix `
    -ModifiedItems keep -DeletedItems reset -AddedItems keep `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Replace DynamicLibraryFixup with a manifest declaration
Add-MsixLoaderSearchPathOverride -PackagePath app.msix `
    -Paths 'VFS/ProgramFilesX64/App/lib','VFS/ProgramFilesX64/App/bin' `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Lifecycle-bound firewall rule
Add-MsixFirewallRule -PackagePath app.msix -AppId App `
    -Executable 'VFS/ProgramFilesX64/App/server.exe' `
    -Direction in -Protocol TCP -LocalPort 5000-5010 `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Modern autostart — fires properly for packaged apps
Add-MsixStartupTask -PackagePath app.msix -AppId App `
    -TaskId ContosoStartup -DisplayName 'Contoso' -Enabled $true `
    -Pfx cert.pfx -PfxPassword 'P@ss'

# Custom protocol + file association
Add-MsixProtocolHandler      -PackagePath app.msix -AppId App `
    -Name contoso -DisplayName 'Contoso Launcher' `
    -Pfx cert.pfx -PfxPassword 'P@ss'

Add-MsixFileTypeAssociation  -PackagePath app.msix -AppId App `
    -Name contosodoc -FileTypes '.cdoc','.cdocx' -DisplayName 'Contoso Document' `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

### How investigation surfaces these

`Get-MsixHeuristicFindings` (and therefore `Invoke-MsixInvestigation`) now
proposes the manifest fix when the runtime symptoms match:

| Symptom | Suggested fix |
|---|---|
| Writes to install dir | `Set-MsixFileSystemWriteVirtualization` |
| HKLM writes | `Set-MsixRegistryWriteVirtualization` |
| HKLM/HKCU `\Run` autostart entries | `Add-MsixStartupTask` |
| LoadLibrary failures (trace) | `Add-MsixLoaderSearchPathOverride` |

These are surfaced **as alternatives** to PSF, not replacements — choose
based on your minimum supported Windows build and the specificity you need
(PSF fixups give finer-grained pattern matching; manifest virtualization is
broader but free of the launcher overhead).

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
