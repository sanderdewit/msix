# MSIX PowerShell Module — v0.73.0

Enterprise-grade MSIX packaging automation for mission-critical environments.
Covers the full conversion lifecycle: static + runtime investigation, PSF
injection, manifest editing, signing (local / Azure Trusted Signing / Key
Vault), CI/CD pipeline orchestration, sandbox debugging, App Attach, Win32
App Isolation, deployment-script templates, and a comprehensive Pester test
suite.

> **Security note** — this module is designed for use in high-assurance
> environments (DoD, NATO, financial, healthcare). All downloaded toolchain
> binaries are Authenticode-verified against a trusted-publisher allowlist
> before use. Signing secrets are kept in `[SecureString]` throughout; they
> never appear in log output, recommendation text, or on the process command
> line (with the exception of the `SignTool` backend which emits a `Write-Warning`
> when this happens).

---

## Table of contents

- [Why this module](#why-this-module)
- [Quick start](#quick-start)
- [Architecture](#architecture)
- [Investigation & auto-fix](#investigation--auto-fix)
- [PSF injection](#psf-injection)
- [Signing backends](#signing-backends)
- [Standard scripts (PSADT)](#standard-scripts-psadt)
- [Win32 App Isolation](#win32-app-isolation)
- [Manifest-only fixers](#manifest-only-fixers)
- [Pipeline orchestrator](#pipeline-orchestrator)
- [App Attach (VHDX / CIM)](#app-attach-vhdx--cim)
- [Context menus](#context-menus)
- [Debug & sandbox](#debug--sandbox)
- [CI/CD](#cicd)
- [Tests](#tests)
- [What's new in v0.73](#whats-new-in-v073)
- [Release history](#release-history)
- [License](#license)

---

## Why this module

Microsoft's MSIX docs describe a manual workflow for every common conversion
problem: download Procmon, set filters, run the app, eyeball the failures,
hand-edit `config.json`, copy DLLs, repack, sign. This module collapses that
into a small set of idempotent, pipeline-safe functions.

**Key design principles**

| Principle | How it's implemented |
|---|---|
| **Sign once** | `Invoke-MsixPipeline` unpacks, edits, repacks, then signs a single scratch copy. The original is never overwritten until signing succeeds. |
| **No secrets on disk** | `PfxPassword` is `[SecureString]` everywhere; `Get-MsixDebugRecommendation` emits `Read-Host -AsSecureString` placeholders, never the real value. |
| **No unverified binaries** | Every toolchain download (PSF, Procmon, msixmgr, SDK tools) is Authenticode-verified before use. |
| **WhatIf everywhere** | All mutating cmdlets support `-WhatIf`. Pack/unpack still runs so you can preview the result; signing and the final file replacement are skipped. |
| **Idempotent** | All manifest mutators are safe to run twice — they check before writing. |

References this module automates:

- [Package Support Framework overview](https://learn.microsoft.com/windows/msix/psf/package-support-framework)
- [PSF — FileSystem Write Permission](https://learn.microsoft.com/windows/msix/psf/psf-filesystem-writepermission)
- [PSF — Run scripts to create shortcuts](https://learn.microsoft.com/windows/msix/psf/create-shortcut-with-script-package-support-framework)
- [Accelerators](https://learn.microsoft.com/windows/msix/toolkit/accelerators)
- [Support legacy context menus](https://learn.microsoft.com/windows/msix/packaging-tool/support-legacy-context-menus)
- [Win32 app isolation](https://learn.microsoft.com/windows/win32/secauthz/app-isolation-overview)
- [TMurgent PSF fork](https://github.com/TimMangan/MSIX-PackageSupportFramework)

---

## Quick start

> The maintainer owns the `MSIX` name on PSGallery (`Install-Module MSIX`).
> When developing against a working copy, import by full path so you load the
> repo version rather than the installed one.

```powershell
Import-Module 'C:\path\to\MSIX\MSIX.psd1' -Force

# One-time toolchain setup: MakeAppx, signtool, PSF, Procmon, msixmgr
# All from official/signed sources, on demand.
Initialize-MsixToolchain
```

`Initialize-MsixToolchain` downloads and Authenticode-verifies:

| Component | Source | Used by |
|---|---|---|
| `MakeAppx.exe` + `signtool.exe` | Microsoft.Windows.SDK.BuildTools (NuGet) | pack / unpack / sign |
| TMurgent PSF | GitHub releases (Tim Mangan) | `Add-MsixPsfV2`, `Add-MsixStandardScript` |
| Sysinternals Process Monitor | Sysinternals (Microsoft) | `Invoke-MsixInvestigation -WithProcMon` |
| msixmgr | `aka.ms/msixmgr` (Microsoft) | `New-MsixAppAttachImage` |

Skip individual components: `Initialize-MsixToolchain -Skip Sdk,Procmon,MsixMgr`

---

## Architecture

```
MSIX\
├── MSIX.psd1                  Module manifest (v0.73.0)
├── MSIX.psm1                  Root module — dot-sources all sub-modules
├── MSIX.Logging.ps1           Write-MsixLog + log-level / file controls
├── MSIX.Core.ps1              Workspace, process runner, tools resolution
├── MSIX.Validation.ps1        Manifest / config / process validators
├── MSIX.Manifest.ps1          XML helpers, namespace registry, pure transforms
├── MSIX.ManifestExtensions.ps1  Manifest-only fixers (desktop6, uap5, uap6…)
├── MSIX.PSF.ps1               Fixup builders + Add-MsixPsfV2 injection engine
├── MSIX.PsfBinaries.ps1       PSF / Procmon / SDK downloader + Authenticode verify
├── MSIX.Signing.ps1           Invoke-MsixSigning (SignTool / TrustedSigning / AzureSignTool)
├── MSIX.Pipeline.ps1          Invoke-MsixPipeline — sign-once orchestrator
├── MSIX.ContextMenu.ps1       com + desktop4/desktop5 context menus (legacy IContextMenu + modern IExplorerCommand)
├── MSIX.Scripts.ps1           PSADT-flavoured standard scripts + Set-MsixScriptSignature
├── MSIX.AppIsolation.ps1      Win32 App Isolation (rescap capabilities, opt-in)
├── MSIX.Investigation.ps1     Static + procmon analysis + recommendations
├── MSIX.Scanners.ps1          Read-only Get-Msix*Candidate/*Entry/HeuristicFinding
├── MSIX.PackageMutators.ps1   Add-MsixCapability + Remove-Msix*Artifact + payload Add-*
├── MSIX.AutoFix.ps1           Invoke-MsixAutoFix + Invoke-MsixAutoFixFromAnalysis
├── MSIX.Detection.ps1         Read-only scanners (fonts, shortcuts, capability hints)
├── MSIX.Debug.ps1             Start-MsixDebugSession + sandbox bootstrap
├── MSIX.AppData.ps1           Container / orphan / merged-fs helpers
├── MSIX.AppAttach.ps1         VHDX/CIM generator (msixmgr, Authenticode-verified)
├── MSIX.Accelerator.ps1       MS Learn accelerator YAML import + apply (safe parser)
├── MSIX.Limitations.ps1       Limitations knowledge base
├── MSIX.Trace.ps1             DebugView / TraceFixup output parser
├── MSIX.MFR.ps1               Modern File Redirection (TMurgent fork)
├── MSIX.VcRuntime.ps1         VC++ runtime detection + bundling
├── MSIX.Compare.ps1           Compare-MsixPackage (manifest + file + signing diff)
├── MSIX.OfflineRegistry.ps1   Offreg (offline hive) read/write helpers
├── MSIX.Distribution.ps1      .appinstaller, modification + framework packages
├── MSIX.Bundle.ps1            .msixbundle: bundle/unbundle + mutate-through-bundle
├── MSIX.RuntimeTest.ps1       Test-MsixDeployment (Hyper-V runtime verification)
├── templates/                 .ps1.tmpl files for standard scripts
├── MSIX.Tests/                Pester v5 test suite (700+ tests)
├── docs/                      Per-fixup reference, limitations, know-your-installer
├── CONTRIBUTING.md            Coding standards and security guidelines
├── EXAMPLES.md                26 copy-paste recipes for all major use cases
└── TEST-PLAN.md               14 manual / integration test scenarios + release checklist
```

All logging uses `Write-Information` (stream 6) — fully capturable in CI
pipelines. Security-critical notices use `Write-Warning` (stream 3) so they
appear in `-WarningVariable` captures.

---

## Investigation & auto-fix

### Static analysis (no install required)

```powershell
$report = Invoke-MsixInvestigation -PackagePath app.msix
$report.Findings            | Format-Table Severity, Category, Symptom
$report.SuggestedFixups     | ConvertTo-Json -Depth 8   # PSF path
$report.SuggestedManifestFixes | Format-Table           # manifest alternatives
$report.RecommendedCommands | Out-File next-steps.ps1
```

### With Process Monitor (runtime)

```powershell
Initialize-MsixToolchain
$report = Invoke-MsixInvestigation -PackagePath app.msix -WithProcMon `
    -PackageFamilyName 'Contoso.App_8wekyb3d8bbwe' -AppId 'App' `
    -DurationSeconds 30 -ProcessName 'app.exe'
```

### One-call auto-remediation

`Invoke-MsixAutoFixFromAnalysis` connects investigation to remediation — it
runs the right fixer for every finding and signs once at the end.

```powershell
$report = Invoke-MsixInvestigation -PackagePath app.msix
Invoke-MsixAutoFixFromAnalysis -Report $report `
    -VcRuntimeSourceFolder 'C:\…\VC143.CRT' `
    -Pfx cert.pfx -PfxPassword (Read-Host -AsSecureString)

# Preview only — no mutation:
Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
```

---

## PSF injection

```powershell
$pw = Read-Host -AsSecureString

# File redirection (writes to install-dir → per-user redirect)
$frf = New-MsixPsfFileRedirectionConfig -Base 'VFS/ProgramFilesX64/App/' `
           -Patterns '.*\.log', '.*\.tmp', '.*\.cache'

# Environment variable injection
$env = New-MsixPsfEnvVarConfig -Variables @{ APP_MODE = 'packaged'; APP_VER = '3' }

# Custom working directory
Add-MsixPsfV2 -PackagePath app.msix `
    -Fixups          @($frf, $env) `
    -WorkingDirectory 'VFS/ProgramFilesX64/App/' `
    -Pfx cert.pfx -PfxPassword $pw
```

Modern File Redirection (MFR — TMurgent fork, ILV-aware):

```powershell
$rule = New-MsixMfrTraditionalRule -KnownFolder 'ProgramFilesX64' `
            -RelativePath 'Contoso/logs' -Patterns '.*\.log' -Cow enablePe

$mfr = New-MsixPsfMfrConfig -TraditionalRules @($rule) -GlobalIlvAware $true
Add-MsixPsfV2 -PackagePath app.msix -Fixups @($mfr) -Pfx cert.pfx -PfxPassword $pw
```

---

## Signing backends

Four backends, all accepting `[SecureString]` for any secret:

```powershell
$pw = Read-Host -AsSecureString

# Local signtool + PFX (emits Write-Warning about cmdline exposure)
Invoke-MsixSigning -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw

# Safe local PFX (SignerSignEx): the password loads the cert in-process and
# signtool signs by thumbprint — the password/PFX path never hit the cmdline.
Invoke-MsixSigning -PackagePath app.msix -Signer SignerSignEx -Pfx cert.pfx -PfxPassword $pw

# Azure Trusted Signing (recommended for production)
Invoke-MsixSigning -PackagePath app.msix -Signer TrustedSigning `
    -TrustedSigningAccount 'contoso' -TrustedSigningProfile 'Code Signing' `
    -TrustedSigningEndpoint 'https://weu.codesigning.azure.net'

# Azure Key Vault via AzureSignTool
Invoke-MsixSigning -PackagePath app.msix -Signer AzureSignTool `
    -KeyVaultUrl 'https://my-vault.vault.azure.net' `
    -KeyVaultCertificate 'my-cert' `
    -KeyVaultClientId $spId -KeyVaultClientSecret $spSecret
```

---

## Standard scripts (PSADT)

Generate, sign, and inject deployment-toolkit-style PowerShell scripts as PSF
`startScript` / `endScript` entries. Customer-specific values are baked in at
generation time.

```powershell
$pw = Read-Host -AsSecureString

# See bundled templates
Get-MsixStandardScript | Format-Table Name, Description

# Generate + sign (no package touched)
New-MsixStandardScript -Name CreateShortcut `
    -Parameters @{ DisplayName = 'Contoso'; Target = 'contoso.exe' } `
    -OutputPath C:\src\createshortcut.ps1 `
    -Pfx cert.pfx -PfxPassword $pw

# Generate + sign + inject into MSIX in one step
Add-MsixStandardScript -PackagePath app.msix -AppId 'App' `
    -Name CreateShortcut `
    -Parameters @{ DisplayName = 'Contoso'; Target = 'contoso.exe' } `
    -RunOnce -WaitForScriptToFinish `
    -Pfx cert.pfx -PfxPassword $pw

# Sign any script with the same cert
Set-MsixScriptSignature -ScriptPath my-script.ps1 -Pfx cert.pfx -PfxPassword $pw
```

Bundled templates: `CreateShortcut`, `CopyIconToAppData`, `CleanupOldUserData`,
`RegisterFileAssociation`, `CustomerSettingsBootstrap`.

---

## Win32 App Isolation

Opt-in AppContainer isolation. The actual isolation switch is the **AppContainer
trust level on a partial-trust entry point** — `Add-MsixAppIsolation` sets, on
each `<Application>`:

- `EntryPoint="Windows.PartialTrustApplication"` (the full-trust entry point
  hard-requires `runFullTrust`, which keeps the process full-trust — so it could
  never isolate);
- `TrustLevel="appContainer"`; and
- **removes `runFullTrust`** (incompatible with AppContainer; the partial-trust
  entry point doesn't need it).

Two modes:

| `-Mode` | Manifest | Status | Behavior |
|---|---|---|---|
| **AppContainer** (default) | `uap10:RuntimeBehavior="packagedClassicApp"` | **GA** (Win10 2004+) | ungranted access **denied** |
| **AppSilo** | `uap18:RuntimeBehavior="appSilo"` + `uap18:EntryPoint="Isolated.App"` + `isolatedWin32-*` | **preview** (Win11 24H2) | access **brokered** (consent prompts); raises MinVersion to 26100 |

`-Capabilities` are standard package capabilities in AppContainer mode (default:
none — strictest) and `isolatedWin32-*` / device capabilities in AppSilo mode
(default: `isolatedWin32-promptForAccess`).

```powershell
$pw = Read-Host -AsSecureString

Get-MsixIsolationCapability   # rich objects: Name / ElementType / Description (AppSilo caps)

# GA AppContainer (strict): app runs in an AppContainer, ungranted access denied.
Add-MsixAppIsolation -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw

# ... grant specific access:
Add-MsixAppIsolation -PackagePath app.msix -Capabilities internetClient -Pfx cert.pfx -PfxPassword $pw

# Win32 App Isolation silo (preview) with the file-access broker:
Add-MsixAppIsolation -PackagePath app.msix -Mode AppSilo -Pfx cert.pfx -PfxPassword $pw

Remove-MsixAppIsolation -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw   # restores full trust
```

**Two things that can't be isolated** (the cmdlet warns/throws) — with escape
hatches:
- **PSF packages** (`PsfLauncher*.exe` entry point) — PSF injects fixup DLLs into
  the target process, which AppContainer blocks. Run **`Remove-MsixPsf`** first:
  it restores the real executable from config.json and strips the PSF payload
  (warning about every behaviour that disappears with it).
- **`windows.comServer` extensions** (e.g. a COM shell context-menu like NppShell)
  — invalid with a partial-trust entry point. Pass **`-RemoveComServer`** to strip
  the COM server and its Explorer context-menu verbs (that functionality is lost).

**Verify and tune with the isolation toolkit:**

```powershell
# Would this package isolate? (static manifest verdict with reasons)
Test-MsixIsolation -PackagePath app-isolated.msix

# Is the RUNNING app actually in an AppContainer? (token check: S-1-15-2 SID)
Test-MsixIsolation -PackageFamilyName 'MyApp_abc123def'    # or -ProcessId <pid>

# Which capabilities does the app need? Trace it, then map the denials:
$pml = Invoke-MsixProcMonCapture -ScriptBlock { <# drive the app #> }
Get-MsixProcMonFailure -PmlPath $pml | Get-MsixIsolationAdvice -Mode AppSilo
```

> **Validate first.** Many legacy apps break under isolation because they expect
> broad filesystem/registry access. Prompts alone are NOT proof of isolation
> (ASR rules also prompt) — only the **`S-1-15-2` AppContainer SID** is
> (`Test-MsixIsolation`). The **AppSilo** layer is a **preview** feature; if its
> brokering doesn't engage on a given build the app still runs in the
> AppContainer (access denied rather than prompted). See `TEST-PLAN.md` Scenario 6.

`Invoke-MsixPipeline` supports `AppIsolation` as a first-class config key —
applied in the same unpack/repack/sign pass as publisher updates and PSF
injection.

---

## Manifest-only fixers

Alternatives to PSF for symptoms the modern manifest schema handles natively
(faster, no foreign DLLs, survives Windows updates cleanly):

| Cmdlet | Schema | Min OS | Replaces |
|---|---|---|---|
| `Set-MsixFileSystemWriteVirtualization` | desktop6 | 19041 | PSF FileRedirection (broad) |
| `Set-MsixRegistryWriteVirtualization` | desktop6 | 19041 | RegLegacy Hklm2Hkcu (broad) |
| `Set-MsixInstalledLocationVirtualization` | uap10 | 19041 | FRF + update-time policy |
| `Add-MsixLoaderSearchPathOverride` | uap6 | 17134 | DynamicLibraryFixup |
| `Add-MsixFirewallRule` | desktop2 | 15063 | post-install netsh |
| `Add-MsixStartupTask` | uap5 | 15063 | HKLM/HKCU `\Run` keys |
| `Add-MsixProtocolHandler` | uap | any | host-side protocol script |
| `Add-MsixFileTypeAssociation` | uap | any | host-side FTA script (now with `-Logo`/`-InfoTip`/EditFlags/`-Verbs`) |
| `Add-MsixService` | desktop6 | 19041 | services the capture's installer registered (agents/updaters/licensing) |
| `Add-MsixShellHandlerExtension` | desktop2 | 15063 | preview/property/thumbnail shell handlers from the registry |
| `Add-MsixToastActivator` | desktop + com | 16299 | toast click re-activation |
| `Add-MsixPackageDependency` | foundation | any | bundling framework DLLs (VCLibs, WindowsAppRuntime as `<PackageDependency>`) |
| `Set-MsixMutablePackageDirectory` | desktop6 | 18362 | plugin/mod folders via `%ProgramFiles%\ModifiableWindowsApps` |
| `Add-MsixPackageCertificate` | foundation | any | the capture's `certutil` step (`windows.certificates`, per-package store) |
| `Add-MsixAppExtensionHost` / `Add-MsixAppExtension` | uap3 | 14393 | ad-hoc plugin folder drops (AppExtensionCatalog contract) |
| `Add-MsixAutoPlayHandler` | uap | any | AutoPlay registry handlers |
| `Add-MsixShareTarget` | uap | any | Share-sheet integration |
| `Add-MsixFullTrustProcess` | desktop | 14393 | UWP-main + Win32-companion pattern |

Scanners feed these into `Invoke-MsixInvestigation` findings and
`Invoke-MsixAutoFixFromAnalysis` planning: `Get-MsixServiceEntry`,
`Get-MsixShellHandlerEntry`, `Get-MsixPackageCertificateCandidate`
(certificate declaration is opt-in via `-DeclarePackageCertificates` +
`-PackageCertificateStore` — installing a certificate is a trust decision).

**Distribution** (after post-processing): `New-MsixAppInstallerFile` generates
a `.appinstaller` with the full auto-update policy; `New-MsixModificationPackage`
builds a `uap4:MainPackageDependency` customization package that layers
settings/plugins onto a vendor MSIX without touching it.

**Multi-arch bundles:** `New-MsixBundle` / `Expand-MsixBundle` /
`Get-MsixBundleInfo` wrap MakeAppx bundle operations, and
`Invoke-MsixBundleOperation` applies any mutator to each inner package
(unbundle → mutate → rebundle → sign) so the whole toolkit works on
`.msixbundle` inputs, not just single `.msix` files.

**Localization repair:** `Update-MsixResourcePri` regenerates `resources.pri`
via makepri, and `Set-MsixBrandMetadata -RegeneratePri` makes brand edits on
`ms-resource:`-localized packages actually take effect at runtime.

**Shared runtime frameworks:** stop bundling a JRE into every app.
`New-MsixFrameworkPackage` packages a runtime once as a `<Framework>` package;
`Add-MsixRuntimeDependency` wires each consumer (`<PackageDependency>` +
optional `JAVA_HOME`/`DOTNET_ROOT` env wiring). `Get-MsixBundledRuntime`
detects private runtime copies in captures, and autofix can strip + rewire
them (opt-in, explicit framework identity).

**Modification packages:** `New-MsixModificationPackage` layers files AND
settings (`-RegistryContent` builds `Registry.dat`/`User.dat`) onto a vendor
MSIX without touching it; `ConvertTo-MsixModificationPackage` productizes the
delta between a vendor package and a customized copy automatically.


## Runtime deployment testing

Static analysis says whether a package *should* work; `Test-MsixDeployment`
proves whether it *does*. It installs a signed package into a clean Hyper-V VM
over PowerShell Direct (no VM networking), launches it via `shell:AppsFolder`,
and probes liveness — returning a verdict object shaped like the other
`Test-Msix*` results, with the event-log artifacts wired to feed the
analyze → autofix loop.

```powershell
$cred = Get-Credential
Test-MsixDeployment -PackagePath app.msix -VMName 'Win11-24H2' `
    -Credential $cred -CertPath app.cer -Checkpoint 'clean'
# -> Passed / Reasons / ProcessAlive / CrashDetected / EventLogArtifacts
```

---

## Pipeline orchestrator

`Invoke-MsixPipeline` applies every requested stage to a single workspace,
then signs once at the very end. Atomic: if signing fails, the original
target is never overwritten — the unsigned scratch package is preserved at
`UnsignedOutputPath` for manual re-sign.

```powershell
$pw = Read-Host -AsSecureString

Invoke-MsixPipeline -PackagePath app.msix -OutputPath app-fixed.msix -Config @{
    Publisher    = 'CN=Contoso, O=Contoso, C=NL'
    PSF          = @{
        Fixups           = @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' )
        WorkingDirectory = 'VFS/ProgramFilesX64/Contoso/'
    }
    AppIsolation = @{
        Capabilities = 'isolatedWin32-promptForAccess', 'isolatedWin32-userProfileMinimal'
    }
    Signing      = @{
        Pfx                = 'cert.pfx'
        PfxPassword        = $pw
        UnsignedOutputPath = 'C:\drop\app-unsigned-fallback.msix'
    }
}
```

---

## App Attach (VHDX / CIM)

```powershell
# VHDX — auto-sized, NTFS, optional ACLs
New-MsixAppAttachImage -PackagePath app.msix -OutputPath app.vhdx

# CIM — no Hyper-V required
New-MsixAppAttachImage -PackagePath app.msix -OutputPath app.cim -FileType cim

# Multiple packages into one image
New-MsixAppAttachImage -PackagePath @('a.msix','b.msix') -OutputPath bundle.vhdx -SizeGB 4

Test-MsixAppAttachImage -ImagePath app.vhdx
```

---

## Context menus

```powershell
# Legacy IContextMenu COM shell extension (com + desktop4/desktop5, Win10 1809+ / build 17763+).
# Emits the com:SurrogateServer registration AND the desktop4:FileExplorerContextMenus
# verb in one call — the field-verified pattern Explorer actually activates.
Add-MsixLegacyContextMenu -PackagePath app.msix `
    -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
    -Clsid       'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX' `
    -DisplayName 'My Context Menu' `
    -FileTypes   '*', '.log', 'Directory' `
    -Pfx cert.pfx -PfxPassword (Read-Host -AsSecureString)

# Modern IExplorerCommand (desktop4, recommended for new extensions)
Add-MsixFileExplorerContextMenu -PackagePath app.msix `
    -AppId 'App' -VerbId 'open' -VerbClsid '{XXXXXXXX-…}' `
    -FileTypes '.txt', '.log'

# Alternative classic-handler schema (-Schema desktop9|Both): the MS-documented /
# commercial-tool shape (windows.fileExplorerClassicContextMenuHandler).
# Win11 21H2+ only; appears in the CLASSIC menu ("Show more options").
Add-MsixLegacyContextMenu -PackagePath app.msix -Schema Both `
    -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
    -Clsid 'XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX' -DisplayName 'My Context Menu'
```

---

## Debug & sandbox

```powershell
# Spin up Windows Sandbox with the broken package + this module pre-loaded
$cfg = New-MsixSandboxConfig -DropFolder 'C:\drop' -PackageName 'broken.msix'
Start-MsixSandbox -ConfigPath $cfg

# Inside the sandbox the LogonCommand auto-runs Start-MsixDebugSession which:
#  - Runs Invoke-MsixInvestigation (static)
#  - Prints numbered copy-paste-ready fix commands (saved to recommended-commands.ps1)
#  - Optionally installs the package, opens Procmon + DebugView
```

---

## CI/CD

All functions are non-interactive — no `Read-Host`, no `PromptForChoice`.

```powershell
Import-Module .\MSIX\MSIX.psd1 -Force
Initialize-MsixToolchain | Out-Null

$report = Invoke-MsixInvestigation -PackagePath $env:BUILD_OUTPUT
if ($report.Findings | Where-Object Severity -eq 'Error') {
    throw 'Compatibility errors detected — aborting.'
}

Invoke-MsixPipeline -PackagePath $env:BUILD_OUTPUT -OutputPath $env:BUILD_FIXED `
    -Config @{
        PSF     = @{ Fixups = $report.SuggestedFixups }
        Signing = @{
            Signer                  = 'TrustedSigning'
            TrustedSigningAccount   = $env:TS_ACCOUNT
            TrustedSigningProfile   = $env:TS_PROFILE
            TrustedSigningEndpoint  = $env:TS_ENDPOINT
        }
    }
```

---

## Tests

Pester v5 tests under `MSIX.Tests\`. 500+ tests cover pure functions, manifest
transforms, XML security (XXE / billion-laughs rejection), secret non-leakage,
input validation, idempotency, and the module export contract — plus
`Integration`-tagged tests that pack real `.msix` fixtures via MakeAppx (skipped
when the SDK toolchain isn't present). A coverage-map guardrail asserts every
mutating cmdlet is exercised by a test.

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser

# All tests
.\MSIX.Tests\Invoke-MsixTests.ps1

# By tag
.\MSIX.Tests\Invoke-MsixTests.ps1 -Tag Security
.\MSIX.Tests\Invoke-MsixTests.ps1 -Tag Manifest,Builders
```

CI runs PSScriptAnalyzer (Error + Warning) and Pester on every push / PR via
`.github/workflows/ci.yml`. Releases publish to PSGallery via
`.github/workflows/publish.yml`.

---

## What's new in v0.73

**Shared runtime frameworks (#130)** — package a JRE/.NET/Python runtime ONCE
as a `<Framework>` package (`New-MsixFrameworkPackage`) and wire any number of
apps to it (`Add-MsixRuntimeDependency`: dependency + optional
`JAVA_HOME`/`DOTNET_ROOT` env wiring). `Get-MsixBundledRuntime` finds private
runtime copies in captures; autofix can strip + rewire them (opt-in, explicit
framework identity).

**Modification packages completed (#131)** — `New-MsixModificationPackage
-RegistryContent` layers HKLM/HKCU settings (built into
`Registry.dat`/`User.dat`), and `ConvertTo-MsixModificationPackage`
productizes the delta between a vendor package and a customized copy.
`Test-MsixDeployment -ModificationPackagePaths` probes main + mods together.

**From 0.72 (source-only, first published here):**

- **`.msixbundle` support** — `New-MsixBundle` / `Expand-MsixBundle` /
  `Get-MsixBundleInfo`, and `Invoke-MsixBundleOperation` to run any mutator
  against each inner package (unbundle → mutate → rebundle → sign, atomic).
- **resources.pri regeneration** — `Update-MsixResourcePri` +
  `Set-MsixBrandMetadata -RegeneratePri` make brand edits on
  `ms-resource:`-localized packages actually take effect.
- **Runtime deployment testing** — `Test-MsixDeployment` deploys into a clean
  Hyper-V VM over PowerShell Direct, launches, probes, and returns a verdict
  whose artifacts feed the analyze → autofix loop.
- **In-process signing** — `Invoke-MsixSigning -Signer SignerSignEx` signs by
  thumbprint with the certificate loaded in-process: no PFX password or path
  on any command line.

**Earlier in the 0.71 line:** the App Isolation rework (partial-trust
AppContainer/AppSilo that provably isolates), the isolation toolkit
(`Remove-MsixPsf`, `Test-MsixIsolation`, `Get-MsixIsolationAdvice`), packaged
services, shell handlers, toast activators, package dependencies/certificates,
distribution (.appinstaller), and the module-wide Get-Help repair.

## Release history

The full per-version history lives in [CHANGELOG.md](CHANGELOG.md).

---

## License

This module is **free to use, modify, and build on** — including
commercially, inside your own organisation, and as part of your own
packaging workflows. It is licensed under the
[PolyForm Shield 1.0.0](LICENSE.md) license.

In plain English: do whatever you like with it, with **one** exception —
you may not use it to build a product that **competes** with this module
(for example, folding it into a rival MSIX-packaging tool or service).
If that's what you're after, get in touch and we'll talk about a separate
commercial license.

PolyForm Shield is a [source-available](https://polyformproject.org/)
license, not an OSI open-source license — that single competitive carve-out
is the only difference from a permissive license like Apache-2.0.
Contributions are welcome under the same terms (see
[CONTRIBUTING.md](CONTRIBUTING.md)).

**Third-party binaries:** PSF binaries fetched at runtime remain the
property of their respective owners (Microsoft / Tim Mangan / TMurgent
Technologies). This module does not redistribute any binaries — it downloads
them on demand from the authors' official release channels and verifies
Authenticode signatures before use.
