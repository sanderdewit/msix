# MSIX Module — Copy-Paste Examples

End-to-end recipes for the common tasks. Every snippet is self-contained:
load the module, set inputs, run. Comments explain the *why* alongside the
*what*.

```powershell
Import-Module C:\temp\msix\MSIX\MSIX.psd1
```

---

## Table of contents

1. [Inspect a package without unpacking](#1-inspect-a-package-without-unpacking)
2. [Update the Publisher and re-sign](#2-update-the-publisher-and-re-sign)
3. [Inject a PSF FileRedirection fixup](#3-inject-a-psf-fileredirection-fixup)
4. [Add a legacy IContextMenu shell extension](#4-add-a-legacy-icontextmenu-shell-extension-com--desktop4desktop5)
5. [Add a modern IExplorerCommand context menu (desktop4)](#5-add-a-modern-iexplorercommand-context-menu-desktop4)
6. [Add an AppExecutionAlias](#6-add-an-appexecutionalias)
7. [Enable / configure FileSystem write virtualization](#7-enable--configure-filesystem-write-virtualization)
8. [Fix Notepad++ plugins that want to write to Program Files](#8-fix-notepad-plugins-that-want-to-write-to-program-files)
9. [Add a Windows Firewall rule that lives with the package](#9-add-a-windows-firewall-rule-that-lives-with-the-package)
10. [Bundle a Visual C++ runtime](#10-bundle-a-visual-c-runtime)
11. [Static analysis + auto-fix in one pass](#11-static-analysis--auto-fix-in-one-pass)
12. [Sign with Azure Trusted Signing (production)](#12-sign-with-azure-trusted-signing-production)
13. [Sign with Azure Key Vault via AzureSignTool](#13-sign-with-azure-key-vault-via-azuresigntool)
14. [Self-signed dev cert and Windows Sandbox debug session](#14-self-signed-dev-cert-and-windows-sandbox-debug-session)
15. [Compare two packages](#15-compare-two-packages)
16. [App Attach VHDX for multi-session hosts](#16-app-attach-vhdx-for-multi-session-hosts)
17. [Full pipeline: publisher + PSF + signing in one call](#17-full-pipeline-publisher--psf--signing-in-one-call)
18. [Standard scripts (PSADT-flavoured, parameterised)](#18-standard-scripts-psadt-flavoured-parameterised)
19. [App isolation (opt-in)](#19-app-isolation-opt-in-appcontainer--appsilo)
20. [Packaged Windows services, shell handlers, toast activators](#20-packaged-windows-services-shell-handlers-toast-activators)
21. [Work with .msixbundle files](#21-work-with-msixbundle-files)
22. [Shared runtime framework packages (one Java for all apps)](#22-shared-runtime-framework-packages-one-java-for-all-apps)
23. [Modification packages: settings + golden-image deltas](#23-modification-packages-settings--golden-image-deltas)
24. [Runtime verification in a Hyper-V VM](#24-runtime-verification-in-a-hyper-v-vm)
25. [Regenerate resources.pri after brand edits](#25-regenerate-resourcespri-after-brand-edits)
26. [Distribute with a .appinstaller (auto-update)](#26-distribute-with-a-appinstaller-auto-update)

---

## 1. Inspect a package without unpacking

`Get-MsixManifest` extracts AppxManifest.xml directly from the archive — no
MakeAppx required.

```powershell
$m = Get-MsixManifest -Path 'C:\drop\App.msix'

$m.Package.Identity.Name      # 'Contoso.App'
$m.Package.Identity.Publisher # 'CN=Contoso, O=Contoso, C=NL'
$m.Package.Identity.Version   # '1.2.3.4'

# Iterate all Application elements
$doc = New-MsixManifestDocument -Document $m
Get-MsixManifestApplication -Manifest $doc -All |
    ForEach-Object { "$($_.GetAttribute('Id')) -> $($_.GetAttribute('Executable'))" }
```

---

## 2. Update the Publisher and re-sign

Use when the original signing identity is gone and you need to re-publisher
the package to match a new cert.

```powershell
$pw = Read-Host -AsSecureString 'New cert PFX password'
Update-MsixSigner `
    -PackagePath 'C:\drop\App.msix' `
    -Publisher   'CN=New Owner, O=NewCo, C=NL' `
    -Pfx 'C:\certs\newco.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-reowned.msix'
```

The cmdlet asserts the cert Subject matches the new Publisher before signing
(prevents "publisher mismatch" install failures).

---

## 3. Inject a PSF FileRedirection fixup

Use when the app writes to `C:\Program Files\<App>\` (or another VFS path)
and MSIX virtualization alone isn't enough. PSF intercepts the Win32 file
APIs and redirects.

```powershell
$logRedirect = New-MsixPsfFileRedirectionConfig `
    -Base 'logs' -Patterns '.*\.log$'

$pw = Read-Host -AsSecureString
Add-MsixPsfV2 `
    -PackagePath 'C:\drop\App.msix' `
    -Fixups @($logRedirect) `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-psf.msix'
```

`New-MsixPsfFileRedirectionConfig` produces the right JSON shape for the
TMurgent PSF fork. For multiple fixups, build them separately and pass an
array to `-Fixups`.

---

## 4. Add a legacy IContextMenu shell extension (com + desktop4/desktop5)

Classic shell extension DLLs (the kind that fail to load if Explorer can't
find the DLL via registry). MSIX hosts them in a surrogate process.

```powershell
$pw = Read-Host -AsSecureString
Add-MsixLegacyContextMenu `
    -PackagePath 'C:\drop\App.msix' `
    -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
    -Clsid       '12345678-1234-1234-1234-1234567890ab' `
    -DisplayName 'My Tools' `
    -FileTypes   '*','.log','Directory' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-ctxmenu.msix'
```

Notes:

- Works from Windows 10 1809 (build 17763) with the default schema;
  `MaxVersionTested` is auto-bumped. Pass `-Schema desktop9` (or `Both`) for
  the classic-handler registration (Win11 21H2+, classic "Show more options"
  menu).
- CLSID can be passed with or without curly braces — the cmdlet normalises.
- `-FileTypes '*'` registers the handler for all files; `.log` is type-specific;
  `Directory` matches folders; `Drive` matches drive roots.
- `runFullTrust` is auto-injected (required for COM surrogate).

---

## 5. Add a modern IExplorerCommand context menu (desktop4)

The modern, recommended pattern for new shell extensions.

```powershell
$pw = Read-Host -AsSecureString
Add-MsixFileExplorerContextMenu `
    -PackagePath 'C:\drop\App.msix' `
    -AppId       'App' `
    -VerbId      'open-with-app' `
    -VerbClsid   '11111111-2222-3333-4444-555555555555' `
    -FileTypes   '.log','.txt' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-modern-ctx.msix'
```

Requires Windows 10 1803 (build 17134). Auto-bumped.

---

## 6. Add an AppExecutionAlias

Lets users invoke the packaged app by short name from cmd or pwsh
(`mytool.exe` → packaged app).

```powershell
$pw = Read-Host -AsSecureString
Add-MsixAlias `
    -PackagePath 'C:\drop\App.msix' `
    -AppId       'App' `
    -ExecutableName 'mytool.exe' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-alias.msix'
```

After install, `where mytool.exe` resolves to
`%LOCALAPPDATA%\Microsoft\WindowsApps\mytool.exe`.

---

## 7. Enable / configure FileSystem write virtualization

The canonical Win32-conversion fix: writes to `C:\Program Files\<App>\`
get redirected to the per-user package cache.

```powershell
$pw = Read-Host -AsSecureString

# Default behaviour: ENABLE virtualization, exclude AppData paths.
Set-MsixFileSystemWriteVirtualization `
    -PackagePath 'C:\drop\App.msix' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-virt.msix'
```

To disable (writes go to the real filesystem; usually wrong for converted
Win32 apps unless you've also added the right ACLs):

```powershell
Set-MsixFileSystemWriteVirtualization -Disable `
    -PackagePath 'C:\drop\App.msix' `
    -OutputPath  'C:\drop\App-no-virt.msix'
```

To customise excluded directories (default: `LocalAppData`, `RoamingAppData`):

```powershell
Set-MsixFileSystemWriteVirtualization `
    -PackagePath 'C:\drop\App.msix' `
    -ExcludedDirectories '$(KnownFolder:LocalAppData)','$(KnownFolder:RoamingAppData)','VFS/ProgramFilesX64/App/Cache' `
    -OutputPath 'C:\drop\App-virt-custom.msix'
```

---

## 8. Fix Notepad++ plugins that want to write to Program Files

The Notepad++ plugin manager extracts to `C:\Program Files\Notepad++\plugins\`.
Out of the box this fails inside MSIX because the plugin manager probes
write-access *before* extracting, and the probe returns "no" even though
MSIX would virtualize the write.

**Solution**: combine VFS virtualization (so the write *can* happen) with a
PSF FileRedirection rule (so the *probe* also sees a writable path).

```powershell
$pw = Read-Host -AsSecureString

# 1. Ensure FS virtualization is enabled (the default — but make it explicit)
Set-MsixFileSystemWriteVirtualization `
    -PackagePath 'C:\drop\Notepadpp.msix' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\Notepadpp-step1.msix'

# 2. Add PSF FileRedirection for the plugins path specifically
$pluginsRedirect = New-MsixPsfFileRedirectionConfig `
    -Base 'VFS\ProgramFilesX64\Notepad++\plugins' `
    -Patterns '.*'

Add-MsixPsfV2 `
    -PackagePath 'C:\drop\Notepadpp-step1.msix' `
    -Fixups @($pluginsRedirect) `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\Notepadpp-final.msix'

Remove-Item 'C:\drop\Notepadpp-step1.msix'
```

Same pattern works for any plugin manager that does an access probe before
extracting (7-Zip themes, Audacity plugins, etc.).

---

## 9. Add a Windows Firewall rule that lives with the package

The rule is created on install and removed on uninstall — no `netsh` in your
deployment scripts.

```powershell
$pw = Read-Host -AsSecureString
Add-MsixFirewallRule `
    -PackagePath 'C:\drop\App.msix' `
    -AppId       'App' `
    -Executable  'VFS\ProgramFilesX64\App\App.exe' `
    -Direction   'in' `
    -Protocol    'TCP' `
    -LocalPort   '8443' `
    -Description 'App HTTPS listener' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-fw.msix'
```

The rule lands under `<Package><Extensions>` (correct per the schema; fixed
in issue #12). `runFullTrust` is auto-injected.

---

## 10. Bundle a Visual C++ runtime

When an app needs `vcruntime140.dll` etc., bundle them directly so the host
doesn't need the redistributable installed.

```powershell
# Detect which VC runtimes the EXEs reference
$refs = Get-MsixVcRuntimeReference -PackagePath 'C:\drop\App.msix'
$refs

# Bundle the matching DLLs from a VS Redist source folder
$pw = Read-Host -AsSecureString
Add-MsixVcRuntimeBundle `
    -PackagePath 'C:\drop\App.msix' `
    -VcRedistRoot 'C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Redist\MSVC\<version>\x64\Microsoft.VC143.CRT' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath 'C:\drop\App-vcrt.msix'
```

---

## 11. Static analysis + auto-fix in one pass

`Invoke-MsixInvestigation` runs the static manifest scanner, the heuristic
finder, and (optionally) procmon capture and DebugView trace parsing.
`Invoke-MsixAutoFixFromAnalysis` then applies the right fixers — signing
ONCE at the end.

```powershell
$report = Invoke-MsixInvestigation -PackagePath 'C:\drop\App.msix'

# Look at what was found
$report.Findings | Format-Table Severity, Category, Symptom
$report.SuggestedFixups | Format-Table

# Apply the recommended fixes (DryRun first)
Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun

# Real run
$pw = Read-Host -AsSecureString
Invoke-MsixAutoFixFromAnalysis -Report $report `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath 'C:\drop\App-autofixed.msix'
```

`-PreferManifestOverPsf` (default `$true`) skips PSF injection when a
manifest-only fix covers the same symptom.

`Invoke-MsixAutoFixFromAnalysis` also picks up `AppExecutionAlias` findings
(emitted by `Get-MsixAliasCandidate` for top-level user-facing executables
that lack an alias) and runs `Add-MsixAlias` for the affected AppIds in
the same one-shot pass.

To trigger the alias step explicitly from the parameterised orchestrator:

```powershell
# Add aliases for every eligible top-level exe (auto-selected via
# Get-MsixAliasCandidate; skips apps that already have an alias).
Invoke-MsixAutoFix -PackagePath 'C:\drop\App.msix' `
    -AddAliases `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword (Read-Host -AsSecureString)

# Or target specific AppIds (implies -AddAliases):
Invoke-MsixAutoFix -PackagePath 'C:\drop\App.msix' `
    -AliasAppIds 'App','Worker' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw
```

---

## 12. Sign with Azure Trusted Signing (production)

The recommended production signing backend. No local PFX, no password on
the command line, no key material on disk.

```powershell
# Prereq: az login; Azure.CodeSigning.Dlib.dll on disk
Invoke-MsixSigning `
    -PackagePath 'C:\drop\App.msix' `
    -Signer TrustedSigning `
    -TrustedSigningAccount  'MyProdAccount' `
    -TrustedSigningProfile  'MyProdProfile' `
    -TrustedSigningEndpoint 'https://eus.codesigning.azure.net'
```

The cmdlet writes a temp metadata JSON for signtool /dlib, then deletes it
in a finally block. Auth flows via the Azure CLI session.

---

## 13. Sign with Azure Key Vault via AzureSignTool

For HSM-backed certs in an Azure Key Vault.

```powershell
$svcSecret = Read-Host -AsSecureString 'Service principal client secret'
Invoke-MsixSigning `
    -PackagePath 'C:\drop\App.msix' `
    -Signer AzureSignTool `
    -KeyVaultUrl 'https://prod-vault.vault.azure.net' `
    -KeyVaultCertificate 'msix-prod-cert' `
    -KeyVaultTenantId '00000000-0000-0000-0000-000000000000' `
    -KeyVaultClientId '11111111-2222-3333-4444-555555555555' `
    -KeyVaultClientSecret $svcSecret
```

The client secret is held as a SecureString and decrypted only at the
signtool CLI boundary (BSTR + ZeroFreeBSTR).

---

## 14. Self-signed dev cert and Windows Sandbox debug session

For dev / sandbox workflows where you need a quick signed package without
involving real signing infrastructure.

```powershell
$cert = New-MsixSelfSignedCertificate `
    -Subject 'CN=Lab Test, O=Lab, C=NL' `
    -OutputPath 'C:\lab\cert\'

# Update the package Publisher to match the cert
Update-MsixSigner `
    -PackagePath 'C:\drop\App.msix' `
    -Publisher   'CN=Lab Test, O=Lab, C=NL' `
    -Pfx $cert.PfxPath -PfxPassword $cert.Password `
    -OutputPath  'C:\drop\App-lab.msix'

# Launch a Windows Sandbox session with the package preloaded + DebugView running
Invoke-MsixSelfSign -PackagePath 'C:\drop\App-lab.msix'
```

---

## 15. Compare two packages

Diff manifest + file list + signing state between two `.msix` files. Useful
in CI gates ("does this build change anything in the manifest?").

```powershell
$diff = Compare-MsixPackage `
    -ReferencePath 'C:\drop\App-v1.msix' `
    -DifferencePath 'C:\drop\App-v2.msix'

$diff.HasChanges
$diff.ManifestChanges | Format-Table
$diff.FileChanges     | Format-Table Status, Path, ReferenceSize, DifferenceSize
$diff.SigningChanges  | Format-Table
```

File-level diffs are SHA-256 based.

---

## 16. App Attach VHDX for multi-session hosts

Generate an Azure Virtual Desktop App Attach image.

```powershell
# Requires admin + Hyper-V
New-MsixAppAttachImage `
    -PackagePath 'C:\drop\App.msix' `
    -OutputPath  'C:\appattach\App.vhdx' `
    -Format VHDX
```

CIM format is also supported (`-Format CIM`). Mount/dismount with
`Mount-MsixAppAttachImage` / `Dismount-MsixAppAttachImage`.

---

## 17. Full pipeline: publisher + PSF + signing in one call

The full unpack → modify → repack → sign-once pipeline.

```powershell
$pw = Read-Host -AsSecureString

$fixup = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'

Invoke-MsixPipeline -PackagePath 'C:\drop\App.msix' `
    -OutputPath 'C:\drop\App-final.msix' `
    -Config @{
        Publisher = 'CN=Contoso, O=Contoso, C=NL'
        PSF       = @{ Fixups = @($fixup) }
        Signing   = @{
            Pfx                = 'C:\certs\cert.pfx'
            PfxPassword        = $pw
            UnsignedOutputPath = 'C:\drop\App-unsigned-fallback.msix'
        }
    }
```

- Unpacks once.
- Applies every edit to the same workspace.
- Signs exactly once at the end.
- Atomic: if signing fails, the original `App.msix` is untouched and the
  unsigned scratch is preserved at `UnsignedOutputPath`.
- `-WhatIf` runs the unpack-edit-pack stages so you can preview the result
  (via `-UnsignedOutputPath` and `-SaveManifestTo`) but skips the destructive
  sign + replace.

---

## 18. Standard scripts (PSADT-flavoured, parameterised)

Generate signed PowerShell scripts from bundled templates and inject them as PSF
`startScript` entries in one call. Customer-specific values are baked in at
generation time, so the same package base can carry per-customer state without
repackaging the binaries.

```powershell
$pw = Read-Host -AsSecureString -Prompt 'PFX password'

# Inspect the catalogue — five templates ship with the module
Get-MsixStandardScript | Format-Table Name, Description, RequiredParams

# 1) Generate + sign a script in isolation (no package touched yet)
New-MsixStandardScript -Name CreateShortcut `
    -Parameters @{
        DisplayName = 'Contoso Expenses'
        Target      = 'contosoexpenses.exe'
        Location    = 'Desktop'        # optional; default is Desktop
    } `
    -OutputPath 'C:\src\createshortcut.ps1' `
    -Pfx cert.pfx -PfxPassword $pw

# 2) Generate + sign + inject into the MSIX in one step
#    The script is added as a PSF startScript: it runs once on first launch,
#    before the main executable starts.
Add-MsixStandardScript -PackagePath app.msix -AppId 'App' `
    -Name CreateShortcut `
    -Parameters @{ DisplayName = 'Contoso Expenses'; Target = 'contosoexpenses.exe' } `
    -RunOnce -WaitForScriptToFinish `
    -Pfx cert.pfx -PfxPassword $pw

# 3) Sign an arbitrary .ps1 you wrote yourself (same cert as the package)
Set-MsixScriptSignature -ScriptPath my-bootstrap.ps1 `
    -Pfx cert.pfx -PfxPassword $pw

# 4) Cleanup script — bake the legacy AppData path as a parameter
New-MsixStandardScript -Name CleanupOldUserData `
    -Parameters @{
        Paths            = '%AppData%\Contoso\v1;%AppData%\Contoso\v2'
        OnlyOlderThanDays = '90'
    } `
    -OutputPath 'C:\src\cleanup.ps1' `
    -Pfx cert.pfx -PfxPassword $pw
```

Bundled templates (`Get-MsixStandardScript | Select-Object Name, Description`):

| Template | What it does |
|---|---|
| `CreateShortcut` | Desktop / Start-menu `.lnk` pointing at the AppExecutionAlias. |
| `CopyIconToAppData` | Copies bundled icons to `%APPDATA%` so `.lnk` files survive updates. |
| `CleanupOldUserData` | Idempotent removal of legacy profile paths and registry keys. |
| `RegisterFileAssociation` | Per-user FTA registration for one or more file extensions. |
| `CustomerSettingsBootstrap` | Writes per-customer JSON settings to HKCU on first run. |

> **Tip:** inject the script via `Add-MsixStandardScript` and then chain
> `Invoke-MsixPipeline` with `Signing.Skip = $true` to produce an unsigned
> package for review before the final sign-off.

---

## 19. App isolation (opt-in): AppContainer + AppSilo

`Add-MsixAppIsolation` makes a packaged Win32 app run in an **AppContainer**:
it switches the Application to `EntryPoint="Windows.PartialTrustApplication"`,
sets `TrustLevel="appContainer"`, and **removes `runFullTrust`** (the full-trust
entry point requires `runFullTrust`, which keeps the process full-trust — so it
could never isolate). Two modes:

- **AppContainer** (default, GA — Win10 2004+): `packagedClassicApp`. Ungranted
  access is **denied**. `-Capabilities` are **standard package capabilities**.
- **AppSilo** (`-Mode AppSilo`, preview — Win11 24H2): the Win32 App Isolation
  silo with the consent **broker** on top of the same AppContainer base.
  `-Capabilities` are **`isolatedWin32-*` / device capabilities**; raises
  `Windows.Desktop` MinVersion to `10.0.26100.0`.

**Validate first** — many legacy apps break under isolation because they rely on
broad filesystem / registry access.  Use Microsoft's
[Application Capability Profiler](https://github.com/microsoft/win32-app-isolation/releases)
to discover exactly which capabilities your app needs before adding them.

```powershell
$pw = Read-Host -AsSecureString -Prompt 'PFX password'

# GA AppContainer (strict): ungranted access denied, no capabilities granted
Add-MsixAppIsolation -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw

# AppContainer with specific standard capabilities granted
Add-MsixAppIsolation -PackagePath app.msix `
    -Capabilities internetClient, privateNetworkClientServer `
    -Pfx cert.pfx -PfxPassword $pw

# AppSilo (preview): brokered access with the consent prompt
# (see all documented silo capabilities: Get-MsixIsolationCapability)
Add-MsixAppIsolation -PackagePath app.msix -Mode AppSilo `
    -Capabilities 'isolatedWin32-promptForAccess', 'isolatedWin32-userProfileMinimal' `
    -Pfx cert.pfx -PfxPassword $pw

# Remove isolation entirely (restores FullTrustApplication + runFullTrust)
Remove-MsixAppIsolation -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw

# Preview what the manifest would look like — no package written
Add-MsixAppIsolation -PackagePath app.msix -Mode AppSilo -Pfx cert.pfx -PfxPassword $pw -WhatIf
```

Common **AppSilo** capabilities and their meaning (`isolatedWin32-*` are ignored
with a warning in AppContainer mode — use standard capability names there):

| Capability | Grants |
|---|---|
| `isolatedWin32-promptForAccess` | Broker dialog for resources outside the isolation boundary |
| `isolatedWin32-userProfileMinimal` | Read/write to a minimal set of known user folders |
| `isolatedWin32-userProfile` | Broader user-profile access (AppData, Documents, etc.) |
| `isolatedWin32-internetClient` | Outbound internet connections |
| `isolatedWin32-internetClientServer` | Inbound + outbound internet connections |
| `isolatedWin32-privateNetworkClientServer` | LAN access |
| `isolatedWin32-allowElevation` | UAC elevation inside the isolation boundary |
| `isolatedWin32-fullFileSystemAccess` | Broad filesystem access (defeats much of the isolation benefit) |

Two package shapes **cannot** be isolated (the cmdlet warns / throws):
a **PSF launcher** entry point (`PsfLauncher*.exe` — PSF injects fixup DLLs,
which AppContainer blocks) and a **`windows.comServer`** extension (invalid
with a partial-trust entry point). Verify isolation actually engaged by
checking the running process for an `S-1-15-2` AppContainer SID — see
`TEST-PLAN.md` Scenario 6.

> The pipeline supports isolation natively — add
> `AppIsolation = @{ Mode = 'AppContainer'|'AppSilo'; Capabilities = @(...) }`
> to your `Invoke-MsixPipeline` config alongside `PSF` and `Signing`; it applies
> the same model in one unpack/repack/sign pass.

---

## 20. Packaged Windows services, shell handlers, toast activators

The manifest features the capture's installer used to configure imperatively.

```powershell
$pw = Read-Host -AsSecureString

# Windows service that installs/starts with the package (agents, licensing)
Add-MsixService -PackagePath app.msix `
    -Executable 'VFS\ProgramFilesX64\App\agent.exe' -Name 'ContosoAgent' `
    -StartupType auto -StartAccount localService `
    -Pfx cert.pfx -PfxPassword $pw

# Preview / thumbnail / property shell handlers (registry-free COM + FTA)
Add-MsixShellHandlerExtension -PackagePath app.msix -Kind Preview `
    -Clsid '{D7E6F1A2-3B4C-4D5E-9F00-112233445566}' `
    -Dll 'VFS\ProgramFilesX64\App\PreviewHandler.dll' -FileTypes '.contoso' -SkipSigning

# Toast clicks re-activate the app
Add-MsixToastActivator -PackagePath app.msix `
    -Clsid '{ff1a2b3c-4d5e-6f70-8899-aabbccddeeff}' `
    -Executable 'VFS\ProgramFilesX64\App\app.exe' -Arguments '-ToastActivated' -SkipSigning

# Framework dependency instead of bundling DLLs (well-known MS publishers auto-filled)
Add-MsixPackageDependency -PackagePath app.msix `
    -Name Microsoft.VCLibs.140.00.UWPDesktop -MinVersion 14.0.33321.0 -SkipSigning

# Ship + install a certificate with the package (replaces the certutil step)
Add-MsixPackageCertificate -PackagePath app.msix `
    -CertificatePath .\internal-ca.cer -StoreName CA -SkipSigning
```

The scanners feed all of these into `Invoke-MsixInvestigation` findings, and
`Invoke-MsixAutoFixFromAnalysis` plans them automatically (certificates are
opt-in via `-DeclarePackageCertificates` — installing a cert is a trust
decision).

---

## 21. Work with .msixbundle files

Every mutator works on bundles through `Invoke-MsixBundleOperation` — no
per-cmdlet bundle support needed.

```powershell
$pw = Read-Host -AsSecureString

# What's inside?
Get-MsixBundleInfo -BundlePath app.msixbundle | Format-Table

# Apply any mutator to every inner package (unbundle -> mutate -> rebundle -> sign)
Invoke-MsixBundleOperation -BundlePath app.msixbundle -Operation {
    param($pkg)
    Add-MsixCapability -PackagePath $pkg -Names runFullTrust -SkipSigning
} -Pfx cert.pfx -PfxPassword $pw

# Only the x64 package; arm64/resource packages pass through untouched
Invoke-MsixBundleOperation -BundlePath app.msixbundle -Architecture x64 -Operation {
    param($pkg)
    Add-MsixAppIsolation -PackagePath $pkg -SkipSigning
} -SkipSigning

# Build a bundle from per-arch packages
New-MsixBundle -PackagePaths .\app-x64.msix, .\app-arm64.msix `
    -OutputPath .\app.msixbundle -Pfx cert.pfx -PfxPassword $pw
```

---

## 22. Shared runtime framework packages (one Java for all apps)

Stop bundling a JRE into every app: package the runtime once, patch it once.

```powershell
$pw = Read-Host -AsSecureString

# 1. Package the runtime ONCE as a framework package
New-MsixFrameworkPackage -RuntimeFolder C:\runtimes\jre-17 `
    -Name 'Contoso.Java.17' -Version 17.0.11.0 `
    -Publisher 'CN=Contoso Ltd' -Pfx cert.pfx -PfxPassword $pw

# 2. Wire each app to it: dependency + JAVA_HOME (via PSF EnvVarFixup)
Add-MsixRuntimeDependency -PackagePath app.msix `
    -FrameworkName 'Contoso.Java.17' -FrameworkMinVersion 17.0.11.0 `
    -FrameworkPublisher 'CN=Contoso Ltd' -Runtime Java `
    -Pfx cert.pfx -PfxPassword $pw

# DLL-based runtimes need no env wiring at all — the package graph is on the
# packaged process's DLL search path:
Add-MsixRuntimeDependency -PackagePath app.msix `
    -FrameworkName 'Contoso.SharedLibs' -FrameworkMinVersion 1.0.0.0 `
    -FrameworkPublisher 'CN=Contoso Ltd' -SkipSigning

# Find apps that still haul their own runtime
Get-MsixBundledRuntime -PackagePath app.msix
# ...and let autofix strip + rewire them (explicit identity required):
$report = Invoke-MsixInvestigation -PackagePath app.msix
Invoke-MsixAutoFixFromAnalysis -Report $report `
    -DeduplicateBundledRuntime `
    -RuntimeFrameworkName 'Contoso.Java.17' `
    -RuntimeFrameworkMinVersion 17.0.11.0 `
    -RuntimeFrameworkPublisher 'CN=Contoso Ltd' `
    -Pfx cert.pfx -PfxPassword $pw
```

Note: env wiring pins the framework install path to the exact MinVersion —
re-run `Add-MsixRuntimeDependency` after servicing the framework.

---

## 23. Modification packages: settings + golden-image deltas

Customize a vendor MSIX without touching it — files AND registry settings.

```powershell
$pw = Read-Host -AsSecureString

# Settings + license files layered onto the vendor app
New-MsixModificationPackage -MainPackagePath vendor.msix `
    -ContentPath .\customization `
    -RegistryContent @{
        'HKLM\SOFTWARE\Vendor\App' = @{ LicenseServer = 'lic01.contoso.com'; Port = 27000 }
        'HKCU\Software\Vendor\App' = @{ Theme = 'dark' }
    } `
    -Pfx cert.pfx -PfxPassword $pw

# Or productize an existing customization: diff vendor vs customized copy
ConvertTo-MsixModificationPackage `
    -MainPackagePath vendor.msix `
    -CustomizedPackagePath vendor-customized.msix `
    -OutputPath vendor-settings.msix `
    -Pfx cert.pfx -PfxPassword $pw
```

Install order on the endpoint: main package first, then the modification
package — Windows layers them into one container view.

---

## 24. Runtime verification in a Hyper-V VM

Static analysis says a package *should* work; this proves it *does*.
Needs a golden VM (sideloading enabled) and PowerShell Direct — no VM network.

```powershell
$cred = Get-Credential   # VM local admin

$result = Test-MsixDeployment -PackagePath app.msix -VMName 'Win11-24H2' `
    -Credential $cred -CertPath app.cer -Checkpoint 'clean' `
    -ModificationPackagePaths .\vendor-settings.msix

$result.Passed          # bottom line
$result.Reasons         # why it failed, if it did
$result.EventLogArtifacts  # WER / AppXDeployment errors -> feed the autofix loop
```

The verdict object is shaped like the other `Test-Msix*` results; on failure
the artifacts flow into `Invoke-MsixAutoFixFromAnalysis` so the loop closes:
test → analyze → autofix → retest.

---

## 25. Regenerate resources.pri after brand edits

On `ms-resource:`-localized packages, editing the manifest alone changes
nothing at runtime — the displayed strings come from `resources.pri`.

```powershell
$pw = Read-Host -AsSecureString

# One call: replace the ms-resource reference AND rebuild the PRI
Set-MsixBrandMetadata -PackagePath app.msix `
    -DisplayName 'Contoso Expenses (Managed)' `
    -RegeneratePri -Pfx cert.pfx -PfxPassword $pw

# Or regenerate standalone (after any resource-affecting edits)
Update-MsixResourcePri -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw
```

---

## 26. Distribute with a .appinstaller (auto-update)

Native sideload distribution with an update policy — no MDM required
(and if you use Intune, upload the .msix directly; it's a native app type).

```powershell
New-MsixAppInstallerFile -PackagePath .\app.msix `
    -PackageUri 'https://dist.contoso.com/app.msix' `
    -OnLaunch -ShowPrompt -HoursBetweenUpdateChecks 12

# Users install by opening the .appinstaller (or:)
# Add-AppxPackage -AppInstallerFile https://dist.contoso.com/app.appinstaller
```

---

## Common gotchas

- **CLSID format**: the MSIX manifest schema wants bare GUIDs
  (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) — no curly braces. The module
  normalises whatever you pass.
- **`MaxVersionTested`**: every manifest mutator auto-bumps this to the
  feature's minimum OS. Don't set it manually unless you know what you're
  doing.
- **`runFullTrust`**: required for COM servers, firewall rules, and most
  desktop integrations. The module auto-injects it where required (issues
  #12 and the M9 fix in PR 2).
- **Signing secrets**: prefer `-Signer TrustedSigning` over `-Signer SignTool
  -Pfx`. SignTool with a PFX exposes the password on the process command
  line (a Write-Warning fires when this happens so it shows up in CI logs).
- **WhatIf**: `-WhatIf` runs the unpack-edit-pack stages so you can preview
  the result, but skips signing and the final Move-Item to the target. Use
  `-SaveManifestTo` to capture the would-be manifest, and
  `-UnsignedOutputPath` to capture the would-be package.
