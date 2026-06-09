# MSIX Module — Manual Test Plan

This document describes the manual / integration test scenarios that complement
the Pester suite. The Pester tests cover pure functions, parameter validation,
idempotency, edge cases, XML security, secret non-leakage, and WhatIf semantics.
The scenarios below cover behaviour that requires real packages, real signing,
real OS extension activation, and other host-dependent state.

**Use these in a controlled lab environment.** Do not run signing tests against
production secrets. Use a self-signed cert (`New-MsixSelfSignedCertificate`)
unless explicitly testing a production signing backend.

---

## Conventions

- All examples assume `Import-Module C:\temp\msix\MSIX\MSIX.psd1`.
- Test packages live in `C:\lab\` for this document. Adjust paths.
- Each scenario lists **Setup → Steps → Expected → Cleanup**.
- Where a scenario writes to disk, use `-OutputPath` to keep an audit trail.

---

## Scenario 1 — Legacy IContextMenu shell extension (desktop9)

Verifies `Add-MsixLegacyContextMenu` produces a manifest that activates a
classic shell extension on Windows 11.

### Setup

- Windows 11 21H2 (build 22000) or later, with Developer Mode enabled.
- A test MSIX package containing a Win32 app and an in-package shell-extension
  DLL (any DLL exporting `DllGetClassObject` for a registered CLSID).
  Reference DLL: `VFS\ProgramFilesX64\Lab\ShellExt.dll`.
- A signed cert in the current user's `Cert:\CurrentUser\My` store (or a PFX
  on disk) whose `Subject` matches the package's `Identity.Publisher`.

### Steps

```powershell
$pw = Read-Host -AsSecureString 'Cert password'
Add-MsixLegacyContextMenu `
    -PackagePath 'C:\lab\TestApp.msix' `
    -ShellExtDll 'VFS\ProgramFilesX64\Lab\ShellExt.dll' `
    -Clsid       '12345678-1234-1234-1234-1234567890ab' `
    -DisplayName 'Lab Context Menu' `
    -FileTypes   '*','.log','Directory' `
    -Pfx 'C:\lab\lab.pfx' -PfxPassword $pw `
    -OutputPath  'C:\lab\TestApp-ctxmenu.msix'
```

Install: `Add-AppxPackage -Path 'C:\lab\TestApp-ctxmenu.msix'`.

Right-click any `.log` file, any directory, and the desktop. The "Lab Context
Menu" entry should appear in each case.

### Expected

- Resulting `.msix` is signed.
- `AppxManifest.xml` contains:
  - `xmlns:com`, `xmlns:desktop9`, both listed in `IgnorableNamespaces`.
  - `<Package><Dependencies><TargetDeviceFamily MaxVersionTested="10.0.22000.0"`
    or higher.
  - One `<com:Extension Category="windows.comServer">` under the Application's
    Extensions block with the surrogate registration.
  - One `<desktop9:Extension Category="windows.fileExplorerClassicContextMenuHandler">`
    with three `<desktop9:ExtensionHandler>` children (`*`, `.log`, `Directory`),
    all referencing the bare CLSID (no curly braces).
- The right-click context menu fires on Windows 11.

### Cleanup

```powershell
Remove-AppxPackage 'TestApp_1.0.0.0_x64__<pfn>'
```

### Common failure modes

- Menu doesn't appear → check `MaxVersionTested` ≥ 22000. desktop9 won't
  activate below that.
- Menu appears but click does nothing → CLSID format wrong. Both `com:Class@Id`
  and `desktop9:ExtensionHandler@Clsid` must be the bare GUID, no `{}`.
- Package fails to install → missing `runFullTrust` capability.
  `Add-MsixComServerExtension` auto-injects it; if you used the lower-level
  helpers, add it manually.

---

## Scenario 2 — Modern IExplorerCommand context menu (desktop4)

Verifies `Add-MsixFileExplorerContextMenu` produces a working modern
context-menu handler.

### Setup

- Windows 10 1803 (build 17134) or later.
- A test MSIX with an `IExplorerCommand`-based COM server.
- Signing cert as above.

### Steps

```powershell
Add-MsixFileExplorerContextMenu `
    -PackagePath 'C:\lab\TestApp.msix' `
    -AppId       'App' `
    -VerbId      'lab-open' `
    -VerbClsid   '11111111-2222-3333-4444-555555555555' `
    -FileTypes   '.log','.txt' `
    -OutputPath  'C:\lab\TestApp-modern.msix'
```

### Expected

- Manifest gains `xmlns:desktop4` and `<desktop4:FileExplorerContextMenus>`.
- `MaxVersionTested` bumped to at least 10.0.17134.0.
- On Windows 11, the verb appears in the modern context menu (Show More
  Options → … hidden by default behind the Win11 design).

---

## Scenario 3 — Add an alias (AppExecutionAlias)

Verifies `Add-MsixAlias` writes a valid `uap3:AppExecutionAlias`.

### Steps

```powershell
Add-MsixAlias `
    -PackagePath 'C:\lab\TestApp.msix' `
    -AppId       'App' `
    -ExecutableName 'lab.exe' `
    -OutputPath  'C:\lab\TestApp-alias.msix'
```

Install. From `cmd` or `pwsh`: `lab.exe`. The packaged executable should launch.

### Expected

- `xmlns:uap3` added to the manifest.
- `<uap3:Extension Category="windows.appExecutionAlias">` under the
  Application's Extensions, with `<uap3:AppExecutionAlias>/<desktop:ExecutionAlias Alias="lab.exe">`.
- After install, `where lab.exe` finds the alias in
  `%LOCALAPPDATA%\Microsoft\WindowsApps\`.

---

## Scenario 4 — FileSystem write virtualization (the Notepad++ plugin case)

Verifies the plugin-install path works when virtualization is properly enabled,
and that disabling it correctly redirects writes.

### Setup

- Windows 10 2004 (build 19041) or later.
- A packaged app that writes to `C:\Program Files\<App>\plugins\` (e.g.
  a packaged Notepad++ with the plugin manager).

### Steps

```powershell
# Default: enable virtualization, exclude user-data paths
Set-MsixFileSystemWriteVirtualization `
    -PackagePath 'C:\lab\Notepadpp.msix' `
    -OutputPath  'C:\lab\Notepadpp-virt.msix'
```

Install. Open the packaged Notepad++. Use the plugin manager to install a
plugin (e.g. NppExport). Verify the plugin loads on next launch.

### Expected

- Manifest gains `<desktop6:FileSystemWriteVirtualization>enabled</...>` under
  `<Properties>`.
- `<virtualization:FileSystemWriteVirtualization>/<ExcludedDirectories>` lists
  `LocalAppData` and `RoamingAppData`.
- `MaxVersionTested` ≥ 10.0.19041.0.
- `rescap:Capability Name="unvirtualizedResources"` added automatically.
- The plugin installs and loads. Writes to
  `C:\Program Files\Notepad++\plugins\` actually land in
  `%LOCALAPPDATA%\Packages\<PFID>\LocalCache\Local\VFS\ProgramFilesX64\Notepad++\plugins\`.

### If the plugin install still fails

Add PSF FileRedirection as a secondary layer. See `docs/fixup-FileRedirection.md`.
Plugin managers that probe write-access with `CreateFile` before extracting
sometimes need the API-level interception that PSF provides.

```powershell
$plug = New-MsixPsfFileRedirectionConfig `
    -Base 'VFS\ProgramFilesX64\Notepad++\plugins' `
    -Patterns '.*'
Add-MsixPsfV2 -PackagePath 'C:\lab\Notepadpp-virt.msix' `
    -Fixups @($plug) `
    -OutputPath 'C:\lab\Notepadpp-virt-psf.msix'
```

---

## Scenario 5 — Registry write virtualization

Verifies `Set-MsixRegistryWriteVirtualization`.

### Steps

```powershell
Set-MsixRegistryWriteVirtualization `
    -PackagePath 'C:\lab\App.msix' `
    -ExcludedKeys 'SOFTWARE\Vendor\PublicConfig' `
    -OutputPath  'C:\lab\App-reg.msix'
```

Install. Use the app to write to `HKEY_LOCAL_MACHINE\SOFTWARE\App\...`.
The write should land in the per-user package hive
(`%LOCALAPPDATA%\Packages\<PFID>\SystemAppData\Helium\User.dat`).

The excluded key `SOFTWARE\Vendor\PublicConfig` should write to the real
HKLM (if the app has the right ACLs).

---

## Scenario 6 — Win32 App Isolation opt-in

Verifies `Add-MsixAppIsolation` produces a Win32 App Isolation-enabled package.

### Setup

- Windows 11 24H2 (build 26100) or later.
- Test MSIX of a Win32 app with known capability needs.

### Steps

```powershell
Add-MsixAppIsolation `
    -PackagePath 'C:\lab\App.msix' `
    -Capabilities 'isolatedWin32-promptForAccess', 'isolatedWin32-accessToDownloadsFolder' `
    -OutputPath 'C:\lab\App-isolated.msix'
```

### Expected

- `xmlns:uap18` and `xmlns:rescap` added (both in `IgnorableNamespaces`).
- **The `<Application>` carries the attributes that actually enable isolation**
  (the capability alone does nothing):
  - `EntryPoint="Windows.FullTrustApplication"`
  - `uap18:EntryPoint="Isolated.App"`
  - `uap18:TrustLevel="appContainer"`
  - `uap18:RuntimeBehavior="appSilo"`
- The `Windows.Desktop` `TargetDeviceFamily` `MinVersion` is raised to
  **`10.0.26100.0`**, and `MaxVersionTested` ≥ 10.0.26100.0. The MinVersion bump
  is **mandatory** — isolation only engages when the package *targets* 24H2;
  with a lower MinVersion, Windows treats the package as legacy full-trust and
  ignores the `uap18` attributes (because `uap18` is in `IgnorableNamespaces`).
  Consequence: the isolated package will **no longer install on Windows older
  than 24H2**.
- One `<rescap:Capability>` per requested capability, plus
  `isolatedWin32-shellExtensionContextMenu` auto-added if the package has a COM
  context menu (`com:Extension windows.comServer` / `FileExplorerContextMenus`).
- **`runFullTrust` REMAINS** in `<Capabilities>`. It is *not* incompatible with
  isolation — it is required *together* with it: the isolated app keeps
  `EntryPoint="Windows.FullTrustApplication"`, and the AppxManifest schema
  requires `runFullTrust` for that entry point (MakeAppx rejects the package
  without it, error `0x80080204`). Isolation is enforced by the `uap18`
  appContainer/appSilo attributes, not by removing `runFullTrust`. Use
  `-RemoveRunFullTrust` only on a toolchain/runtime that accepts the isolated
  entry point without it.
- The package installs and runs with isolation active. Verify access prompts
  fire as expected, and confirm the process runs in an AppContainer (e.g.
  Process Explorer → the process shows an AppContainer SID / low integrity).

### How to confirm isolation is *actually* active

The behavioural test (the access prompt) is necessary but not sufficient —
prompts can come from other features (e.g. ASR rules). The **definitive** check
is the process token:

```powershell
# launch the PACKAGED app (not a same-named desktop install), then:
Get-Process <exe> | Select-Object Id, Path     # Path must be under …\WindowsApps\…
```

In **Process Explorer → Security**, an isolated process shows an
**AppContainer SID `S-1-15-2-…`** and **AppContainer / Low** integrity. If you
instead see **Medium** integrity and no `S-1-15-2` SID, the app is **not**
isolated regardless of what the manifest says.

### Common failure mode — "manifest is correct but it still runs full-trust"

Win32 App Isolation is a **preview** feature. When the OS doesn't have it
active, it **silently falls back to full trust** (documented behaviour, build
26100.2161 release notes) — a perfectly-formed isolated package then runs
exactly like a normal full-trust packaged app. Work through these in order:

1. **`MinVersion` < 10.0.26100.0** → the OS ignores the `uap18` attributes.
   `Add-MsixAppIsolation` raises it automatically; a package hand-edited or
   re-packed by another tool may have reset it.
2. **OS patch level.** Check `(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR`
   — isolation needs build **26100.2161+**. (`[Environment]::OSVersion.Version`
   does *not* report the UBR.)
3. **Windows Sandbox does not engage isolation.** It's a reduced, disposable VM;
   a correct isolated package runs full-trust there. Verify on a real host.
4. **The feature simply isn't active on this build/channel.** It's flighted on
   Insider (Canary/Dev) builds and not necessarily lit up on a retail 24H2
   servicing build, with no Settings toggle. If even a *minimal* isolated
   control app (a trivial exe + the isolation manifest, nothing else) runs
   full-trust on the host, the package is fine — the machine isn't activating
   the feature. Build the official VS "Blank App, isolated" sample (or a minimal
   control) and compare.
5. **PSF.** A `PsfLauncher*.exe` entry point can never isolate (PSF injects
   fixup DLLs, which AppContainer blocks). `Add-MsixAppIsolation` warns on this.

The module's job ends at emitting the documented manifest; steps 2–4 are OS
feature-enablement, outside packaging.

---

## Scenario 7 — Add a Win32 firewall rule

Verifies `Add-MsixFirewallRule` lands under `Package/Extensions` (not
Application/Extensions) per the fix in issue #12.

### Steps

```powershell
Add-MsixFirewallRule `
    -PackagePath 'C:\lab\App.msix' `
    -AppId       'App' `
    -Executable  'VFS\ProgramFilesX64\App\App.exe' `
    -Direction   'in' `
    -Protocol    'TCP' `
    -LocalPort   '8443' `
    -OutputPath  'C:\lab\App-fw.msix'
```

### Expected

- `<desktop2:Extension Category="windows.firewallRules">` lives under
  `<Package><Extensions>`, NOT under `<Application><Extensions>`.
- `runFullTrust` rescap is auto-injected (firewall rules require it).
- After install, `Get-NetFirewallRule -DisplayGroup '<package-display-name>'`
  shows the rule.
- After uninstall, the rule is removed (rule lifecycle follows the package).

---

## Scenario 8 — Self-signed cert + sandbox debug flow

Verifies the end-to-end self-sign + sandbox bootstrap.

### Steps

```powershell
$cert = New-MsixSelfSignedCertificate `
    -Subject 'CN=Lab Test, O=Lab, C=NL' `
    -OutputPath 'C:\lab\cert\'

# Update the package Publisher to match
$pw = ConvertTo-SecureString 'temp' -AsPlainText -Force
Update-MsixSigner -PackagePath 'C:\lab\App.msix' `
    -Pfx $cert.PfxPath -PfxPassword $cert.Password `
    -OutputPath 'C:\lab\App-selfsigned.msix'

Invoke-MsixSelfSignAndDebug -PackagePath 'C:\lab\App-selfsigned.msix'
```

### Expected

- A self-signed cert is generated and installed into both
  CurrentUser\My and LocalMachine\Root (with a clear prompt).
- The package's Identity.Publisher matches the cert Subject.
- A Windows Sandbox session opens with the package preloaded and DebugView
  running.

---

## Scenario 9 — Trusted Signing backend (production-style)

Verifies `Invoke-MsixSigning -Signer TrustedSigning`. Requires an Azure Trusted
Signing account with a CodeSigningProfile.

### Setup

- Az.CodeSigning module installed.
- `$ToolsRoot\Tools\TrustedSigning\Azure.CodeSigning.Dlib.dll` present (or
  pass `-TrustedSigningClientDll`).
- `az login` already completed.

### Steps

```powershell
Invoke-MsixSigning -PackagePath 'C:\lab\App.msix' -Signer TrustedSigning `
    -TrustedSigningAccount  'MyAccount' `
    -TrustedSigningProfile  'MyProfile' `
    -TrustedSigningEndpoint 'https://eus.codesigning.azure.net'
```

### Expected

- No password prompt; auth flows via Azure CLI session.
- A temp JSON metadata file is created in `$env:TEMP`, used by signtool /dlib,
  then deleted in the finally block. Confirm with
  `Get-ChildItem $env:TEMP -Filter 'msix-trustedsigning-*'` after the run —
  should be empty.
- `Get-AuthenticodeSignature 'C:\lab\App.msix'` reports
  `SignerCertificate.Subject` starting with `CN=` of the Trusted Signing cert.
- No `SignTool /p` warning emitted (we're not using a PFX).

---

## Scenario 10 — Atomic packaging: signing failure leaves original intact

Verifies the C4 fix — original package never overwritten if signing fails.

### Steps

```powershell
# Use a deliberately wrong PFX password
$wrongPw = ConvertTo-SecureString 'WRONG' -AsPlainText -Force
$origHash = (Get-FileHash 'C:\lab\App.msix').Hash

try {
    Set-MsixFileSystemWriteVirtualization `
        -PackagePath 'C:\lab\App.msix' `
        -Pfx 'C:\lab\lab.pfx' -PfxPassword $wrongPw `
        -UnsignedOutputPath 'C:\lab\App-unsigned-fallback.msix'
} catch {
    Write-Host "Expected signing failure: $_"
}

$afterHash = (Get-FileHash 'C:\lab\App.msix').Hash
$origHash | Should -Be $afterHash    # unchanged
Test-Path 'C:\lab\App-unsigned-fallback.msix' | Should -BeTrue
```

### Expected

- `App.msix` is byte-identical before and after the failed signing run.
- The unsigned scratch is preserved at `App-unsigned-fallback.msix` so the
  operator can re-sign manually.

---

## Scenario 11 — WhatIf preview produces inspectable XML without mutation

Verifies the M1 fix — `-WhatIf` runs unpack/edit/pack but skips signing and
the final Move-Item.

### Steps

```powershell
$origHash = (Get-FileHash 'C:\lab\App.msix').Hash

Set-MsixFileSystemWriteVirtualization `
    -PackagePath 'C:\lab\App.msix' `
    -UnsignedOutputPath 'C:\lab\App-preview.msix' `
    -SaveManifestTo 'C:\lab\preview-manifest.xml' `
    -WhatIf

$afterHash = (Get-FileHash 'C:\lab\App.msix').Hash
$origHash | Should -Be $afterHash
Test-Path 'C:\lab\preview-manifest.xml' | Should -BeTrue
```

### Expected

- Original package unchanged.
- `preview-manifest.xml` contains the edits we would have made.
- `App-preview.msix` contains the unsigned scratch (if the unpack-edit-pack
  ran without error).
- No signtool invocation occurs.

---

## Scenario 12 — Authenticode-verified tool download

Verifies the H1 fix — every downloaded binary's leaf signer is checked
against the trusted-publisher allowlist.

### Setup

- Fresh machine with no MSIX module toolchain yet.

### Steps

```powershell
Initialize-MsixToolchain -ToolsRoot 'C:\msix-tools'
```

### Expected

- Each tool download (PSF, Procmon, msixmgr, SDK tools, App Runtime, DebugView)
  is followed by an `Authenticode verified:` log line naming the leaf signer.
- If you tamper with a downloaded binary (e.g. replace `signtool.exe` with a
  random EXE) and re-run, the verification fails with a clear error naming the
  file and the actual signer's Subject.

---

## Scenario 13 — XXE / billion-laughs rejected

Verifies the H4 fix — manifest XML loaders refuse hostile input.

### Steps

```powershell
$xxe = @'
<?xml version="1.0"?>
<!DOCTYPE p [ <!ENTITY x SYSTEM "file:///etc/passwd"> ]>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="&x;" Publisher="CN=X" Version="1.0.0.0" />
</Package>
'@

{ New-MsixManifestDocument -XmlText $xxe } | Should -Throw '*DTD*'
```

### Expected

- Throws because DTD processing is prohibited. Identical for billion-laughs
  payloads.

---

## CI regression suite — what runs automatically

The `.github/workflows` Pester + PSScriptAnalyzer job covers:

- The full Pester suite under `MSIX.Tests/` (security, idempotency,
  edge cases, WhatIf, validation, helper-pattern guards, etc.) -- the
  count grows release-on-release, so the authoritative number lives
  in the test-runner output, not this document. As of v0.70.6 the
  suite was 364 / 0 / 1; the next release will report its own count
  in `CHANGELOG.md` and `msix.psd1`'s release notes.
- PSScriptAnalyzer on every `.ps1` and the `.psd1` -- must be 0
  Error + 0 Warning findings scoped to the MSIX module.
- UTF-8 BOM check on `.Tests.ps1` files (the
  `PSUseBOMForUnicodeEncodedFile` rule).
- Module-contract test asserting `msix.psd1`'s `FunctionsToExport` /
  `AliasesToExport` matches the actual runtime exports (issue #41,
  so the manifest stays the single source of truth).

Anything in this document that *can't* be expressed as a Pester test (real
package installs, real signing services, real shell-extension activation)
should be run manually before each release.

### Running the suite on hardened hosts (issue #47)

Pester emits an NUnit XML artifact by default. The exporter calls
`Get-CimInstance Win32_*` for environment metadata, which needs WMI/CIM
privileges that locked-down developer workstations and build agents may
revoke. The tests themselves don't care, but the end-step throws and
the wrapper correctly exits with the infra-failure code.

If you see `Get-CimInstance: Access denied` from
`Write-NUnitEnvironmentInformation` on your host, run the suite with
`-DisableTestResult` (alias `-NoTestResult`):

```powershell
# Hardened workstation -- skip the NUnit artifact:
pwsh .\MSIX.Tests\Invoke-MsixTests.ps1 -DisableTestResult
```

This disables `TestResult.Enabled` for that run only. CI keeps the
default and still publishes the NUnit XML for downstream consumption.

---

## Release checklist

Before tagging a release:

- [ ] Full Pester suite green on PowerShell 7
      (`pwsh MSIX.Tests/Invoke-MsixTests.ps1`). Record the actual
      pass / fail / skip counts in the release notes; the suite grows
      release-on-release so a hard-coded number here will lag.
- [ ] PSScriptAnalyzer reports zero Error + zero Warning findings when
      scoped to the MSIX module (`Invoke-ScriptAnalyzer -Path .
      -Recurse -Severity Error,Warning`).
- [ ] Scenarios 1, 4, 7, 8, 10, 11, 13 executed manually and pass.
- [ ] Scenario 9 executed against the production Trusted Signing account.
- [ ] `CHANGELOG.md` updated.
- [ ] `MSIX.psd1` `ModuleVersion` bumped per SemVer.
- [ ] PSGallery publish dry-run (`Publish-Module -WhatIf`) clean.
