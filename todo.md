# MSIX Module — TODO / Roadmap

> Status: **v0.9.0 shipped**. Tracks gaps and ideas for v1.0+. Entries are
> grouped by area; check items off as they land.

---

## v0.9.0 — what was delivered

Modelled on the feature surface of TMEditX (Tim Mangan's commercial editor),
turned into PowerShell-native, opt-in cmdlets.

- [x] **MFR** (Modern File Redirection — TMurgent fork's `MFRFixup.dll`):
      `New-MsixMfrTraditionalRule`, `New-MsixMfrLocalRule`,
      `New-MsixPsfMfrConfig`, `Get-MsixMfrKnownFolders`. ILV-aware mode,
      COW (default/enablePe/disableAll), Traditional + Local known-folder
      catalogues.
- [x] **RegLegacyFixups** extended with `FakeDelete`, `DeletionMarker`,
      `Hklm2Hkcu` types (was only `ModifyKeyAccess`).
- [x] **VC++ runtime detection + bundling** — `Get-MsixVcRuntimeReferences`
      scans PE imports, `Add-MsixVcRuntimeBundle` copies the right-arch
      DLLs in from a VS Redist source folder.
- [x] **TMEditX-style heuristic auto-fixers** (each opt-in):
  - [x] `Add-MsixCapability` / `Get-MsixKnownCapabilities` —
        standard + rescap.
  - [x] `Get-MsixUninstallerCandidates` / `Remove-MsixUninstallerArtifacts`.
  - [x] `Get-MsixRunKeyEntries` — surface autostart entries baked into
        the package's virtual hive.
  - [x] `Get-MsixAliasCandidates` — suggest AppExecutionAlias targets.
  - [x] `Add-MsixSplashScreen` — patch a splash image into the PSF
        startScript so users see feedback during slow first-run logic.
  - [x] `Update-MsixPackageVersion` — bump the 4-part Identity Version
        (`KeepLastZero` matches TMEditX's behaviour).
  - [x] `Get-MsixHeuristicFindings` — read-only roll-up of all the
        above; merged into `Get-MsixStaticAnalysis`.
- [x] `Invoke-MsixAutoFix` — TMEditX-style staged orchestrator.
      Runs RemoveUninstallers / BumpVersion / AddCapabilities / InjectPsf /
      BundleVcRuntimes / AddSplashImage with a single signing pass at the end.
      `-DryRun` reports stages without mutating anything.
- [x] `Compare-MsixPackage` — diffs two .msix files (manifest, files,
      signing). Returns a structured `HasChanges` / `ManifestChanges` /
      `FileChanges` / `SigningChanges` object. CI-gate ready.

---

## v0.8.0

- [x] Pester test suite under `MSIX.Tests\` (Builders, Manifest, Validation,
      Trace, Limitations, Recommendations, AppIsolation, Scripts).
- [x] Trace Fixup output parser (DebugView log files) integrated into
      `Get-MsixCompatibilityReport` via `-TraceLogPath`.
- [x] `msixmgr` auto-installer + `Initialize-MsixToolchain` upgrade.
- [x] PSADT-style standard scripts (CreateShortcut / CopyIconToAppData /
      CleanupOldUserData / RegisterFileAssociation / CustomerSettingsBootstrap).

## v0.7.0

- [x] TMurgent PSF + Process Monitor auto-installers.
- [x] `Initialize-MsixToolchain` (one-call setup).
- [x] `Start-MsixDebugSession` + Windows Sandbox bootstrap.
- [x] Copy-paste recommended commands.
- [x] App Attach VHDX/CIM (`New-MsixAppAttachImage`).
- [x] Win32 App Isolation (opt-in).
- [x] Limitations knowledge base.
- [x] Pipeline overhaul: signs ONCE at the end, `-OutputPath`.
- [x] `Add-MsixPsfV2 -OutputPath / -SkipSigning`.
- [x] `docs/` per-fixup reference + limitations + know-your-installer.

---

## v1.0 — Signing, distribution, polish

### Signing (deferred since v0.7)
- [ ] **Azure Trusted Signing** wrapper for keyless / cloud-signed MSIX.
      Detect the Trusted Signing client, fall back to PFX when not present.
- [ ] **AzureSignTool** wrapper for Azure Key Vault HSM scenarios.
- [ ] Verify that the manifest Publisher matches the cert Subject
      *before* signing (today: only when `-Publisher` is set).
- [ ] Dual-sign (SHA1 + SHA256) helper for legacy compatibility.
- [ ] `Set-MsixScriptSignature` Trusted-Signing/AzureSignTool variant.

### Tests + CI
- [ ] CI workflow (GitHub Actions or Azure DevOps) running Pester on
      Win-2022.
- [ ] Sample fixture .msix files (small, deterministic) checked in.
- [ ] Pester for: MFR builders, VC runtime scanner, heuristics,
      AutoFix orchestrator (DryRun), Compare-MsixPackage.
- [ ] Mock-based tests for `Add-MsixPsfV2` / `Invoke-MsixPipeline`
      flow control.
- [ ] Script-template smoke test that runs the rendered .ps1 in a runspace
      to catch syntax errors at generation time.

### Investigation / parsing
- [ ] ETW capture mode for trace fixup so a live DebugView session isn't
      required.
- [ ] More static heuristics:
  - [ ] Hardcoded `C:\Users\Public\` paths.
  - [ ] Detect installer-style `.exe` shipped inside the package.
  - [ ] Detect missing `runFullTrust` capability when needed.
  - [ ] Detect missing `desktop:Extension` for COM/file-association edge cases.
- [ ] Map `RecommendedCommands` back to specific AppIds for procmon-driven findings.
- [ ] HTML output mode for `Get-MsixCompatibilityReport`.
- [ ] Full Registry.dat / User.dat hive parser (today: regex string scan)
      so Run-key / service / CPA detection is reliable.

### PSF coverage
- [ ] `DynamicLibraryFixup` typed builder.
- [ ] `WaitForDebuggerFixup` typed builder.
- [ ] `monitor` block (PsfMonitor) for live logging from a packaged app.
- [ ] PSF launcher's `inProcess` mode option.

### Heuristic fixers (build on v0.9)
- [ ] **Font registration** (`Add-MsixFontFixup`) — register
      packaged fonts so they're visible to the host's font system.
- [ ] **Firewall rules** (`Add-MsixFirewallRule` /
      `Remove-MsixFirewallRule`) — manage `windows.firewallRules` extension.
- [ ] **Control Panel Applets** (`Add-MsixControlPanelApplet`).
- [ ] **Desktop shortcut remediation** (`Remove-MsixDesktopShortcut`).
- [ ] **Brand package** metadata (DisplayName/PublisherDisplayName/Description
      uniformly) — TMEditX `BrandPackageOnSave`.
- [ ] **Rule HKLM2HKCU auto-detection** — scan the package's hive for HKLM
      writes and propose patterns.

### Accelerators
- [ ] Round-trip: `Export-MsixAccelerator`.
- [ ] Implement non-PSF FixTypes that can be automated: Capability,
      EntryPoint, LoaderSearchPathOverride, InstalledLocationVirtualization.
- [ ] Bundle popular accelerator templates (Notepad++, 7-Zip, LINE, etc.).

### App Attach
- [ ] Update an existing VHDX/CIM with newer package versions in-place.
- [ ] Generate the share-side metadata (CIM hash, expanded folder
      hierarchy) that AVD App Attach requires.
- [ ] `New-MsixAppAttachImage -Bundle` for `.msixbundle` expansion.

### App Isolation
- [ ] Wrap the [Application Capability Profiler](https://github.com/microsoft/win32-app-isolation/releases)
      so the module can recommend a minimum capability set automatically.
- [ ] Detect mismatch between requested capabilities and what the app needs
      at runtime (post-install validation).

### AppData / out-of-package
- [ ] `Sync-MsixContainerToHost` — reverse direction (export packaged data).
- [ ] Detect AppContainer SID from package family name and use it for ACL fixes.
- [ ] Optional cleanup mode for orphan AppData (`-WhatIf` by default).
- [ ] Handle `LocalCache\Local` (not just Roaming) in `Copy-MsixHostAppDataIntoPackage`.

### Standard scripts (build on v0.8)
- [ ] More templates: PinToTaskbar, RegisterStartupTask, CertificateImport.
- [ ] Validate the rendered script via PSScriptAnalyzer before signing.
- [ ] `New-MsixStandardScript` `-Force` to overwrite (CustomerSettingsBootstrap
      currently honours it; surface in the API).

### Context menus
- [ ] `Remove-MsixContextMenu` (idempotent removal by Clsid).
- [ ] Validation that the referenced shellex DLL actually lives at the path.
- [ ] Auto-resolve Clsid from an existing registered COM server on the host.

### Pipeline
- [ ] Stage gating: opt-out of individual stages.
- [ ] Output: produce a JSON manifest of all changes per pipeline run.
- [ ] Resumable pipeline (skip already-done stages on re-run).

---

## Future / longer term

- [ ] App-V → MSIX migration helpers.
- [ ] Modification Package generator (`Add-MsixModificationPackage`).
- [ ] MSIX-Bundle creation (`pack /f` mapping file generator).
- [ ] Block map / certificate inspection helpers.
- [ ] PSF source-build integration (compile fixups from the PSF source on
      demand for custom branches).

---

## Documentation

- [x] `docs/fixup-*` per-fixup reference docs (FileRedirection, RegLegacy,
      EnvVar, Trace, WorkingDirectory) — done in v0.7
- [x] `docs/limitations.md`, `docs/know-your-installer.md` — done in v0.7
- [ ] `docs/fixup-MFR.md` — Modern File Redirection (added in v0.9, doc still TBD)
- [ ] `docs/auto-fix-stages.md` — explain `Invoke-MsixAutoFix` stages
      and TMEditX → module name mapping.
- [ ] Decision tree: "my app does X, which fixup do I need?"
- [ ] Example accelerators with explanations.
- [ ] Migration guide from v1 → v0.9.
- [ ] FAQ: common signtool error codes mapped to fixes.

---

## Known issues / caveats

- `Get-MsixRunKeyEntries` uses a regex string scan over Registry.dat /
  User.dat as a best-effort. A proper hive parser is on the v1.0 list — for
  now treat the output as triage, not gospel.
- `Get-MsixVcRuntimeReferences` matches strings inside PE files for the
  documented VC runtime DLL names. False negatives are possible for unusual
  toolsets; pass `-Names` to `Add-MsixVcRuntimeBundle` if the auto-detect
  misses a DLL you need.
- `Add-MsixSplashScreen` requires the package to already be PSF-wrapped
  (run `Add-MsixPsfV2` or `Invoke-MsixAutoFix -PsfFixups …` first).
- `Compare-MsixPackage` rehashes every file with SHA-256 in process —
  on very large packages, expect a few seconds of CPU.
- `aka.ms/msixmgr` may serve a download that requires interactive consent
  on first hit. Use `Install-MsixMgr -Force` if it fails.
- The trace parser expects DebugView's "save as .log" format. Pure ETW
  captures aren't supported yet (v1.0).
- Pester tests require Pester v5+ (Pester v3 ships with WinPS 5.1 by default
  and is not compatible).
- The module name `MSIX` clashes with the installed community module owned
  by this project's maintainer. Until the next gallery release, **import by
  full path**.

---

## Triage — resolved

- v0.9: TMEditX feature parity (curated subset).
- v0.8: Pester tests, Trace Fixup parser, msixmgr auto-update, PSADT scripts.
- v0.7: TMurgent PSF binaries, sign-once pipeline, dry-run output path,
        Procmon auto-update.
