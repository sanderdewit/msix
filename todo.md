# MSIX Module — TODO / Roadmap

> Status: **v0.12.0 shipped**. Tracks gaps and ideas for v1.0+.
> Entries are grouped by area; check items off as they land.

---

## v0.12.0 — enterprise readiness, manifest-first priority, bug fixes

### Bug fixes
- [x] `Add-MsixAlias` completely rewritten — correct `uap3:AppExecutionAlias`
      schema, no stray `desktop:Executable` attribute, reliable `SelectSingleNode`
      for multi-extension packages.
- [x] `Add-MsixPsfV2` — `StartingScriptWrapper.ps1` now always copied when
      a startScript/endScript is configured, even without `-AdditionalFiles`.
- [x] `Get-MsixCompatibilityReport` — registry uninstall entries (`Registry.dat`
      string-scan fallback) now reported alongside file-system artifacts.
- [x] Signing failures now throw a terminating error (`throw`) instead of
      `Write-Error`, so `try/catch` and `-ErrorAction Stop` work correctly.

### Renamed cmdlets (backward-compatible aliases retained)
- [x] `Invoke-MsixCmd` → `Invoke-MsixCommand` (`-AppId` override added).
- [x] `Get-PublisherIdFromPublisher` → `Get-MsixPublisherId` (module-prefix
      convention, shorter name).

### New autofix coverage
- [x] `Invoke-MsixAutoFixFromAnalysis` — 4 new finding→fixer mappings:
      `UninstallRegistry` (merged with `UninstallerArtifact`),
      `DesktopShortcuts` → `Remove-MsixDesktopShortcuts`,
      `ManifestFix:SharedFonts` → `Add-MsixFontExtension`,
      `CapabilityHints` → `Add-MsixCapability`.
- [x] `Invoke-MsixAutoFix` — two new stages: `-RemoveDesktopShortcuts`,
      `-AddFontExtension`.  `SupportsShouldProcess` (`-WhatIf`) added.
- [x] `$report.SuggestedManifestFixes` property — manifest alternatives for
      PSF findings surfaced by `Get-MsixCompatibilityReport` /
      `Invoke-MsixInvestigation`.

### Architecture
- [x] 14 v0.7-era editing cmdlets refactored to the shared `_MsixMutateManifest`
      private helper — eliminates ~15 lines of duplicated unpack/repack/sign
      boilerplate per function. Affected: `Add-MsixAppIsolation`,
      `Remove-MsixAppIsolation`, `Add-MsixLegacyContextMenu`,
      `Add-MsixFileExplorerContextMenu`, `Add-MsixAlias`,
      `Remove-MsixStartMenuEntry`, `Add-MsixStartMenuFolder`, and others.
- [x] All `Write-Host` calls replaced with `Write-Information` (stream 6) —
      module output is now fully capturable by CI pipelines and transcripts.
- [x] `_MsixExpandZip` internal helper used in `Install-MsixPsfBinaries`
      (replaces bare `Expand-Archive` call).

### PSF typed builders
- [x] `New-MsixPsfDynamicLibraryConfig` — DLL name → package-relative path
      mappings for `DynamicLibraryFixup.dll`.
- [x] `New-MsixPsfWaitForDebuggerConfig` — halts launch until a debugger
      attaches; optional per-process filter.

### Misc
- [x] `Add-MsixDiagnosticTrace` now accepts `-OutputPath` and
      `-SkipSigning [Alias('NoSign')]`, forwarded to `Add-MsixPsfV2`.
- [x] `New-MsixAppAttachImage` — elevation check added (throws if not admin).
- [x] Pester `-NoSign alias` Describe block rewritten with `-ForEach` pattern
      to fix Pester v5 discovery-phase scoping bug (was 17 failing tests, now 0).
- [x] 127/128 tests pass; 1 skipped (App Attach — requires admin + Hyper-V).

---

## v0.11.0 — connect-the-dots autofix, more detection, -NoSign

### Bug fixes
- [x] `Get-MsixManifest` accepts a .msix / .appx / .msixbundle / .appxbundle
      file and extracts AppxManifest.xml automatically (used to call
      `Get-Content -Raw` on the binary archive).
- [x] `Remove-MsixUninstallerArtifacts` now also strips `Uninstall\<key>`
      entries from `Registry.dat` (the package's virtualized HKLM hive).
      Requires admin (reg.exe load); warns and continues otherwise.

### -NoSign everywhere
- [x] Every editing cmdlet has a `[Alias('NoSign')]` on its `-SkipSigning`
      switch — `Add-MsixPsfV2`, `Add-MsixCapability`, `Add-MsixFontExtension`,
      `Set-MsixFileSystemWriteVirtualization`, `Add-MsixVcRuntimeBundle`,
      ... 19 cmdlets in total.

### Connect-the-dots autofix
- [x] `Invoke-MsixAutoFixFromAnalysis` consumes a report from
      `Invoke-MsixInvestigation` and runs the right fixer for every finding,
      signing once at the end. `-DryRun` shows the plan.
      `-PreferManifestOverPsf` (default $true) avoids double-fixing when both
      a PSF and a manifest fix are suggested for the same symptom.

### PSF typed builders (full coverage now)
- [x] `New-MsixPsfDynamicLibraryConfig` — DLL name -> package-relative path
- [x] `New-MsixPsfWaitForDebuggerConfig` — diagnostic, strip before shipping

### Auto-detection
- [x] `Get-MsixFontCandidates` (.ttf / .otf / .ttc inside the package)
- [x] `Get-MsixDesktopShortcutCandidates` (.lnk under `VFS\Common Desktop`)
- [x] `Get-MsixCapabilityHints` (heuristic capabilities from PE imports)
- [x] `Get-MsixUninstallRegistryEntries` (loads Registry.dat, walks Uninstall\*)
- [x] All four feed `Get-MsixHeuristicFindings` so they show up in
      `Invoke-MsixInvestigation` automatically.

### New manifest fixers
- [x] `Add-MsixFontExtension` — register fonts via `uap4:SharedFonts`
- [x] `Set-MsixBrandMetadata` — bulk DisplayName / PublisherDisplayName /
      Description / Logo (with optional `-ApplyToApplications` fan-out)
- [x] `Remove-MsixDesktopShortcuts` — strip `.lnk` from `VFS\Common Desktop`

---

## v0.10.0 — manifest-only fixers (alternatives to PSF)

- [x] **MSIX.ManifestExtensions.ps1** with 8 manifest-level fixers, idempotent
      namespace registration, automatic `MaxVersionTested` bumps:
  - [x] `Set-MsixFileSystemWriteVirtualization` (desktop6, 19041+)
  - [x] `Set-MsixRegistryWriteVirtualization`   (desktop6, 19041+)
  - [x] `Set-MsixInstalledLocationVirtualization` (uap10, 19041+) with
        ModifiedItems / DeletedItems / AddedItems policy.
  - [x] `Add-MsixLoaderSearchPathOverride` (uap6, 17134+); replaces
        `DynamicLibraryFixup` for the simple case. Caps at 5 entries
        per the schema.
  - [x] `Add-MsixFirewallRule` (desktop2, 15063+); rule lifecycle now
        follows the package.
  - [x] `Add-MsixProtocolHandler` (uap); custom URL schemes.
  - [x] `Add-MsixFileTypeAssociation` (uap); ProgID-style FTA inside the
        manifest. The host-side `RegisterFileAssociation` script template
        is now mostly redundant.
  - [x] `Add-MsixStartupTask` (uap5, 15063+); modern autostart that
        actually fires for packaged apps (HKLM\Run keys do not).
- [x] Namespace registry extended with **uap5, uap6, uap10, desktop2, desktop6**.
- [x] `Get-MsixHeuristicFindings` now proposes manifest fixes when symptoms
      match (writes to install dir, HKLM writes, Run keys, DLL load failures).
- [x] Shared `_MsixMutateManifest` private helper for unpack/edit/repack/sign.

## v0.9.0 — heuristic auto-fixers (curated)

Modelled on the feature surface of leading commercial MSIX editors,
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
- [x] **heuristic heuristic auto-fixers** (each opt-in):
  - [x] `Add-MsixCapability` / `Get-MsixKnownCapabilities` —
        standard + rescap.
  - [x] `Get-MsixUninstallerCandidates` / `Remove-MsixUninstallerArtifacts`.
  - [x] `Get-MsixRunKeyEntries` — surface autostart entries baked into
        the package's virtual hive.
  - [x] `Get-MsixAliasCandidates` — suggest AppExecutionAlias targets.
  - [x] `Add-MsixSplashScreen` — patch a splash image into the PSF
        startScript so users see feedback during slow first-run logic.
  - [x] `Update-MsixPackageVersion` — bump the 4-part Identity Version
        (`KeepLastZero` matches commercial MSIX editors's behaviour).
  - [x] `Get-MsixHeuristicFindings` — read-only roll-up of all the
        above; merged into `Get-MsixStaticAnalysis`.
- [x] `Invoke-MsixAutoFix` — heuristic staged orchestrator.
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
- [x] deployment-script templates (CreateShortcut / CopyIconToAppData /
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
- [x] `DynamicLibraryFixup` typed builder — `New-MsixPsfDynamicLibraryConfig` (v0.12).
- [x] `WaitForDebuggerFixup` typed builder — `New-MsixPsfWaitForDebuggerConfig` (v0.12).
- [ ] `monitor` block (PsfMonitor) for live logging from a packaged app.
- [ ] PSF launcher's `inProcess` mode option.

### Heuristic fixers (build on v0.9)
- [x] **Font registration** — `Add-MsixFontExtension` via `uap4:SharedFonts` (v0.11/v0.12).
- [x] **Firewall rules** — `Add-MsixFirewallRule` via `desktop2` (v0.10).
- [x] **Desktop shortcut remediation** — `Remove-MsixDesktopShortcuts` (v0.11/v0.12).
- [x] **Brand package** metadata — `Set-MsixBrandMetadata` (v0.11).
- [ ] **Control Panel Applets** (`Add-MsixControlPanelApplet`).
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
      and commercial-tool → module name mapping.
- [ ] Decision tree: "my app does X, which fixup do I need?"
- [ ] Example accelerators with explanations.
- [ ] Migration guide from v1 → v0.9.
- [ ] FAQ: common signtool error codes mapped to fixes.

---

## Known issues / caveats

- `Get-MsixRunKeyEntries` uses a regex string scan over Registry.dat /
  User.dat as a best-effort. A proper hive parser is on the v1.0 list — for
  now treat the output as triage, not gospel.
- `Get-MsixUninstallRegistryEntries` uses the same string-scan fallback when
  not running as admin (reg.exe load is skipped). Results are best-effort;
  prefer running as admin for authoritative output.
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
- `New-MsixAppAttachImage` requires an elevated (Administrator) session and
  Hyper-V. The 1 skipped Pester test covers this cmdlet for that reason.

---

## Triage — resolved

- v0.12: Enterprise readiness pass — `Add-MsixAlias` rewrite, PSF wrapper bug,
         registry uninstall detection, terminating signing errors, renamed
         cmdlets with aliases, new autofix mappings, `_MsixMutateManifest`
         refactor, `Write-Information` logging, DynamicLibrary/WaitForDebugger
         PSF builders, 17-test Pester fix (127/128 passing).
- v0.11: Connect-the-dots autofix, `-NoSign` everywhere, font/shortcut/capability
         detection, `New-MsixPsfDynamicLibraryConfig`, `New-MsixPsfWaitForDebuggerConfig`,
         `Get-MsixManifest` polymorphic, `Set-MsixBrandMetadata`,
         `Remove-MsixDesktopShortcuts`.
- v0.10: Manifest-only fixers (8 cmdlets), `_MsixMutateManifest` foundation,
         namespace registry, `Get-MsixHeuristicFindings` manifest proposals.
- v0.9: commercial-editor feature parity (curated subset).
- v0.8: Pester tests, Trace Fixup parser, msixmgr auto-update, PSADT scripts.
- v0.7: TMurgent PSF binaries, sign-once pipeline, dry-run output path,
        Procmon auto-update.
