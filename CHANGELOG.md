# Changelog

Full release history of the MSIX module. The published `ReleaseNotes`
field in `MSIX.psd1` is constrained to PSGallery's 10,600-character
limit and carries only the current version's highlights — everything
older lives here.

## Unreleased - Security review fixes (#49, #50, #51, #52, #53, #56)

### Security / robustness fixes (post-review)

- **#53 — AzureSignTool no longer handles a raw client secret.** `Invoke-MsixSigning
  -Signer AzureSignTool` previously accepted `-KeyVaultClientSecret` and passed
  it as `--azure-key-vault-client-secret` on the process command line
  (WMI-readable). Since this module runs in arbitrary consumer sessions whose
  Azure auth context it does not own, it now passes **no** credential material:
  the `-KeyVaultClientSecret` parameter is removed and the module sets no
  `AZURE_*` environment variables. AzureSignTool authenticates via its
  DefaultAzureCredential chain (managed identity, `az login`, Visual Studio /
  VS Code sign-in, or `AZURE_*` env vars the consumer has set). `-KeyVaultTenantId`
  / `-KeyVaultClientId` remain as non-sensitive scoping hints. **Breaking:**
  callers passing `-KeyVaultClientSecret` must instead set `AZURE_CLIENT_SECRET`
  (+ tenant/client id) in their environment, or use a managed identity.

- **#56 — Run-key scan hardening.** `Get-MsixRunKeyEntry` previously decoded the
  entire Registry.dat / User.dat as a UTF-16 string and ran an unbounded regex
  over it — vulnerable to ReDoS / memory blow-up on a hostile hive, with both
  false positives (matches in binary noise) and false negatives (non-aligned
  strings). It now parses the hives with offreg.dll and enumerates the values
  under `…\CurrentVersion\Run`, returning `Name`/`Command` alongside the
  existing `Hive`/`Match`. New `_MsixOfflineEnumValueNames` helper.

### Security fixes (release-blocking)

- **#49 — template injection.** `_MsixRenderTemplate` substituted parameter
  values into the bundled `templates/*.tmpl` with a raw `String.Replace`. Every
  placeholder lives inside a single-quoted PowerShell literal, so a value
  containing `'` broke out and injected arbitrary code into the generated —
  and subsequently code-signed — startup script. Values now have embedded
  single quotes doubled before substitution.
- **#50 — XXE in `Invoke-MsixManifestTransform`.** The exported transform
  re-parsed string input with a raw `[xml]` cast (default resolver + DTD
  enabled), bypassing `_MsixLoadXmlSecure`. String input now routes through the
  hardened loader (DTD prohibited, no external entity resolution).
- **#51 — Zip-Slip in `_MsixExpandZip`.** .NET's `ZipFile.ExtractToDirectory`
  does not sanitise entry names; a malicious third-party archive could write
  outside the destination. Each entry's resolved path is now validated against
  the destination root before extraction.
- **#52 — TLS floor.** The module now raises `ServicePointManager.SecurityProtocol`
  to TLS 1.2+ at import so PS5.1 hosts no longer negotiate TLS 1.0/SSL3 for
  toolchain downloads.

## v0.70.6 - Atomic pack-sign hardening + heuristics refactor (#34, #35, #36, #37, #38)

### Correctness fixes (post-v0.70.5 review)

- **#34 — atomic pack-sign-move in `Add-MsixCapability` + `Remove-MsixUninstaller-
  Artifact`**. Both functions used to pack straight to `$PackagePath` and then
  sign; a signing failure left the user with an unsigned modified copy of
  their signed package. Both now pack to a scratch path, sign at the scratch,
  and `Move-Item` to the target only on success. `-UnsignedOutputPath`
  preserves the scratch on signing failure for inspection. The other two
  mutators (`Remove-MsixUpdaterArtifact`, `Remove-MsixShellRegistryArtifact`)
  were already atomic.
- **#35 — `Compare-MsixTrace.Summary` undercount fix**. Surfaces
  `ResolvedRowCount` / `PersistedRowCount` / `IntroducedRowCount` alongside
  the categorised finding counts. `ConvertFrom-MsixTraceToFinding` only maps
  paths under System32 / WindowsApps / HKLM / `LoadLibrary*` failures;
  regressions on any other path used to silently disappear from the summary.
  A `Write-MsixLog Warning` fires when `IntroducedRowCount > IntroducedCount`
  so the asymmetry is visible at runtime.

### Refactors (no public API change)

- **#36 — toolchain installer scaffolding**. New `_MsixInstallArchiveTool` +
  `_MsixUpdateToolByAge` helpers collapse six near-identical installers
  (Procmon, DebugView, msixmgr) and four age-based updaters (Procmon,
  DebugView, msixmgr, AppRuntime) into thin wrappers. Bespoke installers
  with version-aware idempotency (`Install-MsixPsfBinary`,
  `Install-MsixSdkTool`, `Install-MsixAppRuntime`) remain self-contained.
  msixmgr's Authenticode opt-out is preserved (upstream signing is broken;
  see microsoft/msix-packaging#710) and surfaces a `Write-Warning`.
- **#37 — `_MsixMutatePackage` helper**. Lives in `MSIX.Pipeline.ps1`. All
  four heuristic mutators (`Add-MsixCapability`, `Remove-MsixUninstaller-
  Artifact`, `Remove-MsixUpdaterArtifact`, `Remove-MsixShellRegistry-
  Artifact`) delegate to it. The atomic pack-sign-move pattern from #34 is
  now enforced by construction — a future mutator that bypassed the helper
  would have to redefine its own scratch + sign block, which the WhatIf
  regression guard forbids.
- **#38 — split `MSIX.Heuristics.ps1`** (2764 lines) into three files:
  - `MSIX.Scanners.ps1` — read-only `Get-Msix*Candidate` / `*Entry` /
    `HeuristicFinding` family + offline-registry path helpers.
  - `MSIX.PackageMutators.ps1` — `Add-MsixCapability`, `Remove-Msix*Artifact`,
    `Add-MsixSplashScreen`, `Update-MsixPackageVersion`, plus
    `$script:KnownCapabilities` + `Get-MsixKnownCapability`.
  - `MSIX.AutoFix.ps1` — `Invoke-MsixAutoFix` + `Invoke-MsixAutoFixFromAnalysis`.

  All ten plural-noun back-compat aliases (`Get-MsixUninstallerCandidates`,
  `Get-MsixHeuristicFindings`, etc.) carried forward. Six test files
  updated to track the new file paths.

### Subtle behaviour change

- `Update-MsixMgr` now previews `Update msixmgr` uniformly under `-WhatIf`
  instead of `Install missing msixmgr` / `Refresh msixmgr` depending on
  state. Matches the pattern already used by `Update-MsixProcMon` /
  `Update-MsixDebugView` / `Update-MsixAppRuntime`.

### Quality bar

- Pester (PowerShell 7): **364 pass / 0 fail / 1 skip** (was 351 in v0.70.5;
  +13 new regression guards covering atomic semantics, raw-row counts, and
  the helper-pattern contract).
- PSScriptAnalyzer (scoped to MSIX module, Error+Warning): **0 findings**.

## v0.70.5 - Tier-2 remediation orchestration (#30 + #31 + #32)

- Compare-MsixTrace (#31): before/after correlation of two runtime trace
  captures (DebugView .log/.txt or ProcMon .pml). Classifies failure rows
  as Resolved / Persisted / Introduced via (Function x Path x Result)
  match key. `-Sarif` emits a 3-run SARIF 2.1.0 document so regressions
  surface as errors and fixes surface as notes.
- New/Export/Import/Test/Invoke-MsixRemediationPlan (#32): serialise a
  remediation plan to YAML, route through change-control, replay
  deterministically against a later build. Strict cmdlet-safety guard
  (only MSIX module cmdlets in appliedFixes), identity + SHA-256
  fingerprint drift detection, single-sign-at-end semantics. YAML
  emitter/parser is dependency-free and scalar-only (same security
  stance as the accelerator YAML).
- Invoke-MsixAutoFixLoop (#30): multi-pass remediation pipeline.
  Per-pass artefacts under `$env:TEMP\msix-autofix-loop-<runId>\pass-N\`,
  optional Compare-MsixTrace integration for the NoRegressions stop
  condition, MinConfidence gate from the evidence model, signs once at
  the end. Closes the loop on chained MSIX issues where fixing one
  problem reveals the next.
- PowerShell 5.1 compatibility: removed null-coalescing operator (??)
  from Merge-MsixFinding and Invoke-MsixAutoFixLoop. Stripped em-dashes
  from string literals in the new files - UTF-8 byte 0x94 was being
  read as a curly double-quote terminator under CP-1252 in Windows
  PowerShell 5.1 (no BOM by default).
- Pester: 351 pass / 0 fail / 1 skip on PowerShell 7 (27 new tests for
  the Tier-2 features). PSScriptAnalyzer (scoped to MSIX module): 0
  findings.

## v0.70.4 - Tier-1 evidence model + PSSA cleanup

- Unified evidence model + confidence scoring (#29). New
  MSIX.Evidence.ps1 with New-MsixFinding / Add-MsixEvidence /
  Merge-MsixFinding / Get-MsixFindingConfidence /
  ConvertTo-MsixFinding / ConvertTo-MsixLegacyFinding.
- Invoke-MsixAutoFixFromAnalysis: new -MinConfidence gate (default 0.85).
  Legacy findings without EvidenceItems are treated as confident so the
  migration is incremental.
- SARIF emitter passes evidenceItems[] + confidence through to
  result.properties when populated.
- PSSA: Get-MsixManifestApplication gets per-parameter-set OutputType +
  XmlNode[] return-site casts; Get-MsixRequiredAppRuntimeChannel returns
  [string[]]; trailing whitespace stripped from Recommendations test.
  Scoped PSSA findings: 0. Pester: 325 / 0 / 1.
- Closes #28, #29.

## v0.70.0
See `MSIX.psd1` (PrivateData.PSData.ReleaseNotes) for the v0.70.0 notes.

## v0.14.0 - Multi-channel WindowsAppRuntime, DebugView auto-install, HTML/JSON reports

Three real-world sandbox failures fixed.

1. WindowsAppRuntime version pinning. Notepad 8.9.x declares
   <PackageDependency Name="Microsoft.WindowsAppRuntime.1.4" .../> but
   we were only installing the 1.6 channel, so the sandbox install died
   with HRESULT 0x80073CF3. v0.14 keeps a per-channel cache (1.4 / 1.5 /
   1.6 by default) and the sandbox bootstrap installs EVERY .exe found
   in C:\msix-runtime\ on first launch.

   New:
     Get-MsixRequiredAppRuntimeChannel  - parse manifest dependencies
     Install-MsixAppRuntime -Channels   - download per-channel installers
                                          (filename has the channel suffix
                                          so they live side-by-side)
     New-MsixSandboxConfig auto-detects required channels from the
     manifest before generating the .wsb and caches whatever's missing.

2. DebugView auto-install. The Sysinternals DebugView zip is separate
   from ProcessMonitor.zip, so Start-MsixDebugSession was logging
   "DebugView not found" even after Initialize-MsixToolchain. v0.14
   adds:
     Install-MsixDebugView, Update-MsixDebugView, Get-MsixDebugViewVersion
     Initialize-MsixToolchain pulls DebugView too (-Skip DebugView to omit)
     Resolve-MsixDebugViewPath now looks in $ToolsRoot\debugview\ first
     Start-MsixDebugSession -LaunchDebugView auto-downloads on miss

3. Structured debug reports. report.txt was unreadable - PowerShell
   Format-List on nested objects rendered Findings as @{Sev=...;Cat=...}
   strings. v0.14 writes:
     report.json   - full structured data (Findings + SuggestedFixups
                     + RecommendedCommands + ProcMonLog), Depth=12
     report.html   - standalone single-file HTML with sortable Findings
                     table, severity colour coding, embedded code block
                     of recommended commands, dark-mode aware CSS.
     recommended-commands.ps1 - unchanged, still the copy-paste path.
   Old report.txt is retired.

   New cmdlet ConvertTo-MsixReportHtml renders any
   Get-MsixCompatibilityReport result to a self-contained HTML page.

## v0.13.0 - Alias collision fix, sandbox runtime, self-signed cert flow

Bug fixes:
- Removed 5 self-aliasing backward-compat entries that broke their own
  functions: update-MsixSigner, new-MsixPsfJson, add-MsixAlias,
  remove-MsixStartMenuEntry, add-MsixStartMenuFolder. PowerShell is
  case-insensitive, so Set-Alias from 'name' to 'Name' shadows the function
  and `Get-Command Name` started returning the alias instead of the
  function. AliasesToExport in this manifest is now down to the four that
  legitimately differ from their target names.

Architecture:
- Public package-operation functions moved out of MSIX.psm1 into a dedicated
  MSIX.Functions.ps1, matching the per-area sub-module convention used by
  the rest of the project. The root .psm1 is now just dot-source loader +
  Export-ModuleMember.

New: Sandbox-ready Windows App Runtime + DesktopAppInstaller cache
- Install-MsixAppRuntime / Update-MsixAppRuntime / Get-MsixAppRuntimeVersion
  cache the DesktopAppInstaller msixbundle (https://aka.ms/getwinget) and
  the Windows App Runtime installer EXE under $ToolsRoot\runtime\. Default
  Win11 Sandbox lacks both and silently fails to install MSIX packages
  until they're present.
- Initialize-MsixToolchain now downloads them too (skip with -Skip Runtime).
- New-MsixSandboxConfig maps the runtime cache into the sandbox at
  C:\msix-runtime\ and the bootstrap script runs the .exe + Add-AppPackage
  of the bundle before installing the target .msix.

New: Self-signed certificate flow (Start-MsixSandbox -AutoSign)
- Test-MsixSignature reports whether a package needs self-signing to install
  in a clean sandbox (NotSigned / HashMismatch / Incompatible / UnknownError).
- New-MsixSelfSignedCertificate creates a cert whose Subject EXACTLY
  matches the manifest's Publisher attribute (mismatch triggers signtool
  0x8007000B), exports PFX + public .cer, returns the paths.
- Invoke-MsixSelfSignAndDebug: end-to-end self-sign helper.
- Start-MsixSandbox -AutoSign auto-generates the cert when needed, signs
  the package, and the sandbox bootstrap installs the .cer into
  LocalMachine\Root + TrustedPeople before installing the package.
- New-MsixSandboxConfig -CertPath: bring your own .cer if you have one.

## v0.11.0 - Connect-the-dots autofix, more detection, -NoSign, polymorphic Get-MsixManifest

Bug fixes:
- Get-MsixManifest now accepts a .msix / .appx / .msixbundle path and
  extracts the AppxManifest.xml on the fly (it used to do
  Get-Content -Raw on the binary archive). It also accepts a folder
  containing AppxManifest.xml. Existing direct-XML-path callers still work.
- Remove-MsixUninstallerArtifacts now ALSO strips Uninstall\<key> entries
  from Registry.dat (the package's virtualized HKLM). Requires admin
  (reg.exe load); a clear warning is emitted if not elevated. -KeepRegistry
  brings back the old "files only" behaviour.

New features:
- -NoSign alias on every editing cmdlet, paralleling -SkipSigning
  (Add-MsixPsfV2, Add-MsixCapability, Set-MsixFileSystemWriteVirtualization,
  Add-MsixVcRuntimeBundle, Add-MsixStartupTask, ... 19 cmdlets).
- Invoke-MsixAutoFixFromAnalysis: takes the report from
  Invoke-MsixInvestigation and runs the right fixer for every finding,
  signing once at the end. -DryRun shows the plan. Maps:
    UninstallerArtifact                -> Remove-MsixUninstallerArtifacts
    VcRuntime                          -> Add-MsixVcRuntimeBundle
    ManifestFix:FileSystemWriteVirt..  -> Set-MsixFileSystemWriteVirtualization
    ManifestFix:RegistryWriteVirt..    -> Set-MsixRegistryWriteVirtualization
    ManifestFix:StartupTask            -> Add-MsixStartupTask
    ManifestFix:LoaderSearchPathOver.. -> Add-MsixLoaderSearchPathOverride
    FileRedirectionFixup               -> Add-MsixPsfV2 (PSF)
  -PreferManifestOverPsf (default $true) avoids double-fixing the same symptom.

- New PSF typed builders (round out the catalogue):
    New-MsixPsfDynamicLibraryConfig    DLL name -> package-relative path
    New-MsixPsfWaitForDebuggerConfig   diagnostic; remove before shipping

- Three new auto-detectors (read-only):
    Get-MsixFontCandidates             find .ttf/.otf/.ttc shipped in package
    Get-MsixDesktopShortcutCandidates  find .lnk under VFS\Common Desktop
    Get-MsixCapabilityHints            guess capabilities from PE imports
    Get-MsixUninstallRegistryEntries   list Uninstall\* keys in Registry.dat

- Three new manifest fixers:
    Add-MsixFontExtension              register fonts via uap4:SharedFonts
    Set-MsixBrandMetadata              bulk DisplayName / PublisherDisplayName
                                       / Description / Logo (with optional
                                       -ApplyToApplications fan-out)
    Remove-MsixDesktopShortcuts        strip .lnk from VFS\Common Desktop

Get-MsixHeuristicFindings (and therefore the unified report) now surfaces:
  - SharedFonts not registered for shipped fonts
  - Desktop shortcuts in package
  - Capability hints from PE imports
  - Uninstall registry leftovers
which all flow through Invoke-MsixAutoFixFromAnalysis automatically.

## v0.10.0 - Manifest-only fixers (alternatives to PSF)

The AppX manifest schema has matured a lot since PSF was first written.
Several runtime issues that PSF traditionally addressed via DLL injection
can now be fixed by adding the right manifest extension - faster at runtime,
no foreign DLLs in the package, and survives Windows updates more cleanly.

This release exposes all of them as PowerShell cmdlets, with idempotent
namespace registration and automatic MaxVersionTested bumps.

  Set-MsixFileSystemWriteVirtualization      desktop6   Win10 19041+
      Per-user redirection of writes to the install dir.
      Manifest alternative to PSF FileRedirectionFixup / MFRFixup.

  Set-MsixRegistryWriteVirtualization        desktop6   Win10 19041+
      Per-user redirection of HKLM writes.
      Manifest alternative to RegLegacyFixups Hklm2Hkcu.

  Set-MsixInstalledLocationVirtualization    uap10      Win10 19041+
      Like FileSystemWriteVirtualization but with explicit update-time
      policy (ModifiedItems / DeletedItems / AddedItems = keep|reset).

  Add-MsixLoaderSearchPathOverride           uap6       Win10 17134+
      Up to 5 additional package-relative DLL search paths.
      Manifest alternative to DynamicLibraryFixup for the simple case.

  Add-MsixFirewallRule                       desktop2   Win10 15063+
      Firewall rule that's installed/removed alongside the package.

  Add-MsixProtocolHandler                    uap        always
      Register a custom URL scheme (e.g. contoso://).

  Add-MsixFileTypeAssociation                uap        always
      Register a ProgID-style FTA inside the manifest. The host-side
      RegisterFileAssociation script template is now mostly redundant.

  Add-MsixStartupTask                        uap5       Win10 15063+
      Modern, manifest-native autostart entry. Properly fires for packaged
      apps, where HKLM\Run keys do not.

Get-MsixHeuristicFindings now surfaces these as alternatives:
  - "package writes to install dir AND no FileSystemWriteVirtualization"
  - "package writes to HKLM AND no RegistryWriteVirtualization"
  - "Run keys present AND no windows.startupTask"
  - "DLL load failures AND no LoaderSearchPathOverride"

Namespace registry extended: uap5, uap6, uap10, desktop2, desktop6.

## v0.9.2 - Bug fixes for the SDK tools installer

- Install-MsixSdkTools no longer fails on the .nupkg extension. Switched to
  System.IO.Compression.ZipFile.ExtractToDirectory which extracts any
  zip-format archive regardless of its filename. Expand-Archive only honours
  ".zip" — that was an oversight.
- Get-MsixToolsRoot error message uses ASCII dashes so it renders correctly
  on the default Windows console codepage (was emitting U+2014 em-dash that
  showed up as garbage on cp1252 / OEM consoles).
- New private helper _MsixExpandZip used by other zip-extraction call sites
  for consistency.

## v0.9.1 - SDK tools auto-installer (no more manual MakeAppx hunt)

Fixes the UX regression when the module is loaded without a sibling toolchain
folder ("MakeAppx.exe not found …" with no actionable path forward).

- Install-MsixSdkTools / Update-MsixSdkTools / Get-MsixSdkToolsVersion —
  fetches Microsoft.Windows.SDK.BuildTools from NuGet and lays the binaries
  out at $ModuleFolder\Tools so Get-MsixToolsRoot finds them automatically.
- Initialize-MsixToolchain now installs the SDK tools first (so MakeAppx +
  signtool are present before PSF / Procmon / msixmgr touch a package).
- Get-MsixToolsRoot now walks up to four parent levels looking for a
  Tools\MakeAppx.exe sibling, scans every versioned subfolder under the
  Windows 10/11 SDK install (not just the unversioned ones), and emits a
  copy-pasteable resolution menu in the error message instead of a one-liner.
- Get-MsixToolsRoot -AutoInstall triggers Install-MsixSdkTools on miss.
- Get-MsixToolsRoot -Refresh drops the session cache.

## v0.9.0 — TMEditX-style auto-fixers, MFR, VC runtime bundling, compare

Modelled on the feature surface of TMEditX (Tim Mangan's commercial MSIX edit
tool). Everything here is opt-in and PowerShell-native.

- MFR (Modern File Redirection) typed builder — TMurgent fork's MFRFixup.dll:
    New-MsixMfrTraditionalRule, New-MsixMfrLocalRule, New-MsixPsfMfrConfig,
    Get-MsixMfrKnownFolders. Supports ILV-aware mode + COW (default/enablePe/
    disableAll) + Traditional & Local known-folder catalogues.

- RegLegacyFixups: extended with FakeDelete, DeletionMarker, Hklm2Hkcu types
    (was previously ModifyKeyAccess only).

- VC++ runtime detection + bundling (Get-MsixVcRuntimeReferences,
    Add-MsixVcRuntimeBundle) — scans PE imports for missing msvcp140 /
    vcruntime140 / ucrtbase, locates them in a VS Redist source folder
    (architecture-aware), copies them in.

- TMEditX-style heuristic auto-fixers (each opt-in):
    Add-MsixCapability / Get-MsixKnownCapabilities — standard + rescap.
    Get-MsixUninstallerCandidates / Remove-MsixUninstallerArtifacts —
        strip uninst*/setup* leftovers.
    Get-MsixRunKeyEntries — surface HKLM/HKCU \Run autostart entries
        baked in by the original installer.
    Get-MsixAliasCandidates — suggest AppExecutionAlias targets.
    Add-MsixSplashScreen — patch a splash image into the PSF launcher
        startScript so users see feedback while a slow first-run runs.
    Update-MsixPackageVersion — bump the 4-part Identity Version
        (Major/Minor/Build/Revision) with optional KeepLastZero.
    Get-MsixHeuristicFindings — read-only roll-up of all the above; merged
        into Get-MsixStaticAnalysis so Invoke-MsixInvestigation surfaces
        them automatically.

- Invoke-MsixAutoFix — TMEditX-style staged orchestrator. Drives a curated
    set of fixers (RemoveUninstallers, BumpVersion, AddCapabilities,
    InjectPsf, BundleVcRuntimes, AddSplashImage) and signs ONCE at the end.
    -DryRun reports stages without mutating.

- Compare-MsixPackage — diffs two .msix files: Identity / Properties /
    Capabilities / Applications, file list (added/removed/modified by
    SHA-256 hash), and signing state. Returns a structured
    HasChanges / ManifestChanges / FileChanges / SigningChanges object.

## v0.8.0 — Trace parser, Pester tests, msixmgr auto-update, PSADT scripts

- Trace Fixup output parser (DebugView-saved logs):
    ConvertFrom-MsixTraceLine, Get-MsixTraceOutput, Get-MsixTraceFailures,
    ConvertFrom-MsixTraceToFindings — turns OutputDebugString lines back
    into structured failure objects and maps them to fixup categories.
    Get-MsixCompatibilityReport / Invoke-MsixInvestigation now accept
    -TraceLogPath so a saved DebugView trace folds straight into the
    same Findings + RecommendedCommands flow that procmon already uses.

- msixmgr auto-installer (App Attach):
    Install-MsixMgr / Update-MsixMgr / Get-MsixMgrVersion pull
    https://aka.ms/msixmgr. Initialize-MsixToolchain now installs PSF +
    Procmon + msixmgr in one call (skip individual ones with -Skip).

- Standard scripts (PSADT-flavoured templates):
    Get-MsixStandardScripts catalogue.
    New-MsixStandardScript renders a customised .ps1 from a template
        (CreateShortcut, CopyIconToAppData, CleanupOldUserData,
         RegisterFileAssociation, CustomerSettingsBootstrap).
    Set-MsixScriptSignature signs scripts with the same cert as the package.
    Add-MsixStandardScript: high-level "generate + sign + inject as PSF
        startScript" in one call.

- Pester test suite under MSIX.Tests\:
    Builders, Manifest, Validation, Trace, Limitations, Recommendations,
    AppIsolation, Scripts. Runner: MSIX.Tests\Invoke-MsixTests.ps1.
    Pure-function tests so CI does not need the toolchain installed.

## v0.7.0 — TMurgent PSF, Sandbox debug, App Attach, App Isolation

- TMurgent PSF auto-installer:
    Install-MsixPsfBinaries / Update-MsixPsfBinaries / Get-MsixPsfBinariesVersion
    Pulls latest release from TimMangan/MSIX-PackageSupportFramework, includes
    PsfLauncher / PsfRuntime / StartingScriptWrapper / MFRFixup.
- Procmon auto-installer:
    Install-MsixProcMon / Update-MsixProcMon — pulls Sysinternals zip.
- Initialize-MsixToolchain — one-call setup of both PSF and Procmon.

- Debug session helper:
    Start-MsixDebugSession — runs static analysis, prints copy-paste recommended
    commands, optionally installs the package, launches Procmon and DebugView.
    Get-MsixDebugRecommendations — emits exact PowerShell commands per finding.

- Windows Sandbox bootstrap:
    New-MsixSandboxConfig / Start-MsixSandbox — generates a .wsb file that
    boots a clean sandbox with the module + drop folder mapped, and auto-runs
    Start-MsixDebugSession on logon.

- App Attach:
    New-MsixAppAttachImage — produces a VHDX (Hyper-V module) or CIM (msixmgr)
    from one or more .msix files.
    Mount/Dismount/Test-MsixAppAttachImage — round-trip inspection.

- Win32 App Isolation (opt-in, never enabled by default):
    Add-MsixAppIsolation / Remove-MsixAppIsolation / Get-MsixIsolationCapabilities
    Adds rescap isolatedWin32-* capabilities; bumps MaxVersionTested to 26100.

- Limitations knowledge base:
    Get-MsixLimitations / Test-MsixAgainstLimitations — lists current MS-documented
    limitations and matches them against a specific package.

- Pipeline overhaul:
    Invoke-MsixPipeline now signs ONCE at the very end (no per-stage resign).
    Added -OutputPath for non-destructive runs (output to a separate file).
    Added Config.AppIsolation block.

- Add-MsixPsfV2: -OutputPath dry-run + -SkipSigning for chained mutations.

- Get-MsixCompatibilityReport now returns RecommendedCommands: a string array
  of copy-paste-ready PowerShell that addresses each finding.

- docs/ folder with per-fixup reference and limitations doc.

## v0.6.0 — Investigation + AppData + Accelerators
(see CHANGELOG section)