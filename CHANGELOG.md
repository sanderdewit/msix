# Changelog

Full release history of the MSIX module. The published `ReleaseNotes`
field in `MSIX.psd1` is constrained to PSGallery's 10,600-character
limit and carries only the current version's highlights — everything
older lives here.

## v0.73.4 - 2026-07-08 — Diagnostic: surface heuristic scanner failures (#140)

Generalizes the 0.73.3 offreg honesty fix to the whole scanner pipeline.
`Get-MsixHeuristicFinding` runs each read-only scanner in its own try/catch so
one broken scanner can't abort the analysis — but the catch swallowed the
failure at **Debug** level, so a scanner that failed for an environmental reason
(missing DLL, absent tool, denied path in a headless image) silently dropped an
entire finding category, and the report looked identical to a clean package.

- **`_MsixAddScannerError`** — new helper: on a scanner throw it logs at Warning
  and appends a low-severity `ScannerError` finding naming the scanner + the
  underlying error, so an incomplete analysis is visible. `[AllowEmptyCollection()]`
  so it works even when the first scanner fails before any finding is added.
- **`_MsixAddOffregScannerError`** — the registry-derived scanners (ShellExt/
  ShellVerb, services, preview/property/thumbnail handlers, uninstall keys, run
  keys, COM servers) defer to the single `OfflineRegistryUnavailable` umbrella
  finding when `offreg.dll` is absent, rather than emitting one redundant
  `ScannerError` each; a genuine failure while offreg IS present still surfaces.
- Every `catch { Write-MsixLog -Level Debug … }` in `Get-MsixHeuristicFinding`
  now routes through these helpers.
- The **Run-key** scanner (offreg-dependent) was previously *unwrapped*, so on a
  host without `offreg.dll` it threw `DllNotFoundException` that aborted the
  whole analysis; it is now wrapped and gated. The Uninstaller and Alias loops
  were likewise wrapped for consistency.
- Minor: the availability-probe `catch` in `_MsixTestOffregAvailable` now
  Debug-logs, for symmetry.

Regression coverage in `MSIX.ScannerError.Tests.ps1`.

Also in this release, two fixes to the offreg / scanner work above (both found
by running `Invoke-MsixInvestigation` on a real package on a Win11 host):

- **offreg probe robustness.** `_MsixTestOffregAvailable` probed via the newer
  `LoadLibraryW` method added to `MsixOffReg` in 0.73.3. A .NET type cannot be
  redefined once loaded, so a session that had imported an *older* module
  version (whose `MsixOffReg` predates `LoadLibraryW`) kept the old type; the
  probe then threw "method not found", was caught, and reported offreg.dll
  **missing on a Win11 host that has it** — silently dropping every
  registry-derived finding (shell extensions, services, …). The probe now
  exercises `ORCreateHive` (present in every version of the wrapper), so it
  tests the exact P/Invoke binding the scanners use and survives a stale cached
  type. `DllNotFoundException` => unavailable; any other error => the DLL bound,
  so available.
- **Manifest-fix NRE.** The manifest-level block in `Get-MsixHeuristicFinding`
  called `.SelectSingleNode` on `$mf.Package.Properties` (null when a package
  has no `<Properties>`) and iterated `@($mf.Package.Extensions.Extension)`
  which is `@($null)` — an array holding one `$null` — when there is no
  package-level `<Extensions>`. Both NRE'd and aborted the block, dropping every
  manifest-fix finding for those very common shapes. `<Properties>` access is
  now guarded and the extension lists are null-stripped.

## v0.73.3 - 2026-07-08 — Windows container / Server Core: honest offreg.dll handling

`offreg.dll` (the Offline Registry API) parses a package's `Registry.dat` from
disk without mounting it, and every registry-derived scanner P/Invokes it:
ShellExt / ShellVerb handlers, Windows services, preview / property / thumbnail
handlers, uninstall keys, run keys, and COM servers. It ships in `System32` on
client Windows 10/11 but is **absent from Windows Server Core containers**,
where those calls threw `DllNotFoundException` that the heuristic aggregator
swallowed at Debug level — silently dropping shell extensions (and their
`AddLegacyContextMenu` autofix) with no indication the report was incomplete.

- **`_MsixTestOffregAvailable`** — new memoized probe that `LoadLibraryW`s
  `offreg.dll` and returns whether the Offline Registry API can be resolved in
  this process, without triggering a `DllNotFoundException` from a lazy-bound
  `OR*` import. Logs a one-time Warning when it is missing.
- **`Get-MsixHeuristicFinding`** now surfaces a loud `OfflineRegistryUnavailable`
  Warning finding (with remediation: run on Windows 10/11, or provision
  `offreg.dll` into the Server Core image's `System32`) instead of returning a
  registry-blind report that looks clean. On hosts where `offreg.dll` is present
  (client Windows, GitHub `windows-latest` CI) behaviour is unchanged.
- If the module ships a bundled `native\offreg.dll`, it is pre-loaded by full
  path so the unqualified `OR*` imports bind to it.

## v0.73.2 - 2026-07-08 — Bugfix: PSF re-injection merge + new PSF release layout

Two PSF fixes surfaced by `Invoke-MsixAutoFixFromAnalysis` in the field, plus
a licensing change.

- **Crash re-injecting PSF (merge mode).** `Add-MsixPsfV2` merges new fixups
  into an existing `config.json` when the package already carries a
  PsfLauncher. The merge branch keyed process entries in an `[ordered]@{}`
  (`OrderedDictionary`) and probed key existence with `.ContainsKey()` — a
  method that only exists on `Hashtable`/`Dictionary`. The call threw
  `[OrderedDictionary] does not contain a method named 'ContainsKey'`. Switched
  to `.Contains()`. Only re-injection reaches this branch, so a regression test
  in `MSIX.MutatorCoverage.Tests.ps1` now injects PSF twice (verified: fails on
  the old code, passes on the fix).
- **New TMurgent PSF release layout.** `Install-MsixPsfBinary` now handles the
  v2026.07.01+ "zip-of-zips" asset (a `ReleasePsf.zip` + `DebugPsf.zip` nested
  inside the downloaded archive) instead of launcher binaries directly. The
  Release payload is expanded, nested archives are removed, the result is
  Authenticode-verified, and a fail-fast `throw` fires if no `PsfLauncher*.exe`
  surfaces. The old flat layout still works. Regression coverage in
  `MSIX.PsfBinaries.Tests.ps1`.
- **License.** The project moved to the source-available
  [PolyForm Shield 1.0.0](LICENSE.md) license — free to use, modify, and
  contribute to (including commercially and internally), with a single carve-out
  against building a competing product. `LicenseUri` added to the manifest;
  `ProjectUri` corrected to this repo.

## v0.73.1 - 2026-07-06 — Bugfix: nested / sparse package handling

Fixes three latent bugs surfaced by `Invoke-MsixAutoFixFromAnalysis` on a
package with a nested sparse shell-extension package (Notepad++-8.9.4.msix),
where the run crashed unless `-IgnoreNestedPackages` was passed.

- **Crash on inner unpack.** `Import-MsixSparseShellExtension` unpacked the
  inner sparse package with MakeAppx, which VALIDATES the manifest during
  unpack. A sparse inner package legitimately references an executable in the
  OUTER package (NppShell's `Executable="notepad++.exe"`), so MakeAppx rejected
  it with `0x80080204`. The inner package is only read, so extraction now uses
  plain zip (no validation gate).
- **8.3 short-path corruption.** The inner temp directory and the shared scan
  workspace were created via `Join-Path` against `$env:TEMP`, which can carry an
  8.3 short segment (`SANDER~1`) while `Get-ChildItem` returns long-form paths.
  The payload-copy relative-path `Substring` then chopped the wrong count and
  mis-filed the inner `AppxManifest.xml` under a corrupt `NN\AppxManifest.xml`
  path inside the outer VFS. `New-MsixWorkspace`, `_MsixResolveScanWorkspace`,
  and the sparse inner dir are now normalized to long-form.
- **Wrong manifest returned.** `Get-MsixManifest` matched `AppxManifest.xml` by
  basename with `-First 1`, so a package carrying a nested manifest could return
  the wrong one. It now matches the archive-ROOT `AppxManifest.xml`, with a
  shallowest-path basename fallback only when no root manifest exists.

Regression coverage in `MSIX.NestedPackage.Tests.ps1`.
## v0.73.0 - 2026-07-06 — Shared runtime frameworks, settings-capable modification packages

The "one Java, patched once, used by forty apps" release (#130) plus the
modification-package completion (#131).

### Shared runtime framework packages (#130)

- **`New-MsixFrameworkPackage`** — builds a `<Framework>true</Framework>`
  package from a runtime folder (JRE, private .NET, Python, shared libraries):
  one servicing point instead of a bundled copy per app.
- **`Add-MsixRuntimeDependency`** — wires a consumer app in one call:
  `<PackageDependency>` plus optional environment wiring (`-Runtime Java` →
  `JAVA_HOME`, `-Runtime DotNet` → `DOTNET_ROOT`, or custom variables with the
  `{frameworkRoot}` token) via PSF EnvVarFixup against the computed
  `WindowsApps` install root (publisher-hash derived; warns that env wiring
  pins the framework version). DLL-based runtimes need no wiring at all —
  the package graph is on the packaged process's DLL search path.
- **`Get-MsixBundledRuntime`** (new scanner, + plural alias) — trait-based
  detection of private JRE/JDK (`bin\java.exe`), .NET (`hostfxr.dll`) and
  Python (`python3*.dll` + `python.exe`) copies, with size accounting.
  Surfaces as a `BundledRuntime` finding; autofix strips the bundled copy and
  wires the framework via the opt-in `-DeduplicateBundledRuntime` +
  `-RuntimeFrameworkName/-MinVersion/-Publisher` (destructive — identity is
  never guessed).

### Modification packages, completed (#131)

- **`New-MsixModificationPackage -RegistryContent`** — modification packages
  now layer SETTINGS, not just files: `HKLM\...`/`HKCU\...` key/value
  hashtables are built into `Registry.dat` / `User.dat` with the module's
  offline-registry (offreg) helpers (REG_SZ / REG_DWORD).
- **`ConvertTo-MsixModificationPackage`** — productize the golden-image
  delta: diffs a vendor package against a customized copy (SHA-256, footprint
  files excluded), stages added/changed files (customized registry hives are
  carried with a review warning), and emits the `uap4:MainPackageDependency`
  package. Returns null with a warning when nothing differs.
- **`Test-MsixDeployment -ModificationPackagePaths`** — the runtime test loop
  installs modification packages after the main app so the layered
  content/settings are part of the probed run (`ModificationsInstalled` on
  the verdict object).
## v0.72.0 - 2026-07-05 — Bundles, resource-PRI regeneration, runtime deployment testing, in-process signing

> *(Source-only: merged to `main` but never published to PSGallery — the
> gallery went 0.71.4 → 0.73.0, which includes everything below.)*

The first feature release beyond post-processing: multi-arch bundles,
localization repair, an automated runtime verification loop, and safe local
signing.

### .msixbundle handling (#125)

- **`New-MsixBundle`** / **`Expand-MsixBundle`** / **`Get-MsixBundleInfo`** —
  MakeAppx bundle/unbundle wrappers + inner-package inventory (name, version,
  architecture, resource language).
- **`Invoke-MsixBundleOperation`** — the bridge that gives *every* existing
  mutator bundle support without per-cmdlet changes: unbundle → run a
  scriptblock per inner package (optionally filtered by `-Architecture`, with
  resource packages passed through) → rebundle → sign, atomically (the original
  bundle is only replaced after a successful repack+sign).

### resources.pri regeneration (#124)

- **`Update-MsixResourcePri`** — regenerates `resources.pri` via makepri
  (Authenticode-verified), repacks and signs. Fixes the root cause behind the
  #109 warning: brand/identity edits on `ms-resource:`-localized packages that
  previously had no runtime effect.
- **`Set-MsixBrandMetadata -RegeneratePri`** — replaces the `ms-resource:`
  reference with the literal value *and* rebuilds the PRI so the displayed
  string actually changes.

### Runtime deployment testing (automated runtime loop)

- **`Test-MsixDeployment`** — installs a signed package into a clean Hyper-V VM
  via PowerShell Direct (no VM networking), launches it through
  `shell:AppsFolder`, and probes liveness (process alive after settle, no WER
  crash, no AppXDeployment errors, optional `-RequireWindow`). Returns a verdict
  object shaped like the other `Test-Msix*` results (bottom-line boolean +
  reasons + event-log artifacts) with optional checkpoint restore. On failure
  the artifacts feed straight into the existing analyze → autofix loop. VM
  interaction is behind a mockable seam; orchestration is unit-tested.

### In-process signing (#17 / #126)

- **`Invoke-MsixSigning -Signer SignerSignEx`** now implemented — the safe
  local-PFX path. The password decrypts only in-process to load the certificate
  into an ephemeral `CurrentUser\My` entry; signtool selects it by thumbprint
  (public), so neither the PFX password nor its path ever appears on a process
  command line (the SignTool `/f /p` weakness). The temporary store entry is
  removed afterward. Explicit `-Signer` now always wins over the SignToolPfx
  parameter-set inference (extends the #77 fail-closed contract).

## v0.71.4 - 2026-07-05 — Manifest feature coverage: services, shell handlers, dependencies, distribution

The v2 review's missing-feature list implemented (issues #108-#119, all but
the #120 niche backlog), wired end-to-end into static analysis and autofix.

### New manifest mutators

- **`Add-MsixService`** (#112) — packaged Windows services (desktop6
  `windows.service` + `desktop6:Service`), auto-adding `packagedServices`
  (+ `localSystemServices` for `-StartAccount localSystem`), SCM
  dependencies, MinVersion floor 19041. MakeAppx validates the service
  executable exists in the package.
- **`Add-MsixShellHandlerExtension`** (#113) — preview / property / thumbnail
  shell handlers (`desktop2:DesktopPreviewHandler` /
  `DesktopPropertyHandler` / `ThumbnailHandler` on an FTA) with the
  registry-free `com:SurrogateServer` class registration in one call.
- **`Add-MsixToastActivator`** (#114) — `windows.toastNotificationActivation`
  + the `com:ExeServer` activator class, so toast clicks re-activate the
  packaged app.
- **`Add-MsixPackageDependency`** (#115) — declare framework dependencies
  (`<PackageDependency>`); well-known Microsoft frameworks get the Publisher
  auto-filled; MinVersion is raised but never lowered.
- **`Set-MsixMutablePackageDirectory`** (#116) — desktop6
  `windows.mutablePackageDirectories` extension + `modifiableApp` capability
  (the OS-native plugin/mod-folder story; gated feature, documented).
- **`Add-MsixFileTypeAssociation`** enriched (#119) — `-Logo`, `-InfoTip`,
  `-OpenIsSafe`/`-AlwaysUnsafe` (EditFlags) and `-Verbs`
  (uap2:SupportedVerbs / uap3:Verb with Parameters).

### Context menus: desktop9 is back as an option (#108)

`Add-MsixLegacyContextMenu -Schema desktop4|desktop9|Both` — desktop4/5
remains the default (Win10 1809+, field-verified); `desktop9` emits the
MS-documented classic-handler shape (also used by commercial packaging tools)
(`windows.fileExplorerClassicContextMenuHandler`, Win11 21H2+, classic
"Show more options" menu, raises MaxVersionTested to 22000); `Both` emits
the two registrations against the same CLSID.

### Distribution (new MSIX.Distribution.ps1)

- **`New-MsixAppInstallerFile`** (#117) — .appinstaller generation with the
  full update policy (OnLaunch / HoursBetweenUpdateChecks / ShowPrompt /
  UpdateBlocksActivation / ForceUpdateFromAnyVersion), identity read from
  the package.
- **`New-MsixModificationPackage`** (#118) — vendor-package customization:
  builds a `uap4:MainPackageDependency` package (no Applications element)
  from a content folder, packs + signs atomically.

### Static analysis / autofix integration

- New scanners: **`Get-MsixServiceEntry`** (packaged-service candidates) and
  **`Get-MsixShellHandlerEntry`** (preview/property/thumbnail handlers) with
  plural aliases.
- `Invoke-MsixInvestigation` now reports the isolation blockers (PSF launcher,
  `windows.comServer`) as static-analysis findings.
- `Invoke-MsixAutoFix` plans/applies: `Add-MsixService`,
  `Add-MsixShellHandlerExtension`, VCLibs via
  `-VcRuntimeAsPackageDependency`, and opt-in isolation via
  `-AddAppIsolation` (with `Remove-MsixPsf` preparation and COM/PSF
  incompatibility guards).

### Niche extension points (#120)

- **`Add-MsixAppExtensionHost`** / **`Add-MsixAppExtension`** — the uap3
  plugin-ecosystem contract pair (host declares contract names; extension
  packages target them; discovery via the AppExtensionCatalog API).
- **`Add-MsixAutoPlayHandler`** — AutoPlay content/device launch actions
  (`windows.autoPlayContent` / `windows.autoPlayDevice`).
- **`Add-MsixShareTarget`** — Share-sheet target (file types, any-file,
  data formats).
- **`Add-MsixFullTrustProcess`** — full-trust companion process for a UWP
  main app (+ auto-added runFullTrust).
- **`Add-MsixPackageCertificate`** — bundles a .cer into the package and
  declares it via the `windows.certificates` package extension (Root / CA /
  TrustedPeople / TrustedPublisher), replacing the capture's certutil step.
- **`Get-MsixPackageCertificateCandidate`** (new scanner, + plural alias) —
  finds shipped-but-undeclared .cer/.crt files; surfaces as a
  `ManifestFix:PackageCertificate` static-analysis finding; autofix declares
  them via the opt-in `-DeclarePackageCertificates`
  (+ `-PackageCertificateStore`, default TrustedPeople — a trust decision is
  never made automatically).

### Signing fail-closed fix (#77)

- `Invoke-MsixSigning -Signer SignerSignEx` now throws the reserved-backend
  error even when `-Pfx`/`-PfxPassword` are supplied. Previously those
  parameters bound the SignToolPfx parameter set, whose set-name inference
  silently overrode the explicit `-Signer` and entered the SignTool path
  (including its command-line password exposure). Explicit `-Signer` now
  always wins; regression test added.

### Fixes & docs

- `Set-MsixBrandMetadata` warns when the target field is pri-localized
  (`ms-resource:` - the displayed value comes from resources.pri) (#109).
- AppIsolation file banner + `Get-MsixIsolationCapability` help corrected for
  the two-mode model; CHANGELOG marks 0.71.1 as source-only (#110).
- Help example ratchet burned to EMPTY: all previously-grandfathered
  functions now carry a `.EXAMPLE` (#111).

## v0.71.3 - 2026-07-05 — Isolation toolkit, module-review fixes, Get-Help repaired

Everything from the full module review (issues #97-#106) plus four product
bugs the new coverage tests caught.

### App isolation toolkit (#103-#106)

- **`Remove-MsixPsf`** (new) — the inverse of `Add-MsixPsfV2`: restores each
  Application's real executable from config.json and strips the PSF payload
  (launcher, runtime, fixup DLLs, config, script wrappers), warning about every
  behaviour that disappears (redirection, env vars, scripts, argument /
  working-directory overrides). Primary use: PSF and AppContainer isolation are
  mutually exclusive, so strip PSF before `Add-MsixAppIsolation` (whose PSF
  warning now points here).
- **`Add-MsixAppIsolation -RemoveComServer`** (new switch, also a pipeline
  config key) — a `windows.comServer` extension is invalid with a partial-trust
  entry point; instead of only throwing, the switch strips the COM server and
  its Explorer context-menu verbs so the package can isolate (losing that menu).
- **`Test-MsixIsolation`** (new) — static mode gives a per-application
  `WouldIsolate` verdict with reasons (entry point, trust level, runFullTrust,
  PSF/comServer blockers, AppSilo MinVersion); runtime mode reads the process
  token (`-ProcessId` / `-PackageFamilyName`) and reports the definitive
  `S-1-15-2` AppContainer SID + integrity level — prompts alone are not proof
  (ASR rules also prompt).
- **`Get-MsixIsolationAdvice`** (new) — feeds ProcMon ACCESS-DENIED rows
  (`Get-MsixProcMonFailure | Get-MsixIsolationAdvice`) into concrete
  suggestions: user-profile denials -> prompt broker / userProfileMinimal,
  network -> internetClient (per mode), ProgramData -> publisher directory,
  HKLM writes -> "needs a code change; no capability grants that".

### Review fixes (#97-#102)

- **#97** `Invoke-MsixPipeline`'s AppIsolation stage still used the obsolete
  capability-only shape (packages did NOT isolate). It now delegates to the
  same core as `Add-MsixAppIsolation` (`_MsixApplyAppIsolation`) with
  `Mode` / `Capabilities` / `AppId` / `RemoveComServer` config keys.
- **#98** `Get-Help` was broken for 62 of 166 exported functions: combined
  `.PARAMETER A / B` tags and description lines starting with `.msix` (parsed
  as unknown help directives) make PowerShell reject the whole help block.
  All fixed; a new help contract test keeps it that way.
- **#99/#100** EXAMPLES.md isolation recipe rewritten for the two-mode API;
  README + TEST-PLAN Scenario 1 corrected from desktop9 to the implemented
  com + desktop4/desktop5 context-menu pattern.
- **#101** NoSign contract sweep is now dynamic over every `-SkipSigning`
  cmdlet (the static list had missed the isolation cmdlets) and also asserts
  `-WhatIf`; approved-verb + Verb-MsixNoun guards added to the module contract.
- **#102** Coverage-map debt burned to EMPTY: 19 behavioural tests added; the
  4 network toolchain updaters moved to a documented permanent exclusion.

### Bugs found by the new coverage tests (all fixed)

- `Add-MsixFontExtension` emitted `windows.sharedFonts` under
  Package/Extensions; the schema requires Application/Extensions (MakeAppx
  C00CE014) — the cmdlet could never produce an installable package.
- `Add-MsixStartMenuFolder` wrote a bare `VisualGroup` attribute, which
  MakeAppx rejects. Per MS Learn the element must become `uap3:VisualElements`
  (unprefixed `VisualGroup` attribute); also warns that a Start-menu folder
  only materialises with >= 2 apps sharing the group.
- `Add-MsixSplashScreen` used `Split-Path -LiteralPath ... -Parent` — an
  unresolvable parameter-set combination, so the cmdlet always threw.
- `Add-MsixPsfV2` / `New-MsixPsfConfig` rejected an empty `-Fixups` array,
  making script-only PSF injection (`Add-MsixStandardScript`) impossible.
- `_MsixGetOrCreateApplicationExtensions` broke on its documented
  empty-AppId ("first application") path.

### Rename

- `Invoke-MsixSelfSignAndDebug` -> **`Invoke-MsixSelfSign`** (it only signs; it
  never attached a debugger). The old name remains as an exported alias. Note:
  it does NOT rewrite the manifest Publisher — it generates a cert matching the
  existing one; use `Update-MsixSigner` to change the publisher.

## v0.71.1 - 2026-06-09 — App isolation that actually isolates (partial-trust / AppContainer)

> *(Source-only: this version was merged to `main` but never published to
> PSGallery — the gallery went 0.71.0 → 0.71.3, which includes everything
> below.)*

The v0.71.0 isolation work emitted the `uap18` appSilo attributes but kept
`EntryPoint="Windows.FullTrustApplication"` and `runFullTrust` — and the
full-trust entry point hard-requires `runFullTrust`, which keeps the process
full-trust. Result: packages "isolated" by v0.71.0 still ran full-trust
(Medium integrity, no `S-1-15-2` AppContainer SID). Verified on a real 25H2
host: a perfectly-formed v0.71.0 package never entered an AppContainer.

**Root cause + fix.** The AppContainer boundary is the `TrustLevel="appContainer"`
attribute, and to reach it a packaged Win32 app must use
`EntryPoint="Windows.PartialTrustApplication"` and **drop `runFullTrust`** (per
the MSIX AppContainer guidance, https://learn.microsoft.com/windows/msix/msix-container).
`Add-MsixAppIsolation` now does exactly that, and a minimal probe built this way
**provably isolates** (token shows an `S-1-15-2` AppContainer SID; `C:\` access
is denied).

### `Add-MsixAppIsolation` reworked — two modes

- **AppContainer (default)** — GA `packagedClassicApp` AppContainer
  (`uap10:TrustLevel="appContainer"` + `uap10:RuntimeBehavior="packagedClassicApp"`,
  `EntryPoint="Windows.PartialTrustApplication"`, no `runFullTrust`). Ungranted
  access is denied. `-Capabilities` are standard package capabilities (default:
  none).
- **AppSilo** (`-Mode AppSilo`) — the preview Win32 App Isolation silo
  (`uap18:RuntimeBehavior="appSilo"` + `uap18:EntryPoint="Isolated.App"` +
  `isolatedWin32-*` broker capabilities), layered on the same partial-trust
  AppContainer base; raises `Windows.Desktop` MinVersion to 10.0.26100.0.
  `-Capabilities` are `isolatedWin32-*` / device caps (default:
  `isolatedWin32-promptForAccess`).

`runFullTrust` is now **always removed** (it's incompatible with AppContainer and
the partial-trust entry point doesn't require it). The obsolete
`-RemoveRunFullTrust` / `-KeepRunFullTrust` switches are gone.

### Things that block isolation (now detected)

- **PSF** (`PsfLauncher*.exe` entry point) — warns; PSF injects fixup DLLs the
  AppContainer blocks.
- **`windows.comServer` extensions** (e.g. a COM shell context-menu like NppShell)
  — throws: that extension is invalid with a partial-trust entry point. Strip the
  comServer + its `desktop4:FileExplorerContextMenus` first.

### `Remove-MsixAppIsolation`

Restores `EntryPoint="Windows.FullTrustApplication"` + `runFullTrust` and strips
the uap10/uap18 isolation attributes and `isolatedWin32-*` capabilities — i.e.
returns the package to a normal full-trust packaged app.

### Docs

README Win32 App Isolation section and TEST-PLAN Scenario 6 rewritten for the
partial-trust model; the incorrect "Insider-only" runtime claim from v0.71.0
corrected (the feature ships on GA 24H2/25H2).

## v0.71.0 - 2026-06-09 — Win32 App Isolation, security hardening, offreg scanning & test infrastructure

### Win32 App Isolation — now writes a manifest that actually isolates

- **`Add-MsixAppIsolation` emits the attributes that enable isolation, not just
  the capability.** It previously added an `isolatedWin32-*` `rescap:Capability`
  and nothing else — which does not isolate anything. It now writes, per the MS
  Learn packaging guidance, the `uap18` attributes on each `<Application>`
  (`EntryPoint="Windows.FullTrustApplication"`, `uap18:EntryPoint="Isolated.App"`,
  `uap18:TrustLevel="appContainer"`, `uap18:RuntimeBehavior="appSilo"`), declares
  the `uap18` namespace (and adds it to `IgnorableNamespaces`), and **raises the
  `Windows.Desktop` `TargetDeviceFamily` MinVersion to 10.0.26100.0** — isolation
  only engages when the package targets 24H2, so the package will no longer
  install on older Windows. (#91, #92)
- **`runFullTrust` is retained, by design.** The isolated app keeps the
  `Windows.FullTrustApplication` entry point, and the AppxManifest schema
  *requires* `runFullTrust` for that entry point (MakeAppx rejects the package
  with `0x80080204` otherwise). So `runFullTrust` and isolation are required
  *together*, not mutually exclusive; isolation is enforced by the `uap18`
  appContainer/appSilo attributes. `-RemoveRunFullTrust` / `-KeepRunFullTrust`
  switches added for control. (#91)
- **COM context menus under isolation:** when the package has a
  `windows.comServer` / `FileExplorerContextMenus` extension,
  `isolatedWin32-shellExtensionContextMenu` is auto-added so the menu keeps
  working inside the AppContainer. (#91)
- **PSF packages are detected and warned about.** A package whose entry point is
  `PsfLauncher*.exe` cannot be isolated — PSF injects fixup DLLs into the target
  process, which AppContainer blocks — so `Add-MsixAppIsolation` now warns
  clearly instead of silently producing a non-isolating package. (#93)
- **`Remove-MsixAppIsolation`** now also strips the `uap18` attributes, fully
  reversing `Add`. (#91)
- **`Get-MsixIsolationCapability`** rebuilt against the MS Learn supported-
  capabilities page: returns rich objects (`Name` / `ElementType` /
  `Description`), the full documented `isolatedWin32-*` set, and device
  capabilities (`microphone`, `webcam`) emitted as `<DeviceCapability>`. Fixed an
  `OrderedDictionary.ContainsKey` runtime error in `Add-MsixAppIsolation` (it's
  `.Contains()`, not `.ContainsKey()`). (#85, #86)
- **`Import-MsixSparseShellExtension`** resolves a bare nested-package filename
  by searching the unpacked package, and skips gracefully (a warning, not a
  throw) when the nested package is absent — so `Invoke-MsixAutoFixFromAnalysis`
  no longer aborts mid-run on a `NestedPackage` finding. (#94)

> **Runtime note.** (Superseded by v0.71.1 — see below.) This release kept
> `EntryPoint="Windows.FullTrustApplication"` + `runFullTrust`, which kept the
> process full-trust, so packages built by this version do **not** actually
> isolate. v0.71.1 fixes the model (partial-trust entry point + drop
> `runFullTrust`). The earlier claim that the feature is "Insider-only" was
> incorrect — Win32 App Isolation ships on GA 24H2/25H2.

### Test infrastructure & repo

- **Real-MSIX integration harness** (`Build-MsixTestFixture` + a dedicated CI
  job) packs genuine `.msix` fixtures via MakeAppx, enabling end-to-end
  integration tests for the mutating cmdlets instead of mock-only coverage.
  (#61, #87)
- **Pester suite restructured** by cmdlet-family + cross-cutting contract;
  issue/version-named test files dissolved into feature-named homes; a
  coverage-map guardrail asserts every exported `Add`/`Remove`/`Set`/`Update`
  mutator is actually *invoked* by a test (the gap that let the
  `.ContainsKey()` bug ship). `CONTRIBUTING.md` gained function-authoring
  conventions (approved verbs, comment-based-help skeleton, per-function test
  rule). (#88, #89)
- `.gitignore` added for generated test artifacts; `actions/checkout` bumped to
  v6 (Node 24); CI parse-check gate so a syntactically broken module fails lint
  rather than Pester. (#90)

### Bug fixes

- **Mutator scriptblocks could not resolve module-private functions.**
  `Remove-MsixShellRegistryArtifact` (and the `StripLegacyShellRegistry`
  auto-fix stage that calls it) threw `_MsixOpenOfflineHive is not recognized`
  at runtime: the `-Mutator` scriptblock is defined in one module file but
  invoked from `_MsixMutatePackage` in another, and under some module-load
  conditions the block lost its module session affinity so module-private
  offreg helpers were unresolvable. `_MsixMutatePackage` and
  `Invoke-MsixManifestTransform` now rebind the scriptblock to the module
  session state (`NewBoundScriptBlock`) before invoking it, so private helpers
  always resolve. The shell-registry mutator path was previously only covered
  by export/`-WhatIf` tests (which skip the mutator body); an end-to-end
  regression test now runs it against a real packed `Registry.dat`.
- **#80 — folder context menus (e.g. 7-Zip) were missing.** The shell
  context-menu scanner only walked the `*`, `Directory`, `Directory\Background`
  and `AllFilesystemObjects` shell classes, so handlers registered under the
  `Folder` class (which 7-Zip uses) were never detected. Added `Folder` and
  `Drive` to the scanned targets, and widened the `-FileTypes` validation on
  `Add-MsixLegacyContextMenu` / `Add-MsixFileExplorerContextMenu` to accept the
  container item-types the shell uses (`Folder`, `Directory\Background`,
  `DesktopBackground`, `AllFilesystemObjects`, `Drive`).
- **#81 — MakeAppx schema failure on install-dir plugin folders.**
  `Invoke-MsixAutoFixFromAnalysis` passed install-relative VFS paths (e.g.
  `VFS\ProgramFilesX64\7-Zip\Lang`) to `virtualization:ExcludedDirectory`, but
  that element's schema only accepts `$(KnownFolder:Name)[\subpath]` tokens, so
  MakeAppx aborted with `error C00CE169 … violates pattern constraint`. The
  PluginDirectory autofix now redirects install-dir folders via PSF
  FileRedirection (the mechanism that can express them) and only feeds valid
  KnownFolder tokens to `-ExcludedDirectories`. As defence-in-depth,
  `Set-MsixFileSystemWriteVirtualization` now validates each excluded directory
  against the KnownFolder pattern and skips (with a warning) any that can't be
  expressed, so it can never again emit a manifest MakeAppx rejects.

### Security / robustness fixes (post-review)

- **#55 — download integrity (opt-in, out-of-box safe).** Two configurable
  integrity controls, both empty by default so the module works out of the box:
  - `_MsixDownloadFile` gains an optional `-ExpectedSha256`; when supplied the
    download is hashed and a mismatch throws (the partial file is deleted). It
    is threaded through `_MsixInstallArchiveTool`, `Install-MsixMgr`, and
    `Update-MsixMgr`. The observed SHA-256 is logged on every pinned download so
    operators can capture a known-good value. A new `$script:MsixMgrKnownSha256`
    constant (empty by default) lets you pin msixmgr — which is unsigned upstream
    (microsoft/msix-packaging#710) — for every call in one place.
  - `signers.json` entries may now carry an optional `thumbprint`; when present,
    `_MsixVerifyAuthenticode` requires the signer's thumbprint to match exactly
    for that matching publisher entry, closing the CN-prefix-only gap (a hostile
    `CN=Microsoft Corporation, O=Evil` cert). Prefix-only entries keep working
    unchanged even when another publisher is pinned.

### Features

- **#17 — `SignerSignEx` backend reserved (API only).** `Invoke-MsixSigning
  -Signer` now accepts `SignerSignEx`, intended for a future
  `mssign32!SignerSignEx2` P/Invoke backend that keeps the PFX password off the
  command line. The implementation is deliberately NOT shipped yet — it is
  security-critical Win32 interop that must be validated on Windows against a
  real code-signing certificate first — so the value currently throws a clear
  "not yet implemented" error rather than risk producing improperly-signed
  packages. Existing backends are unchanged.

- **#18 — nested-tree accelerator YAML (safe parser).** New
  `ConvertFrom-MsixAcceleratorYaml` parses accelerator YAML from a string with
  support for indentation-based nested maps and block lists (so accelerators can
  declare structured `RemediationApproach` trees), in addition to the original
  top-level scalars and inline lists. `ConvertFrom-MsixYamlAccelerator -Path`
  becomes a thin file wrapper over it. It remains a hand-rolled, value-only
  recursive-descent parser: every leaf is a `[string]`/`[string[]]`, containers
  are `[hashtable]`/`[object[]]`, and it never instantiates types — YAML type
  tags (`!!...`), anchors/aliases (`&`/`*`), and multi-document markers are inert
  text or ignored, so hostile accelerator files cannot execute code. Tabs in
  indentation are rejected with a clear error.

### Performance

- **#58 — unpack the package once per analysis run.** Each read-only scanner
  used to unpack the whole package independently, so a single
  `Get-MsixHeuristicFinding` unpacked it ~14 times (and `Get-MsixStaticAnalysis`
  ~15). All 14 scanners (`Get-Msix*Candidate` / `*Entry` / `*Hint` /
  `Get-MsixVcRuntimeReference`) now accept an optional `-WorkspacePath`; when
  supplied they reuse a pre-unpacked directory and skip their own unpack/cleanup
  (direct callers are unaffected — they still unpack on demand). New
  `_MsixResolveScanWorkspace` helper. `Get-MsixHeuristicFinding` unpacks once
  and threads the shared workspace to every scanner, so a full sweep now unpacks
  exactly once (a `Get-MsixStaticAnalysis` run drops from ~15 to 2). A mock-based
  unit test asserts the single-unpack invariant.

### Testing

- **#61 — real-MSIX integration tests.** New `MSIX.Tests/Build-MsixTestFixture.ps1`
  synthesizes a genuine `.msix` at test time (MakeAppx via `Get-MsixToolsRoot`)
  from a declarative spec — multi-TDF manifests, extra VFS files, optional
  self-sign — so integration tests exercise the real unpack/scan/repack paths
  instead of mocks. `MSIX.Integration.Tests.ps1` (tag `Integration`) covers a
  pack→read-manifest round-trip, the multi-TDF `MaxVersionTested` bump (#57) on
  a real package, and a heuristic-scan smoke test (a guard point for the #58
  unpack-once refactor). A dedicated CI `integration` job provisions the SDK
  toolchain and runs the tag; tests skip loudly when the toolchain is absent
  (e.g. non-Windows dev boxes) rather than giving false confidence.

### Security / robustness fixes (post-review)

- **#54 — Authenticode-verify resolved SDK tools (binary-planting).**
  `Get-MsixToolsRoot` discovers `signtool.exe` / `MakeAppx.exe` by env override,
  parent-walk, or Windows SDK glob and then executes them (signtool signs the
  output package), but only the module's own downloader verified its binaries.
  Every resolved tools root — however found, including an explicit
  `MSIX_TOOLS_PATH` / `Set-MsixToolsRoot` — is now Authenticode-verified
  fail-closed against the trusted-publisher allowlist before it is cached or
  used. An `MSIX_SKIP_TOOL_VERIFICATION` env var bypasses the check (with a loud
  warning) for offline / air-gapped agents where CRL/OCSP chain checks can't
  complete. msixmgr is unaffected — it resolves via its own path and keeps its
  documented unsigned/preview exception (microsoft/msix-packaging#710).
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

## v0.9.0 — heuristic auto-fixers, MFR, VC runtime bundling, compare

Modelled on the feature surface of leading commercial MSIX edit
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

- heuristic heuristic auto-fixers (each opt-in):
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

- Invoke-MsixAutoFix — heuristic staged orchestrator. Drives a curated
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
