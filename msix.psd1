@{
    ModuleVersion     = '0.12.0'
    GUID              = 'a3f1c2d4-8e5b-4f7a-9c3d-1b2e4f6a8c0d'
    Author            = 'Sander de Wit'
    Description       = 'Enterprise-grade MSIX packaging automation. PSF (TMurgent) injection with the full RegLegacy + MFR fixup palette, context menus, signing, CI/CD pipeline, compatibility investigation (procmon + DebugView trace parsing), sandbox debug helper, App Attach VHDX/CIM generator, Win32 App Isolation, AppData helpers, accelerator import, PSADT-style standard scripts, TMEditX-style heuristic auto-fixers (uninstaller / Run-key / VC runtime / capability / splash / alias / version-bump), package compare, and a Pester test suite.'
    PowerShellVersion = '5.1'
    RootModule        = 'MSIX.psm1'

    FunctionsToExport = @(
        # Logging
        'Write-MsixLog', 'Set-MsixLogLevel', 'Set-MsixLogFile',
        # Core / tools
        'Get-MsixToolsRoot', 'Set-MsixToolsRoot',
        'New-MsixWorkspace', 'Invoke-MsixProcess', 'Get-MsixPublisherId',
        # Validation
        'Test-MsixManifest', 'Test-MsixPsfConfig', 'Assert-MsixProcessSuccess',
        # Manifest helpers
        'Get-MsixManifest', 'Save-MsixManifest', 'Add-MsixManifestNamespace',
        'Get-MsixManifestApplications', 'Get-MsixManifestNamespaceUri',
        'Set-MsixManifestMaxVersionTested',
        # PSF builders
        'New-MsixPsfFileRedirectionConfig', 'New-MsixPsfRegLegacyConfig',
        'New-MsixPsfEnvVarConfig', 'New-MsixPsfTraceConfig',
        'New-MsixPsfArguments', 'New-MsixPsfStartScriptConfig',
        'New-MsixPsfDynamicLibraryConfig', 'New-MsixPsfWaitForDebuggerConfig',
        'New-MsixPsfConfig', 'Add-MsixPsfV2',
        # Signing
        'Invoke-MsixSigning',
        # Context menus
        'Add-MsixLegacyContextMenu', 'Add-MsixFileExplorerContextMenu',
        # Pipeline
        'Invoke-MsixPipeline',
        # Investigation
        'Invoke-MsixInvestigation', 'Get-MsixCompatibilityReport',
        'Get-MsixStaticAnalysis', 'Invoke-MsixProcMonCapture',
        'Get-MsixProcMonFailures', 'Add-MsixDiagnosticTrace',
        'Resolve-MsixProcMonPath',
        # AppData / out-of-package
        'Get-MsixContainerAppData', 'Get-MsixOrphanedAppData',
        'Copy-MsixHostAppDataIntoPackage', 'Invoke-MsixContainerCommand',
        'Get-MsixPackageStorageSummary',
        # Accelerators
        'Import-MsixAccelerator', 'Invoke-MsixAccelerator',
        'ConvertFrom-MsixYamlAccelerator',
        # PSF binaries / procmon / SDK tools (auto-install + auto-update)
        'Install-MsixPsfBinaries', 'Update-MsixPsfBinaries',
        'Get-MsixPsfBinariesVersion', 'Install-MsixProcMon',
        'Update-MsixProcMon',
        'Install-MsixSdkTools', 'Update-MsixSdkTools', 'Get-MsixSdkToolsVersion',
        'Initialize-MsixToolchain',
        # Debug + sandbox
        'Start-MsixDebugSession', 'Get-MsixDebugRecommendations',
        'New-MsixSandboxConfig', 'Start-MsixSandbox',
        'Resolve-MsixDebugViewPath',
        # App Attach (VHDX / CIM)
        'New-MsixAppAttachImage', 'Mount-MsixAppAttachImage',
        'Dismount-MsixAppAttachImage', 'Test-MsixAppAttachImage',
        'Resolve-MsixMgrPath',
        # Win32 App Isolation
        'Add-MsixAppIsolation', 'Remove-MsixAppIsolation',
        'Get-MsixIsolationCapabilities',
        # Limitations / know-your-installer
        'Get-MsixLimitations', 'Test-MsixAgainstLimitations',
        # Trace Fixup parser
        'ConvertFrom-MsixTraceLine', 'Get-MsixTraceOutput',
        'Get-MsixTraceFailures', 'ConvertFrom-MsixTraceToFindings',
        # msixmgr (App Attach binary)
        'Install-MsixMgr', 'Update-MsixMgr', 'Get-MsixMgrVersion',
        # Standard scripts (PSADT-flavoured)
        'Get-MsixStandardScripts', 'New-MsixStandardScript',
        'Set-MsixScriptSignature', 'Add-MsixStandardScript',
        # MFR (Modern File Redirection — TMurgent fork)
        'New-MsixMfrTraditionalRule', 'New-MsixMfrLocalRule',
        'New-MsixPsfMfrConfig', 'Get-MsixMfrKnownFolders',
        # VC++ runtime detection / bundling
        'Get-MsixVcRuntimeReferences', 'Add-MsixVcRuntimeBundle',
        # TMEditX-style heuristic auto-fixers
        'Get-MsixKnownCapabilities', 'Add-MsixCapability',
        'Get-MsixUninstallerCandidates', 'Get-MsixUninstallRegistryEntries',
        'Remove-MsixUninstallerArtifacts',
        'Get-MsixRunKeyEntries', 'Get-MsixAliasCandidates',
        'Add-MsixSplashScreen', 'Update-MsixPackageVersion',
        'Get-MsixHeuristicFindings', 'Invoke-MsixAutoFix',
        'Invoke-MsixAutoFixFromAnalysis',
        # Auto-detection scanners
        'Get-MsixFontCandidates', 'Get-MsixDesktopShortcutCandidates',
        'Get-MsixCapabilityHints',
        # Package compare
        'Compare-MsixPackage',
        # Manifest-only fixers (alternatives to PSF DLL injection)
        'Set-MsixFileSystemWriteVirtualization',
        'Set-MsixRegistryWriteVirtualization',
        'Set-MsixInstalledLocationVirtualization',
        'Add-MsixLoaderSearchPathOverride',
        'Add-MsixFirewallRule',
        'Add-MsixProtocolHandler',
        'Add-MsixFileTypeAssociation',
        'Add-MsixStartupTask',
        'Add-MsixFontExtension', 'Set-MsixBrandMetadata',
        'Remove-MsixDesktopShortcuts',
        # Public (legacy package ops)
        'Get-MsixInfo', 'Invoke-MsixCommand', 'Update-MsixSigner',
        'New-MsixPsfJson', 'Add-MsixAlias',
        'Remove-MsixStartMenuEntry', 'Add-MsixStartMenuFolder'
    )

    AliasesToExport   = @(
        'Invoke-MsixCmd', 'start-MsixCmd', 'update-MsixSigner', 'add-MsixPsf',
        'new-MsixPsfJson', 'add-MsixAlias',
        'remove-MsixStartMenuEntry', 'add-MsixStartMenuFolder',
        'Get-PublisherIdFromPublisher'
    )

    PrivateData = @{
        PSData = @{
            Tags        = @('MSIX','PSF','Packaging','AppX','WindowsApps',
                            'ContextMenu','Investigation','ProcMon','Accelerator',
                            'AppData','AppAttach','VHDX','CIM','AppIsolation',
                            'Sandbox','TMurgent','MFR','VcRuntime','Compare',
                            'TMEditX','Enterprise','CICD','Pester','PSADT')
            ProjectUri  = 'https://github.com/microsoft/MSIX-PackageSupportFramework'
            ReleaseNotes = @'
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
'@
        }
    }
}
