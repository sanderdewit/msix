@{
    ModuleVersion     = '0.75.4'
    GUID              = 'a3f1c2d4-8e5b-4f7a-9c3d-1b2e4f6a8c0d'
    Author            = 'Sander de Wit'
    Description       = 'Enterprise-grade MSIX packaging automation. PSF (TMurgent) injection with the full RegLegacy + MFR fixup palette, context menus, signing, CI/CD pipeline, compatibility investigation (procmon + DebugView trace parsing), sandbox debug helper, App Attach VHDX/CIM generator, Win32 App Isolation, AppData helpers, accelerator import, deployment-script templates, heuristic heuristic auto-fixers (uninstaller / Run-key / VC runtime / capability / splash / alias / version-bump), package compare, and a Pester test suite.'
    PowerShellVersion = '5.1'
    RootModule        = 'MSIX.psm1'

    FunctionsToExport = @(
        'Add-MsixAlias',
        'Add-MsixAppExtension',
        'Add-MsixAppExtensionHost',
        'Add-MsixAppIsolation',
        'Add-MsixAutoPlayHandler',
        'Add-MsixCapability',
        'Add-MsixComServerExtension',
        'Add-MsixDiagnosticTrace',
        'Add-MsixEvidence',
        'Add-MsixFileExplorerContextMenu',
        'Add-MsixFileTypeAssociation',
        'Add-MsixFirewallRule',
        'Add-MsixFontExtension',
        'Add-MsixFullTrustProcess',
        'Add-MsixLegacyContextMenu',
        'Add-MsixLoaderSearchPathOverride',
        'Add-MsixManifestNamespace',
        'Add-MsixPackageCertificate',
        'Add-MsixPackageDependency',
        'Add-MsixProtocolHandler',
        'Add-MsixPsfV2',
        'Remove-MsixPsf',
        'Add-MsixRuntimeDependency',
        'Add-MsixService',
        'Add-MsixShareTarget',
        'Add-MsixShellHandlerExtension',
        'Add-MsixShellVerbExtension',
        'Add-MsixSplashScreen',
        'Add-MsixStandardScript',
        'Add-MsixStartMenuFolder',
        'Add-MsixStartupTask',
        'Add-MsixToastActivator',
        'Add-MsixVcRuntimeBundle',
        'Assert-MsixProcessSuccess',
        'Compare-MsixPackage',
        'Compare-MsixTrace',
        'ConvertFrom-MsixTraceLine',
        'ConvertFrom-MsixTraceToFinding',
        'ConvertFrom-MsixYamlAccelerator',
        'ConvertTo-MsixFinding',
        'ConvertTo-MsixLegacyFinding',
        'ConvertTo-MsixModificationPackage',
        'ConvertTo-MsixSarif',
        'ConvertTo-MsixReportHtml',
        'Copy-MsixHostAppDataIntoPackage',
        'Expand-MsixBundle',
        'Export-MsixRemediationPlan',
        'Dismount-MsixAppAttachImage',
        'Find-MsixPlaybook',
        'Get-MsixAliasCandidate',
        'Get-MsixAppRuntimeVersion',
        'Get-MsixBundleInfo',
        'Get-MsixBundledRuntime',
        'Get-MsixCapabilityHint',
        'Get-MsixCompatibilityReport',
        'Get-MsixComServerEntry',
        'Get-MsixContainerAppData',
        'Get-MsixDebugRecommendation',
        'Get-MsixDebugViewVersion',
        'Get-MsixDesktopShortcutCandidate',
        'Get-MsixFindingConfidence',
        'Get-MsixFontCandidate',
        'Get-MsixHeuristicFinding',
        'Get-MsixInfo',
        'Get-MsixIsolationCapability',
        'Get-MsixIsolationAdvice',
        'Test-MsixIsolation',
        'Get-MsixKnownCapability',
        'Get-MsixLimitation',
        'Get-MsixManifest',
        'Get-MsixManifestApplication',
        'Get-MsixManifestApplications',
        'Get-MsixManifestNamespaceUri',
        'Get-MsixMfrKnownFolder',
        'Get-MsixMgrVersion',
        'Get-MsixNestedPackageCandidate',
        'Get-MsixOrphanedAppData',
        'Get-MsixPackageCertificateCandidate',
        'Get-MsixPackageStorageSummary',
        'Get-MsixPlaybook',
        'Get-MsixPluginExtensionPoint',
        'Get-MsixProcMonFailure',
        'Get-MsixPsfBinariesVersion',
        'Get-MsixPublisherId',
        'Get-MsixRequiredAppRuntimeChannel',
        'Get-MsixRunKeyEntry',
        'Get-MsixSdkToolsVersion',
        'Get-MsixServiceEntry',
        'Get-MsixShellContextMenuEntry',
        'Get-MsixShellHandlerEntry',
        'Get-MsixStandardScript',
        'Get-MsixStaticAnalysis',
        'Get-MsixToolsRoot',
        'Get-MsixTraceFailure',
        'Get-MsixTraceOutput',
        'Get-MsixUninstallerCandidate',
        'Get-MsixUninstallRegistryEntry',
        'Get-MsixUpdaterCandidate',
        'Get-MsixVcRuntimeReference',
        'Import-MsixAccelerator',
        'Import-MsixRemediationPlan',
        'Import-MsixSparseShellExtension',
        'Initialize-MsixToolchain',
        'Install-MsixAppRuntime',
        'Install-MsixDebugView',
        'Install-MsixMgr',
        'Install-MsixProcMon',
        'Install-MsixPsfBinary',
        'Install-MsixSdkTool',
        'Invoke-MsixAccelerator',
        'Invoke-MsixAutoFix',
        'Invoke-MsixBundleOperation',
        'Invoke-MsixAutoFixFromAnalysis',
        'Invoke-MsixAutoFixLoop',
        'Invoke-MsixBulkAnalysis',
        'Invoke-MsixCommand',
        'Invoke-MsixContainerCommand',
        'Invoke-MsixInvestigation',
        'Invoke-MsixManifestTransform',
        'Invoke-MsixPipeline',
        'Invoke-MsixPlaybook',
        'Invoke-MsixProcess',
        'Invoke-MsixRemediationPlan',
        'Invoke-MsixProcMonCapture',
        'Invoke-MsixSelfSign',
        'Invoke-MsixSigning',
        'Merge-MsixFinding',
        'Mount-MsixAppAttachImage',
        'New-MsixAppAttachImage',
        'New-MsixBundle',
        'New-MsixAppInstallerFile',
        'New-MsixFinding',
        'New-MsixFrameworkPackage',
        'New-MsixManifestDocument',
        'New-MsixModificationPackage',
        'New-MsixRemediationPlan',
        'New-MsixMfrLocalRule',
        'New-MsixMfrTraditionalRule',
        'New-MsixPsfArgument',
        'New-MsixPsfConfig',
        'New-MsixPsfDynamicLibraryConfig',
        'New-MsixPsfEnvVarConfig',
        'New-MsixPsfFileRedirectionConfig',
        'New-MsixPsfJson',
        'New-MsixPsfMfrConfig',
        'New-MsixPsfRegLegacyConfig',
        'New-MsixPsfStartScriptConfig',
        'New-MsixPsfTraceConfig',
        'New-MsixPsfWaitForDebuggerConfig',
        'New-MsixSandboxConfig',
        'New-MsixSelfSignedCertificate',
        'New-MsixStandardScript',
        'New-MsixWorkspace',
        'Remove-MsixAppIsolation',
        'Remove-MsixDesktopShortcut',
        'Remove-MsixStartMenuEntry',
        'Remove-MsixShellRegistryArtifact',
        'Remove-MsixUninstallerArtifact',
        'Remove-MsixUpdaterArtifact',
        'Resolve-MsixDebugViewPath',
        'Resolve-MsixMgrPath',
        'Resolve-MsixProcMonPath',
        'Save-MsixManifest',
        'Select-MsixManifestNode',
        'Select-MsixManifestNodes',
        'Set-MsixBrandMetadata',
        'Set-MsixFileSystemWriteVirtualization',
        'Set-MsixInstalledLocationVirtualization',
        'Set-MsixLogFile',
        'Set-MsixLogLevel',
        'Set-MsixManifestIdentity',
        'Set-MsixManifestMaxVersionTested',
        'Set-MsixManifestPublisher',
        'Set-MsixMutablePackageDirectory',
        'Set-MsixRegistryWriteVirtualization',
        'Set-MsixScriptSignature',
        'Set-MsixToolsRoot',
        'Set-MsixToolVerification',
        'Start-MsixDebugSession',
        'Start-MsixSandbox',
        'Test-MsixAgainstLimitation',
        'Test-MsixAppAttachImage',
        'Test-MsixDeployment',
        'Test-MsixManifest',
        'Test-MsixPsfConfig',
        'Test-MsixRemediationPlan',
        'Test-MsixSignature',
        'Update-MsixAppRuntime',
        'Update-MsixDebugView',
        'Update-MsixMgr',
        'Update-MsixPackageVersion',
        'Update-MsixResourcePri',
        'Update-MsixProcMon',
        'Update-MsixPsfBinary',
        'Update-MsixSdkTool',
        'Update-MsixSigner',
        'Write-MsixLog'
    )

    AliasesToExport   = @(
        'add-MsixPsf',
        'Invoke-MsixSelfSignAndDebug',
        'ConvertFrom-MsixTraceToFindings',
        'Get-MsixAliasCandidates',
        'Get-MsixCapabilityHints',
        'Get-MsixComServerEntries',
        'Get-MsixDebugRecommendations',
        'Get-MsixDesktopShortcutCandidates',
        'Get-MsixFontCandidates',
        'Get-MsixHeuristicFindings',
        'Get-MsixBundledRuntimes',
        'Get-MsixIsolationCapabilities',
        'Get-MsixKnownCapabilities',
        'Get-MsixLimitations',
        'Get-MsixMfrKnownFolders',
        'Get-MsixNestedPackageCandidates',
        'Get-MsixPluginExtensionPoints',
        'Get-MsixProcMonFailures',
        'Get-MsixRunKeyEntries',
        'Get-MsixPackageCertificateCandidates',
        'Get-MsixServiceEntries',
        'Get-MsixShellContextMenuEntries',
        'Get-MsixShellHandlerEntries',
        'Get-MsixStandardScripts',
        'Get-MsixTraceFailures',
        'Get-MsixUninstallerCandidates',
        'Get-MsixUninstallRegistryEntries',
        'Get-MsixUpdaterCandidates',
        'Get-MsixVcRuntimeReferences',
        'Get-PublisherIdFromPublisher',
        'Install-MsixPsfBinaries',
        'Install-MsixSdkTools',
        'Invoke-MsixCmd',
        'New-MsixPsfArguments',
        'Remove-MsixDesktopShortcuts',
        'Remove-MsixUninstallerArtifacts',
        'start-MsixCmd',
        'Test-MsixAgainstLimitations',
        'Update-MsixPsfBinaries',
        'Update-MsixSdkTools'
    )

    PrivateData = @{
        PSData = @{
            Tags        = @('MSIX','PSF','Packaging','AppX','WindowsApps',
                            'ContextMenu','Investigation','ProcMon','Accelerator',
                            'AppData','AppAttach','VHDX','CIM','AppIsolation',
                            'Sandbox','TMurgent','MFR','VcRuntime','Compare',
                            'Enterprise','CICD','Pester')
            ProjectUri  = 'https://github.com/sanderdewit/msix'
            LicenseUri  = 'https://github.com/sanderdewit/msix/blob/main/LICENSE.md'
            ReleaseNotes = @'
## v0.75.4 (auto-fix: one repack per stage, manifests MakeAppx accepts)

FIXED: Invoke-MsixAutoFixFromAnalysis repacked the whole package once per shell
handler (about 30 s each for 40 MB). K-Lite Codec Pack (83 handlers) ran past 40
minutes.
- Add-MsixShellHandlerExtension -Handlers declares many handlers in ONE
  unpack/repack, with the same manifest as one call per handler. The stage uses
  it, and skips (with a warning) an entry the cmdlet would reject.
- Same for AddPackagedServices (Add-MsixService -Services) and
  DeclarePackageCertificates (Add-MsixPackageCertificate takes several paths).

FIXED: a thumbnail AND a property handler on one file type declared the type
twice ("'.mkv' is a duplicate key ... 'Extension_FileType'"). The second handler
joins the FTA that already declares the type; if that FTA also declares other
types, the handler is skipped with a warning.

FIXED: removal stages left the manifest pointing at removed files. RemoveUpdaters
deleted Chrome's updater.exe but kept the windows.service extensions on it
(MakeAppx 0x80080204). Every file-removal stage (Remove-MsixUninstallerArtifact,
Remove-MsixUpdaterArtifact, Remove-MsixDesktopShortcut, Remove-MsixPsf, the
bundled-runtime strip) now uses one helper. It removes and logs:
- the declarations that named a removed file: Extensions with that Executable
  (service, alias, startup task, protocol, ...), com ExeServer / SurrogateServer
  class / InProcessServer, desktop2 FirewallRules, emptied LoaderSearchPathEntry
  folders;
- what named a removed COM class by CLSID (verbs, thumbnail/preview/property
  handlers, ProgIds, toast activator);
- containers left empty.
It never removes an Application: an Application's own Executable is kept and
logged. AddPackagedServices skips a service whose executable an earlier stage
removed. Remove-MsixPsf re-points extensions that named the PSF launcher.

FIXED: Applications sharing an executable (one per Start-menu shortcut, e.g.
"Configure Java" / "About Java" on javacpl.exe) all got the same
AppExecutionAlias, which MakeAppx rejects. Add-MsixAlias declares each alias name
once per package: for the Application without uap10:Parameters, else the first,
never a name the package already has, and logs the rest. Get-MsixAliasCandidate
returns one candidate per alias name (new SharedWith property).

FIXED: Registry.dat folder tokens mapped to VFS folders MSIX does not have:
[{ProgramFilesX86}] became VFS\ProgramFiles(x86) (not VFS\ProgramFilesX86), and
SystemX86, CommonAppData, AppData and LocalAppData were wrong too. The path was
returned even when no file was there, so K-Lite's 83 shell handlers pointed at
DLLs that were not in the package.
- Tokens now resolve to the canonical VFS folders (ProgramFilesX64/X86,
  ProgramFilesCommonX64/X86, SystemX64/X86, Windows, Fonts, Common AppData,
  AppData, Local AppData, ...), one table for the service, COM, shell-handler and
  context-menu scanners and Add-MsixLegacyContextMenu.
- A path that is not in the package maps to nothing. The shell-handler,
  context-menu and service stages skip such an entry with a warning (new
  UnresolvedShellHandlerEntries on the shell-handler finding), and re-check each
  file against the package before declaring it.

FIXED: an alias on a PSF-launched app was named after its Application Id
(python.a3.a13.a17.a64.bit.exe). Add-MsixAlias now reads the PSF config.json
target (pythonw.exe); the once-per-package rule still applies. The mutate block
of _MsixMutateManifest receives the unpacked folder as a second argument
(Invoke-MsixManifestTransform -ArgumentList).

FIXED: PSF was injected into Chromium-based apps that did not need it. A
captured Chrome got PSF through a false-positive PluginDirectory finding; with
PSF its window took 50.5 s (9.3 s without) and a chrome.exe exited 0x1.
Chromium's sandboxed child processes refuse the injected runtime. When the
Application PSF wraps is Chromium-based (chrome_elf.dll, msedge_elf.dll,
libcef.dll, resources\app.asar, or a V8 snapshot next to icudtl.dat, in its
folder or a version subfolder), PluginDirectory keeps only its manifest change,
and InjectPsf, the runtime JAVA_HOME/DOTNET_ROOT wiring and Invoke-MsixAutoFix's
InjectPsf/splash stages are skipped, each with a warning. Packages that already
carry PSF are not affected.

## v0.75.3 (keep a verified SDK toolchain when an update is rejected)

FIXED: Initialize-MsixToolchain failed on machines that already had working SDK
tools whenever the newest Microsoft.Windows.SDK.BuildTools release was rejected
by Authenticode verification, as 10.0.28000.2957 was before 0.75.1.
Install-MsixSdkTool left the installed tools alone, but Update-MsixSdkTool
passed its error on.
- Update-MsixSdkTool now re-verifies the installed tools with the check
  Get-MsixToolsRoot applies, and keeps them. It writes one warning (a real
  Write-Warning, so -WarningVariable and CI logs see it) that names the
  rejected version and repeats the install error's advice. The result has
  Updated = $false and a new RejectedVersion property.
- Still an error: no SDK tools installed yet, installed tools that no longer
  pass verification, and any failure other than a rejection (NuGet
  unreachable, download failed).
- The SDK advice no longer offers to pin the verified version when the
  installed tools are already at least that version, and no longer claims
  that Initialize-MsixToolchain always replaces a pinned SDK install. PSF is
  unchanged: Update-MsixPsfBinary still fails on a rejected latest release.

## v0.75.2 (Process Monitor / DebugView / msixmgr installs copy their files again)

FIXED: since v0.71.0, Install-MsixProcMon, Install-MsixDebugView and
Install-MsixMgr installed nothing. Their shared helper copied the verified
archive with Copy-Item -LiteralPath "<stage>\*". -LiteralPath never expands
wildcards, so nothing was copied:
- Windows PowerShell 5.1 raised no error. PowerShell 7 raised a non-terminating
  "Cannot find path" error, which rolled back only under ErrorAction Stop.
- Otherwise the install wrote its marker and reported success. The tool looked
  installed with only the marker in its folder, and later calls skipped it.
- The copy now enumerates the stage and copies each item with -LiteralPath.
  It also stops on any copy error, so the marker is written only after a real
  copy. Destination paths containing [ ] work.

REPAIR: a tool folder that holds only its install marker now counts as not
installed. Install-MsixProcMon / Install-MsixDebugView / Install-MsixMgr
reinstall it with a warning. Update-MsixProcMon / Update-MsixDebugView /
Update-MsixMgr (and so Initialize-MsixToolchain) reinstall it instead of
reporting it fresh. No -Force needed.

TESTS: MSIX.ArchiveToolInstall.Tests.ps1 runs the three installers end to end
on a real zip, with only the download and Authenticode mocked.

## v0.75.1 (Windows SDK BuildTools signer)

FIXED: an unpinned Install-MsixSdkTool / Initialize-MsixToolchain failed on
every fresh machine. Microsoft.Windows.SDK.BuildTools 10.0.26100.9457 and
10.0.28000.2957 (2026-10-28) sign appxsip.dll (x64 and x86) with
"CN=Microsoft Windows Kits Publisher, O=Microsoft Corporation, ...". That CN was
not in signers.json, so the install rolled back and callers only saw
"MakeAppx.exe not found".
- signers.json now trusts "CN=Microsoft Windows Kits Publisher," (prefix-only,
  like the other Microsoft entries). Its chain was verified: Microsoft Windows
  Code Signing PCA 2024 -> Microsoft Root Certificate Authority 2010, the same
  intermediate and root as the CN=Microsoft Corporation certs on signtool and
  MakeAppx in the same package.

CLEARER FAILURE when a BuildTools release is rejected:
- Every rejected file is reported, grouped by signer, instead of only the first.
  Invalid or missing signatures are listed separately and are never presented
  as fixable through signers.json.
- Install-MsixSdkTool says that nothing was installed (and that an existing
  install was kept). It names the signer, offers the newest verified version to
  pin (Install-MsixSdkTool -Version 10.0.28000.2957, then
  Initialize-MsixToolchain -Skip Sdk), and links the signers.json governance.
- Get-MsixToolsRoot's "MakeAppx.exe not found" quotes that failure first when
  an install failed earlier in the session.

PSF PIN: TMurgent PSF v2026.10.13 and v2026.11.14 ship PsfLauncher, PsfRuntime
and every fixup unsigned, which the module refuses. v2026.07.01 is the last
signed release.
- Install-MsixPsfBinary / Update-MsixPsfBinary take -Version <tag> to install or
  keep a specific release. A rejected release now names that tag
  (Install-MsixPsfBinary -Version v2026.07.01, then Initialize-MsixToolchain
  -Skip Psf).
- CI provisions PSF at that verified tag. For users, the default is still the
  latest release.

Full history: CHANGELOG.md.
'@
        }
    }
}

