@{
    ModuleVersion     = '0.74.1'
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
## v0.74.1 (completes the 0.74.0 audit fixes)

0.74.0 closed issues #147, #152 and #153 only partially. This finishes them.

SECURITY (#147) - and without requiring administrator rights
- New Set-MsixToolVerification -Enabled $false: the supported escape hatch for
  air-gapped agents. Session-scoped and in-memory, so NO admin is needed and it
  cannot be planted for a future session to pick up. The module must never
  require elevation - that is why it parses hives via offreg.dll rather than
  reg.exe load, which demands SeBackupPrivilege/SeRestorePrivilege.
- A process/user-scoped MSIX_SKIP_TOOL_VERIFICATION is now IGNORED (with a loud
  warning). That was the real attack: a non-admin persists it in
  HKCU\Environment and every later session silently trusts an arbitrary tools
  root. A machine-scoped value is still honoured for fleet configuration.
- Resolve-MsixProcMonPath / Resolve-MsixDebugViewPath now Authenticode-verify
  every candidate before returning it. ProcMon loads a kernel driver so it runs
  ELEVATED, and the resolver trusted both a user-settable override and a fixed
  C:\PSF\ProcessMonitor\Procmon.exe fallback - a directory any standard user can
  create, because the root of C: grants Authenticated Users CreateDirectories.
  That was a local privilege-escalation path. msixmgr keeps its documented
  unsigned exception (microsoft/msix-packaging#710) and is unaffected.

CORRECTNESS (#153)
- _MsixOfflineSaveHive's return value is no longer discarded: it signals failure
  only by returning $false, so a failed save shipped a SIGNED modification
  package containing none of the requested registry keys, exit code 0, and a log
  line claiming success.
- Idempotency guards for Add-MsixFileTypeAssociation, Add-MsixShellVerbExtension,
  Add-MsixFileExplorerContextMenu and the Rule element of Add-MsixFirewallRule.
- The rest of the @($null) null-deref cluster: 15 further sites.
- Invoke-MsixAutoFixLoop -CaptureTrace now works. It called
  Invoke-MsixProcMonCapture -PackagePath, which is not a parameter of that
  cmdlet, inside a catch that logged and continued - so the documented feature
  had never once produced a .pml.
- Test-MsixSignature includes NotTrusted in NeedsSelfSign; such a package does
  not install in a clean sandbox, which is what -AutoSign exists for.
- Add-MsixVcRuntimeBundle no longer coerces an undetectable (or arm64)
  architecture to x86 while logging "auto-detected", and no longer packs a
  PARTIAL bundle as success. Both shipped a package that fails at launch.
- Write-MsixLog writes UTF-8 with -LiteralPath. The ANSI default on 5.1 turned
  the arrows and box drawing this module emits into a literal '?', and -Path
  treated [ ] in a log path as wildcards and silently dropped the line.

TEST COVERAGE (#152)
- Never-invoked exported functions: 73 -> 26, and all 26 remaining are genuinely
  environment-bound (network installers, Hyper-V/VHDX, the ProcMon kernel
  driver, Windows Sandbox, a live installed package), each listed with a reason.
- The coverage ratchet now guards the WHOLE exported surface rather than only
  Add/Remove/Set/Update mutators - the narrow scope is how 73 functions came to
  be uncovered with nothing reporting it.
- Authenticode REJECTION is tested for the first time: both existing tests
  mocked a Valid signature, so the throw branch - the control that stops a
  planted toolchain binary from executing - had never executed.
- Read-only scanner matrix: all 15 scanners against a well-formed package,
  against the degenerate manifest the module generates itself, and against a
  missing package (must fail loudly, not return a clean-looking empty result).
- Code coverage is now measured in CI (60.5%) and reported in the job summary.

CI
- Both lanes provision the toolchain with Initialize-MsixToolchain, so the 10
  PSF-dependent tests that used to skip now actually run - including the
  regression guards for #138 and #145.
- actions/upload-artifact bumped to v7, which runs on Node 24. Both v4 AND v5
  declare using: node20, so the runner force-migrated them and warned on every
  build; v6 was the first Node 24 line.

Suite: 848 passing. Full history: CHANGELOG.md.
'@
        }
    }
}
