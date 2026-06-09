@{
    ModuleVersion     = '0.71.0'
    GUID              = 'a3f1c2d4-8e5b-4f7a-9c3d-1b2e4f6a8c0d'
    Author            = 'Sander de Wit'
    Description       = 'Enterprise-grade MSIX packaging automation. PSF (TMurgent) injection with the full RegLegacy + MFR fixup palette, context menus, signing, CI/CD pipeline, compatibility investigation (procmon + DebugView trace parsing), sandbox debug helper, App Attach VHDX/CIM generator, Win32 App Isolation, AppData helpers, accelerator import, PSADT-style standard scripts, TMEditX-style heuristic auto-fixers (uninstaller / Run-key / VC runtime / capability / splash / alias / version-bump), package compare, and a Pester test suite.'
    PowerShellVersion = '5.1'
    RootModule        = 'MSIX.psm1'

    FunctionsToExport = @(
        'Add-MsixAlias',
        'Add-MsixAppIsolation',
        'Add-MsixCapability',
        'Add-MsixComServerExtension',
        'Add-MsixDiagnosticTrace',
        'Add-MsixEvidence',
        'Add-MsixFileExplorerContextMenu',
        'Add-MsixFileTypeAssociation',
        'Add-MsixFirewallRule',
        'Add-MsixFontExtension',
        'Add-MsixLegacyContextMenu',
        'Add-MsixLoaderSearchPathOverride',
        'Add-MsixManifestNamespace',
        'Add-MsixProtocolHandler',
        'Add-MsixPsfV2',
        'Add-MsixShellVerbExtension',
        'Add-MsixSplashScreen',
        'Add-MsixStandardScript',
        'Add-MsixStartMenuFolder',
        'Add-MsixStartupTask',
        'Add-MsixVcRuntimeBundle',
        'Assert-MsixProcessSuccess',
        'Compare-MsixPackage',
        'Compare-MsixTrace',
        'ConvertFrom-MsixTraceLine',
        'ConvertFrom-MsixTraceToFinding',
        'ConvertFrom-MsixYamlAccelerator',
        'ConvertTo-MsixFinding',
        'ConvertTo-MsixLegacyFinding',
        'ConvertTo-MsixSarif',
        'ConvertTo-MsixReportHtml',
        'Copy-MsixHostAppDataIntoPackage',
        'Export-MsixRemediationPlan',
        'Dismount-MsixAppAttachImage',
        'Find-MsixPlaybook',
        'Get-MsixAliasCandidate',
        'Get-MsixAppRuntimeVersion',
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
        'Get-MsixPackageStorageSummary',
        'Get-MsixPlaybook',
        'Get-MsixPluginExtensionPoint',
        'Get-MsixProcMonFailure',
        'Get-MsixPsfBinariesVersion',
        'Get-MsixPublisherId',
        'Get-MsixRequiredAppRuntimeChannel',
        'Get-MsixRunKeyEntry',
        'Get-MsixSdkToolsVersion',
        'Get-MsixShellContextMenuEntry',
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
        'Invoke-MsixSelfSignAndDebug',
        'Invoke-MsixSigning',
        'Merge-MsixFinding',
        'Mount-MsixAppAttachImage',
        'New-MsixAppAttachImage',
        'New-MsixFinding',
        'New-MsixManifestDocument',
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
        'Set-MsixRegistryWriteVirtualization',
        'Set-MsixScriptSignature',
        'Set-MsixToolsRoot',
        'Start-MsixDebugSession',
        'Start-MsixSandbox',
        'Test-MsixAgainstLimitation',
        'Test-MsixAppAttachImage',
        'Test-MsixManifest',
        'Test-MsixPsfConfig',
        'Test-MsixRemediationPlan',
        'Test-MsixSignature',
        'Update-MsixAppRuntime',
        'Update-MsixDebugView',
        'Update-MsixMgr',
        'Update-MsixPackageVersion',
        'Update-MsixProcMon',
        'Update-MsixPsfBinary',
        'Update-MsixSdkTool',
        'Update-MsixSigner',
        'Write-MsixLog'
    )

    AliasesToExport   = @(
        'add-MsixPsf',
        'ConvertFrom-MsixTraceToFindings',
        'Get-MsixAliasCandidates',
        'Get-MsixCapabilityHints',
        'Get-MsixComServerEntries',
        'Get-MsixDebugRecommendations',
        'Get-MsixDesktopShortcutCandidates',
        'Get-MsixFontCandidates',
        'Get-MsixHeuristicFindings',
        'Get-MsixIsolationCapabilities',
        'Get-MsixKnownCapabilities',
        'Get-MsixLimitations',
        'Get-MsixMfrKnownFolders',
        'Get-MsixNestedPackageCandidates',
        'Get-MsixPluginExtensionPoints',
        'Get-MsixProcMonFailures',
        'Get-MsixRunKeyEntries',
        'Get-MsixShellContextMenuEntries',
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
                            'TMEditX','Enterprise','CICD','Pester','PSADT')
            ProjectUri  = 'https://github.com/microsoft/MSIX-PackageSupportFramework'
            ReleaseNotes = @'
## v0.71.0

### Win32 App Isolation — now writes a manifest that actually isolates
- Add-MsixAppIsolation previously only added an isolatedWin32-* capability,
  which does NOT isolate anything. It now writes the uap18 attributes that
  enable isolation on each <Application> (EntryPoint="Windows.FullTrustApplication",
  uap18:EntryPoint="Isolated.App", uap18:TrustLevel="appContainer",
  uap18:RuntimeBehavior="appSilo"), declares the uap18 namespace, and raises the
  Windows.Desktop TargetDeviceFamily MinVersion to 10.0.26100.0 (isolation only
  engages when the package targets 24H2; it will no longer install on older
  Windows). (#91, #92)
- runFullTrust is retained by design: the FullTrust entry point requires it
  (MakeAppx 0x80080204 otherwise), so isolation + runFullTrust are required
  together, not mutually exclusive. -RemoveRunFullTrust / -KeepRunFullTrust
  switches added. (#91)
- COM context menus: isolatedWin32-shellExtensionContextMenu is auto-added when
  the package has a comServer / FileExplorerContextMenus extension. (#91)
- PSF packages (PsfLauncher*.exe entry point) are detected and warned about —
  they cannot be isolated (PSF injects fixup DLLs, which AppContainer blocks). (#93)
- Remove-MsixAppIsolation also strips the uap18 attributes now. (#91)
- Get-MsixIsolationCapability rebuilt against the MS Learn supported-capabilities
  page: rich objects (Name/ElementType/Description), full isolatedWin32-* set,
  and device capabilities (microphone/webcam) as <DeviceCapability>. Fixed an
  OrderedDictionary.ContainsKey runtime error. (#85, #86)
- Import-MsixSparseShellExtension resolves a bare nested-package name and skips
  gracefully (warning, not a throw) when the nested package is absent, so
  Invoke-MsixAutoFixFromAnalysis no longer aborts mid-run. (#94)

  NOTE: Win32 App Isolation is a preview Windows feature. A correct package
  still falls back to full trust on an OS where the feature isn't active
  (Insider builds vs retail 24H2 servicing) and does not engage in Windows
  Sandbox. See TEST-PLAN.md Scenario 6 to verify activation.

### Shell / context menus
- Folder context menus (e.g. 7-Zip): the scanner now walks the Folder and Drive
  shell classes, and -FileTypes accepts container item-types. DragDropHandlers
  are scanned and stripped. (#80, #84)
- #81: install-relative VFS plugin folders are routed via PSF FileRedirection;
  Set-MsixFileSystemWriteVirtualization validates ExcludedDirectory entries
  against the $(KnownFolder:Name) schema and skips invalid ones, so it can never
  emit a manifest MakeAppx rejects.

### Security hardening (post code-security review)
- Fixed P1 findings: template injection, XXE, Zip-Slip, TLS floor (#49–#52).
- AzureSignTool client secret delivered via environment variable, never the
  command line (#53).
- Authenticode-verify resolved SDK tools before use (#54).
- Opt-in download integrity: SHA-256 + per-publisher thumbprint pinning (#55).
- Escape package-derived values in scanner recommendation snippets (#60).
- Reserved the SignerSignEx signing backend (API only) (#17).

### Offline-registry scanning & reliability
- Run-key scan now uses offreg parsing instead of raw strings; fixed
  _MsixOfflineEnumValueNames returning empty names (#56).
- Validate the offline hive before parsing; _MsixWithOfflineHive wrapper (#59).
- Bind mutator scriptblocks to module session state so private offreg helpers
  resolve at invocation (#83).
- Unpack the package once per analysis run (#58).
- Set-MsixManifestMaxVersionTested handles multi-TDF packages and short
  version strings (#57).
- Complete -LiteralPath migration + guard; -DisableTestResult switch (#46, #47).
- Always-use-named-parameters rule documented + swept across the module (#48).

### Test infrastructure & repo
- Real-MSIX integration harness (Build-MsixTestFixture) + CI job; end-to-end
  integration tests for the mutating cmdlets (#61, #87).
- Pester suite restructured by cmdlet-family + cross-cutting contract;
  issue/version-named files dissolved; coverage-map guardrail asserts every
  Add/Remove/Set/Update mutator is invoked by a test (#88, #89).
- .gitignore for test artifacts; actions/checkout bumped to v6 / Node 24 (#90).
- CI parse-check gate so a syntactically broken module fails lint, not Pester.

Full history: CHANGELOG.md.

'@
        }
    }
}
