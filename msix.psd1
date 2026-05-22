@{
    ModuleVersion     = '0.70.3'
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
        'ConvertFrom-MsixTraceLine',
        'ConvertFrom-MsixTraceToFinding',
        'ConvertFrom-MsixYamlAccelerator',
        'ConvertTo-MsixReportHtml',
        'Copy-MsixHostAppDataIntoPackage',
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
        'Invoke-MsixCommand',
        'Invoke-MsixContainerCommand',
        'Invoke-MsixInvestigation',
        'Invoke-MsixManifestTransform',
        'Invoke-MsixPipeline',
        'Invoke-MsixPlaybook',
        'Invoke-MsixProcess',
        'Invoke-MsixProcMonCapture',
        'Invoke-MsixSelfSignAndDebug',
        'Invoke-MsixSigning',
        'Mount-MsixAppAttachImage',
        'New-MsixAppAttachImage',
        'New-MsixManifestDocument',
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
## v0.70.0

### Security hardening
- Authenticode verification for every downloaded toolchain binary
  (PSF, Procmon, msixmgr, SDK tools) before use.
- SecureString for all signing/PFX secrets end-to-end. ConvertTo-SecureString
  -AsPlainText -Force is banned; tests use ConvertTo-TestSecureString instead.
- Secret non-leakage: Get-MsixDebugRecommendation emits a Read-Host
  -AsSecureString placeholder, never the real value. SignTool with -Pfx
  now emits a -WarningVariable-capturable warning about cmdline exposure.
- XML hardening: all manifest loading via _MsixLoadXmlSecure
  (DtdProcessing=Prohibit, MaxCharactersFromEntities=1MB). XXE and
  billion-laughs payloads are rejected.
- powershell-yaml dependency removed; accelerator parser is a restricted
  scalar-only implementation that cannot instantiate .NET objects from
  untrusted YAML.

### Reliability & architecture
- Atomic pack-sign-move: Invoke-MsixPipeline packs to a scratch path,
  signs at the scratch, then Move-Item to the target only on success.
  UnsignedOutputPath preserves the scratch when signing fails.
- Consistent -WhatIf semantics across every mutating cmdlet.
- Pure manifest transforms: Invoke-MsixManifestTransform,
  Set-MsixManifestPublisher, Set-MsixManifestIdentity (in-memory XML
  only, no pack/sign).
- Three signing backends: SignTool (default), TrustedSigning,
  AzureSignTool. PFX password is a SecureString throughout.
- offreg.dll integration: Get-MsixUninstallRegistryEntry,
  Get-MsixShellContextMenuEntry, Get-MsixComServerEntry, and the
  Remove-MsixUninstallerArtifact registry-cleanup path no longer
  require elevation. reg.exe load (admin-only) replaced with the
  Offline Registry API.
- Shell-extension context menus generated via the TMEditX-verified
  desktop4 + desktop5 schema. New AppExecutionAlias autofix stage.
  Alias inheritance from parent Application Executable.

### Documentation & testing
- EXAMPLES.md: 19 copy-paste recipes covering all major use cases.
- TEST-PLAN.md: 13 integration scenarios + release checklist.
- CONTRIBUTING.md: coding standards (SecureString hygiene, XML loading,
  WhatIf semantics, Authenticode requirements).
- 230+ Pester tests; CI runs PSScriptAnalyzer (Error+Warning) and Pester
  on every push/PR. All tests import via .psd1 (not .psm1).

Full release history: see CHANGELOG.md in the project repository.
'@
        }
    }
}
