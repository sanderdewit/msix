@{
    ModuleVersion     = '0.75.1'
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

