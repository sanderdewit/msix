@{
    ModuleVersion     = '0.74.0'
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
## v0.74.0 (hardening release - data loss, security, PS 5.1)

Outcome of a full-codebase audit. Several of these could destroy or corrupt an
operator's package, or hand an attacker control of signing; all shipped in 0.73.x.

DATA LOSS (#145)
- Remove-MsixPsf deleted 'config.json' and '*Fixup*.dll' recursively from ANY
  package, then repacked, signed and moved the result over the operator's
  original. A PSF-free app shipping its own config.json (Electron/.NET - very
  common) silently lost it, exit code 0. Now gated on real PSF presence, with
  precise patterns.
- Add-MsixVcRuntimeBundle packed and signed directly over the input file, so a
  signing failure left an unsigned repack where a signed package had been, with
  no recovery. Now builds to scratch, signs, then moves; gains
  -UnsignedOutputPath.
- -WhatIf was broken for all ~46 mutators: New-MsixWorkspace honoured the
  inherited WhatIfPreference and returned an empty path.
- -UnsignedOutputPath could destroy the artifact it promised to preserve: the
  copy used -ErrorAction SilentlyContinue and "preserved" was logged
  unconditionally, then the scratch was deleted.

SECURITY (#147, #148)
- Signing-toolchain hijack: only 3 .exe files were Authenticode-verified, but
  SDK signtool.exe loads wintrust.dll / mssign32.dll / AppxSip.dll from its OWN
  directory. Every .exe/.dll in the resolved root is now verified.
- Tool discovery walked up to four parent levels and took the lexically highest
  match, reaching the user-writable Documents folder for a CurrentUser install.
  Now one level.
- The "verifier not loaded" branch trusted the root silently; now fail-closed.
- The PFX password reached the log file via the Exec: line (and therefore CI
  artifacts and support bundles). Secret-bearing switches are now redacted.
- SignerSignEx left the PFX PRIVATE KEY in the user's key store on every run.
  The key container is now deleted explicitly.

WINDOWS POWERSHELL 5.1 (#146)
- Join-String (PS6+) silently replaced the real ComServer finding with a
  scanner error on 5.1.
- Get-PfxCertificate -Password (PS6+) made Set-MsixScriptSignature and
  Add-MsixStandardScript -Pfx unusable on 5.1.
- "-Encoding utf8" means BOM on 5.1 and no BOM on 7. That put a BOM in the
  Trusted Signing metadata JSON - rejected by System.Text.Json, on the DEFAULT
  signing backend - and in PSF config.json.

MANIFEST CORRECTNESS (#153)
- Add-MsixLoaderSearchPathOverride emitted attribute "LoaderSearchPath" (the
  schema requires "FolderPath") and declared the extension under Application
  instead of Package, so it could never produce a packable package.
- Add-MsixFirewallRule passed the caller's casing to a schema that requires
  lowercase, so -Direction In failed to parse.

RELIABILITY + CI (#150, #151, #152)
- Fixed the workspace leak behind ~46 mutators (1,077 stale dirs observed).
- CI now provisions PSF, so the PSF regression guards actually run; provisioning
  failure is fatal and an all-skip run is red.
- The coverage ratchet counted Get-Command calls and It titles as coverage;
  replaced with AST detection, and six never-tested mutators gained real tests.

NEW
- Import-Module notifies when a newer version is on PSGallery. Silent in CI and
  non-interactive hosts, cached 24h, hard network timeout, never blocks import.
  Opt out with MSIX_NO_UPDATE_CHECK=1.

Full history: CHANGELOG.md.
'@
        }
    }
}
