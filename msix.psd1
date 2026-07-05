@{
    ModuleVersion     = '0.71.3'
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
        'Remove-MsixPsf',
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
        'Invoke-MsixSelfSign',
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
        'Invoke-MsixSelfSignAndDebug',
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
## v0.71.3

### App isolation toolkit
- Remove-MsixPsf (new): inverse of Add-MsixPsfV2 — restores the real
  executable from config.json and strips the PSF payload, warning about every
  behaviour that disappears. PSF and AppContainer isolation are mutually
  exclusive; run this before Add-MsixAppIsolation.
- Add-MsixAppIsolation -RemoveComServer (new): windows.comServer is invalid
  with a partial-trust entry point; the switch strips the COM server + its
  Explorer context-menu verbs so the package can isolate.
- Test-MsixIsolation (new): static WouldIsolate verdict with reasons, and a
  runtime process-token check (-ProcessId / -PackageFamilyName) for the
  definitive S-1-15-2 AppContainer SID. Prompts are not proof; the token is.
- Get-MsixIsolationAdvice (new): maps ProcMon ACCESS-DENIED rows to concrete
  capability / consent suggestions per isolation mode.

### Review fixes (#97-#102)
- Invoke-MsixPipeline AppIsolation stage now applies the real isolation model
  (it still used the obsolete capability-only shape — packages did not
  isolate). Config keys: Mode / Capabilities / AppId / RemoveComServer.
- Get-Help repaired for 62 of 166 exported functions (malformed .PARAMETER
  tags and '.msix'-leading description lines made PowerShell reject entire
  help blocks). A help contract test now guards this.
- Docs: EXAMPLES isolation recipe on the two-mode API; desktop9 references
  corrected to the implemented com + desktop4/desktop5 pattern.
- Contract sweeps: NoSign/WhatIf now discovered dynamically; approved-verb
  guard added. Coverage-map debt burned to empty (19 behavioural tests).

### Bugs fixed (caught by the new coverage tests)
- Add-MsixFontExtension placed windows.sharedFonts at Package level; schema
  requires Application level (MakeAppx C00CE014).
- Add-MsixStartMenuFolder wrote a schema-invalid bare VisualGroup attribute;
  the element must be uap3:VisualElements per MS Learn.
- Add-MsixSplashScreen always threw (Split-Path -LiteralPath + -Parent is an
  unresolvable parameter-set combination).
- Add-MsixPsfV2 rejected empty -Fixups, blocking script-only PSF injection.

### Rename
- Invoke-MsixSelfSignAndDebug -> Invoke-MsixSelfSign (alias kept). It only
  signs — and does not rewrite the Publisher (use Update-MsixSigner for that).

Full history: CHANGELOG.md.
'@
        }
    }
}
