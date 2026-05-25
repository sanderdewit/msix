@{
    ModuleVersion     = '0.70.6'
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
## v0.70.6

### Correctness fixes from the post-v0.70.5 code review
- Atomic pack-sign-move in Add-MsixCapability + Remove-MsixUninstaller-
  Artifact (#34). Both used to pack straight to $PackagePath and then
  sign; a signing failure left the user with an unsigned modified copy
  of their signed package. Both now pack to a scratch path, sign at
  the scratch, and Move-Item to the target only on success.
  -UnsignedOutputPath preserves the scratch on signing failure.
- Compare-MsixTrace.Summary now exposes ResolvedRowCount /
  PersistedRowCount / IntroducedRowCount alongside the categorised
  finding counts (#35). Uncategorised regressions on paths outside
  System32 / WindowsApps / HKLM / LoadLibrary used to silently
  disappear from the summary; a Warning fires when IntroducedRow-
  Count > IntroducedCount.

### Refactors (no public API change)
- _MsixInstallArchiveTool + _MsixUpdateToolByAge helpers (#36) collapse
  six near-identical toolchain installers (Procmon, DebugView, msixmgr)
  + four age-based updaters (Procmon, DebugView, msixmgr, AppRuntime)
  to thin wrappers. Bespoke installers with version-aware idempotency
  (PSF / SDK BuildTools / AppRuntime multi-channel) remain self-
  contained because forcing them into the helper would create a leaky
  abstraction.
- _MsixMutatePackage helper (#37) centralises the unpack -> mutate ->
  atomic-pack-sign-move pattern for the four heuristic mutators
  (Add-MsixCapability, Remove-MsixUninstallerArtifact,
  Remove-MsixUpdaterArtifact, Remove-MsixShellRegistryArtifact). The
  H1 atomic semantics from #34 are now enforced by construction.
- MSIX.Heuristics.ps1 (2764 lines) split into MSIX.Scanners.ps1,
  MSIX.PackageMutators.ps1, and MSIX.AutoFix.ps1 (#38). All ten
  plural-noun back-compat aliases carried forward.

### Subtle behaviour change
- Update-MsixMgr now previews 'Update msixmgr' uniformly under -WhatIf
  instead of 'Install missing msixmgr' / 'Refresh msixmgr' depending
  on state. Matches the pattern already used by Update-MsixProcMon /
  Update-MsixDebugView / Update-MsixAppRuntime.

### Quality bar
- Pester (PowerShell 7): 364 pass / 0 fail / 1 skip
  (was 351 in v0.70.5; +13 new regression guards).
- PSScriptAnalyzer (scoped to MSIX module): 0 findings.

## v0.70.5

### Tier-2 remediation orchestration: #30 + #31 + #32
- Compare-MsixTrace (#31): before/after correlation of two runtime
  trace captures (DebugView .log/.txt or ProcMon .pml). Classifies
  every observed failure row as Resolved / Persisted / Introduced
  based on a (Function x Path x Result) match key. -Sarif emits a
  three-run SARIF 2.1.0 document so regressions show up as errors,
  fixes show up as notes.
- New/Export/Import/Test/Invoke-MsixRemediationPlan (#32):
  serialise a remediation plan to YAML, route through change-control,
  and replay it deterministically against a later package build.
  Strict cmdlet-safety guard (only MSIX module cmdlets may appear in
  appliedFixes), identity + SHA-256 fingerprint drift detection,
  single-sign-at-end semantics matching Invoke-MsixPlaybook.
  YAML emitter/parser is dependency-free and scalar-only - same
  security stance as the accelerator YAML.
- Invoke-MsixAutoFixLoop (#30): multi-pass remediation pipeline.
  Per-pass artefacts under $env:TEMP\msix-autofix-loop-<runId>\pass-N\,
  optional Compare-MsixTrace integration for NoRegressions stop
  condition, MinConfidence gate from the evidence model, signs once
  at the end. Closes the loop on chained MSIX issues where fixing
  one problem reveals the next.

### PowerShell 5.1 compatibility
- Removed PS7-only null-coalescing operator (??) from Merge-MsixFinding
  and Invoke-MsixAutoFixLoop.
- Stripped em-dashes from string literals in MSIX.RemediationPlan.ps1
  and MSIX.AutoFixLoop.ps1: the UTF-8 byte 0x94 was read as a curly
  double-quote terminator under CP-1252 when files lack a BOM, which
  is the default on Windows PowerShell 5.1.

### Quality bar
- Pester: 351 pass / 0 fail / 1 skip on PowerShell 7
  (27 new tests for the Tier-2 features).
- PSScriptAnalyzer (scoped to MSIX module): 0 findings.

## v0.70.4

### Tier-1 foundation: unified evidence model + confidence scoring (#29)
- New MSIX.Evidence.ps1: New-MsixFinding / Add-MsixEvidence /
  Merge-MsixFinding / Get-MsixFindingConfidence /
  ConvertTo-MsixFinding (legacy adapter) / ConvertTo-MsixLegacyFinding.
- Invoke-MsixAutoFixFromAnalysis: new -MinConfidence gate (default 0.85).
  Legacy findings without EvidenceItems are treated as confident so the
  migration is incremental and nothing regresses.
- SARIF emitter surfaces evidenceItems[] and confidence in
  result.properties when the analyzer populated them.
- Unblocks #30 (Invoke-MsixAutoFixLoop), #31 (Compare-MsixTrace),
  #32 (Export/Import/Invoke-MsixRemediationPlan).

### PSSA cleanup
- Get-MsixManifestApplication: per-parameter-set OutputType (XmlNode
  for First/ById, XmlNode[] for All), plus return-site casts so PSSA's
  static type inference matches.
- Get-MsixRequiredAppRuntimeChannel: returns [string[]] (was Object[]).
- Tests: trailing whitespace stripped from Recommendations test file.
- PSScriptAnalyzer (scoped to MSIX module): 0 findings.
- Pester: 325 pass / 0 fail / 1 skip.

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
