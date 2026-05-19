#region --- Load sub-modules ------------------------------------------------
. "$PSScriptRoot\MSIX.Logging.ps1"
. "$PSScriptRoot\MSIX.Core.ps1"
. "$PSScriptRoot\MSIX.Validation.ps1"
. "$PSScriptRoot\MSIX.Manifest.ps1"
. "$PSScriptRoot\MSIX.PSF.ps1"
. "$PSScriptRoot\MSIX.Signing.ps1"
. "$PSScriptRoot\MSIX.ContextMenu.ps1"
. "$PSScriptRoot\MSIX.Pipeline.ps1"
. "$PSScriptRoot\MSIX.Investigation.ps1"
. "$PSScriptRoot\MSIX.AppData.ps1"
. "$PSScriptRoot\MSIX.Accelerator.ps1"
. "$PSScriptRoot\MSIX.PsfBinaries.ps1"
. "$PSScriptRoot\MSIX.Debug.ps1"
. "$PSScriptRoot\MSIX.AppAttach.ps1"
. "$PSScriptRoot\MSIX.AppIsolation.ps1"
. "$PSScriptRoot\MSIX.Limitations.ps1"
. "$PSScriptRoot\MSIX.Trace.ps1"
. "$PSScriptRoot\MSIX.Scripts.ps1"
. "$PSScriptRoot\MSIX.MFR.ps1"
. "$PSScriptRoot\MSIX.VcRuntime.ps1"
. "$PSScriptRoot\MSIX.Detection.ps1"
. "$PSScriptRoot\MSIX.ManifestExtensions.ps1"
. "$PSScriptRoot\MSIX.Heuristics.ps1"
. "$PSScriptRoot\MSIX.Compare.ps1"
. "$PSScriptRoot\MSIX.Functions.ps1"
#endregion


#region --- Backward-compatible aliases ------------------------------------
# Only aliases whose NAME genuinely differs from the function's name belong
# here. PowerShell is case-insensitive: 'update-MsixSigner' and
# 'Update-MsixSigner' are the SAME identifier, so a Set-Alias from one onto
# the other shadows the function and breaks all subsequent invocations.
#
# Removed in v0.13 (were self-aliasing and broke their own functions):
#   update-MsixSigner, new-MsixPsfJson, add-MsixAlias,
#   remove-MsixStartMenuEntry, add-MsixStartMenuFolder
Set-Alias -Name add-MsixPsf                  -Value Add-MsixPsfV2
#endregion


#region --- Exports ---------------------------------------------------------
Export-ModuleMember -Function @(
    # Logging
    'Write-MsixLog'
    'Set-MsixLogLevel'
    'Set-MsixLogFile'
    # Core / tools
    'Get-MsixToolsRoot'
    'Set-MsixToolsRoot'
    'New-MsixWorkspace'
    'Invoke-MsixProcess'
    'Get-MsixPublisherId'
    # Validation
    'Test-MsixManifest'
    'Test-MsixPsfConfig'
    'Assert-MsixProcessSuccess'
    # Manifest helpers
    'Get-MsixManifest'
    'New-MsixManifestDocument'
    'Select-MsixManifestNode'
    'Select-MsixManifestNodes'
    'Save-MsixManifest'
    'Add-MsixManifestNamespace'
    'Get-MsixManifestApplications'
    'Get-MsixManifestApplication'
    'Get-MsixManifestNamespaceUri'
    'Set-MsixManifestMaxVersionTested'
    'Set-MsixManifestPublisher'
    'Set-MsixManifestIdentity'
    'Invoke-MsixManifestTransform'
    # PSF builders
    'New-MsixPsfFileRedirectionConfig'
    'New-MsixPsfRegLegacyConfig'
    'New-MsixPsfEnvVarConfig'
    'New-MsixPsfTraceConfig'
    'New-MsixPsfArgument'
    'New-MsixPsfStartScriptConfig'
    'New-MsixPsfDynamicLibraryConfig'
    'New-MsixPsfWaitForDebuggerConfig'
    'New-MsixPsfConfig'
    'Add-MsixPsfV2'
    # Investigation
    'Invoke-MsixInvestigation'
    'Get-MsixCompatibilityReport'
    'Get-MsixStaticAnalysis'
    'Invoke-MsixProcMonCapture'
    'Get-MsixProcMonFailure'
    'Add-MsixDiagnosticTrace'
    'Resolve-MsixProcMonPath'
    # AppData / out-of-package
    'Get-MsixContainerAppData'
    'Get-MsixOrphanedAppData'
    'Copy-MsixHostAppDataIntoPackage'
    'Invoke-MsixContainerCommand'
    'Get-MsixPackageStorageSummary'
    # Accelerators
    'Import-MsixAccelerator'
    'Invoke-MsixAccelerator'
    'ConvertFrom-MsixYamlAccelerator'
    # PSF binaries / Procmon / SDK / Runtime
    'Install-MsixPsfBinary'
    'Update-MsixPsfBinary'
    'Get-MsixPsfBinariesVersion'
    'Install-MsixProcMon'
    'Update-MsixProcMon'
    'Install-MsixSdkTool'
    'Update-MsixSdkTool'
    'Get-MsixSdkToolsVersion'
    'Install-MsixAppRuntime'
    'Update-MsixAppRuntime'
    'Get-MsixAppRuntimeVersion'
    'Get-MsixRequiredAppRuntimeChannel'
    'Install-MsixDebugView'
    'Update-MsixDebugView'
    'Get-MsixDebugViewVersion'
    'Initialize-MsixToolchain'
    # Debug session
    'Start-MsixDebugSession'
    'Get-MsixDebugRecommendation'
    'New-MsixSandboxConfig'
    'Start-MsixSandbox'
    'Resolve-MsixDebugViewPath'
    'ConvertTo-MsixReportHtml'
    # Self-signed certificate flow for debug / sandbox
    'New-MsixSelfSignedCertificate'
    'Test-MsixSignature'
    'Invoke-MsixSelfSignAndDebug'
    # App Attach
    'New-MsixAppAttachImage'
    'Mount-MsixAppAttachImage'
    'Dismount-MsixAppAttachImage'
    'Test-MsixAppAttachImage'
    'Resolve-MsixMgrPath'
    # App Isolation (Win32)
    'Add-MsixAppIsolation'
    'Remove-MsixAppIsolation'
    'Get-MsixIsolationCapability'
    # Limitations / know-your-installer
    'Get-MsixLimitation'
    'Test-MsixAgainstLimitation'
    # Trace Fixup parser
    'ConvertFrom-MsixTraceLine'
    'Get-MsixTraceOutput'
    'Get-MsixTraceFailure'
    'ConvertFrom-MsixTraceToFinding'
    # msixmgr binary management
    'Install-MsixMgr'
    'Update-MsixMgr'
    'Get-MsixMgrVersion'
    # Standard scripts (PSADT-flavoured)
    'Get-MsixStandardScript'
    'New-MsixStandardScript'
    'Set-MsixScriptSignature'
    'Add-MsixStandardScript'
    # MFR (Modern File Redirection -- TMurgent fork)
    'New-MsixMfrTraditionalRule'
    'New-MsixMfrLocalRule'
    'New-MsixPsfMfrConfig'
    'Get-MsixMfrKnownFolder'
    # VC++ runtime detection / bundling
    'Get-MsixVcRuntimeReference'
    'Add-MsixVcRuntimeBundle'
    # TMEditX-style heuristics
    'Get-MsixKnownCapability'
    'Add-MsixCapability'
    'Get-MsixUninstallerCandidate'
    'Get-MsixUninstallRegistryEntry'
    'Remove-MsixUninstallerArtifact'
    'Get-MsixRunKeyEntry'
    'Get-MsixShellContextMenuEntry'
    'Get-MsixComServerEntry'
    'Get-MsixAliasCandidate'
    'Add-MsixSplashScreen'
    'Update-MsixPackageVersion'
    'Get-MsixHeuristicFinding'
    'Invoke-MsixAutoFix'
    'Invoke-MsixAutoFixFromAnalysis'
    # Auto-detection scanners (v0.11)
    'Get-MsixFontCandidate'
    'Get-MsixDesktopShortcutCandidate'
    'Get-MsixCapabilityHint'
    'Get-MsixNestedPackageCandidate'
    # Package compare
    'Compare-MsixPackage'
    # Manifest-only fixers (alternatives to PSF)
    'Set-MsixFileSystemWriteVirtualization'
    'Set-MsixRegistryWriteVirtualization'
    'Set-MsixInstalledLocationVirtualization'
    'Add-MsixLoaderSearchPathOverride'
    'Add-MsixFirewallRule'
    'Add-MsixProtocolHandler'
    'Add-MsixFileTypeAssociation'
    'Add-MsixStartupTask'
    'Add-MsixFontExtension'
    'Set-MsixBrandMetadata'
    'Add-MsixShellVerbExtension'
    'Add-MsixComServerExtension'
    'Remove-MsixDesktopShortcut'
    # Signing
    'Invoke-MsixSigning'
    # Context menus
    'Add-MsixLegacyContextMenu'
    'Add-MsixFileExplorerContextMenu'
    # Pipeline
    'Invoke-MsixPipeline'
    # Public package ops (defined in MSIX.Functions.ps1)
    'Get-MsixInfo'
    'Invoke-MsixCommand'
    'Update-MsixSigner'
    'New-MsixPsfJson'
    'Add-MsixAlias'
    'Remove-MsixStartMenuEntry'
    'Add-MsixStartMenuFolder'
) -Alias @(
    'Invoke-MsixCmd'
    'start-MsixCmd'
    'add-MsixPsf'
    'Get-PublisherIdFromPublisher'
    'Get-MsixDebugRecommendations'
    'Get-MsixFontCandidates'
    'Get-MsixDesktopShortcutCandidates'
    'Remove-MsixDesktopShortcuts'
    'Get-MsixCapabilityHints'
    'Get-MsixNestedPackageCandidates'
    'Get-MsixKnownCapabilities'
    'Get-MsixUninstallerCandidates'
    'Get-MsixUninstallRegistryEntries'
    'Remove-MsixUninstallerArtifacts'
    'Get-MsixRunKeyEntries'
    'Get-MsixShellContextMenuEntries'
    'Get-MsixComServerEntries'
    'Get-MsixAliasCandidates'
    'Get-MsixHeuristicFindings'
    'Get-MsixProcMonFailures'
    'Get-MsixLimitations'
    'Test-MsixAgainstLimitations'
    'Get-MsixMfrKnownFolders'
    'New-MsixPsfArguments'
    'Install-MsixPsfBinaries'
    'Update-MsixPsfBinaries'
    'Install-MsixSdkTools'
    'Update-MsixSdkTools'
    'Get-MsixStandardScripts'
    'Get-MsixTraceFailures'
    'ConvertFrom-MsixTraceToFindings'
    'Get-MsixVcRuntimeReferences'
    'Get-MsixIsolationCapabilities'
)
#endregion
