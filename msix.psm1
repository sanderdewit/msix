#region --- Transport security ----------------------------------------------
# SECURITY: Windows PowerShell 5.1 / .NET Framework 4.x frequently default
# ServicePointManager.SecurityProtocol to 'Ssl3, Tls' (TLS 1.0). Every
# toolchain download relies on this process-wide setting, so raise the floor
# to TLS 1.2+ once at import, before any download runs. Tls13 is guarded
# because the enum value is absent on older .NET 4.x builds.
try {
    $script:MsixTlsFloor = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    if ([enum]::IsDefined([Net.SecurityProtocolType], 'Tls13')) {
        $script:MsixTlsFloor = $script:MsixTlsFloor -bor [Net.SecurityProtocolType]::Tls13
    }
    [Net.ServicePointManager]::SecurityProtocol = $script:MsixTlsFloor
} catch {
    Write-Warning "MSIX: could not raise the TLS security protocol floor: $($_.Exception.Message)"
}
#endregion


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
. "$PSScriptRoot\MSIX.SparseShell.ps1"
. "$PSScriptRoot\MSIX.MFR.ps1"
. "$PSScriptRoot\MSIX.VcRuntime.ps1"
. "$PSScriptRoot\MSIX.Detection.ps1"
. "$PSScriptRoot\MSIX.ManifestExtensions.ps1"
. "$PSScriptRoot\MSIX.OfflineRegistry.ps1"
# Heuristic family — split from the original MSIX.Heuristics.ps1 in issue #38.
# Order matters: PackageMutators uses $script:KnownCapabilities + the
# offline-registry helpers from Scanners; AutoFix invokes both.
. "$PSScriptRoot\MSIX.Scanners.ps1"
. "$PSScriptRoot\MSIX.PackageMutators.ps1"
. "$PSScriptRoot\MSIX.AutoFix.ps1"
. "$PSScriptRoot\MSIX.Compare.ps1"
. "$PSScriptRoot\MSIX.Functions.ps1"
. "$PSScriptRoot\MSIX.Playbooks.ps1"
. "$PSScriptRoot\MSIX.Sarif.ps1"
. "$PSScriptRoot\MSIX.Evidence.ps1"
. "$PSScriptRoot\MSIX.TraceDelta.ps1"
. "$PSScriptRoot\MSIX.RemediationPlan.ps1"
. "$PSScriptRoot\MSIX.AutoFixLoop.ps1"
. "$PSScriptRoot\MSIX.Distribution.ps1"
. "$PSScriptRoot\MSIX.Bundle.ps1"
. "$PSScriptRoot\MSIX.RuntimeTest.ps1"
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
# Exports (issue #41 -- single source of truth)
# --------------------------------------------------
# msix.psd1 is the authoritative list of public commands. 'FunctionsToExport'
# and 'AliasesToExport' in that manifest control what consumers actually see.
# Here we re-export EVERY function and alias defined in the dot-sourced files;
# the manifest then filters that surface to the documented public API.
#
# Adding a public cmdlet: append the function name to msix.psd1's
# FunctionsToExport array. No psm1 edit required.
# Adding a back-compat alias: define it above (Set-Alias) AND append the alias
# name to msix.psd1's AliasesToExport array. The module-contract test in
# MSIX.Tests/MSIX.ModuleContract.Tests.ps1 asserts the two lists agree.
Export-ModuleMember -Function * -Alias *
#endregion
