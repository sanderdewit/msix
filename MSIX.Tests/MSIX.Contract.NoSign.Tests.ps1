BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Cross-cutting CONTRACT sweep (axis 2 in issue #88): every signing-capable
# cmdlet must expose the -NoSign alias on its -SkipSigning switch, so the whole
# surface stays uniform. A new cmdlet that forgets the alias is caught here
# automatically — do NOT split this per-cmdlet.

Describe '-NoSign alias: <Name>' -Tag 'NoSign' -ForEach @(
    @{ Name = 'Add-MsixPsfV2' }
    @{ Name = 'Add-MsixCapability' }
    @{ Name = 'Remove-MsixUninstallerArtifact' }
    @{ Name = 'Add-MsixSplashScreen' }
    @{ Name = 'Update-MsixPackageVersion' }
    @{ Name = 'Add-MsixVcRuntimeBundle' }
    @{ Name = 'Set-MsixFileSystemWriteVirtualization' }
    @{ Name = 'Set-MsixRegistryWriteVirtualization' }
    @{ Name = 'Set-MsixInstalledLocationVirtualization' }
    @{ Name = 'Add-MsixLoaderSearchPathOverride' }
    @{ Name = 'Add-MsixFirewallRule' }
    @{ Name = 'Add-MsixProtocolHandler' }
    @{ Name = 'Add-MsixFileTypeAssociation' }
    @{ Name = 'Add-MsixStartupTask' }
    @{ Name = 'Add-MsixFontExtension' }
    @{ Name = 'Set-MsixBrandMetadata' }
    @{ Name = 'Remove-MsixDesktopShortcut' }
) {
    It 'has -NoSign alias' {
        $cmd = Get-Command -Name $Name -Module MSIX -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
        $skip = $cmd.Parameters['SkipSigning']
        $skip | Should -Not -BeNullOrEmpty
        $skip.Aliases | Should -Contain 'NoSign'
    }
}
