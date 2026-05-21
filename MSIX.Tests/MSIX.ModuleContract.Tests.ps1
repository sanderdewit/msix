BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Module contract' -Tag 'ModuleContract' {
    It 'Imports through the manifest with command versions' {
        $module = Get-Module MSIX

        # The manifest is the source of truth — read its version once and
        # compare everything else against it. Pinning a literal version
        # string here forces a test edit on every release bump (it did
        # exactly that at 0.70.0 -> 0.70.2). The functional invariants
        # the test cares about are:
        #   - The module's runtime version matches the .psd1 manifest
        #   - Exported cmdlets carry the same module version
        $manifestPath = Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')
        $manifestData = Import-PowerShellDataFile -Path $manifestPath
        $expectedVersion = $manifestData.ModuleVersion

        # Sanity guard: ensure the version is well-formed (e.g. '0.70.2')
        # so a broken/missing manifest never silently passes the test.
        $expectedVersion | Should -Match '^\d+\.\d+\.\d+(\.\d+)?$'

        $module.Version.ToString() | Should -Be $expectedVersion
        (Get-Command Add-MsixFirewallRule -Module MSIX).Version.ToString() | Should -Be $expectedVersion
    }

    It 'Exports compatibility aliases from the packaged module' {
        $aliases = Get-Command -Module MSIX -CommandType Alias

        $aliases.Name | Should -Contain 'Install-MsixPsfBinaries'
        $aliases.Name | Should -Contain 'New-MsixPsfArguments'
        $aliases.Name | Should -Contain 'Get-MsixProcMonFailures'
    }

    It 'Exports plural manifest application reader as a real function' {
        $cmd = Get-Command Get-MsixManifestApplications -Module MSIX

        $cmd.CommandType | Should -Be 'Function'
    }
}
