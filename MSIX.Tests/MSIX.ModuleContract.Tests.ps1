BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Module contract' -Tag 'ModuleContract' {
    It 'Imports through the manifest with command versions' {
        $module = Get-Module MSIX

        $module.Version.ToString() | Should -Be '0.14.0'
        (Get-Command Add-MsixFirewallRule -Module MSIX).Version.ToString() | Should -Be '0.14.0'
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
