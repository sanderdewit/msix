BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
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
        $manifestPath = Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')
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

Describe 'Export source-of-truth contract (issue #41)' -Tag 'ModuleContract' {
    # msix.psd1's FunctionsToExport / AliasesToExport is the authoritative
    # list. MSIX.psm1 just does `Export-ModuleMember -Function * -Alias *`
    # so the manifest is the gate. These tests assert the two are in
    # lockstep so a new public function declared in the manifest must
    # also exist in the module's loaded surface, and vice versa.

    BeforeAll {
        $script:Manifest = Import-PowerShellDataFile -Path (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1'))
        $script:Loaded   = Get-Command -Module MSIX
        $script:LoadedFunctions = @($script:Loaded | Where-Object { $_.CommandType -eq 'Function' } | Select-Object -ExpandProperty Name)
        $script:LoadedAliases   = @($script:Loaded | Where-Object { $_.CommandType -eq 'Alias'    } | Select-Object -ExpandProperty Name)
    }

    It 'FunctionsToExport in psd1 lists every function the module actually exports' {
        $declared = @($script:Manifest.FunctionsToExport)
        $missingInManifest = @($script:LoadedFunctions | Where-Object { $_ -notin $declared })
        $missingInManifest.Count | Should -Be 0 -Because (
            'Functions exported at runtime but NOT in psd1 FunctionsToExport: ' +
            ($missingInManifest -join ', '))
    }

    It 'Every name in psd1 FunctionsToExport resolves to a real loaded function' {
        $declared = @($script:Manifest.FunctionsToExport)
        $undefined = @($declared | Where-Object { $_ -notin $script:LoadedFunctions })
        $undefined.Count | Should -Be 0 -Because (
            'Declared in psd1 FunctionsToExport but no such function loaded: ' +
            ($undefined -join ', '))
    }

    It 'AliasesToExport in psd1 lists every alias the module actually exports' {
        $declared = @($script:Manifest.AliasesToExport)
        $missingInManifest = @($script:LoadedAliases | Where-Object { $_ -notin $declared })
        $missingInManifest.Count | Should -Be 0 -Because (
            'Aliases exported at runtime but NOT in psd1 AliasesToExport: ' +
            ($missingInManifest -join ', '))
    }

    It 'Every name in psd1 AliasesToExport resolves to a real loaded alias' {
        $declared = @($script:Manifest.AliasesToExport)
        $undefined = @($declared | Where-Object { $_ -notin $script:LoadedAliases })
        $undefined.Count | Should -Be 0 -Because (
            'Declared in psd1 AliasesToExport but no such alias loaded: ' +
            ($undefined -join ', '))
    }

    It 'MSIX.psm1 uses wildcard Export-ModuleMember (no hand-maintained explicit list)' {
        # Source-level guard so the explicit list never re-appears via a
        # well-intentioned PR. The wildcard form is what makes the
        # manifest the source of truth.
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\msix.psm1')) -Raw
        $src | Should -Match 'Export-ModuleMember\s+-Function\s+\*\s+-Alias\s+\*'
        # And the old explicit-array form must NOT appear.
        $src | Should -Not -Match 'Export-ModuleMember\s+-Function\s+@\('
    }
}
