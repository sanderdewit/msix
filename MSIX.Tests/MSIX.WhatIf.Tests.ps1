BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe '-WhatIf semantics on manifest mutators' -Tag 'WhatIf' {

    It 'Add-MsixLegacyContextMenu supports -WhatIf' {
        $cmd = Get-Command Add-MsixLegacyContextMenu
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }

    It 'Add-MsixFileExplorerContextMenu supports -WhatIf' {
        $cmd = Get-Command Add-MsixFileExplorerContextMenu
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }

    It 'Set-MsixFileSystemWriteVirtualization supports -WhatIf' {
        $cmd = Get-Command Set-MsixFileSystemWriteVirtualization
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }

    It '_MsixMutateManifest exposes the -WhatIfPreview switch (private helper)' {
        $hasIt = (Get-Module MSIX).Invoke({
            $cmd = Get-Command _MsixMutateManifest -Module MSIX -ErrorAction SilentlyContinue
            if ($null -eq $cmd) { return $false }
            $cmd.Parameters.ContainsKey('WhatIfPreview')
        })
        $hasIt | Should -BeTrue
    }

    It 'Invoke-MsixPipeline supports -WhatIf' {
        $cmd = Get-Command Invoke-MsixPipeline
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue
    }
}

Describe '-UnsignedOutputPath forwarded by every mutator' -Tag 'WhatIf' {
    $mutators = @(
        'Add-MsixLegacyContextMenu'
        'Add-MsixFileExplorerContextMenu'
        'Set-MsixFileSystemWriteVirtualization'
        'Set-MsixRegistryWriteVirtualization'
        'Add-MsixLoaderSearchPathOverride'
        'Add-MsixFirewallRule'
        'Add-MsixProtocolHandler'
        'Add-MsixFileTypeAssociation'
        'Add-MsixStartupTask'
        'Add-MsixFontExtension'
        'Set-MsixBrandMetadata'
        'Add-MsixShellVerbExtension'
        'Add-MsixComServerExtension'
    )
    foreach ($name in $mutators) {
        It "$name accepts -UnsignedOutputPath" -TestCases @(@{ Name = $name }) {
            param($Name)
            $cmd = Get-Command $Name -Module MSIX -ErrorAction SilentlyContinue
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.Parameters.ContainsKey('UnsignedOutputPath') | Should -BeTrue
        }
    }
}
