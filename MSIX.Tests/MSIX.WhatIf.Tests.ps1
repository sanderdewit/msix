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
        # Heuristic mutators (issue #34 — must keep -UnsignedOutputPath so the
        # atomic pack-sign-move can hand back the unsigned scratch on signing
        # failure instead of wrecking the user's signed package).
        'Add-MsixCapability'
        'Remove-MsixUninstallerArtifact'
        'Remove-MsixUpdaterArtifact'
        'Remove-MsixShellRegistryArtifact'
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

Describe 'Atomic pack-sign-move enforced in heuristic mutators (issue #34)' -Tag 'WhatIf' {
    # Source-level guard: every heuristic mutator must follow the
    # "pack to scratch -> sign scratch -> Move-Item on success" pattern.
    # Without this, a signing failure leaves the user with an unsigned
    # modified copy of their signed package.
    BeforeDiscovery {
        $script:HeuristicsSrc = Get-Content (Join-Path $PSScriptRoot '..\MSIX.Heuristics.ps1') -Raw
    }
    BeforeAll {
        $script:HeuristicsSrc = Get-Content (Join-Path $PSScriptRoot '..\MSIX.Heuristics.ps1') -Raw
    }

    $cases = @(
        'Add-MsixCapability',
        'Remove-MsixUninstallerArtifact',
        'Remove-MsixUpdaterArtifact',
        'Remove-MsixShellRegistryArtifact'
    ) | ForEach-Object { @{ Fn = $_ } }

    It 'carries scratch + atomic move + UnsignedOutputPath for <Fn>' -TestCases $cases {
        param($Fn)
        $idx = $script:HeuristicsSrc.IndexOf("function $Fn {")
        $idx | Should -BeGreaterThan -1
        $window = $script:HeuristicsSrc.Substring($idx, [Math]::Min(15000, $script:HeuristicsSrc.Length - $idx))
        # Cuts off at the next top-level `function ` so we don't accidentally
        # match scaffolding from the following function in the file.
        $nextFn = $window.IndexOf("`nfunction ", 10)
        if ($nextFn -gt 0) { $window = $window.Substring(0, $nextFn) }

        # The package is packed to a scratch path...
        $window | Should -Match '\$scratch\s*=\s*Join-Path'
        # ...signed at the scratch (when SkipSigning is false)...
        $window | Should -Match 'Invoke-MsixSigning\s+-PackagePath\s+\$scratch'
        # ...and only moved to $target on success.
        $window | Should -Match 'Move-Item\s+-LiteralPath\s+\$scratch\s+-Destination\s+\$target\s+-Force'
        # And the function exposes -UnsignedOutputPath for failure recovery.
        $window | Should -Match 'UnsignedOutputPath'
    }
}
