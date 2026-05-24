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

Describe 'Atomic pack-sign-move enforced in heuristic mutators (issues #34 + #37)' -Tag 'WhatIf' {
    # After issue #37 the atomic pack-sign-move pattern lives in ONE place:
    # _MsixMutatePackage in MSIX.Pipeline.ps1. Two-part guard:
    #   1. The helper itself carries the atomic pattern (so it cannot be
    #      regressed without also rewriting the helper).
    #   2. Every heuristic mutator delegates to that helper (so no mutator
    #      can sneak around it via its own pack/sign sequence).
    BeforeAll {
        # Issue #38: heuristics split into three files. The mutators live in
        # MSIX.PackageMutators.ps1 now.
        $script:HeuristicsSrc = Get-Content (Join-Path $PSScriptRoot '..\MSIX.PackageMutators.ps1') -Raw
        $script:PipelineSrc   = Get-Content (Join-Path $PSScriptRoot '..\MSIX.Pipeline.ps1')        -Raw
    }

    It '_MsixMutatePackage in MSIX.Pipeline.ps1 carries the atomic scratch + sign + Move pattern' {
        $idx = $script:PipelineSrc.IndexOf('function _MsixMutatePackage {')
        $idx | Should -BeGreaterThan -1
        $window = $script:PipelineSrc.Substring($idx)
        # Pack to scratch
        $window | Should -Match '\$scratch\s*=\s*Join-Path'
        # Sign at scratch (when SkipSigning is false)
        $window | Should -Match 'Invoke-MsixSigning\s+-PackagePath\s+\$scratch'
        # Move to $target on success
        $window | Should -Match 'Move-Item\s+-LiteralPath\s+\$scratch\s+-Destination\s+\$target\s+-Force'
        # UnsignedOutputPath recovery path on signing failure
        $window | Should -Match 'UnsignedOutputPath'
    }

    $cases = @(
        'Add-MsixCapability',
        'Remove-MsixUninstallerArtifact',
        'Remove-MsixUpdaterArtifact',
        'Remove-MsixShellRegistryArtifact'
    ) | ForEach-Object { @{ Fn = $_ } }

    It '<Fn> delegates to _MsixMutatePackage AND exposes -UnsignedOutputPath' -TestCases $cases {
        param($Fn)
        $idx = $script:HeuristicsSrc.IndexOf("function $Fn {")
        $idx | Should -BeGreaterThan -1
        $window = $script:HeuristicsSrc.Substring($idx, [Math]::Min(15000, $script:HeuristicsSrc.Length - $idx))
        $nextFn = $window.IndexOf("`nfunction ", 10)
        if ($nextFn -gt 0) { $window = $window.Substring(0, $nextFn) }

        # The mutator must route its pack/sign through the helper...
        $window | Should -Match '_MsixMutatePackage\s'
        # ...and surface -UnsignedOutputPath to callers for failure recovery.
        $window | Should -Match 'UnsignedOutputPath'
        # And it must NOT redefine its own scratch-pack sequence (that would
        # bypass the helper's atomic semantics).
        $window | Should -Not -Match 'Invoke-MsixSigning\s+-PackagePath\s+\$scratch'
    }
}
