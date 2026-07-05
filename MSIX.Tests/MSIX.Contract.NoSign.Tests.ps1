BeforeDiscovery {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    # Discover the signing-capable surface dynamically so a new cmdlet that adds
    # -SkipSigning can never be forgotten here (issue #101). Previously this was
    # a hand-maintained 17-entry list that silently missed Add/Remove-MsixAppIsolation.
    $script:SigningCapable = @(
        Get-Command -Module MSIX -CommandType Function |
            Where-Object { $_.Parameters.ContainsKey('SkipSigning') } |
            ForEach-Object { @{ Name = $_.Name } }
    )
}

BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Cross-cutting CONTRACT sweeps (axis 2 in issue #88) over every cmdlet that
# exposes -SkipSigning. Do NOT split these per-cmdlet — their value is the
# uniformity guarantee across the whole surface.

Describe 'Signing contract: <Name>' -Tag 'NoSign' -ForEach $script:SigningCapable {

    It 'has the -NoSign alias on -SkipSigning' {
        $cmd  = Get-Command -Name $Name -Module MSIX -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
        $skip = $cmd.Parameters['SkipSigning']
        $skip | Should -Not -BeNullOrEmpty
        $skip.Aliases | Should -Contain 'NoSign'
    }

    It 'supports -WhatIf (SupportsShouldProcess)' {
        $cmd = Get-Command -Name $Name -Module MSIX
        $cmd.Parameters.ContainsKey('WhatIf') | Should -BeTrue -Because 'every signing-capable cmdlet mutates a package and must be previewable'
    }
}

Describe 'Signing contract discovery sanity' -Tag 'NoSign' {
    It 'found at least the historical 17 signing-capable cmdlets (discovery is not silently broken)' {
        @(Get-Command -Module MSIX -CommandType Function |
            Where-Object { $_.Parameters.ContainsKey('SkipSigning') }).Count |
            Should -BeGreaterOrEqual 17
    }

    It 'covers Add-MsixAppIsolation and Remove-MsixAppIsolation (the cmdlets the static list missed)' {
        $names = @(Get-Command -Module MSIX -CommandType Function |
            Where-Object { $_.Parameters.ContainsKey('SkipSigning') } |
            ForEach-Object { $_.Name })
        $names | Should -Contain 'Add-MsixAppIsolation'
        $names | Should -Contain 'Remove-MsixAppIsolation'
    }
}
