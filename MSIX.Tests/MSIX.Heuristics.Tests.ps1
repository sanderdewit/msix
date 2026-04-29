BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psm1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Heuristic catalogues (v0.9)' -Tag 'Heuristics' {

    Context 'Get-MsixKnownCapabilities' {
        It 'Returns at least 10 entries' {
            (Get-MsixKnownCapabilities).Count | Should -BeGreaterOrEqual 10
        }
        It 'Tags rescap entries correctly' {
            $rescap = Get-MsixKnownCapabilities | Where-Object Name -eq 'runFullTrust'
            $rescap.Namespace | Should -Be 'rescap'
        }
        It 'Tags standard entries correctly' {
            $std = Get-MsixKnownCapabilities | Where-Object Name -eq 'internetClient'
            $std.Namespace | Should -Be 'standard'
        }
    }

    Context 'Invoke-MsixAutoFix DryRun' {
        It 'Returns DryRun=true and lists planned stages without mutating' {
            # Use a path that need not exist; DryRun shouldn't unpack anything.
            $r = Invoke-MsixAutoFix -PackagePath 'C:\does-not-exist.msix' `
                                    -RemoveUninstallers `
                                    -VersionBumpComponent Build `
                                    -Capabilities runFullTrust `
                                    -DryRun
            $r.DryRun  | Should -BeTrue
            $r.Stages  | Should -Contain 'PrePsf:RemoveUninstallers'
            $r.Stages  | Should -Contain 'PrePsf:BumpVersion'
            $r.Stages  | Should -Contain 'Recommended:AddCapabilities'
        }
        It 'Skips PSF stage when no fixups provided' {
            $r = Invoke-MsixAutoFix -PackagePath 'C:\nope.msix' -RemoveUninstallers -DryRun
            $r.Stages | Should -Not -Contain 'Recommended:InjectPsf'
        }
    }
}
