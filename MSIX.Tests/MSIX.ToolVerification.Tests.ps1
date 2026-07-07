BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Regression coverage for #54 — Get-MsixToolsRoot must Authenticode-verify the
# resolved signtool/MakeAppx (fail-closed) before trusting/executing them, with
# an MSIX_SKIP_TOOL_VERIFICATION escape hatch for offline agents.

Describe '_MsixSetVerifiedToolsRoot (#54)' -Tag 'Toolchain', 'Security' {

    AfterEach {
        # Never leak the bypass var or a cached root between cases.
        Remove-Item Env:\MSIX_SKIP_TOOL_VERIFICATION -ErrorAction SilentlyContinue
        InModuleScope MSIX { $script:ToolsRoot = $null }
    }

    It 'verifies a resolved tool and caches the root on success' {
        $result = InModuleScope MSIX {
            $script:verified = @()
            Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*signtool.exe' -or $LiteralPath -like '*MakeAppx.exe' -or $LiteralPath -like '*makepri.exe' }
            Mock _MsixVerifyAuthenticode { $script:verified += $Path }
            $r = _MsixSetVerifiedToolsRoot -Root 'C:\fake\root'
            [pscustomobject]@{ Returned = $r; Cached = $script:ToolsRoot; VerifiedCount = $script:verified.Count }
        }
        $result.Returned      | Should -Be 'C:\fake\root'
        $result.Cached        | Should -Be 'C:\fake\root'
        $result.VerifiedCount | Should -BeGreaterThan 0
    }

    It 'is fail-closed: a verification failure propagates and the root is NOT cached' {
        InModuleScope MSIX {
            Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*signtool.exe' -or $LiteralPath -like '*MakeAppx.exe' -or $LiteralPath -like '*makepri.exe' }
            Mock _MsixVerifyAuthenticode { throw 'Authenticode verification FAILED (planted binary)' }
            { _MsixSetVerifiedToolsRoot -Root 'C:\evil\root' } | Should -Throw '*Authenticode verification FAILED*'
            $script:ToolsRoot | Should -BeNullOrEmpty
        }
    }

    It 'bypasses verification when MSIX_SKIP_TOOL_VERIFICATION is set (offline escape hatch)' {
        $env:MSIX_SKIP_TOOL_VERIFICATION = '1'
        $result = InModuleScope MSIX {
            $script:verifyCalled = $false
            Mock Test-Path { $true }
            Mock _MsixVerifyAuthenticode { $script:verifyCalled = $true }
            $r = _MsixSetVerifiedToolsRoot -Root 'C:\offline\root'
            [pscustomobject]@{ Returned = $r; Cached = $script:ToolsRoot; VerifyCalled = $script:verifyCalled }
        }
        $result.Returned     | Should -Be 'C:\offline\root'
        $result.Cached       | Should -Be 'C:\offline\root'
        $result.VerifyCalled | Should -BeFalse
    }
}
