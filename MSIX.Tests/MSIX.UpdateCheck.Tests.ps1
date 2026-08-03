BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# PSGallery update notification
# -----------------------------------------------------------------------------
# The notice is a convenience; Import-Module working is not. These tests pin the
# guarantees that matter: silent in automation, silent when opted out, silent
# when the network is unavailable, and never throwing.
# =============================================================================

Describe 'Update-check gating' -Tag 'UpdateCheck' {

    AfterEach {
        foreach ($v in 'MSIX_NO_UPDATE_CHECK', 'CI', 'GITHUB_ACTIONS', 'TF_BUILD') {
            Remove-Item -Path "Env:\$v" -ErrorAction SilentlyContinue
        }
    }

    It 'is disabled by MSIX_NO_UPDATE_CHECK' {
        $env:MSIX_NO_UPDATE_CHECK = '1'
        InModuleScope MSIX { _MsixShouldCheckForUpdate } | Should -BeFalse
    }

    It 'is disabled in CI' -ForEach @(
        @{ Var = 'CI' }, @{ Var = 'GITHUB_ACTIONS' }, @{ Var = 'TF_BUILD' }
    ) {
        Set-Item -Path "Env:\$Var" -Value 'true'
        InModuleScope MSIX { _MsixShouldCheckForUpdate } | Should -BeFalse
    }
}

Describe 'Update-check failure behaviour' -Tag 'UpdateCheck' {

    It 'returns nothing and does not throw when the endpoint is unreachable' {
        $result = InModuleScope MSIX {
            $script:MsixUpdateCheckUrl = 'https://invalid.invalid.invalid/nope'
            _MsixGetLatestPublishedVersion -TimeoutSec 3
        }
        $result | Should -BeNullOrEmpty
    }

    It 'never throws even when everything underneath fails' {
        # The whole point: an update notice must not be able to fail an import.
        {
            InModuleScope MSIX {
                Mock _MsixShouldCheckForUpdate { throw 'boom' }
                _MsixNotifyIfUpdateAvailable -CurrentVersion ([version]'1.0.0')
            }
        } | Should -Not -Throw
    }
}

Describe 'Update-check notification decision' -Tag 'UpdateCheck' {

    It 'notifies when PSGallery has a newer version' {
        $msg = InModuleScope MSIX {
            Mock _MsixShouldCheckForUpdate { $true }
            Mock _MsixGetLatestPublishedVersion { [version]'9.9.9' }
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*update-check.json' }
            _MsixNotifyIfUpdateAvailable -CurrentVersion ([version]'1.0.0') 6>&1
        }
        ($msg -join ' ') | Should -Match '9\.9\.9'
        ($msg -join ' ') | Should -Match 'Update-Module MSIX'
    }

    It 'stays silent when the installed version is current' {
        $msg = InModuleScope MSIX {
            Mock _MsixShouldCheckForUpdate { $true }
            Mock _MsixGetLatestPublishedVersion { [version]'1.0.0' }
            Mock Test-Path { $false } -ParameterFilter { $LiteralPath -like '*update-check.json' }
            _MsixNotifyIfUpdateAvailable -CurrentVersion ([version]'1.0.0') 6>&1
        }
        $msg | Should -BeNullOrEmpty
    }

    It 'uses the cache instead of the network while it is fresh' {
        $invoked = InModuleScope MSIX {
            $script:netCalls = 0
            Mock _MsixShouldCheckForUpdate { $true }
            Mock _MsixGetLatestPublishedVersion { $script:netCalls++; [version]'9.9.9' }
            Mock Test-Path { $true } -ParameterFilter { $LiteralPath -like '*update-check.json' }
            Mock Get-Content { '{"CheckedAt":"' + (Get-Date).ToString('o') + '","Latest":"9.9.9"}' }
            $null = _MsixNotifyIfUpdateAvailable -CurrentVersion ([version]'1.0.0') 6>&1
            $script:netCalls
        }
        $invoked | Should -Be 0
    }
}
