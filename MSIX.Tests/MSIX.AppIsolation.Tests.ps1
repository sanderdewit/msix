BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psm1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Win32 App Isolation' -Tag 'AppIsolation' {

    It 'Get-MsixIsolationCapabilities returns a list with promptForAccess' {
        Get-MsixIsolationCapabilities | Should -Contain 'isolatedWin32-promptForAccess'
    }

    It 'All capabilities follow isolatedWin32- naming' {
        Get-MsixIsolationCapabilities | ForEach-Object {
            $_ | Should -Match '^isolatedWin32-'
        }
    }
}
