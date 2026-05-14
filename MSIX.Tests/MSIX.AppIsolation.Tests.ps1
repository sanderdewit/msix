BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psm1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Win32 App Isolation' -Tag 'AppIsolation' {

    It 'Get-MsixIsolationCapability returns a list with promptForAccess' {
        Get-MsixIsolationCapability | Should -Contain 'isolatedWin32-promptForAccess'
    }

    It 'All capabilities follow isolatedWin32- naming' {
        Get-MsixIsolationCapability | ForEach-Object {
            $_ | Should -Match '^isolatedWin32-'
        }
    }
}
