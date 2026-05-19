BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Limitations knowledge base' -Tag 'Limitations' {

    It 'Has at least 10 entries' {
        (Get-MsixLimitation).Count | Should -BeGreaterOrEqual 10
    }

    It 'Filters by severity' {
        $blockers = Get-MsixLimitation -Severity blocker
        $blockers | ForEach-Object { $_.Severity | Should -Be 'blocker' }
    }

    It 'Filters by id' {
        $r = Get-MsixLimitation -Id 'no-drivers'
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'blocker'
    }

    It '-ExcludeVendor drops non-msft-docs' {
        $r = Get-MsixLimitation -ExcludeVendor
        $r | ForEach-Object { $_.Source | Should -Be 'msft-docs' }
    }

    It 'Every entry has the required fields' {
        foreach ($e in Get-MsixLimitation) {
            $e.Id          | Should -Not -BeNullOrEmpty
            $e.Title       | Should -Not -BeNullOrEmpty
            $e.Severity    | Should -BeIn @('blocker','medium','low')
            $e.Source      | Should -BeIn @('msft-docs','mixed','vendor')
            $e.Description | Should -Not -BeNullOrEmpty
            $e.Workaround  | Should -Not -BeNullOrEmpty
        }
    }
}
