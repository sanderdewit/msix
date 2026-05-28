BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'RegLegacyFixups types (v0.9)' -Tag 'RegLegacy' {

    It 'ModifyKeyAccess requires -Access' {
        { New-MsixPsfRegLegacyConfig -Type ModifyKeyAccess -Hive HKCU -Patterns 'X' } |
            Should -Throw '*Access*'
    }

    It 'ModifyKeyAccess includes access in remediation' {
        $r = New-MsixPsfRegLegacyConfig -Type ModifyKeyAccess -Hive HKCU `
                -Access Full2MaxAllowed -Patterns 'SOFTWARE\App\*'
        $r.config.type                 | Should -Be 'ModifyKeyAccess'
        $r.config.remediation[0].hive  | Should -Be 'HKCU'
        $r.config.remediation[0].access| Should -Be 'Full2MaxAllowed'
    }

    It 'FakeDelete omits access field' {
        $r = New-MsixPsfRegLegacyConfig -Type FakeDelete -Hive HKLM -Patterns 'X'
        $r.config.type                  | Should -Be 'FakeDelete'
        $r.config.remediation[0].Keys   | Should -Not -Contain 'access'
        $r.config.remediation[0].patterns[0] | Should -Be 'X'
    }

    It 'DeletionMarker passes through' {
        $r = New-MsixPsfRegLegacyConfig -Type DeletionMarker -Hive HKLM -Patterns 'X'
        $r.config.type | Should -Be 'DeletionMarker'
    }

    It 'Hklm2Hkcu passes through' {
        $r = New-MsixPsfRegLegacyConfig -Type Hklm2Hkcu -Hive HKLM -Patterns 'SOFTWARE\App\*'
        $r.config.type | Should -Be 'Hklm2Hkcu'
    }

    It 'Validates Type enum' {
        { New-MsixPsfRegLegacyConfig -Type 'Bogus' -Hive HKCU -Patterns 'X' } | Should -Throw
    }
}
