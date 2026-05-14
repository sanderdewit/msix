BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psm1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'MFR builders' -Tag 'MFR' {

    Context 'Get-MsixMfrKnownFolder' {
        It 'Mode Traditional contains ProgramFilesX64' {
            (Get-MsixMfrKnownFolder -Mode Traditional) | Should -Contain 'ProgramFilesX64'
        }
        It 'Mode Local contains ThisPCDesktopFolder' {
            (Get-MsixMfrKnownFolder -Mode Local) | Should -Contain 'ThisPCDesktopFolder'
        }
        It 'Mode Both returns combined object with COW options' {
            $r = Get-MsixMfrKnownFolder
            $r.COW | Should -Contain 'enablePe'
            $r.COW | Should -Contain 'disableAll'
        }
    }

    Context 'New-MsixMfrTraditionalRule' {
        It 'Validates KnownFolder against known list' {
            { New-MsixMfrTraditionalRule -KnownFolder 'NotAFolder' -RelativePath 'x' -Patterns 'y' } |
                Should -Throw '*Unknown traditional folder*'
        }
        It 'Returns hashtable with knownFolder/relativePath/patterns' {
            $r = New-MsixMfrTraditionalRule -KnownFolder 'ProgramFilesX64' -RelativePath 'App' -Patterns '.*\.log'
            $r.knownFolder  | Should -Be 'ProgramFilesX64'
            $r.relativePath | Should -Be 'App'
            $r.patterns[0]  | Should -Be '.*\.log'
        }
        It 'Honours -Cow' {
            $r = New-MsixMfrTraditionalRule -KnownFolder 'ProgramFilesX64' -RelativePath 'A' -Patterns '.*' -Cow enablePe
            $r.copyOnWrite | Should -Be 'enablePe'
        }
        It 'Honours -IlvAware' {
            $r = New-MsixMfrTraditionalRule -KnownFolder 'ProgramFilesX64' -RelativePath 'A' -Patterns '.*' -IlvAware $true
            $r.ilvAware | Should -BeTrue
        }
    }

    Context 'New-MsixMfrLocalRule' {
        It 'Rejects a Traditional folder name' {
            { New-MsixMfrLocalRule -KnownFolder 'ProgramFilesX64' -RelativePath 'x' -Patterns 'y' } |
                Should -Throw '*Unknown local folder*'
        }
        It 'Accepts ThisPCDesktopFolder' {
            $r = New-MsixMfrLocalRule -KnownFolder 'ThisPCDesktopFolder' -RelativePath 'A' -Patterns '.*'
            $r.knownFolder | Should -Be 'ThisPCDesktopFolder'
        }
    }

    Context 'New-MsixPsfMfrConfig' {
        It 'Returns MFRFixup.dll' {
            $rule = New-MsixMfrTraditionalRule -KnownFolder 'AppData' -RelativePath 'A' -Patterns '.*'
            $cfg  = New-MsixPsfMfrConfig -TraditionalRules @($rule)
            $cfg.dll | Should -Be 'MFRFixup.dll'
        }
        It 'Splits Traditional and Local into separate paths' {
            $t = New-MsixMfrTraditionalRule -KnownFolder 'AppData' -RelativePath 'a' -Patterns '.*'
            $l = New-MsixMfrLocalRule       -KnownFolder 'Personal' -RelativePath 'b' -Patterns '.*'
            $cfg = New-MsixPsfMfrConfig -TraditionalRules @($t) -LocalRules @($l)
            $cfg.config.redirectedPaths.traditionalRedirectedPaths | Should -Not -BeNullOrEmpty
            $cfg.config.redirectedPaths.localRedirectedPaths       | Should -Not -BeNullOrEmpty
        }
        It 'Honours -GlobalIlvAware and -GlobalCow' {
            $cfg = New-MsixPsfMfrConfig -GlobalIlvAware $true -GlobalCow disableAll
            $cfg.config.ilvAware    | Should -BeTrue
            $cfg.config.copyOnWrite | Should -Be 'disableAll'
        }
    }
}
