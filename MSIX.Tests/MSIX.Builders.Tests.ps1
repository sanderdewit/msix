BeforeAll {
    $modulePath = Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')
    Import-Module -Name $modulePath -Force
}

AfterAll {
    Remove-Module MSIX -ErrorAction SilentlyContinue
}

Describe 'PSF builders' -Tag 'Builders' {

    Context 'New-MsixPsfFileRedirectionConfig' {
        It 'Returns FileRedirectionFixup.dll' {
            $r = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'
            $r.dll | Should -Be 'FileRedirectionFixup.dll'
        }
        It 'Defaults to packageRelative' {
            $r = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'
            $r.config.redirectedPaths.packageRelative | Should -Not -BeNullOrEmpty
        }
        It 'Honours -PathType' {
            $r = New-MsixPsfFileRedirectionConfig -Base 'Documents' -Patterns '.*\.csv' -PathType knownFolderRelative
            $r.config.redirectedPaths.knownFolderRelative | Should -Not -BeNullOrEmpty
            $r.config.redirectedPaths.PSObject.Properties.Name | Should -Not -Contain 'packageRelative'
        }
        It 'Wraps single Patterns into an array' {
            $r = New-MsixPsfFileRedirectionConfig -Base 'x' -Patterns 'one'
            # Bypass pipeline unwrapping with comma operator
            ,($r.config.redirectedPaths.packageRelative[0].patterns) -is [array] | Should -BeTrue
        }
    }

    Context 'New-MsixPsfRegLegacyConfig' {
        It 'Sets type=ModifyKeyAccess' {
            $r = New-MsixPsfRegLegacyConfig -Hive HKCU -Access RW2R -Patterns 'SOFTWARE\App\*'
            $r.config.type | Should -Be 'ModifyKeyAccess'
        }
        It 'Validates Hive enum' {
            { New-MsixPsfRegLegacyConfig -Hive 'HKZZ' -Access RW2R -Patterns 'X' } | Should -Throw
        }
        It 'Validates Access enum' {
            { New-MsixPsfRegLegacyConfig -Hive HKCU -Access 'NOPE' -Patterns 'X' } | Should -Throw
        }
    }

    Context 'New-MsixPsfEnvVarConfig' {
        It 'Returns EnvVarFixup.dll with envVars hashtable' {
            $r = New-MsixPsfEnvVarConfig -Variables @{ X = '1'; Y = 'two' }
            $r.dll | Should -Be 'EnvVarFixup.dll'
            $r.config.envVars.X | Should -Be '1'
            $r.config.envVars.Y | Should -Be 'two'
        }
    }

    Context 'New-MsixPsfTraceConfig' {
        It 'Has filesystem + registry levels' {
            $r = New-MsixPsfTraceConfig -FilesystemLevel allFailures -RegistryLevel ignore
            $r.config.traceLevels.filesystem | Should -Be 'allFailures'
            $r.config.traceLevels.registry   | Should -Be 'ignore'
        }
    }

    Context 'New-MsixPsfArgument' {
        It 'Returns app id and arguments' {
            $r = New-MsixPsfArgument -AppId 'App' -Arguments '/silent' -WorkingDirectory 'app/'
            $r.id | Should -Be 'App'
            $r.arguments | Should -Be '/silent'
            $r.workingDirectory | Should -Be 'app/'
        }
        It 'Omits empty fields' {
            $r = New-MsixPsfArgument -AppId 'App'
            $r.ContainsKey('arguments')        | Should -BeFalse
            $r.ContainsKey('workingDirectory') | Should -BeFalse
        }
    }

    Context 'New-MsixPsfStartScriptConfig' {
        It 'Builds startScript by default' {
            $r = New-MsixPsfStartScriptConfig -AppId 'App' -ScriptPath 's.ps1' -RunOnce -WaitForScriptToFinish
            $r.kind | Should -Be 'startScript'
            $r.appId | Should -Be 'App'
            $r.block.runOnce | Should -BeTrue
            $r.block.waitForScriptToFinish | Should -BeTrue
        }
        It 'Switches to endScript when -EndScript' {
            $r = New-MsixPsfStartScriptConfig -AppId 'App' -ScriptPath 's.ps1' -EndScript
            $r.kind | Should -Be 'endScript'
        }
    }
}


Describe 'PSF builders: New-MsixPsfDynamicLibraryConfig / New-MsixPsfWaitForDebuggerConfig' -Tag 'Builders' {

    Context 'New-MsixPsfDynamicLibraryConfig' {
        It 'Returns DynamicLibraryFixup.dll' {
            $r = New-MsixPsfDynamicLibraryConfig -Mappings @(
                @{ name='liba.dll'; filepath='VFS/ProgramFilesX64/App/lib/liba.dll' }
            )
            $r.dll | Should -Be 'DynamicLibraryFixup.dll'
        }
        It 'Throws on missing fields' {
            { New-MsixPsfDynamicLibraryConfig -Mappings @(@{ name='liba.dll' }) } |
                Should -Throw '*filepath*'
            { New-MsixPsfDynamicLibraryConfig -Mappings @(@{ filepath='x' }) } |
                Should -Throw '*name*'
        }
        It 'Preserves order in relativePaths' {
            $r = New-MsixPsfDynamicLibraryConfig -Mappings @(
                @{ name='a.dll'; filepath='lib/a.dll' }
                @{ name='b.dll'; filepath='lib/b.dll' }
            )
            $r.config.relativePaths.Count | Should -Be 2
            $r.config.relativePaths[0].name | Should -Be 'a.dll'
        }
    }

    Context 'New-MsixPsfWaitForDebuggerConfig' {
        It 'Returns WaitForDebuggerFixup.dll' {
            (New-MsixPsfWaitForDebuggerConfig).dll | Should -Be 'WaitForDebuggerFixup.dll'
        }
        It 'Includes processes when given' {
            $r = New-MsixPsfWaitForDebuggerConfig -Processes 'app','launcher'
            $r.config.processes.Count | Should -Be 2
            $r.config.processes[0].executable | Should -Be 'app'
        }
        It 'Empty config when no processes' {
            $r = New-MsixPsfWaitForDebuggerConfig
            $r.config.Keys | Should -Not -Contain 'processes'
        }
    }
}
