BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Parameter validation rejects malformed input' -Tag 'Validation' {

    Context 'Add-MsixLegacyContextMenu -Clsid' {
        It 'Accepts a well-formed CLSID' {
            $cmd = Get-Command Add-MsixLegacyContextMenu
            $clsidParam = $cmd.Parameters['Clsid']
            $vp = $clsidParam.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] } |
                Select-Object -First 1
            $vp | Should -Not -BeNullOrEmpty
            '12345678-1234-1234-1234-1234567890ab'   | Should -Match $vp.RegexPattern
            '{12345678-1234-1234-1234-1234567890ab}' | Should -Match $vp.RegexPattern
        }
        It 'Rejects a non-GUID' {
            $cmd = Get-Command Add-MsixLegacyContextMenu
            $clsidParam = $cmd.Parameters['Clsid']
            $vp = $clsidParam.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] } |
                Select-Object -First 1
            'not-a-guid' | Should -Not -Match $vp.RegexPattern
        }
    }

    Context 'Add-MsixFileExplorerContextMenu -VerbClsid' {
        It 'Has a CLSID-shaped ValidatePattern' {
            $cmd = Get-Command Add-MsixFileExplorerContextMenu
            $p = $cmd.Parameters['VerbClsid']
            $vp = $p.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] } |
                Select-Object -First 1
            $vp | Should -Not -BeNullOrEmpty
            '12345678-1234-1234-1234-1234567890ab'   | Should -Match $vp.RegexPattern
            '{12345678-1234-1234-1234-1234567890ab}' | Should -Match $vp.RegexPattern
            'oops' | Should -Not -Match $vp.RegexPattern
        }
    }

    Context 'Add-MsixComServerExtension -Servers' {
        It 'Rejects servers with a non-GUID Clsid' {
            { Add-MsixComServerExtension -PackagePath 'x' `
                -Servers @(@{ Clsid = 'not-a-guid'; VfsDllPath = 'foo.dll' }) `
                -WhatIf } | Should -Throw '*Invalid Clsid*'
        }
        It 'Rejects servers missing VfsDllPath' {
            { Add-MsixComServerExtension -PackagePath 'x' `
                -Servers @(@{ Clsid = '12345678-1234-1234-1234-1234567890ab' }) `
                -WhatIf } | Should -Throw "*VfsDllPath*"
        }
    }

    Context 'Update-MsixPackageVersion -NewVersion' {
        It 'Has a 4-part dotted-decimal ValidatePattern' {
            $cmd = Get-Command Update-MsixPackageVersion -ErrorAction SilentlyContinue
            if (-not $cmd) { Set-ItResult -Skipped -Because 'cmdlet not present'; return }
            $p = $cmd.Parameters['NewVersion']
            $vp = $p.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] } |
                Select-Object -First 1
            $vp | Should -Not -BeNullOrEmpty
            '1.2.3'   | Should -Not -Match $vp.RegexPattern
            '1.2.3.4' | Should     -Match $vp.RegexPattern
            'abc'     | Should -Not -Match $vp.RegexPattern
        }
    }

    Context 'AppId NCName validation' {
        It 'Add-MsixFileExplorerContextMenu -AppId rejects spaces' {
            $cmd = Get-Command Add-MsixFileExplorerContextMenu
            $p = $cmd.Parameters['AppId']
            $vp = $p.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] } |
                Select-Object -First 1
            $vp | Should -Not -BeNullOrEmpty
            'App'         | Should     -Match $vp.RegexPattern
            'App.Sub-1'   | Should     -Match $vp.RegexPattern
            '1BadStart'   | Should -Not -Match $vp.RegexPattern
            'has space'   | Should -Not -Match $vp.RegexPattern
            'bad<char>'   | Should -Not -Match $vp.RegexPattern
        }
        It 'Add-MsixFirewallRule -AppId is NCName-validated' {
            $cmd = Get-Command Add-MsixFirewallRule
            $p = $cmd.Parameters['AppId']
            $vp = $p.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] } |
                Select-Object -First 1
            $vp | Should -Not -BeNullOrEmpty
        }
        It 'Add-MsixStartupTask -TaskId is NCName-validated' {
            $cmd = Get-Command Add-MsixStartupTask
            $p = $cmd.Parameters['TaskId']
            $vp = $p.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] } |
                Select-Object -First 1
            $vp | Should -Not -BeNullOrEmpty
        }
    }

    Context 'FileTypes validation' {
        It 'Add-MsixLegacyContextMenu accepts wildcards, extensions, Directory, Drive' {
            $cmd = Get-Command Add-MsixLegacyContextMenu
            $p = $cmd.Parameters['FileTypes']
            $vs = $p.Attributes |
                Where-Object { $_ -is [System.Management.Automation.ValidateScriptAttribute] } |
                Select-Object -First 1
            $vs | Should -Not -BeNullOrEmpty
            # Exercise the ValidateScript directly: $_ is the parameter value,
            # so we use $vs.ScriptBlock.InvokeWithContext.
            foreach ($good in '*','.log','.tar.gz','Directory','Drive') {
                $dollarUnder = New-Object psvariable '_', @([string[]]@($good))
                { $vs.ScriptBlock.InvokeWithContext(@{}, $dollarUnder, @()) } |
                    Should -Not -Throw
            }
        }
        It 'Add-MsixLegacyContextMenu rejects XML-unsafe file types' {
            { Add-MsixLegacyContextMenu -PackagePath 'x' `
                -ShellExtDll 'y' `
                -Clsid '12345678-1234-1234-1234-1234567890ab' `
                -DisplayName 'z' `
                -FileTypes '<test>' `
                -WhatIf } | Should -Throw '*Invalid file type*'
        }
        It 'Add-MsixFileExplorerContextMenu rejects XML-unsafe file types' {
            { Add-MsixFileExplorerContextMenu -PackagePath 'x' `
                -AppId 'App' `
                -VerbId 'open' `
                -VerbClsid '12345678-1234-1234-1234-1234567890ab' `
                -FileTypes 'has space' `
                -WhatIf } | Should -Throw '*Invalid file type*'
        }
    }
}

Describe 'Add-MsixCapability -Namespace override' -Tag 'Validation' {
    It 'Exposes a -Namespace parameter accepting the documented namespaces' {
        $cmd = Get-Command Add-MsixCapability
        $cmd.Parameters.ContainsKey('Namespace') | Should -BeTrue
        $vs = $cmd.Parameters['Namespace'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
            Select-Object -First 1
        $vs | Should -Not -BeNullOrEmpty
        $vs.ValidValues | Should -Contain 'rescap'
        $vs.ValidValues | Should -Contain 'standard'
        $vs.ValidValues | Should -Contain 'uap'
    }
}
