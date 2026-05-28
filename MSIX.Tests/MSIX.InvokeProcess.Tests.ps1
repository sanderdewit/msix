BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Invoke-MsixProcess' -Tag 'Core' {

    # ---------------------------------------------------------------------------
    # Parameter-binding contract — these catch signature regressions without
    # needing MakeAppx.exe on disk.
    # ---------------------------------------------------------------------------

    It 'FilePath is positional (Position 0)' {
        $cmd = Get-Command Invoke-MsixProcess -Module MSIX
        $p   = $cmd.Parameters['FilePath']
        $p | Should -Not -BeNullOrEmpty
        $attr = $p.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
        $attr.Position | Should -Be 0
    }

    It 'ArgumentList is positional (Position 1)' {
        $cmd = Get-Command Invoke-MsixProcess -Module MSIX
        $p   = $cmd.Parameters['ArgumentList']
        $p | Should -Not -BeNullOrEmpty
        $attr = $p.Attributes | Where-Object {
            $_ -is [System.Management.Automation.ParameterAttribute] -and
            $_.ParameterSetName -in @('ArgumentList', '__AllParameterSets')
        }
        ($attr | Measure-Object).Count | Should -BeGreaterThan 0
        ($attr | Where-Object { $_.Position -eq 1 } | Measure-Object).Count | Should -Be 1
    }

    It 'Accepts FilePath as the first positional argument without -FilePath name' {
        # Verify PowerShell binds the first positional arg to FilePath.
        # Use a real, always-present Windows binary so no toolchain is needed.
        # cmd.exe /c exit 0 is the safest no-op available everywhere.
        $result = Invoke-MsixProcess -FilePath "$env:SystemRoot\System32\cmd.exe" `
                      -ArgumentList @('/c', 'exit', '0')
        $result | Should -Not -BeNullOrEmpty
        $result.ExitCode | Should -Be 0
    }

    # ---------------------------------------------------------------------------
    # Functional contract — output shape and exit code handling
    # ---------------------------------------------------------------------------

    It 'Returns an object with ExitCode, StdOut, and StdErr properties' {
        $result = Invoke-MsixProcess -FilePath "$env:SystemRoot\System32\cmd.exe" `
                      -ArgumentList @('/c', 'exit', '0')
        $result.PSObject.Properties.Name | Should -Contain 'ExitCode'
        $result.PSObject.Properties.Name | Should -Contain 'StdOut'
        $result.PSObject.Properties.Name | Should -Contain 'StdErr'
    }

    It 'Captures a non-zero exit code correctly' {
        $result = Invoke-MsixProcess -FilePath "$env:SystemRoot\System32\cmd.exe" `
                      -ArgumentList @('/c', 'exit', '42')
        $result.ExitCode | Should -Be 42
    }

    It 'Captures stdout from the child process' {
        $result = Invoke-MsixProcess -FilePath "$env:SystemRoot\System32\cmd.exe" `
                      -ArgumentList @('/c', 'echo hello-from-child')
        $result.StdOut | Should -Match 'hello-from-child'
    }

    It 'Throws when executable path does not exist' {
        { Invoke-MsixProcess 'C:\does\not\exist\fake.exe' -ArgumentList @() } |
            Should -Throw
    }
}
