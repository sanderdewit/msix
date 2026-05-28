BeforeAll {
    $script:WrapperPath = (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-MsixTests.ps1')).Path
    $script:WrapperSrc  = Get-Content -LiteralPath $script:WrapperPath -Raw
}

Describe 'Pester wrapper fail-fast contract (issue #43)' -Tag 'TestRunner' {

    # Source-level guards. We do NOT spin up a subprocess that invokes the
    # wrapper here -- that would require staging a synthetic Invoke-Pester
    # that throws after returning some output, which is convoluted across
    # Pester versions. Instead we pin the structural invariants that make
    # the wrapper fail closed: try/catch around Invoke-Pester, result-object
    # validation, distinct exit codes for infra vs test failure.

    It 'Invoke-Pester is wrapped in a try/catch' {
        # The try { ... Invoke-Pester ... } catch { ... } pattern is the
        # only thing standing between an end-step throw and an exit-0
        # silent failure. Future edits that revert to a bare call should
        # be caught here.
        $script:WrapperSrc | Should -Match '(?s)try\s*\{[^}]*Invoke-Pester[^}]*\}\s*catch'
    }

    It 'Catch block exits with a non-zero infrastructure-failure code' {
        # Inside the catch we must emit a distinct non-zero exit code so
        # CI can tell "tests failed" (expected) apart from "Pester itself
        # broke" (infra issue). Use a permissive regex because the catch
        # body may contain nested braces (if/while/etc.) before the exit.
        ($script:WrapperSrc -match '(?s)catch\s*\{[\s\S]*?exit\s+\$WrapperExitInfraFailure[\s\S]*?\n\}') | Should -BeTrue
    }

    It 'The two exit codes are different and both non-zero' {
        $script:WrapperSrc | Should -Match '\$WrapperExitTestsFailed\s*=\s*1'
        $script:WrapperSrc | Should -Match '\$WrapperExitInfraFailure\s*=\s*2'
    }

    It 'Validates that $result has the expected properties before reading them' {
        # If Invoke-Pester returns nothing or returns an object without
        # PassedCount/FailedCount, the wrapper must NOT print blank
        # counters and exit 0. It must exit with the infra-failure code.
        $script:WrapperSrc | Should -Match "PSObject\.Properties\['PassedCount'\]"
        $script:WrapperSrc | Should -Match "PSObject\.Properties\['FailedCount'\]"
    }

    It 'Pass/fail/skipped counts are only printed AFTER the result is validated' {
        # Find the validation block and the Write-Host of the counts and
        # assert the validation comes first.
        $valIdx = $script:WrapperSrc.IndexOf("PSObject.Properties['FailedCount']")
        $writeIdx = $script:WrapperSrc.IndexOf('"Passed:')
        $valIdx   | Should -BeGreaterThan -1
        $writeIdx | Should -BeGreaterThan -1
        $valIdx   | Should -BeLessThan $writeIdx
    }
}

Describe 'Pester wrapper -DisableTestResult switch (issue #47)' -Tag 'TestRunner' {

    # Hardened workstations / build agents may revoke the WMI/CIM
    # privileges Pester's NUnit metadata exporter needs (Get-CimInstance
    # Win32_*). The tests don't care, but Pester's end-step throws and
    # the wrapper exits with the infra-failure code. -DisableTestResult
    # skips the NUnit XML emission so the suite can run to completion.

    BeforeAll {
        # Resolve the wrapper as a real PowerShell command so we can
        # inspect its parameter metadata without invoking it.
        $script:WrapperCmd = Get-Command -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-MsixTests.ps1')).Path
    }

    It 'Wrapper exposes -DisableTestResult (with -NoTestResult alias)' {
        $script:WrapperCmd.Parameters.ContainsKey('DisableTestResult') | Should -BeTrue
        $script:WrapperCmd.Parameters['DisableTestResult'].ParameterType.FullName |
            Should -Be 'System.Management.Automation.SwitchParameter'
        $script:WrapperCmd.Parameters['DisableTestResult'].Aliases | Should -Contain 'NoTestResult'
    }

    It 'When -DisableTestResult is set, the script disables TestResult.Enabled' {
        # Source-level guard: there must be an explicit if/else gating the
        # TestResult configuration on the switch. Otherwise a future edit
        # could silently re-enable the NUnit exporter on hardened hosts.
        $script:WrapperSrc | Should -Match 'if\s*\(\s*\$DisableTestResult\s*\)\s*\{[\s\S]*?\$config\.TestResult\.Enabled\s*=\s*\$false'
        # And the default branch (no switch) must enable it -- CI relies
        # on the artifact.
        $script:WrapperSrc | Should -Match '\}\s*else\s*\{[\s\S]*?\$config\.TestResult\.Enabled\s*=\s*\$true'
    }

    It 'Disabled-mode notice is loud (Write-Host with a colour)' {
        # An operator running with -DisableTestResult must SEE that no
        # artifact will be produced; silent skip would defeat the purpose.
        $script:WrapperSrc | Should -Match 'TestResult XML emission DISABLED.+-DisableTestResult'
    }
}
