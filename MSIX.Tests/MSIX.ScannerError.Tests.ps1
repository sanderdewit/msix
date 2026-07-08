BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Scanner-failure visibility (issue #140)
# -----------------------------------------------------------------------------
# Get-MsixHeuristicFinding runs each scanner in its own try/catch so one broken
# scanner can't abort the analysis. Before #140 the catch swallowed the failure
# at Debug level, silently dropping an entire finding category — a report with
# a category missing looked identical to a genuinely clean package. The catch
# handlers now surface the failure as a 'ScannerError' finding (or, for the
# registry-derived scanners when offreg.dll is absent, defer to the single
# OfflineRegistryUnavailable umbrella finding instead of double-reporting).
# =============================================================================

Describe '_MsixAddScannerError' -Tag 'Scanners' {

    It 'adds a Warning-severity ScannerError finding naming the scanner and error' {
        $r = InModuleScope MSIX {
            $findings = [System.Collections.Generic.List[object]]::new()
            _MsixAddScannerError -Findings $findings -Scanner 'Font' -ErrorRecord 'boom: it broke'
            $findings
        }
        @($r).Count            | Should -Be 1
        $r[0].Category         | Should -Be 'ScannerError'
        $r[0].Severity         | Should -Be 'Warning'
        $r[0].Symptom          | Should -Match "'Font'"
        $r[0].Evidence         | Should -Be 'boom: it broke'
        $r[0].AppId            | Should -BeNullOrEmpty
    }

    It 'appends (does not replace) existing findings' {
        $r = InModuleScope MSIX {
            $findings = [System.Collections.Generic.List[object]]::new()
            $findings.Add([pscustomobject]@{ Category = 'PSF' })
            _MsixAddScannerError -Findings $findings -Scanner 'VcRuntime' -ErrorRecord 'x'
            $findings
        }
        @($r).Count | Should -Be 2
        @($r | Where-Object Category -eq 'PSF').Count         | Should -Be 1
        @($r | Where-Object Category -eq 'ScannerError').Count | Should -Be 1
    }
}

Describe '_MsixAddOffregScannerError' -Tag 'Scanners' {

    It 'emits a ScannerError when offreg.dll IS available (a genuine scanner failure)' {
        $r = InModuleScope MSIX {
            $findings = [System.Collections.Generic.List[object]]::new()
            _MsixAddOffregScannerError -Findings $findings -Scanner 'ShellContextMenu' `
                -ErrorRecord 'unexpected parse failure' -OffregAvailable $true
            $findings
        }
        @($r).Count    | Should -Be 1
        $r[0].Category | Should -Be 'ScannerError'
        $r[0].Symptom  | Should -Match 'ShellContextMenu'
    }

    It 'stays silent when offreg.dll is NOT available (umbrella finding already covers it)' {
        $r = InModuleScope MSIX {
            $findings = [System.Collections.Generic.List[object]]::new()
            _MsixAddOffregScannerError -Findings $findings -Scanner 'ShellContextMenu' `
                -ErrorRecord 'DllNotFound: offreg.dll' -OffregAvailable $false
            $findings
        }
        @($r).Count | Should -Be 0
    }
}
