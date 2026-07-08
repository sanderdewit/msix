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

Describe "Get-MsixHeuristicFinding manifest-fix block is null-safe" -Tag 'Scanners' {

    # Regression: a manifest with NO <Properties> element (so $mf.Package.Properties
    # is $null) and NO package-level <Extensions> (so @($mf.Package.Extensions.Extension)
    # is @($null) — an array holding one $null) NRE'd the manifest-fix block, which
    # aborted it and dropped every manifest-fix finding. On a Win11 host this
    # surfaced as "ManifestFix failed; ... You cannot call a method on a null-valued
    # expression". Both shapes are common in real packages.
    It 'does not emit a ManifestFix ScannerError for a manifest without <Properties> or package <Extensions>' {
        $seen = InModuleScope MSIX {
            Mock Get-MsixToolsRoot { 'C:\fake-tools' }
            Mock New-MsixWorkspace {
                $d = Join-Path ([IO.Path]::GetTempPath()) ("hfnull-" + [guid]::NewGuid().ToString('N').Substring(0,8))
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                $d
            }
            Mock Invoke-MsixProcess {
                if ($ArgumentList -contains 'unpack') {
                    $idx  = [array]::IndexOf($ArgumentList, '/d')
                    $dest = $ArgumentList[$idx + 1]
                    Set-Content -LiteralPath "$dest\AppxManifest.xml" -Encoding utf8 -Value @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Applications><Application Id="A" Executable="a.exe" /></Applications>
</Package>
'@
                }
                [pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' }
            }
            $pkg = Join-Path ([IO.Path]::GetTempPath()) ("hfnull-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.msix')
            Set-Content -LiteralPath $pkg -Value 'stub' -Encoding utf8
            $findings = Get-MsixHeuristicFinding -PackagePath $pkg
            Remove-Item -LiteralPath $pkg -Force -ErrorAction SilentlyContinue
            @($findings | Where-Object { $_.Category -eq 'ScannerError' -and $_.Symptom -match 'ManifestFix' })
        }
        @($seen).Count | Should -Be 0
    }
}
