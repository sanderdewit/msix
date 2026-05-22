BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'SARIF export' -Tag 'Sarif' {

    Context 'ConvertTo-MsixSarif shape' {

        BeforeAll {
            $script:Findings = @(
                [pscustomobject]@{
                    Severity       = 'Warning'
                    Category       = 'ManifestFix:FileSystemWriteVirtualization'
                    Symptom        = 'Writable-looking files shipped inside the VFS payload.'
                    Recommendation = "Set-MsixFileSystemWriteVirtualization -PackagePath 'app.msix'"
                    Evidence       = 'app.log, cache.tmp'
                    AppId          = 'App'
                }
                [pscustomobject]@{
                    Severity       = 'Error'
                    Category       = 'ShellExt'
                    Symptom        = 'Legacy shellex handler in Registry.dat.'
                    Recommendation = 'Add-MsixLegacyContextMenu ...'
                    Evidence       = 'NppShell'
                    AppId          = $null
                }
                [pscustomobject]@{
                    Severity       = 'Info'
                    Category       = 'AppExecutionAlias'
                    Symptom        = 'NOTEPAD has no AppExecutionAlias.'
                    Recommendation = "Add-MsixAlias ..."
                    Evidence       = 'notepad++.exe'
                    AppId          = 'NOTEPAD'
                }
            )
            $script:Sarif = ConvertTo-MsixSarif -Findings $script:Findings -PackagePath 'C:\drop\app.msix'
        }

        It 'Produces a SARIF 2.1.0 document' {
            $script:Sarif.version | Should -Be '2.1.0'
            $script:Sarif.'$schema' | Should -Match 'sarif-schema-2\.1\.0'
        }

        It 'Has exactly one run with a driver named MSIX.PowerShell by default' {
            $script:Sarif.runs.Count | Should -Be 1
            $script:Sarif.runs[0].tool.driver.name | Should -Be 'MSIX.PowerShell'
        }

        It 'Produces one rule per distinct Category in the findings' {
            $rules = $script:Sarif.runs[0].tool.driver.rules
            $rules.Count | Should -Be 3
            $rules.id    | Should -Contain 'MSIX.ManifestFix:FileSystemWriteVirtualization'
            $rules.id    | Should -Contain 'MSIX.ShellExt'
            $rules.id    | Should -Contain 'MSIX.AppExecutionAlias'
        }

        It 'Produces one result per finding' {
            $results = $script:Sarif.runs[0].results
            $results.Count | Should -Be 3
        }

        It 'Maps Severity to SARIF level correctly' {
            $results = $script:Sarif.runs[0].results
            ($results | Where-Object ruleId -eq 'MSIX.ShellExt').level                              | Should -Be 'error'
            ($results | Where-Object ruleId -eq 'MSIX.ManifestFix:FileSystemWriteVirtualization').level | Should -Be 'warning'
            ($results | Where-Object ruleId -eq 'MSIX.AppExecutionAlias').level                     | Should -Be 'note'
        }

        It 'Records the package path as the SARIF analysisTarget' {
            $artifact = $script:Sarif.runs[0].artifacts[0]
            $artifact.roles | Should -Contain 'analysisTarget'
            $artifact.location.uri | Should -Match 'app\.msix$'
        }

        It 'Carries AppId + Evidence in logicalLocations' {
            $r = @($script:Sarif.runs[0].results | Where-Object ruleId -eq 'MSIX.AppExecutionAlias')[0]
            # Hashtable arrays don't filter cleanly with Where-Object fullyQualifiedName syntax
            # (PowerShell's PSObject adapter for hashtables yields each KEY as a property bag),
            # so collect the names explicitly and check membership.
            $fqNames = @($r.locations[0].logicalLocations | ForEach-Object { $_.fullyQualifiedName })
            $fqNames | Should -Contain 'AppId/NOTEPAD'
            $fqNames | Should -Contain 'Evidence/notepad++.exe'
        }

        It 'Keeps the original Recommendation in result.properties' {
            $r = $script:Sarif.runs[0].results | Where-Object ruleId -eq 'MSIX.ManifestFix:FileSystemWriteVirtualization'
            $r.properties.recommendation | Should -Match 'Set-MsixFileSystemWriteVirtualization'
        }

        It 'Serialises to valid JSON via ConvertTo-Json' {
            { $script:Sarif | ConvertTo-Json -Depth 100 -Compress | Out-Null } | Should -Not -Throw
        }

        It 'Handles an empty findings array without crashing' {
            $empty = ConvertTo-MsixSarif -Findings @() -PackagePath 'C:\nope.msix'
            $empty.runs[0].results.Count | Should -Be 0
            $empty.runs[0].tool.driver.rules.Count | Should -Be 0
        }
    }

    Context 'Get-MsixStaticAnalysis -Sarif' {

        It 'Exposes the -Sarif switch' {
            $cmd = Get-Command Get-MsixStaticAnalysis -Module MSIX
            $cmd.Parameters.Keys | Should -Contain 'Sarif'
            $cmd.Parameters['Sarif'].ParameterType.FullName | Should -Be 'System.Management.Automation.SwitchParameter'
        }

        It 'Source-level guard: -Sarif routes through ConvertTo-MsixSarif' {
            $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.Investigation.ps1')) -Raw
            $src | Should -Match 'if \(\$Sarif\)'
            $src | Should -Match 'ConvertTo-MsixSarif -Findings'
        }
    }
}
