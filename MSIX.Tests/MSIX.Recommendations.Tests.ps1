BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psm1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Get-MsixDebugRecommendations' -Tag 'Recommendations' {

    It 'Emits a friendly no-issue message when Findings is empty' {
        $stub = [pscustomobject]@{ PackagePath = 'x.msix'; Findings = @() }
        $out = Get-MsixDebugRecommendations -Report $stub
        ($out -join "`n") | Should -Match 'No issues detected'
    }

    It 'Renders an Add-MsixPsfV2 line for FileRedirectionFixup findings' {
        $stub = [pscustomobject]@{
            PackagePath = 'x.msix'
            Findings    = @(
                [pscustomobject]@{
                    Severity='Warning'; Category='FileRedirectionFixup';
                    Symptom='log files'; AppId='App';
                    Recommendation="-Base 'logs/'"; Evidence='a.log'
                }
            )
        }
        $out = Get-MsixDebugRecommendations -Report $stub
        ($out -join "`n") | Should -Match 'Add-MsixPsfV2'
        ($out -join "`n") | Should -Match 'New-MsixPsfFileRedirectionConfig'
        ($out -join "`n") | Should -Match "-Base 'logs/'"
    }

    It 'Renders -WorkingDirectory for WorkingDirectory findings' {
        $stub = [pscustomobject]@{
            PackagePath = 'x.msix'
            Findings    = @(
                [pscustomobject]@{
                    Severity='Warning'; Category='WorkingDirectory';
                    Symptom='cwd'; AppId='App';
                    Recommendation="workingDirectory='VFS/ProgramFilesX64/A/'"
                    Evidence='ini'
                }
            )
        }
        $out = Get-MsixDebugRecommendations -Report $stub
        ($out -join "`n") | Should -Match "-WorkingDirectory 'VFS/ProgramFilesX64/A/'"
    }

    It 'Substitutes -Pfx and -PfxPassword' {
        $stub = [pscustomobject]@{
            PackagePath = 'x.msix'
            Findings    = @([pscustomobject]@{ Severity='Warning'; Category='FileRedirectionFixup'; Symptom='x'; AppId='A'; Recommendation="-Base 'a/'"; Evidence='b' })
        }
        $out = Get-MsixDebugRecommendations -Report $stub -Pfx 'C:\c.pfx' -PfxPassword 'P@s'
        ($out -join "`n") | Should -Match "C:\\c\.pfx"
        ($out -join "`n") | Should -Match "P@s"
    }

    It 'Numbers each recommendation' {
        $stub = [pscustomobject]@{
            PackagePath = 'x.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Warning'; Category='FileRedirectionFixup'; Symptom='1'; Recommendation="-Base 'a/'" }
                [pscustomobject]@{ Severity='Warning'; Category='WorkingDirectory';     Symptom='2'; Recommendation="workingDirectory='b/'" }
            )
        }
        $out = (Get-MsixDebugRecommendations -Report $stub) -join "`n"
        $out | Should -Match '\[1\]'
        $out | Should -Match '\[2\]'
    }
}
