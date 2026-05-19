BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psm1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Get-MsixDebugRecommendation' -Tag 'Recommendations' {

    It 'Emits a friendly no-issue message when Findings is empty' {
        $stub = [pscustomobject]@{ PackagePath = 'x.msix'; Findings = @() }
        $out = Get-MsixDebugRecommendation -Report $stub
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
        $out = Get-MsixDebugRecommendation -Report $stub
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
        $out = Get-MsixDebugRecommendation -Report $stub
        ($out -join "`n") | Should -Match "-WorkingDirectory 'VFS/ProgramFilesX64/A/'"
    }

    It 'Substitutes -Pfx but emits a SecureString placeholder for -PfxPassword' {
        $stub = [pscustomobject]@{
            PackagePath = 'x.msix'
            Findings    = @([pscustomobject]@{ Severity='Warning'; Category='FileRedirectionFixup'; Symptom='x'; AppId='A'; Recommendation="-Base 'a/'"; Evidence='b' })
        }
        $secret = 'P@s-DoNotLeak-Token'
        $secure = ConvertTo-SecureString $secret -AsPlainText -Force
        $out = Get-MsixDebugRecommendation -Report $stub -Pfx 'C:\c.pfx' -PfxPassword $secure
        $joined = ($out -join "`n")
        # -Pfx path is interpolated verbatim
        $joined | Should -Match 'C:\\c\.pfx'
        # The literal secret must NEVER reach the output
        $joined | Should -Not -Match ([regex]::Escape($secret))
        # The placeholder must direct the operator to re-supply via Read-Host
        $joined | Should -Match 'Read-Host -AsSecureString'
    }

    It 'Numbers each recommendation' {
        $stub = [pscustomobject]@{
            PackagePath = 'x.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Warning'; Category='FileRedirectionFixup'; Symptom='1'; Recommendation="-Base 'a/'" }
                [pscustomobject]@{ Severity='Warning'; Category='WorkingDirectory';     Symptom='2'; Recommendation="workingDirectory='b/'" }
            )
        }
        $out = (Get-MsixDebugRecommendation -Report $stub) -join "`n"
        $out | Should -Match '\[1\]'
        $out | Should -Match '\[2\]'
    }
}
