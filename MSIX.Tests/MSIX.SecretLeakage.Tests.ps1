BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    function ConvertTo-TestSecureString {
        [OutputType([SecureString])]
        param(
            [Parameter(Mandatory)]
            [string] $Value
        )

        $secure = [System.Security.SecureString]::new()

        foreach ($char in $Value.ToCharArray()) {
            $secure.AppendChar($char)
        }

        $secure.MakeReadOnly()

        return $secure
    }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Secret non-leakage' -Tag 'Security' {

    It 'Get-MsixDebugRecommendation does not interpolate the literal PFX password' {
        $secret = 'SuperSecretPassword123!'
        $secure = ConvertTo-TestSecureString -Value $secret
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{
                    Severity       = 'Warning'
                    Category       = 'FileRedirectionFixup'
                    Symptom        = 'writes to install dir'
                    AppId          = 'App'
                    Recommendation = "-Base 'VFS/ProgramFilesX64/App/'"
                    Evidence       = 'log files'
                }
            )
            SuggestedFixups = @()
        }
        # Function may not need a report; pass minimum context to exercise the password path.
        $rec = Get-MsixDebugRecommendation -Report $stub -Pfx 'C:\nope.pfx' -PfxPassword $secure -ErrorAction SilentlyContinue
        ($rec | Out-String) | Should -Not -Match ([regex]::Escape($secret))
    }

    It 'Get-MsixDebugRecommendation emits a SecureString prompt placeholder instead of the literal password' {
        $secure = ConvertTo-TestSecureString -Value 'irrelevant-but-must-not-leak'
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{
                    Severity       = 'Warning'
                    Category       = 'RegLegacyFixups'
                    Symptom        = 'HKLM write'
                    AppId          = 'App'
                    Recommendation = ''
                    Evidence       = ''
                }
            )
        }
        $rec = Get-MsixDebugRecommendation -Report $stub -PfxPassword $secure
        ($rec -join "`n") | Should -Match 'Read-Host -AsSecureString'
    }

    It 'Invoke-MsixSigning -Signer SignTool with PFX warns about cmdline exposure' {
        # Use -WhatIf so we don't actually call signtool
        $warn = $null
        $secure = ConvertTo-TestSecureString -Value 'x'
        try {
            Invoke-MsixSigning -PackagePath 'C:\nope.msix' -Pfx 'C:\nope.pfx' -PfxPassword $secure -Signer SignTool -WarningVariable warn -WarningAction Continue -WhatIf
        }
        catch {
            Write-Verbose $_
        }
        ($warn -join ' ') | Should -Match 'command line'
    }
}
