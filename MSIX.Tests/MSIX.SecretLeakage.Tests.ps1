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
            Write-Verbose -Message $_
        }
        ($warn -join ' ') | Should -Match 'command line'
    }

    It 'AzureSignTool does not place the client secret on the command line (#53)' {
        $secret = 'Kv-Secret-Should-Not-Leak-987'
        $secure = ConvertTo-TestSecureString -Value $secret
        $pkg    = Join-Path -Path $TestDrive -ChildPath 'pkg.msix'
        Set-Content -LiteralPath $pkg -Value 'stub' -Encoding utf8

        # Capture the args + the env-delivered secret without running AzureSignTool.
        $script:capturedArgs   = $null
        $script:capturedEnvSet = $null
        Mock -ModuleName MSIX Get-MsixToolsRoot { 'C:\fake-tools' }
        Mock -ModuleName MSIX Invoke-MsixProcess {
            $script:capturedArgs   = $ArgumentList
            $script:capturedEnvSet = [Environment]::GetEnvironmentVariable('AZURE_CLIENT_SECRET', 'Process')
            [pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' }
        }
        # AzureSignTool.exe resolution: pretend it exists on PATH.
        Mock -ModuleName MSIX Get-Command { [pscustomobject]@{ Source = 'C:\fake\AzureSignTool.exe' } } -ParameterFilter { $Name -eq 'AzureSignTool.exe' }

        Invoke-MsixSigning -PackagePath $pkg -Signer AzureSignTool `
            -KeyVaultUrl 'https://v.vault.azure.net' -KeyVaultCertificate 'c' `
            -KeyVaultTenantId 't' -KeyVaultClientId 'ci' -KeyVaultClientSecret $secure

        # The secret must NOT be anywhere in the command-line args ...
        ($script:capturedArgs -join ' ') | Should -Not -Match ([regex]::Escape($secret))
        ($script:capturedArgs -join ' ') | Should -Not -Match '--azure-key-vault-client-secret'
        # ... but it MUST have been delivered via the environment.
        $script:capturedEnvSet | Should -Be $secret
        # And the env var must be cleaned up afterward.
        [Environment]::GetEnvironmentVariable('AZURE_CLIENT_SECRET', 'Process') | Should -BeNullOrEmpty
    }

    It 'AzureSignTool client secret requires tenant + client id (#53)' {
        $secure = ConvertTo-TestSecureString -Value 'x'
        $pkg    = Join-Path -Path $TestDrive -ChildPath 'pkg2.msix'
        Set-Content -LiteralPath $pkg -Value 'stub' -Encoding utf8
        Mock -ModuleName MSIX Get-MsixToolsRoot { 'C:\fake-tools' }
        Mock -ModuleName MSIX Invoke-MsixProcess { [pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' } }
        Mock -ModuleName MSIX Get-Command { [pscustomobject]@{ Source = 'C:\fake\AzureSignTool.exe' } } -ParameterFilter { $Name -eq 'AzureSignTool.exe' }

        { Invoke-MsixSigning -PackagePath $pkg -Signer AzureSignTool `
            -KeyVaultUrl 'https://v.vault.azure.net' -KeyVaultCertificate 'c' `
            -KeyVaultClientSecret $secure } |
            Should -Throw -ExpectedMessage '*requires -KeyVaultTenantId and -KeyVaultClientId*'
    }
}
