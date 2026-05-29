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

    It 'Invoke-MsixSigning exposes no raw client-secret parameter for AzureSignTool (#53)' {
        # The module must never handle a raw Key Vault secret — auth is delegated
        # to AzureSignTool's DefaultAzureCredential chain.
        $params = (Get-Command Invoke-MsixSigning).Parameters.Keys
        $params | Should -Not -Contain 'KeyVaultClientSecret'
    }

    It 'AzureSignTool passes no credential material and sets no AZURE_* env var (#53)' {
        $pkg = Join-Path -Path $TestDrive -ChildPath 'pkg.msix'
        Set-Content -LiteralPath $pkg -Value 'stub' -Encoding utf8

        # Snapshot AZURE_* env so we can prove the module doesn't touch it.
        $before = @{}
        foreach ($n in 'AZURE_TENANT_ID','AZURE_CLIENT_ID','AZURE_CLIENT_SECRET') {
            $before[$n] = [Environment]::GetEnvironmentVariable($n, 'Process')
        }

        $script:capturedArgs    = $null
        $script:capturedEnvMid  = $null
        Mock -ModuleName MSIX Get-MsixToolsRoot { 'C:\fake-tools' }
        Mock -ModuleName MSIX Invoke-MsixProcess {
            $script:capturedArgs   = $ArgumentList
            $script:capturedEnvMid = [Environment]::GetEnvironmentVariable('AZURE_CLIENT_SECRET', 'Process')
            [pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' }
        }
        Mock -ModuleName MSIX Get-Command { [pscustomobject]@{ Source = 'C:\fake\AzureSignTool.exe' } } -ParameterFilter { $Name -eq 'AzureSignTool.exe' }

        Invoke-MsixSigning -PackagePath $pkg -Signer AzureSignTool `
            -KeyVaultUrl 'https://v.vault.azure.net' -KeyVaultCertificate 'c' `
            -KeyVaultTenantId 't' -KeyVaultClientId 'ci'

        $joined = $script:capturedArgs -join ' '
        # Non-sensitive scoping hints are forwarded ...
        $joined | Should -Match '--azure-key-vault-tenant-id'
        $joined | Should -Match '--azure-key-vault-client-id'
        # ... but no secret flag, and the module must not force MI-only.
        $joined | Should -Not -Match '--azure-key-vault-client-secret'
        $joined | Should -Not -Match '--azure-key-vault-managed-identity'
        # The module must not have set AZURE_CLIENT_SECRET during the call ...
        $script:capturedEnvMid | Should -Be $before['AZURE_CLIENT_SECRET']
        # ... nor left any AZURE_* env var altered afterward.
        foreach ($n in 'AZURE_TENANT_ID','AZURE_CLIENT_ID','AZURE_CLIENT_SECRET') {
            [Environment]::GetEnvironmentVariable($n, 'Process') | Should -Be $before[$n]
        }
    }
}
