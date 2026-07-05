BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# SignerSignEx backend (#17 / #126): in-process certificate handling so local
# PFX signing never puts the password (or PFX path) on a process command line.
# The explicit -Signer must win over the SignToolPfx parameter-set inference
# (fail-closed contract, #77).
# =============================================================================

Describe 'SignerSignEx backend (#17 / #126 / #77)' -Tag 'Signing' {

    It 'is an accepted value of -Signer' {
        $signerParam = (Get-Command Invoke-MsixSigning).Parameters['Signer']
        $validate = $signerParam.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
        $validate.ValidValues | Should -Contain 'SignerSignEx'
    }

    It 'requires a PFX (its purpose is safe local PFX signing)' {
        $pkg = Join-Path -Path $TestDrive -ChildPath 'nopfx.msix'
        Set-Content -LiteralPath $pkg -Value 'stub' -Encoding ascii
        { Invoke-MsixSigning -PackagePath $pkg -Signer SignerSignEx } |
            Should -Throw -ExpectedMessage '*requires -Pfx*'
    }

    It 'passes only the thumbprint to signtool — never the PFX path or password (#17)' {
        # Real self-signed PFX so the in-process X509Certificate2 load succeeds;
        # signtool itself is mocked so we can inspect the argument list.
        $work = Join-Path -Path $TestDrive -ChildPath 'ss'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=SignerSignExTest' `
                    -CertStoreLocation Cert:\CurrentUser\My
        $thumb = $cert.Thumbprint
        $pfx = Join-Path $work 'c.pfx'
        $pw  = [System.Security.SecureString]::new(); 'p'.ToCharArray() | ForEach-Object { $pw.AppendChar($_) }; $pw.MakeReadOnly()
        Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pw | Out-Null
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumb" -Force -ErrorAction SilentlyContinue

        Mock -ModuleName MSIX Get-MsixToolsRoot { $work }
        Mock -ModuleName MSIX Invoke-MsixProcess { [pscustomobject]@{ ExitCode = 0; StdOut = 'ok'; StdErr = '' } }

        $pkg = Join-Path $work 'p.msix'
        Set-Content -LiteralPath $pkg -Value 'stub' -Encoding ascii
        try {
            Invoke-MsixSigning -PackagePath $pkg -Signer SignerSignEx -Pfx $pfx -PfxPassword $pw
        } finally {
            # Belt-and-suspenders: ensure the temp store entry is gone.
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumb" -Force -ErrorAction SilentlyContinue
        }

        Should -Invoke -ModuleName MSIX Invoke-MsixProcess -Times 1 -ParameterFilter {
            # thumbprint present via /sha1; PFX path and password absent.
            ($ArgumentList -contains '/sha1') -and
            ($ArgumentList -contains $thumb) -and
            (-not ($ArgumentList -contains $pfx)) -and
            (-not ($ArgumentList -contains '/f')) -and
            (-not ($ArgumentList -contains '/p'))
        }
    }

    It 'explicit -Signer SignerSignEx wins over the SignToolPfx parameter set (#77)' {
        # -Pfx/-PfxPassword bind the SignToolPfx set; the explicit signer must
        # still route to SignerSignEx (thumbprint path), not the SignTool /p path.
        $work = Join-Path -Path $TestDrive -ChildPath 'win'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=SignerSignExWin' `
                    -CertStoreLocation Cert:\CurrentUser\My
        $thumb = $cert.Thumbprint
        $pfx = Join-Path $work 'c.pfx'
        $pw  = [System.Security.SecureString]::new(); 'p'.ToCharArray() | ForEach-Object { $pw.AppendChar($_) }; $pw.MakeReadOnly()
        Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pw | Out-Null
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumb" -Force -ErrorAction SilentlyContinue

        Mock -ModuleName MSIX Get-MsixToolsRoot { $work }
        Mock -ModuleName MSIX Invoke-MsixProcess { [pscustomobject]@{ ExitCode = 0; StdOut = 'ok'; StdErr = '' } }
        $pkg = Join-Path $work 'p.msix'
        Set-Content -LiteralPath $pkg -Value 'stub' -Encoding ascii
        try {
            Invoke-MsixSigning -PackagePath $pkg -Signer SignerSignEx -Pfx $pfx -PfxPassword $pw
        } finally {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumb" -Force -ErrorAction SilentlyContinue
        }
        Should -Invoke -ModuleName MSIX Invoke-MsixProcess -Times 1 -ParameterFilter {
            ($ArgumentList -contains '/sha1') -and (-not ($ArgumentList -contains '/p'))
        }
    }

    It 'removes the temporary store certificate after signing' {
        $work = Join-Path -Path $TestDrive -ChildPath 'cleanup'
        New-Item -ItemType Directory -Path $work -Force | Out-Null
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=SignerSignExCleanup' `
                    -CertStoreLocation Cert:\CurrentUser\My
        $thumb = $cert.Thumbprint
        $pfx = Join-Path $work 'c.pfx'
        $pw  = [System.Security.SecureString]::new(); 'p'.ToCharArray() | ForEach-Object { $pw.AppendChar($_) }; $pw.MakeReadOnly()
        Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pw | Out-Null
        Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumb" -Force -ErrorAction SilentlyContinue

        Mock -ModuleName MSIX Get-MsixToolsRoot { $work }
        Mock -ModuleName MSIX Invoke-MsixProcess { [pscustomobject]@{ ExitCode = 0; StdOut = 'ok'; StdErr = '' } }
        $pkg = Join-Path $work 'p.msix'
        Set-Content -LiteralPath $pkg -Value 'stub' -Encoding ascii
        try {
            Invoke-MsixSigning -PackagePath $pkg -Signer SignerSignEx -Pfx $pfx -PfxPassword $pw
            # We imported it (it was not present before) so it must be gone now.
            @(Get-ChildItem "Cert:\CurrentUser\My\$thumb" -ErrorAction SilentlyContinue).Count | Should -Be 0
        } finally {
            Remove-Item -LiteralPath "Cert:\CurrentUser\My\$thumb" -Force -ErrorAction SilentlyContinue
        }
    }
}
