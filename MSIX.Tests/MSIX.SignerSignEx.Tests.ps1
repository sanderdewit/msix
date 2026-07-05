BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Coverage for #17 — the SignerSignEx backend is RESERVED (API surface only).
# The real mssign32!SignerSignEx2 P/Invoke implementation is intentionally not
# shipped until it can be validated on Windows against a real code-signing
# certificate, so the actual-signing test is skipped (documented below).

Describe 'SignerSignEx reserved backend (#17)' -Tag 'Signing' {

    It 'is an accepted value of -Signer' {
        $signerParam = (Get-Command Invoke-MsixSigning).Parameters['Signer']
        $validate = $signerParam.Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] }
        $validate.ValidValues | Should -Contain 'SignerSignEx'
    }

    It 'throws a clear not-yet-implemented error and never invokes signtool' {
        $spawned = $false
        Mock -ModuleName MSIX Get-MsixToolsRoot { 'C:\fake-tools' }
        Mock -ModuleName MSIX Invoke-MsixProcess { $script:spawned = $true; [pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' } }
        # PackagePath just needs to exist far enough to reach the backend switch.
        $pkg = Join-Path -Path $TestDrive -ChildPath 'p.msix'
        Set-Content -LiteralPath $pkg -Value 'stub' -Encoding ascii

        { Invoke-MsixSigning -PackagePath $pkg -Signer SignerSignEx } |
            Should -Throw -ExpectedMessage '*not yet implemented*'

        Should -Invoke -ModuleName MSIX Invoke-MsixProcess -Times 0
    }

    It 'fails closed even when PFX parameters push it into the SignToolPfx set (issue #77)' {
        # -Pfx/-PfxPassword bind the SignToolPfx parameter set, whose set-name
        # inference used to override the explicit -Signer SignerSignEx and
        # silently enter the SignTool path (command-line password exposure).
        Mock -ModuleName MSIX Get-MsixToolsRoot { 'C:\fake-tools' }
        Mock -ModuleName MSIX Invoke-MsixProcess { [pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' } }
        $pkg = Join-Path -Path $TestDrive -ChildPath 'p77.msix'
        Set-Content -LiteralPath $pkg -Value 'stub' -Encoding ascii
        $pfx = Join-Path -Path $TestDrive -ChildPath 'p77.pfx'
        Set-Content -LiteralPath $pfx -Value 'stub' -Encoding ascii
        $pw  = [System.Security.SecureString]::new()
        $pw.AppendChar('x'); $pw.MakeReadOnly()

        { Invoke-MsixSigning -PackagePath $pkg -Signer SignerSignEx -Pfx $pfx -PfxPassword $pw } |
            Should -Throw -ExpectedMessage '*not yet implemented*'

        Should -Invoke -ModuleName MSIX Invoke-MsixProcess -Times 0
    }

    It 'real SignerSignEx2 signing path' -Skip {
        # SKIPPED BY DESIGN (#17): exercising the actual mssign32!SignerSignEx2
        # P/Invoke requires Windows + a real code-signing certificate and a way
        # to verify the produced Authenticode signature. This cannot run in the
        # cross-platform unit suite. Implement and un-skip when the backend is
        # built and validated on a Windows host with a test cert.
        $true | Should -BeTrue
    }
}
