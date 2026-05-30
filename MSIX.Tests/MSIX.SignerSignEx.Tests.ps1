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

    It 'real SignerSignEx2 signing path' -Skip {
        # SKIPPED BY DESIGN (#17): exercising the actual mssign32!SignerSignEx2
        # P/Invoke requires Windows + a real code-signing certificate and a way
        # to verify the produced Authenticode signature. This cannot run in the
        # cross-platform unit suite. Implement and un-skip when the backend is
        # built and validated on a Windows host with a test cert.
        $true | Should -BeTrue
    }
}
