function Invoke-MsixSigning {
    <#
    .SYNOPSIS
        Signs an MSIX package using signtool.exe.

    .DESCRIPTION
        Uses the bundled signtool.exe. Supports both PFX file signing and
        automatic certificate selection from the machine certificate store.
        Always timestamps with SHA-256.

    .PARAMETER PackagePath
        Path to the .msix file to sign.

    .PARAMETER Pfx
        Path to a PFX certificate file. Omit to use automatic store selection (/a).

    .PARAMETER PfxPassword
        Password for the PFX file. Required when -Pfx is provided.

    .PARAMETER TimestampUrl
        RFC 3161 timestamp server URL. Defaults to DigiCert.

    .EXAMPLE
        $pw = Read-Host -AsSecureString
        Invoke-MsixSigning -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        Invoke-MsixSigning -PackagePath app.msix
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$TimestampUrl = 'http://timestamp.digicert.com'
    )

    if ($Pfx -and -not $PfxPassword) {
        throw 'PfxPassword is required when Pfx is specified.'
    }

    $toolsRoot = Get-MsixToolsRoot
    $signtool  = Join-Path $toolsRoot 'Tools\signtool.exe'
    $fileinfo  = Get-Item $PackagePath

    $sigArgs = if ($Pfx) {
        $cert   = Get-Item $Pfx
        # Decrypt SecureString only at the CLI boundary — never stored in a plain variable
        $bstr   = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
        try {
            $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
            "sign /v /tr `"$TimestampUrl`" /td sha256 /fd sha256 /f `"$($cert.FullName)`" /p `"$plain`" `"$($fileinfo.FullName)`""
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    } else {
        "sign /v /tr `"$TimestampUrl`" /td sha256 /fd sha256 /a `"$($fileinfo.FullName)`""
    }

    Write-MsixLog Info "Signing: $($fileinfo.Name)"

    if ($PSCmdlet.ShouldProcess($fileinfo.FullName, 'Sign with signtool')) {
        $r = Invoke-MsixProcess $signtool $sigArgs
        if ($r.ExitCode -ne 0) {
            $detail = if ($r.StdErr) { $r.StdErr } else { $r.StdOut }
            throw "signtool failed (exit $($r.ExitCode)): $detail`nCheck: Microsoft-Windows-AppxPackagingOM event log."
        } else {
            Write-MsixLog Info "Signed successfully: $($fileinfo.Name)"
        }
    }
}
