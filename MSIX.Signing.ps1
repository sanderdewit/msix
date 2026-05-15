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


# ===========================================================================
# Self-signed certificate flow (for debug / sandbox)
# ===========================================================================
# Sandbox / dev hosts often need to install an MSIX whose signature is
# missing, expired, or chained to a CA that the sandbox doesn't trust. The
# helpers below let you:
#
#   - Generate a code-signing cert whose Subject matches the manifest's
#     Publisher (this is REQUIRED — MSIX install fails with 0x8007000B if
#     Publisher and Subject don't match exactly).
#   - Sign the package with that cert.
#   - Export the public .cer so the sandbox bootstrap can trust it.
# ===========================================================================

function Test-MsixSignature {
    <#
    .SYNOPSIS
        Reports the signature state of an .msix and whether it needs a
        self-signed cert to install in a clean sandbox.

    .DESCRIPTION
        Returns an object with:
          - Status            (NotSigned / Valid / HashMismatch / NotTrusted / Unknown)
          - SignerSubject
          - Thumbprint
          - NeedsSelfSign     ($true if the sandbox install would fail
                              without trusting a cert ourselves)

    .EXAMPLE
        (Test-MsixSignature -PackagePath app.msix).NeedsSelfSign
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath
    )

    $sig = Get-AuthenticodeSignature -FilePath $PackagePath

    # The sandbox has no trust for the signing CA unless we install it, so
    # anything other than NotSigned/HashMismatch is fine on the host but
    # won't necessarily survive a fresh sandbox without -AutoSign.
    $needsSelfSign = $sig.Status -in @(
        'NotSigned', 'HashMismatch', 'Incompatible', 'UnknownError'
    )

    return [pscustomobject]@{
        PackagePath    = $PackagePath
        Status         = $sig.Status
        SignerSubject  = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
        Thumbprint     = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
        NeedsSelfSign  = $needsSelfSign
    }
}


function New-MsixSelfSignedCertificate {
    <#
    .SYNOPSIS
        Creates a self-signed code-signing certificate whose Subject matches
        the MSIX manifest's Publisher, exports it as PFX + public .cer, and
        returns the paths.

    .DESCRIPTION
        Why the Subject MUST match Publisher: MSIX install fails with
        SignerSign() error 0x8007000B if the Authenticode Subject doesn't
        exactly equal the manifest's Identity.Publisher attribute, character
        for character.

        The PFX is written to a temp folder. The .cer is the public part you
        feed into the sandbox bootstrap to install into LocalMachine\Root +
        TrustedPeople.

    .PARAMETER PackagePath
        .msix whose Publisher is read to use as the cert Subject.

    .PARAMETER OutputFolder
        Where to place the cert files. Defaults to a temp folder.

    .PARAMETER FriendlyName
        Cert friendly name. Defaults to 'MSIX Debug Self-Signed'.

    .PARAMETER ValidYears
        Cert validity in years (default 1).

    .EXAMPLE
        $cert = New-MsixSelfSignedCertificate -PackagePath app.msix
        $cert.PfxPath, $cert.CertPath
    #>
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Generates a self-signed dev cert and exports it to files. Idempotent within a temp folder; not a destructive system change.')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSAvoidUsingConvertToSecureStringWithPlainText', '',
        Justification = 'Ephemeral per-run cryptographically-random GUID used as the PFX password for a throw-away debug cert. Never persisted to disk, never logged, and the PFX file lives in a temp folder for a single sandbox debug session.')]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [string]$OutputFolder,
        [string]$FriendlyName = 'MSIX Debug Self-Signed',
        [int]$ValidYears = 1
    )

    [xml]$manifest = Get-MsixManifest -Path $PackagePath
    $subject = $manifest.Package.Identity.Publisher
    if (-not $subject) {
        throw "Could not read Publisher from manifest at $PackagePath"
    }
    Write-MsixLog Info "Generating self-signed cert with Subject = $subject"

    if (-not $OutputFolder) {
        $base         = (Get-Item $PackagePath).BaseName
        $OutputFolder = Join-Path $env:TEMP "msix-selfsign-$base-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    }
    New-Item $OutputFolder -ItemType Directory -Force | Out-Null

    $cert = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $subject `
        -KeyUsage DigitalSignature `
        -FriendlyName $FriendlyName `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -NotAfter (Get-Date).AddYears($ValidYears) `
        -TextExtension @(
            '2.5.29.37={text}1.3.6.1.5.5.7.3.3',   # EKU: Code Signing
            '2.5.29.19={text}'                     # Basic Constraints: end-entity
        )

    $pfxPath  = Join-Path $OutputFolder 'debug-cert.pfx'
    $cerPath  = Join-Path $OutputFolder 'debug-cert.cer'
    $pwdPlain = [guid]::NewGuid().ToString('N')    # random per-run password
    $pwdSec   = ConvertTo-SecureString $pwdPlain -AsPlainText -Force

    Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $pwdSec | Out-Null
    Export-Certificate    -Cert $cert -FilePath $cerPath                    | Out-Null

    Write-MsixLog Info "Cert PFX:  $pfxPath"
    Write-MsixLog Info "Cert CER:  $cerPath"

    return [pscustomobject]@{
        Subject      = $subject
        Thumbprint   = $cert.Thumbprint
        PfxPath      = $pfxPath
        CertPath     = $cerPath
        PfxPassword  = $pwdSec       # SecureString — feed into Invoke-MsixSigning
        OutputFolder = $OutputFolder
    }
}


function Invoke-MsixSelfSignAndDebug {
    <#
    .SYNOPSIS
        End-to-end: detect if an .msix needs a self-signed cert, generate one
        matching the manifest Publisher, sign the package, return the cert +
        signed-package paths ready for Start-MsixSandbox -CertPath.

    .DESCRIPTION
        The .cer should be passed to New-MsixSandboxConfig -CertPath so the
        sandbox bootstrap installs it into LocalMachine\Root +
        TrustedPeople before installing the package. Start-MsixSandbox
        -AutoSign calls this automatically.

    .PARAMETER PackagePath
        .msix to sign in place.

    .PARAMETER Force
        Re-sign even if the package already has a valid signature.

    .EXAMPLE
        $r = Invoke-MsixSelfSignAndDebug -PackagePath app.msix
        Start-MsixSandbox -DropFolder (Split-Path $r.PackagePath) `
                          -PackageName (Split-Path $r.PackagePath -Leaf) `
                          -CertPath $r.CertPath
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [switch]$Force
    )

    $check = Test-MsixSignature -PackagePath $PackagePath
    if (-not $check.NeedsSelfSign -and -not $Force) {
        Write-MsixLog Info "Package signature is valid ($($check.Status)); skipping self-sign. Use -Force to override."
        return [pscustomobject]@{
            PackagePath = $PackagePath
            CertPath    = $null
            PfxPath     = $null
            Signed      = $false
            Reason      = "Already $($check.Status)"
        }
    }

    if (-not $PSCmdlet.ShouldProcess($PackagePath, 'Self-sign with auto-generated cert')) { return }

    $cert = New-MsixSelfSignedCertificate -PackagePath $PackagePath
    Invoke-MsixSigning -PackagePath $PackagePath -Pfx $cert.PfxPath -PfxPassword $cert.PfxPassword

    return [pscustomobject]@{
        PackagePath = $PackagePath
        CertPath    = $cert.CertPath
        PfxPath     = $cert.PfxPath
        Thumbprint  = $cert.Thumbprint
        Subject     = $cert.Subject
        Signed      = $true
    }
}
