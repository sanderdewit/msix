function Invoke-MsixSigning {
    <#
    .SYNOPSIS
        Signs an MSIX package using one of three signer backends: local
        signtool.exe (default), Azure Trusted Signing, or AzureSignTool
        (Azure Key Vault HSM).

    .DESCRIPTION
        Backends:

          SignTool       (default) — local signtool.exe, optional PFX or
                                       /a auto-store selection. Suitable for
                                       dev / sandbox / self-signed flows.
                                       WARNING: when -Pfx + -PfxPassword is
                                       used, the password is passed on the
                                       process command line which other
                                       processes can read via WMI. For
                                       production secrets use TrustedSigning
                                       or AzureSignTool.

          TrustedSigning           — signtool /dlib + Azure CodeSigning Dlib
                                       (Azure Trusted Signing service). Account,
                                       profile, and endpoint are written to a
                                       temp JSON metadata file that is deleted
                                       in a finally block. Recommended for
                                       production.

          AzureSignTool            — AzureSignTool.exe targeting an Azure Key
                                       Vault HSM. Service-principal credentials
                                       are decrypted only at the CLI boundary.

        All backends timestamp with SHA-256.

    .PARAMETER PackagePath
        Path to the .msix file to sign.

    .PARAMETER Pfx
        (SignTool only.) Path to a PFX certificate file. Omit to use the
        machine cert store with /a.

    .PARAMETER PfxPassword
        (SignTool only, required when -Pfx is specified.) SecureString password
        for the PFX file.

    .PARAMETER TrustedSigningAccount
        (TrustedSigning only.) The Azure Trusted Signing CodeSigningAccount name.

    .PARAMETER TrustedSigningProfile
        (TrustedSigning only.) The CertificateProfile name inside the account.

    .PARAMETER TrustedSigningEndpoint
        (TrustedSigning only.) Regional endpoint URL,
        e.g. 'https://eus.codesigning.azure.net'.

    .PARAMETER TrustedSigningClientDll
        (TrustedSigning only.) Path to Azure.CodeSigning.Dlib.dll. When
        omitted, $ToolsRoot\Tools\TrustedSigning\Azure.CodeSigning.Dlib.dll is
        tried; a clear install hint is thrown if neither resolves.

    .PARAMETER KeyVaultUrl
        (AzureSignTool only.) Key Vault URL, e.g. 'https://my-vault.vault.azure.net'.

    .PARAMETER KeyVaultCertificate
        (AzureSignTool only.) Certificate name inside the Key Vault.

    .PARAMETER KeyVaultTenantId
        (AzureSignTool only, optional.) Azure AD tenant id for SP auth. When
        omitted, AzureSignTool falls back to managed identity / interactive.

    .PARAMETER KeyVaultClientId
        (AzureSignTool only, optional.) Service-principal client id.

    .PARAMETER KeyVaultClientSecret
        (AzureSignTool only, optional.) SecureString service-principal
        secret. Decrypted via BSTR/ZeroFreeBSTR only at the signtool CLI
        boundary.

    .PARAMETER TimestampUrl
        RFC 3161 timestamp server URL. Defaults to DigiCert.

    .PARAMETER Signer
        Which backend to use. See top-level description.

    .EXAMPLE
        # Local PFX (dev / self-signed)
        $pw = Read-Host -AsSecureString
        Invoke-MsixSigning -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Machine store (no PFX)
        Invoke-MsixSigning -PackagePath app.msix

    .EXAMPLE
        # Azure Trusted Signing (production)
        Invoke-MsixSigning -PackagePath app.msix -Signer TrustedSigning `
            -TrustedSigningAccount  'MyAccount' `
            -TrustedSigningProfile  'MyProfile' `
            -TrustedSigningEndpoint 'https://eus.codesigning.azure.net'

    .EXAMPLE
        # Azure Key Vault via AzureSignTool (managed identity)
        Invoke-MsixSigning -PackagePath app.msix -Signer AzureSignTool `
            -KeyVaultUrl 'https://my-vault.vault.azure.net' `
            -KeyVaultCertificate 'msix-prod'
    #>
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'SignTool')]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,

        # -Signer is shared across all sets. ParameterSetName auto-resolves
        # when set-unique parameters (-Pfx, -TrustedSigningAccount,
        # -KeyVaultUrl …) are supplied; otherwise SignTool is the default.
        [Parameter(ParameterSetName = 'SignTool')]
        [Parameter(ParameterSetName = 'SignToolPfx')]
        [Parameter(ParameterSetName = 'TrustedSigning')]
        [Parameter(ParameterSetName = 'AzureSignTool')]
        [ValidateSet('SignTool','TrustedSigning','AzureSignTool')]
        [string]$Signer = 'SignTool',

        # --- PFX (SignTool with PFX) ---
        [Parameter(ParameterSetName = 'SignToolPfx', Mandatory)]
        [string]$Pfx,
        [Parameter(ParameterSetName = 'SignToolPfx', Mandatory)]
        [SecureString]$PfxPassword,

        # --- Trusted Signing ---
        [Parameter(ParameterSetName = 'TrustedSigning', Mandatory)]
        [string]$TrustedSigningAccount,
        [Parameter(ParameterSetName = 'TrustedSigning', Mandatory)]
        [string]$TrustedSigningProfile,
        [Parameter(ParameterSetName = 'TrustedSigning', Mandatory)]
        [string]$TrustedSigningEndpoint,
        [Parameter(ParameterSetName = 'TrustedSigning')]
        [string]$TrustedSigningClientDll,

        # --- AzureSignTool ---
        [Parameter(ParameterSetName = 'AzureSignTool', Mandatory)]
        [string]$KeyVaultUrl,
        [Parameter(ParameterSetName = 'AzureSignTool', Mandatory)]
        [string]$KeyVaultCertificate,
        [Parameter(ParameterSetName = 'AzureSignTool')]
        [string]$KeyVaultTenantId,
        [Parameter(ParameterSetName = 'AzureSignTool')]
        [string]$KeyVaultClientId,
        [Parameter(ParameterSetName = 'AzureSignTool')]
        [SecureString]$KeyVaultClientSecret,

        [string]$TimestampUrl = 'http://timestamp.digicert.com'
    )

    # ParameterSetName drives the backend; fall back to the explicit -Signer
    # when caller used the default SignTool set.
    $effectiveSigner = switch ($PSCmdlet.ParameterSetName) {
        'SignToolPfx'    { 'SignTool' }
        'TrustedSigning' { 'TrustedSigning' }
        'AzureSignTool'  { 'AzureSignTool' }
        default          { $Signer }
    }

    # Emit security warning before any file I/O so it is always visible even
    # when PackagePath does not yet exist (e.g. -WhatIf / staging scenarios).
    # Uses the real Warning stream so callers can capture it via -WarningVariable.
    if ($effectiveSigner -eq 'SignTool' -and $Pfx) {
        Write-Warning 'SignTool /p exposes the PFX password on the process command line (visible to other processes via WMI). For mission-critical environments, use -Signer TrustedSigning.'
    }

    $toolsRoot = Get-MsixToolsRoot
    $signtool  = Join-Path $toolsRoot 'Tools\signtool.exe'
    $fileinfo  = Get-Item $PackagePath

    Write-MsixLog Info "Signing: $($fileinfo.Name) (backend: $effectiveSigner)"

    switch ($effectiveSigner) {

        # =====================================================================
        # SignTool (local) — current default behaviour
        # =====================================================================
        'SignTool' {
            $sigArgs = if ($Pfx) {

                $cert = Get-Item $Pfx
                # Decrypt SecureString only at the CLI boundary — never stored in a plain variable
                $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
                try {
                    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                    @('sign', '/v', '/tr', $TimestampUrl, '/td', 'sha256', '/fd', 'sha256',
                      '/f', $cert.FullName, '/p', $plain, $fileinfo.FullName)
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
            } else {
                @('sign', '/v', '/tr', $TimestampUrl, '/td', 'sha256', '/fd', 'sha256',
                  '/a', $fileinfo.FullName)
            }

            if ($PSCmdlet.ShouldProcess($fileinfo.FullName, 'Sign with signtool')) {
                $r = Invoke-MsixProcess $signtool -ArgumentList $sigArgs
                if ($r.ExitCode -ne 0) {
                    $detail = if ($r.StdErr) { $r.StdErr } else { $r.StdOut }
                    throw "signtool failed (exit $($r.ExitCode)): $detail`nCheck: Microsoft-Windows-AppxPackagingOM event log."
                } else {
                    Write-MsixLog Info "Signed successfully: $($fileinfo.Name)"
                }
            }
        }

        # =====================================================================
        # Azure Trusted Signing — signtool /dlib + Azure.CodeSigning.Dlib.dll
        # =====================================================================
        'TrustedSigning' {
            if (-not $TrustedSigningAccount -or -not $TrustedSigningProfile -or -not $TrustedSigningEndpoint) {
                throw "-Signer TrustedSigning requires -TrustedSigningAccount, -TrustedSigningProfile, and -TrustedSigningEndpoint."
            }
            # Resolve the dlib path: explicit param, then bundled fallback.
            $resolvedDlib = $TrustedSigningClientDll
            if (-not $resolvedDlib) {
                $candidate = Join-Path $toolsRoot 'Tools\TrustedSigning\Azure.CodeSigning.Dlib.dll'
                if (Test-Path -LiteralPath $candidate) { $resolvedDlib = $candidate }
            }
            if (-not $resolvedDlib -or -not (Test-Path -LiteralPath $resolvedDlib)) {
                throw "Azure.CodeSigning.Dlib.dll not found. Pass -TrustedSigningClientDll <path>, or stage it at:`n  $(Join-Path $toolsRoot 'Tools\TrustedSigning\Azure.CodeSigning.Dlib.dll')`nInstall via: dotnet tool install --global TrustedSigning.Client"
            }

            Write-MsixLog Info "TrustedSigning account=$TrustedSigningAccount profile=$TrustedSigningProfile endpoint=$TrustedSigningEndpoint"

            $metadataPath = Join-Path $env:TEMP "ts-metadata-$([guid]::NewGuid().ToString('N').Substring(0,8)).json"
            $metadata = @{
                Endpoint               = $TrustedSigningEndpoint
                CodeSigningAccountName = $TrustedSigningAccount
                CertificateProfileName = $TrustedSigningProfile
            } | ConvertTo-Json -Compress

            try {
                Set-Content -LiteralPath $metadataPath -Value $metadata -NoNewline -Encoding utf8

                $sigArgs = @('sign', '/v', '/tr', $TimestampUrl, '/td', 'sha256', '/fd', 'sha256',
                             '/dlib', $resolvedDlib, '/dmdf', $metadataPath, $fileinfo.FullName)

                if ($PSCmdlet.ShouldProcess($fileinfo.FullName, 'Sign with signtool (Trusted Signing)')) {
                    $r = Invoke-MsixProcess $signtool -ArgumentList $sigArgs
                    if ($r.ExitCode -ne 0) {
                        $detail = if ($r.StdErr) { $r.StdErr } else { $r.StdOut }
                        throw "signtool (TrustedSigning) failed (exit $($r.ExitCode)): $detail"
                    } else {
                        Write-MsixLog Info "Signed successfully via Trusted Signing: $($fileinfo.Name)"
                    }
                }
            } finally {
                Remove-Item -LiteralPath $metadataPath -Force -ErrorAction SilentlyContinue
            }
        }

        # =====================================================================
        # AzureSignTool — Azure Key Vault HSM
        # =====================================================================
        'AzureSignTool' {
            if (-not $KeyVaultUrl -or -not $KeyVaultCertificate) {
                throw "-Signer AzureSignTool requires -KeyVaultUrl and -KeyVaultCertificate."
            }
            $azst = $null
            $cmd  = Get-Command 'AzureSignTool.exe' -ErrorAction SilentlyContinue
            if ($cmd) { $azst = $cmd.Source }
            if (-not $azst) {
                $candidate = Join-Path $toolsRoot 'Tools\AzureSignTool\AzureSignTool.exe'
                if (Test-Path -LiteralPath $candidate) { $azst = $candidate }
            }
            if (-not $azst) {
                throw "AzureSignTool.exe not found in PATH or at $(Join-Path $toolsRoot 'Tools\AzureSignTool\AzureSignTool.exe').`nInstall via: dotnet tool install --global AzureSignTool"
            }

            Write-MsixLog Info "AzureSignTool vault=$KeyVaultUrl cert=$KeyVaultCertificate"

            # Build base arguments — omit auth-mode args when not provided so
            # AzureSignTool falls back to managed identity / interactive auth.
            $azArgsBase = @(
                'sign',
                '--timestamp-rfc3161',  $TimestampUrl,
                '--timestamp-digest',   'sha256',
                '--file-digest',        'sha256',
                '--azure-key-vault-url',         $KeyVaultUrl,
                '--azure-key-vault-certificate', $KeyVaultCertificate
            )
            if ($KeyVaultTenantId) {
                $azArgsBase += @('--azure-key-vault-tenant-id', $KeyVaultTenantId)
            }
            if ($KeyVaultClientId) {
                $azArgsBase += @('--azure-key-vault-client-id', $KeyVaultClientId)
            }

            $bstr = [IntPtr]::Zero
            try {
                if ($KeyVaultClientSecret) {
                    # Decrypt SecureString only here, append immediately.
                    $bstr  = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeyVaultClientSecret)
                    $plain = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
                    $azArgsBase += @('--azure-key-vault-client-secret', $plain)
                }
                $azArgsBase += $fileinfo.FullName

                if ($PSCmdlet.ShouldProcess($fileinfo.FullName, 'Sign with AzureSignTool (Key Vault)')) {
                    $r = Invoke-MsixProcess $azst -ArgumentList $azArgsBase
                    if ($r.ExitCode -ne 0) {
                        $detail = if ($r.StdErr) { $r.StdErr } else { $r.StdOut }
                        throw "AzureSignTool failed (exit $($r.ExitCode)): $detail"
                    } else {
                        Write-MsixLog Info "Signed successfully via AzureSignTool: $($fileinfo.Name)"
                    }
                }
            } finally {
                if ($bstr -ne [IntPtr]::Zero) {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
            }
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
    # Drop the plaintext reference immediately. The SecureString is what we
    # keep; the GUID-derived plaintext is low-value (ephemeral, throw-away
    # cert) but the hygiene principle is identical regardless of value.
    $pwdPlain = $null

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
