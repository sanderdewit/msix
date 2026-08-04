BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Authenticode REJECTION (issue #152)
# -----------------------------------------------------------------------------
# _MsixVerifyAuthenticode is the control that stops a planted toolchain binary
# from being executed, and signtool signs the output package - so a bypass here
# is a bypass of everything.
#
# It was invoked by two existing tests, but BOTH mocked Get-AuthenticodeSignature
# to return Status = 'Valid', so the `if ($sig.Status -ne 'Valid') { throw }`
# branch had never executed. The control was only ever tested doing nothing.
# These drive every rejection reason.
# =============================================================================

BeforeDiscovery {
    # Statuses Get-AuthenticodeSignature can return that must be refused.
    $script:BadStatuses = @(
        'NotSigned', 'HashMismatch', 'NotTrusted', 'UnknownError',
        'Incompatible', 'NotSupportedFileFormat'
    ) | ForEach-Object { @{ Status = $_ } }
}

Describe 'Toolchain Authenticode verification rejects untrusted binaries' -Tag 'Security' {

    BeforeAll {
        $script:Probe = Join-Path ([IO.Path]::GetTempPath()) ("auth-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.exe')
        Set-Content -LiteralPath $script:Probe -Value 'stub' -Encoding ascii
    }
    AfterAll { Remove-Item -LiteralPath $script:Probe -Force -ErrorAction SilentlyContinue }

    It 'throws for signature status <Status>' -ForEach $script:BadStatuses {
        $threw = InModuleScope MSIX -Parameters @{ Status = $Status; Probe = $script:Probe } {
            param($Status, $Probe)
            $badStatus = $Status
            $path      = $Probe
            Mock Get-AuthenticodeSignature {
                [pscustomobject]@{ Status = $badStatus; StatusMessage = 'mocked'; SignerCertificate = $null }
            }
            try { $null = _MsixVerifyAuthenticode -Path $path -ToolName 'probe'; $false } catch { $true }
        }
        $threw | Should -BeTrue -Because "status '$Status' must never be treated as trusted"
    }

    It 'throws when the signature is Valid but the publisher is not on the allowlist' {
        $threw = InModuleScope MSIX -Parameters @{ Probe = $script:Probe } {
            param($Probe)
            $path = $Probe
            Mock Get-AuthenticodeSignature {
                [pscustomobject]@{
                    Status            = 'Valid'
                    StatusMessage     = 'ok'
                    SignerCertificate = [pscustomobject]@{
                        Subject    = 'CN=Definitely Not Microsoft, O=Evil, C=XX'
                        Thumbprint = '0000000000000000000000000000000000000000'
                    }
                }
            }
            try { $null = _MsixVerifyAuthenticode -Path $path -ToolName 'probe'; $false } catch { $true }
        }
        $threw | Should -BeTrue -Because 'a valid signature from an untrusted publisher is still untrusted'
    }

    It 'accepts a Valid signature from an allowlisted publisher' {
        # The positive control: proves the rejections above are not simply
        # "throws for everything".
        $ok = InModuleScope MSIX -Parameters @{ Probe = $script:Probe } {
            param($Probe)
            $path = $Probe
            Mock Get-AuthenticodeSignature {
                [pscustomobject]@{
                    Status            = 'Valid'
                    StatusMessage     = 'ok'
                    SignerCertificate = [pscustomobject]@{
                        Subject    = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
                        Thumbprint = '1111111111111111111111111111111111111111'
                    }
                }
            }
            try { $null = _MsixVerifyAuthenticode -Path $path -ToolName 'probe'; $true } catch { $false }
        }
        $ok | Should -BeTrue
    }

    It 'is fail-closed when the file does not exist' {
        $threw = InModuleScope MSIX {
            $missing = Join-Path ([IO.Path]::GetTempPath()) ("nope-" + [guid]::NewGuid().ToString('N') + '.exe')
            try { $null = _MsixVerifyAuthenticode -Path $missing -ToolName 'probe'; $false } catch { $true }
        }
        $threw | Should -BeTrue
    }
}

Describe 'The trusted-publisher allowlist is fail-closed' -Tag 'Security' {

    It 'ships a non-empty allowlist, every entry anchored to a CN= prefix' {
        # A missing/malformed signers.json must abort module import rather than
        # degrade to "no allowlist" - verify the shipped file is well-formed.
        $signers = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'signers.json') -Raw | ConvertFrom-Json
        $entries = @($signers.publishers)
        $entries.Count | Should -BeGreaterThan 0
        foreach ($e in $entries) {
            $e.subjectPrefix | Should -Match '^CN=.+,$' -Because 'the trailing comma is what stops "CN=Microsoft Corporation Evil Ltd" matching'
        }
    }
}
