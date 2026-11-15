BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Install-MsixPsfBinary extraction layout (nested zip-of-zips)
# -----------------------------------------------------------------------------
# Newer TMurgent PSF releases (v2026.07.01+) ship a zip whose payload is two
# nested zips (ReleasePsf.zip + DebugPsf.zip) rather than the launcher/runtime
# binaries directly. Install-MsixPsfBinary must expand the Release payload and
# fail fast if no PsfLauncher*.exe ever surfaces. Fully mocked (no network).
# =============================================================================

Describe 'Install-MsixPsfBinary handles the nested zip-of-zips layout' -Tag 'PsfBinaries' {

    BeforeEach {
        $script:Dest = Join-Path -Path $TestDrive -ChildPath "psf-$([guid]::NewGuid().ToString('N').Substring(0,6))"

        Mock -ModuleName MSIX Get-MsixToolsRoot { $TestDrive }
        Mock -ModuleName MSIX _MsixGitHubLatest {
            [pscustomobject]@{
                tag_name = 'v2026.07.01'
                assets   = @([pscustomobject]@{ name = 'PSF.zip'; browser_download_url = 'https://example/PSF.zip' })
            }
        }
        # The outer download just needs the file to exist (it's excluded from
        # the flat copy by path).
        Mock -ModuleName MSIX _MsixDownloadFile {
            Set-Content -LiteralPath $Destination -Value 'outer-zip-stub' -Encoding ascii
        }
        # Authenticode verification is exercised elsewhere; no-op here.
        Mock -ModuleName MSIX _MsixVerifyAuthenticodeFolder {}
    }

    It 'expands the nested Release payload so PsfLauncher binaries are installed' {
        # Simulate the layout: outer expand drops ReleasePsf.zip + DebugPsf.zip;
        # expanding ReleasePsf.zip drops the real launcher/runtime binaries.
        Mock -ModuleName MSIX _MsixExpandZip {
            param($ArchivePath, $DestinationPath)
            if ($ArchivePath -match 'ReleasePsf') {
                Set-Content -LiteralPath (Join-Path $DestinationPath 'PsfLauncher32.exe') -Value 'MZ' -Encoding ascii
                Set-Content -LiteralPath (Join-Path $DestinationPath 'PsfLauncher64.exe') -Value 'MZ' -Encoding ascii
                Set-Content -LiteralPath (Join-Path $DestinationPath 'PsfRuntime64.dll')  -Value 'MZ' -Encoding ascii
            } elseif ($ArchivePath -match 'DebugPsf') {
                Set-Content -LiteralPath (Join-Path $DestinationPath 'PsfLauncher64.pdb') -Value 'pdb' -Encoding ascii
            } else {
                # outer asset -> the two nested payload zips
                Set-Content -LiteralPath (Join-Path $DestinationPath 'ReleasePsf.zip') -Value 'z' -Encoding ascii
                Set-Content -LiteralPath (Join-Path $DestinationPath 'DebugPsf.zip')   -Value 'z' -Encoding ascii
            }
        }

        $r = Install-MsixPsfBinary -Destination $script:Dest
        $r.Version | Should -Be 'v2026.07.01'

        # The real binaries landed; the nested archives did NOT leak into the toolchain.
        Test-Path -LiteralPath (Join-Path $script:Dest 'PsfLauncher32.exe') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Dest 'PsfLauncher64.exe') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Dest 'PsfRuntime64.dll')  | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $script:Dest 'ReleasePsf.zip')    | Should -BeFalse
        Test-Path -LiteralPath (Join-Path $script:Dest 'DebugPsf.zip')      | Should -BeFalse
    }

    It 'still works for the OLD flat layout (binaries directly in the asset)' {
        Mock -ModuleName MSIX _MsixExpandZip {
            # Old releases: launcher binaries are right there in the outer zip.
            Set-Content -LiteralPath (Join-Path $DestinationPath 'PsfLauncher32.exe') -Value 'MZ' -Encoding ascii
            Set-Content -LiteralPath (Join-Path $DestinationPath 'PsfLauncher64.exe') -Value 'MZ' -Encoding ascii
        }
        $r = Install-MsixPsfBinary -Destination $script:Dest
        $r.Version | Should -Be 'v2026.07.01'
        Test-Path -LiteralPath (Join-Path $script:Dest 'PsfLauncher32.exe') | Should -BeTrue
        # Nested-expand path must NOT have run a second expand (no nested zips).
        Should -Invoke -ModuleName MSIX _MsixExpandZip -Times 1
    }

    It 'fails fast when no PsfLauncher*.exe surfaces (layout changed again)' {
        Mock -ModuleName MSIX _MsixExpandZip {
            # Neither a launcher nor a nested payload zip — an unrecognised layout.
            Set-Content -LiteralPath (Join-Path $DestinationPath 'README.txt') -Value 'surprise' -Encoding ascii
        }
        { Install-MsixPsfBinary -Destination $script:Dest -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*did not yield any PsfLauncher*'
        # Rolled back: the destination it created is gone.
        Test-Path -LiteralPath $script:Dest | Should -BeFalse
    }
}

# =============================================================================
# Pinning a PSF release, and what an unsigned release does
# -----------------------------------------------------------------------------
# TMurgent v2026.10.13 and v2026.11.14 ship PsfLauncher*, PsfRuntime* and every
# fixup UNSIGNED; only the Microsoft redistributables in the zip are signed.
# The latest release is therefore rejected (correctly - an unsigned binary is
# not a trust decision signers.json can make), so there has to be a way to pin
# the last signed release, and the rejection has to say which one that is.
# Fully mocked: GitHub, the download and Get-AuthenticodeSignature; extraction
# layout, the real folder verifier and the copy run as in production.
# =============================================================================

Describe 'Install-MsixPsfBinary -Version and unsigned releases' -Tag 'PsfBinaries', 'Security' {

    BeforeEach {
        $script:Dest = Join-Path -Path $TestDrive -ChildPath "psfv-$([guid]::NewGuid().ToString('N').Substring(0,6))"
        Mock -ModuleName MSIX Get-MsixToolsRoot { $TestDrive }
        Mock -ModuleName MSIX Write-MsixLog {}
        Mock -ModuleName MSIX _MsixGitHubLatest {
            [pscustomobject]@{
                tag_name = 'v2026.11.14'
                assets   = @([pscustomobject]@{ name = 'PSF.zip'; browser_download_url = 'https://example/latest.zip' })
            }
        }
        Mock -ModuleName MSIX _MsixGitHubRelease {
            [pscustomobject]@{
                tag_name = $Tag
                assets   = @([pscustomobject]@{ name = 'PSF.zip'; browser_download_url = "https://example/$Tag.zip" })
            }
        }
        Mock -ModuleName MSIX _MsixDownloadFile {
            Set-Content -LiteralPath $Destination -Value 'outer-zip-stub' -Encoding ascii
        }
        Mock -ModuleName MSIX _MsixExpandZip {
            Set-Content -LiteralPath (Join-Path -Path $DestinationPath -ChildPath 'PsfLauncher64.exe') -Value 'MZ' -Encoding ascii
            Set-Content -LiteralPath (Join-Path -Path $DestinationPath -ChildPath 'PsfRuntime64.dll') -Value 'MZ' -Encoding ascii
            Set-Content -LiteralPath (Join-Path -Path $DestinationPath -ChildPath 'msdia140.dll') -Value 'MZ' -Encoding ascii
        }
        # The v2026.10.13 / v2026.11.14 shape: PSF binaries unsigned, the
        # Microsoft redistributable signed.
        Mock -ModuleName MSIX Get-AuthenticodeSignature {
            $name = [IO.Path]::GetFileName([string]@($LiteralPath)[0])
            if ($name -like 'Psf*') {
                [pscustomobject]@{ Status = 'NotSigned'; StatusMessage = 'not signed'; SignerCertificate = $null }
            } else {
                [pscustomobject]@{
                    Status            = 'Valid'
                    StatusMessage     = 'Signature verified.'
                    SignerCertificate = [pscustomobject]@{
                        Subject    = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
                        Thumbprint = '1111111111111111111111111111111111111111'
                    }
                }
            }
        }
    }

    It '-Version installs that release tag instead of the latest' {
        Mock -ModuleName MSIX _MsixVerifyAuthenticodeFolder {}
        $r = Install-MsixPsfBinary -Destination $script:Dest -Version 'v2026.07.01'
        $r.Version | Should -Be 'v2026.07.01'
        (Get-Content -LiteralPath (Join-Path -Path $script:Dest -ChildPath 'psf.version') -Raw).Trim() | Should -Be 'v2026.07.01'
        Should -Invoke -ModuleName MSIX _MsixGitHubRelease -Times 1 -ParameterFilter { $Tag -eq 'v2026.07.01' }
        Should -Invoke -ModuleName MSIX _MsixGitHubLatest -Times 0
    }

    It 'rejects an unsigned release, installs nothing, and offers the last verified release' {
        $knownGood = InModuleScope MSIX { $script:PsfKnownGoodVersion }
        $err = $null
        try { $null = Install-MsixPsfBinary -Destination $script:Dest } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $msg = $err.Exception.Message
        $msg | Should -BeLike '*TMurgent PSF v2026.11.14 was NOT installed: nothing was copied*'
        $msg | Should -BeLike '*PSF v2026.11.14: 2 of 3 binaries rejected*'
        $msg | Should -BeLike '*PsfLauncher64.exe: signature status NotSigned*'
        $msg | Should -BeLike "*Install-MsixPsfBinary -Version $knownGood -Destination*"
        $msg | Should -BeLike '*Initialize-MsixToolchain -Skip Psf*'
        $msg | Should -BeLike '*cannot be made trustworthy through signers.json*'
        $msg | Should -Not -BeLike '*add it to signers.json*' -Because 'an unsigned file is not a trust decision signers.json can make'
        @($err.Exception.Data['MsixAuthenticodeRejected']).Count | Should -Be 2
        Test-Path -LiteralPath $script:Dest | Should -BeFalse -Because 'the destination this call created is rolled back'
    }

    It 'leaves the pinned install in place when the latest release is rejected' {
        # What happens when Initialize-MsixToolchain (latest) runs after a pin.
        New-Item -ItemType Directory -Path $script:Dest -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $script:Dest -ChildPath 'psf.version') -Value 'v2026.07.01' -Encoding ascii
        Set-Content -LiteralPath (Join-Path -Path $script:Dest -ChildPath 'PsfLauncher64.exe') -Value 'previous' -Encoding ascii
        $err = $null
        try { $null = Install-MsixPsfBinary -Destination $script:Dest -Force } catch { $err = $_ }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -BeLike '*already installed there (v2026.07.01) were left as they were*'
        (Get-Content -LiteralPath (Join-Path -Path $script:Dest -ChildPath 'PsfLauncher64.exe') -Raw).Trim() | Should -Be 'previous'
        (Get-Content -LiteralPath (Join-Path -Path $script:Dest -ChildPath 'psf.version') -Raw).Trim() | Should -Be 'v2026.07.01'
    }

    It 'Update-MsixPsfBinary -Version is a no-op when that release is already installed' {
        New-Item -ItemType Directory -Path $script:Dest -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $script:Dest -ChildPath 'psf.version') -Value 'v2026.07.01' -Encoding ascii
        Set-Content -LiteralPath (Join-Path -Path $script:Dest -ChildPath 'PsfLauncher32.exe') -Value 'MZ' -Encoding ascii
        $r = Update-MsixPsfBinary -Destination $script:Dest -Version 'v2026.07.01'
        $r.Version | Should -Be 'v2026.07.01'
        Should -Invoke -ModuleName MSIX _MsixDownloadFile -Times 0
        Should -Invoke -ModuleName MSIX _MsixGitHubLatest -Times 0 -Because 'a pinned release needs no latest-release query'
    }

    It 'Update-MsixPsfBinary -Version moves an existing install to the pinned release' {
        Mock -ModuleName MSIX _MsixVerifyAuthenticodeFolder {}
        New-Item -ItemType Directory -Path $script:Dest -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $script:Dest -ChildPath 'psf.version') -Value 'v2026.05.01' -Encoding ascii
        $r = Update-MsixPsfBinary -Destination $script:Dest -Version 'v2026.07.01'
        $r.Version | Should -Be 'v2026.07.01'
        Should -Invoke -ModuleName MSIX _MsixGitHubRelease -Times 1 -ParameterFilter { $Tag -eq 'v2026.07.01' }
        Should -Invoke -ModuleName MSIX _MsixGitHubLatest -Times 0
    }
}

Describe '_MsixGitHubRelease' -Tag 'PsfBinaries', 'Security' {

    It 'escapes the pinned tag before it goes into the GitHub API path' {
        $uri = InModuleScope MSIX {
            $script:capturedUri = $null
            # -Uri binds as [System.Uri], whose ToString() unescapes: keep the
            # string the module actually built.
            Mock Invoke-RestMethod {
                $script:capturedUri = if ($Uri -is [uri]) { $Uri.OriginalString } else { [string]$Uri }
                [pscustomobject]@{ tag_name = 'x'; assets = @() }
            }
            $null = _MsixGitHubRelease -Repo 'TimMangan/MSIX-PackageSupportFramework' -Tag '../../../user'
            $script:capturedUri
        }
        $uri | Should -Be 'https://api.github.com/repos/TimMangan/MSIX-PackageSupportFramework/releases/tags/..%2F..%2F..%2Fuser'
    }
}
