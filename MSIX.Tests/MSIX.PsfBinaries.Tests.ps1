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
