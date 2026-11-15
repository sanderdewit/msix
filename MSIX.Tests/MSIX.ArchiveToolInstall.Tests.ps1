BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    # A real zip with one stub file per relative path. The installers only
    # extract, verify and copy, so stubs are enough. Each file's content names
    # the file and a version, so a test can tell a fresh copy from a stale one.
    function script:New-FakeToolArchive {
        param(
            [Parameter(Mandatory)][string]$WorkDir,
            [Parameter(Mandatory)][string[]]$Files,
            [string]$Content = 'v1'
        )
        $id  = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $src = Join-Path -Path $WorkDir -ChildPath "archive-src-$id"
        foreach ($f in $Files) {
            $path = Join-Path -Path $src -ChildPath $f
            New-Item -ItemType Directory -Path ([System.IO.Path]::GetDirectoryName($path)) -Force | Out-Null
            Set-Content -LiteralPath $path -Value "$Content $f" -Encoding ascii
        }
        $zip = Join-Path -Path $WorkDir -ChildPath "archive-$id.zip"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($src, $zip)
        return $zip
    }

    # Destination must hold exactly the archive's files, with the expected
    # content, plus the install marker. A copied stage folder, a leftover
    # download or a nested second copy all fail one of these checks.
    function script:Assert-ToolInstalled {
        param(
            [Parameter(Mandatory)][string]$Destination,
            [Parameter(Mandatory)][string[]]$Files,
            [Parameter(Mandatory)][string]$Marker,
            [string]$Content = 'v1'
        )
        foreach ($f in $Files) {
            $path = Join-Path -Path $Destination -ChildPath $f
            Test-Path -LiteralPath $path -PathType Leaf | Should -BeTrue -Because "$f is in the archive"
            (Get-Content -LiteralPath $path -Raw).Trim() | Should -Be "$Content $f"
        }
        $markerPath = Join-Path -Path $Destination -ChildPath $Marker
        Test-Path -LiteralPath $markerPath -PathType Leaf | Should -BeTrue
        { [datetime](Get-Content -LiteralPath $markerPath -Raw).Trim() } | Should -Not -Throw
        @(Get-ChildItem -LiteralPath $Destination -Recurse -File -Force).Count |
            Should -Be ($Files.Count + 1) -Because 'the destination holds the archive files and the marker, nothing else'
    }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Install-MsixProcMon / Install-MsixDebugView / Install-MsixMgr all go through
# _MsixInstallArchiveTool: download a zip, Authenticode-verify the extracted
# stage, copy the stage into the destination, write the marker.
#
# From v0.71.0 the copy passed '*' to Copy-Item -LiteralPath, which never
# expands wildcards, so it copied nothing. Windows PowerShell 5.1 raised no
# error. PowerShell 7 raised "Cannot find path '...\extracted\*'" as a
# non-terminating error, which rolled the install back only under
# ErrorActionPreference Stop. Otherwise the marker was written anyway and the
# tool looked installed with nothing but the marker in its folder. CI
# provisions the toolchain with these three skipped and no test ran them.
#
# Nothing here touches the network: the download and Get-AuthenticodeSignature
# are mocked. Extraction of a real zip, verification, the copy, the marker and
# the PostInstall hooks run for real.
# =============================================================================

Describe 'Archive-tool installers copy the verified archive into the destination' -Tag 'PsfBinaries', 'Toolchain' {

    BeforeAll {
        # PostInstall exports these; put back whatever the session had.
        $script:SavedToolEnv = @{}
        foreach ($name in 'MSIX_DEBUGVIEW_PATH', 'MSIX_PROCMON_PATH', 'MSIX_MSIXMGR_PATH') {
            $script:SavedToolEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        }
    }
    AfterAll {
        foreach ($name in $script:SavedToolEnv.Keys) {
            [Environment]::SetEnvironmentVariable($name, $script:SavedToolEnv[$name], 'Process')
        }
    }

    BeforeEach {
        InModuleScope MSIX {
            Mock Write-MsixLog {}
            # Valid and allowlisted, except file names listed in
            # $script:TestUnsigned, which come back NotSigned.
            Mock Get-AuthenticodeSignature {
                $name = [System.IO.Path]::GetFileName([string]@($LiteralPath)[0])
                if (@($script:TestUnsigned) -contains $name) {
                    return [pscustomobject]@{ Status = 'NotSigned'; StatusMessage = 'mocked: not signed'; SignerCertificate = $null }
                }
                [pscustomobject]@{
                    Status            = 'Valid'
                    StatusMessage     = 'mocked'
                    SignerCertificate = [pscustomobject]@{
                        Subject    = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
                        Thumbprint = '1111111111111111111111111111111111111111'
                    }
                }
            }
            # The only network call: hand back the test's zip instead.
            Mock _MsixDownloadFile { Copy-Item -LiteralPath $script:TestArchive -Destination $Destination -Force }
        }
    }
    AfterEach {
        InModuleScope MSIX {
            Remove-Variable -Name TestArchive, TestUnsigned, TestDest -Scope Script -ErrorAction SilentlyContinue
        }
    }

    It 'Install-MsixDebugView copies every file of the archive into the destination' {
        # The DebugView.zip layout: flat, three executables plus help and EULA.
        $files = @('Dbgview.exe', 'dbgview64.exe', 'dbgview64a.exe', 'Dbgview.chm', 'Eula.txt')
        $zip   = New-FakeToolArchive -WorkDir $TestDrive -Files $files
        $dest  = Join-Path -Path $TestDrive -ChildPath 'debugview'
        $r = InModuleScope MSIX -Parameters @{ Zip = $zip; Dest = $dest } {
            param($Zip, $Dest)
            $script:TestArchive = $Zip
            Install-MsixDebugView -Destination $Dest
        }
        $r.Updated | Should -BeTrue
        $r.Path    | Should -Be $dest
        Assert-ToolInstalled -Destination $dest -Files $files -Marker 'debugview.installed'
        # PostInstall ran after the copy, so it found the 64-bit build.
        $env:MSIX_DEBUGVIEW_PATH | Should -Be (Join-Path -Path $dest -ChildPath 'Dbgview64.exe')
        # The three executables were verified; the .chm and .txt are not binaries.
        Should -Invoke -CommandName Get-AuthenticodeSignature -ModuleName MSIX -Times 3 -Exactly
    }

    It 'Install-MsixProcMon copies Process Monitor into the destination' {
        $files = @('Procmon.exe', 'Procmon64.exe', 'Procmon64a.exe', 'procmon.chm', 'Eula.txt')
        $zip   = New-FakeToolArchive -WorkDir $TestDrive -Files $files
        $dest  = Join-Path -Path $TestDrive -ChildPath 'procmon'
        $r = InModuleScope MSIX -Parameters @{ Zip = $zip; Dest = $dest } {
            param($Zip, $Dest)
            $script:TestArchive = $Zip
            Install-MsixProcMon -Destination $Dest
        }
        $r.Updated | Should -BeTrue
        Assert-ToolInstalled -Destination $dest -Files $files -Marker 'procmon.installed'
        $env:MSIX_PROCMON_PATH | Should -Be (Join-Path -Path $dest -ChildPath 'Procmon.exe')
        Should -Invoke -CommandName Get-AuthenticodeSignature -ModuleName MSIX -Times 3 -Exactly
    }

    It 'Install-MsixMgr copies the nested per-architecture layout' {
        $files = @('x64\msixmgr.exe', 'x64\msix.dll', 'x86\msixmgr.exe', 'x86\msix.dll')
        $zip   = New-FakeToolArchive -WorkDir $TestDrive -Files $files
        $dest  = Join-Path -Path $TestDrive -ChildPath 'msixmgr'
        $r = InModuleScope MSIX -Parameters @{ Zip = $zip; Dest = $dest } {
            param($Zip, $Dest)
            $script:TestArchive = $Zip
            Install-MsixMgr -Destination $Dest -WarningAction SilentlyContinue
        }
        $r.Updated | Should -BeTrue
        Assert-ToolInstalled -Destination $dest -Files $files -Marker 'msixmgr.installed'
        Test-Path -LiteralPath $env:MSIX_MSIXMGR_PATH -PathType Leaf | Should -BeTrue
        [System.IO.Path]::GetFileName($env:MSIX_MSIXMGR_PATH) | Should -Be 'msixmgr.exe'
        # msixmgr's documented exception (microsoft/msix-packaging#710): no
        # Authenticode check unless -VerifyAuthenticode.
        Should -Invoke -CommandName Get-AuthenticodeSignature -ModuleName MSIX -Times 0 -Exactly
    }

    It '-Force reinstalls over an existing install, replacing files in place' {
        $files = @('x64\msixmgr.exe', 'x64\msix.dll', 'x86\msixmgr.exe')
        $v1   = New-FakeToolArchive -WorkDir $TestDrive -Files $files -Content 'v1'
        $v2   = New-FakeToolArchive -WorkDir $TestDrive -Files $files -Content 'v2'
        $dest = Join-Path -Path $TestDrive -ChildPath 'msixmgr-force'
        $r = InModuleScope MSIX -Parameters @{ V1 = $v1; V2 = $v2; Dest = $dest } {
            param($V1, $V2, $Dest)
            $script:TestArchive = $V1
            $null = Install-MsixMgr -Destination $Dest -WarningAction SilentlyContinue
            $script:TestArchive = $V2
            Install-MsixMgr -Destination $Dest -Force -WarningAction SilentlyContinue
        }
        $r.Updated | Should -BeTrue
        # Same files with the new content: existing subfolders were merged into,
        # not copied inside themselves (no x64\x64).
        Assert-ToolInstalled -Destination $dest -Files $files -Marker 'msixmgr.installed' -Content 'v2'
    }

    It 'installs into a destination whose path contains wildcard characters' {
        $files = @('Dbgview.exe', 'dbgview64.exe', 'Eula.txt')
        $zip   = New-FakeToolArchive -WorkDir $TestDrive -Files $files
        $dest  = Join-Path -Path $TestDrive -ChildPath 'tools[1]\debugview'
        $r = InModuleScope MSIX -Parameters @{ Zip = $zip; Dest = $dest } {
            param($Zip, $Dest)
            $script:TestArchive = $Zip
            Install-MsixDebugView -Destination $Dest
        }
        $r.Updated | Should -BeTrue
        Assert-ToolInstalled -Destination $dest -Files $files -Marker 'debugview.installed'
    }

    It 'rejects an unsigned binary before copying: no destination, no marker' {
        $files = @('Dbgview.exe', 'dbgview64.exe', 'Eula.txt')
        $zip   = New-FakeToolArchive -WorkDir $TestDrive -Files $files
        $dest  = Join-Path -Path $TestDrive -ChildPath 'debugview-rejected'
        $err = InModuleScope MSIX -Parameters @{ Zip = $zip; Dest = $dest } {
            param($Zip, $Dest)
            $script:TestArchive  = $Zip
            $script:TestUnsigned = @('dbgview64.exe')
            try { $null = Install-MsixDebugView -Destination $Dest; $null } catch { $_ }
        }
        $err | Should -Not -BeNullOrEmpty -Because 'an unsigned binary must fail the install'
        $err.Exception.Message | Should -BeLike '*Authenticode verification FAILED*'
        Test-Path -LiteralPath $dest | Should -BeFalse -Because 'the destination did not exist before the call, so the rollback removes it'
    }

    It 'fails instead of writing the marker when the copy fails' {
        $files = @('Dbgview.exe', 'dbgview64.exe', 'Eula.txt')
        $zip   = New-FakeToolArchive -WorkDir $TestDrive -Files $files
        $dest  = Join-Path -Path $TestDrive -ChildPath 'debugview-copy-fails'
        $err = InModuleScope MSIX -Parameters @{ Zip = $zip; Dest = $dest } {
            param($Zip, $Dest)
            $script:TestArchive = $Zip
            $script:TestDest    = $Dest
            # A non-terminating error, the way the '*' bug and a locked file
            # both surface. Copies elsewhere (the mocked download) are real.
            Mock Copy-Item -ParameterFilter { $Destination -eq $script:TestDest } {
                Write-Error -Message 'mocked: the file is in use'
            }
            try { $null = Install-MsixDebugView -Destination $Dest; $null } catch { $_ }
        }
        $err | Should -Not -BeNullOrEmpty -Because 'a copy that did not happen must not pass as an install'
        Test-Path -LiteralPath $dest | Should -BeFalse -Because 'the destination did not exist before the call, so the rollback removes it, marker included'
    }

    It 'reinstalls a folder that holds only its install marker instead of calling it installed' {
        # What the copy bug usually left behind: the marker and no files.
        $files = @('Dbgview.exe', 'dbgview64.exe', 'Eula.txt')
        $zip   = New-FakeToolArchive -WorkDir $TestDrive -Files $files
        $dest  = Join-Path -Path $TestDrive -ChildPath 'debugview-marker-only'
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        (Get-Date -Format o) | Set-Content -LiteralPath (Join-Path -Path $dest -ChildPath 'debugview.installed') -Encoding ascii
        $r = InModuleScope MSIX -Parameters @{ Zip = $zip; Dest = $dest } {
            param($Zip, $Dest)
            $script:TestArchive = $Zip
            $first  = Install-MsixDebugView -Destination $Dest
            $second = Install-MsixDebugView -Destination $Dest
            [pscustomobject]@{ First = $first; Second = $second }
        }
        $r.First.Updated | Should -BeTrue -Because 'a marker with no files is not an install'
        Assert-ToolInstalled -Destination $dest -Files $files -Marker 'debugview.installed'
        Should -Invoke -CommandName Write-MsixLog -ModuleName MSIX -Times 1 -Exactly -ParameterFilter {
            $Level -eq 'Warning' -and $Message -like '*install marker but no files*'
        }
        # Now that the files are there, the marker means installed again.
        $r.Second.Updated | Should -BeFalse
        Should -Invoke -CommandName _MsixDownloadFile -ModuleName MSIX -Times 1 -Exactly
    }

    It 'Update-MsixDebugView reinstalls a marker-only folder even when the marker is recent' {
        $files = @('Dbgview.exe', 'dbgview64.exe', 'Eula.txt')
        $zip   = New-FakeToolArchive -WorkDir $TestDrive -Files $files
        $dest  = Join-Path -Path $TestDrive -ChildPath 'debugview-update'
        New-Item -ItemType Directory -Path $dest -Force | Out-Null
        (Get-Date -Format o) | Set-Content -LiteralPath (Join-Path -Path $dest -ChildPath 'debugview.installed') -Encoding ascii
        $r = InModuleScope MSIX -Parameters @{ Zip = $zip; Dest = $dest } {
            param($Zip, $Dest)
            $script:TestArchive = $Zip
            $first  = Update-MsixDebugView -Destination $Dest
            $second = Update-MsixDebugView -Destination $Dest
            [pscustomobject]@{ First = $first; Second = $second }
        }
        $r.First.Updated | Should -BeTrue -Because 'a recent marker with nothing beside it must not read as fresh'
        Assert-ToolInstalled -Destination $dest -Files $files -Marker 'debugview.installed'
        $r.Second.Updated | Should -BeFalse -Because 'a real install with a recent marker is fresh'
        Should -Invoke -CommandName _MsixDownloadFile -ModuleName MSIX -Times 1 -Exactly
    }
}
