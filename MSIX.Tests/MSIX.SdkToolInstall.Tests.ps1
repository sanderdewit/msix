BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    # A Microsoft.Windows.SDK.BuildTools-shaped nupkg: bin\<sdk>\<arch>\ holding
    # stub binaries. Install-MsixSdkTool only extracts, verifies and copies, so
    # stubs are enough; Get-AuthenticodeSignature is mocked per file name.
    function script:New-FakeBuildToolsPackage {
        param(
            [Parameter(Mandatory)][string]$WorkDir,
            [string]$SdkFolder = '10.0.28000.0',
            [string[]]$Files = @('MakeAppx.exe', 'signtool.exe', 'makepri.exe', 'appxsip.dll', 'wintrust.dll')
        )
        $id    = [guid]::NewGuid().ToString('N').Substring(0, 8)
        $stage = Join-Path -Path $WorkDir -ChildPath "pkg-$id"
        foreach ($arch in 'x64', 'x86') {
            $dir = Join-Path -Path $stage -ChildPath "bin\$SdkFolder\$arch"
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            foreach ($f in $Files) {
                Set-Content -LiteralPath (Join-Path -Path $dir -ChildPath $f) -Value 'stub' -Encoding ascii
            }
        }
        $nupkg = Join-Path -Path $WorkDir -ChildPath "microsoft.windows.sdk.buildtools.$id.nupkg"
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::CreateFromDirectory($stage, $nupkg)
        return $nupkg
    }

    $script:KitsPublisher = 'CN=Microsoft Windows Kits Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Microsoft.Windows.SDK.BuildTools 10.0.26100.9457 and 10.0.28000.2957 (both
# 2026-10-28) moved AppxSip.dll - in x64 and x86 - to a new signer,
# CN=Microsoft Windows Kits Publisher. That CN was not in signers.json, so every
# unpinned Install-MsixSdkTool / Initialize-MsixToolchain on a fresh machine
# rolled back, and the error most callers saw was Get-MsixToolsRoot's
# "MakeAppx.exe not found", which names every remedy except the real cause.
#
# Nothing here touches the network: the NuGet index, the download and
# Get-AuthenticodeSignature are mocked; extraction, verification, the copy into
# Tools\ and the post-install tools-root verification run for real.
# =============================================================================

Describe 'Install-MsixSdkTool' -Tag 'Toolchain', 'Security' {

    BeforeEach {
        InModuleScope MSIX {
            Mock Write-MsixLog {}
            Mock Get-AuthenticodeSignature {
                $name   = [IO.Path]::GetFileName([string]@($LiteralPath)[0])
                $signer = $script:TestSigners[$name]
                if (-not $signer) {
                    $signer = @{ Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'; Thumbprint = 'B835FC295FFB94EA2FCA23B0E9C1EDA3FBA4E07D' }
                }
                [pscustomobject]@{
                    Status            = 'Valid'
                    StatusMessage     = 'Signature verified.'
                    SignerCertificate = [pscustomobject]@{ Subject = $signer.Subject; Thumbprint = $signer.Thumbprint }
                }
            }
            Mock _MsixDownloadFile { Copy-Item -LiteralPath $script:TestNupkg -Destination $Destination }
        }
    }

    AfterEach {
        InModuleScope MSIX {
            $script:ToolsRoot = $null
            $script:MsixLastSdkInstallError = $null
            Remove-Variable -Name TestNupkg, TestSigners -Scope Script -ErrorAction SilentlyContinue
        }
    }

    It 'installs the newest stable release when appxsip.dll is signed by CN=Microsoft Windows Kits Publisher' {
        # The real 10.0.28000.2957 x64 layout: appxsip.dll on the Kits Publisher
        # cert, everything else on CN=Microsoft Corporation certs.
        $nupkg = New-FakeBuildToolsPackage -WorkDir $TestDrive
        $dest  = Join-Path -Path $TestDrive -ChildPath 'fresh'
        $r = InModuleScope MSIX -Parameters @{ Nupkg = $nupkg; Dest = $dest; Kits = $script:KitsPublisher } {
            param($Nupkg, $Dest, $Kits)
            $script:TestNupkg   = $Nupkg
            $script:TestSigners = @{ 'appxsip.dll' = @{ Subject = $Kits; Thumbprint = '2C3BD48A6836D6CEBAC6FFB4A972A0A69B5D6B49' } }
            # A stale failure from earlier in the session must not outlive a good install.
            $script:MsixLastSdkInstallError = 'stale failure'
            Mock Invoke-RestMethod {
                [pscustomobject]@{ versions = @('10.0.26100.4188', '10.0.28000.2957', '10.0.29648.1000-preview') }
            }
            $out = Install-MsixSdkTool -Destination $Dest
            [pscustomobject]@{ Out = $out; LastError = $script:MsixLastSdkInstallError; ToolsRoot = $script:ToolsRoot }
        }
        $r.Out.Version | Should -Be '10.0.28000.2957' -Because 'unpinned means the newest STABLE version; the -preview one is skipped'
        $r.Out.Updated | Should -BeTrue
        Test-Path -LiteralPath (Join-Path -Path $dest -ChildPath 'Tools\appxsip.dll') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path -Path $dest -ChildPath 'Tools\MakeAppx.exe') | Should -BeTrue
        (Get-Content -LiteralPath (Join-Path -Path $dest -ChildPath 'Tools\sdk.version') -Raw).Trim() |
            Should -Be '10.0.28000.2957|x64'
        $r.ToolsRoot | Should -Be $dest -Because 'the installed root passed the post-install verification too'
        $r.LastError | Should -BeNullOrEmpty
    }

    It 'rejects a release with an untrusted signer: installs nothing, lists every rejected file, and says what to do' {
        # A hypothetical future release that moves two files to a signer that is
        # not in signers.json.
        $nupkg = New-FakeBuildToolsPackage -WorkDir $TestDrive -SdkFolder '10.0.29000.0'
        $dest  = Join-Path -Path $TestDrive -ChildPath 'rejected'
        $r = InModuleScope MSIX -Parameters @{ Nupkg = $nupkg; Dest = $dest } {
            param($Nupkg, $Dest)
            $script:TestNupkg   = $Nupkg
            $contoso = @{ Subject = 'CN=Contoso Kits Signer, O=Contoso, C=US'; Thumbprint = 'AAAABBBBCCCCDDDDEEEEFFFF0000111122223333' }
            $script:TestSigners = @{ 'appxsip.dll' = $contoso; 'wintrust.dll' = $contoso }
            Mock Invoke-RestMethod { [pscustomobject]@{ versions = @('10.0.28000.2957', '10.0.29000.100') } }
            $caught = $null
            try { $null = Install-MsixSdkTool -Destination $Dest } catch { $caught = $_ }
            [pscustomobject]@{
                Error     = $caught
                LastError = $script:MsixLastSdkInstallError
                KnownGood = $script:SdkToolsKnownGoodVersion
                ToolsRoot = $script:ToolsRoot
            }
        }
        $r.Error | Should -Not -BeNullOrEmpty
        $msg = $r.Error.Exception.Message
        $msg | Should -BeLike '*BuildTools 10.0.29000.100 (x64) was NOT installed: nothing was copied*'
        $msg | Should -BeLike '*2 of 5 binaries rejected*'
        $msg | Should -BeLike '*Subject:    CN=Contoso Kits Signer, O=Contoso, C=US*'
        $msg | Should -BeLike '*Thumbprint: AAAABBBBCCCCDDDDEEEEFFFF0000111122223333*'
        $msg | Should -BeLike '*Files (2): appxsip.dll, wintrust.dll*' -Because 'every rejected file is listed, not only the first'
        $msg | Should -BeLike "*Install-MsixSdkTool -Version $($r.KnownGood)*"
        $msg | Should -BeLike '*Initialize-MsixToolchain -Skip Sdk*'
        $msg | Should -BeLike '*signers.json*Trusted-publisher governance*CONTRIBUTING.md*'
        Test-Path -LiteralPath (Join-Path -Path $dest -ChildPath 'Tools') | Should -BeFalse
        $r.ToolsRoot | Should -BeNullOrEmpty
        $r.LastError | Should -Be $msg -Because 'Get-MsixToolsRoot quotes it later in the session'
        @($r.Error.Exception.Data['MsixAuthenticodeRejected']).Count | Should -Be 2
        $r.Error.Exception.InnerException | Should -Not -BeNullOrEmpty
    }

    It 'leaves an existing install as it was when an update is rejected, and says so' {
        $nupkg = New-FakeBuildToolsPackage -WorkDir $TestDrive -SdkFolder '10.0.29000.0'
        $dest  = Join-Path -Path $TestDrive -ChildPath 'existing'
        $tools = Join-Path -Path $dest -ChildPath 'Tools'
        New-Item -ItemType Directory -Path $tools -Force | Out-Null
        Set-Content -LiteralPath (Join-Path -Path $tools -ChildPath 'MakeAppx.exe') -Value 'previous' -Encoding ascii
        Set-Content -LiteralPath (Join-Path -Path $tools -ChildPath 'sdk.version') -Value '10.0.28000.2705|x64' -Encoding ascii
        $err = InModuleScope MSIX -Parameters @{ Nupkg = $nupkg; Dest = $dest } {
            param($Nupkg, $Dest)
            $script:TestNupkg   = $Nupkg
            $script:TestSigners = @{ 'appxsip.dll' = @{ Subject = 'CN=Contoso Kits Signer, O=Contoso, C=US'; Thumbprint = 'AAAABBBBCCCCDDDDEEEEFFFF0000111122223333' } }
            Mock Invoke-RestMethod { throw 'an explicit -Version must not query NuGet' }
            try { $null = Install-MsixSdkTool -Destination $Dest -Version '10.0.29000.100' -Force; $null } catch { $_ }
        }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -BeLike '*already installed there (10.0.28000.2705|x64) were left as they were*'
        (Get-Content -LiteralPath (Join-Path -Path $tools -ChildPath 'MakeAppx.exe') -Raw).Trim() | Should -Be 'previous'
        (Get-Content -LiteralPath (Join-Path -Path $tools -ChildPath 'sdk.version') -Raw).Trim() | Should -Be '10.0.28000.2705|x64'
    }

    It 'does not offer the rejected version itself as the version to pin' {
        # If the version this release was verified against is rejected, a newer
        # upstream signer is not the explanation - do not send the operator in a
        # circle, and do not invite them to add trust blindly.
        $nupkg = New-FakeBuildToolsPackage -WorkDir $TestDrive
        $dest  = Join-Path -Path $TestDrive -ChildPath 'knowngood'
        $r = InModuleScope MSIX -Parameters @{ Nupkg = $nupkg; Dest = $dest } {
            param($Nupkg, $Dest)
            $script:TestNupkg   = $Nupkg
            $script:TestSigners = @{ 'appxsip.dll' = @{ Subject = 'CN=Contoso Kits Signer, O=Contoso, C=US'; Thumbprint = 'AAAABBBBCCCCDDDDEEEEFFFF0000111122223333' } }
            $knownGood = $script:SdkToolsKnownGoodVersion
            $caught = $null
            try { $null = Install-MsixSdkTool -Destination $Dest -Version $knownGood } catch { $caught = $_ }
            [pscustomobject]@{ Error = $caught; KnownGood = $knownGood }
        }
        $r.Error | Should -Not -BeNullOrEmpty
        $r.Error.Exception.Message | Should -Not -BeLike "*Install-MsixSdkTool -Version $($r.KnownGood)*"
        $r.Error.Exception.Message | Should -BeLike '*Investigate before adding trust*'
    }

    It 'records a failed NuGet version query for Get-MsixToolsRoot as well' {
        $msg = InModuleScope MSIX {
            Mock Invoke-RestMethod { throw 'offline' }
            try { $null = Install-MsixSdkTool -Destination 'C:\never-used' } catch { Write-Verbose -Message $_ }
            $script:MsixLastSdkInstallError
        }
        $msg | Should -BeLike 'Could not query NuGet for Microsoft.Windows.SDK.BuildTools versions:*offline*'
    }
}

Describe '_MsixVerifyAuthenticodeFolder' -Tag 'Security' {

    BeforeEach {
        InModuleScope MSIX {
            Mock Write-MsixLog {}
            Mock Get-AuthenticodeSignature {
                $name   = [IO.Path]::GetFileName([string]@($LiteralPath)[0])
                $signer = $script:TestSigners[$name]
                if (-not $signer) {
                    $signer = @{ Status = 'Valid'; Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'; Thumbprint = 'B835FC295FFB94EA2FCA23B0E9C1EDA3FBA4E07D' }
                }
                $status = if ($signer.Status) { $signer.Status } else { 'Valid' }
                [pscustomobject]@{
                    Status            = $status
                    StatusMessage     = 'mocked'
                    SignerCertificate = [pscustomobject]@{ Subject = $signer.Subject; Thumbprint = $signer.Thumbprint }
                }
            }
        }
    }
    AfterEach {
        InModuleScope MSIX { Remove-Variable -Name TestSigners -Scope Script -ErrorAction SilentlyContinue }
    }

    It 'reports every rejected binary grouped by signer, instead of stopping at the first' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'multi'
        New-Item -ItemType Directory -Path (Join-Path -Path $dir -ChildPath 'sub') -Force | Out-Null
        foreach ($f in 'a.exe', 'b.dll', 'c.dll', 'sub\d.dll') {
            Set-Content -LiteralPath (Join-Path -Path $dir -ChildPath $f) -Value 'stub' -Encoding ascii
        }
        $err = InModuleScope MSIX -Parameters @{ Dir = $dir } {
            param($Dir)
            $fabrikam = @{ Subject = 'CN=Fabrikam Signing, O=Fabrikam'; Thumbprint = 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB' }
            $script:TestSigners = @{
                'b.dll' = $fabrikam
                'd.dll' = $fabrikam
                'c.dll' = @{ Subject = 'CN=Northwind, O=Northwind'; Thumbprint = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC' }
            }
            try { _MsixVerifyAuthenticodeFolder -Folder $Dir -ToolName 'probe'; $null } catch { $_ }
        }
        $err | Should -Not -BeNullOrEmpty
        $msg = $err.Exception.Message
        $msg | Should -BeLike '*probe: 3 of 4 binaries rejected*'
        $msg | Should -BeLike '*CN=Fabrikam Signing, O=Fabrikam*Files (2): b.dll, sub\d.dll*'
        $msg | Should -BeLike '*CN=Northwind, O=Northwind*Files (1): c.dll*'
        $msg | Should -Not -BeLike '*a.exe*' -Because 'trusted files are not reported'
        $msg | Should -BeLike '*add its CN prefix to signers.json*'
        $records = @($err.Exception.Data['MsixAuthenticodeRejected'])
        $records.Count | Should -Be 3
        @($records | Where-Object { $_.Reason -ne 'UntrustedPublisher' }).Count | Should -Be 0
        $err.Exception.Data['MsixAuthenticodeTotalCount'] | Should -Be 4
    }

    It 'does not present an invalid signature as fixable through signers.json' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'tampered'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        foreach ($f in 'ok.dll', 'tampered.dll') {
            Set-Content -LiteralPath (Join-Path -Path $dir -ChildPath $f) -Value 'stub' -Encoding ascii
        }
        $err = InModuleScope MSIX -Parameters @{ Dir = $dir } {
            param($Dir)
            $script:TestSigners = @{
                'tampered.dll' = @{ Status = 'HashMismatch'; Subject = 'CN=Microsoft Corporation, O=Microsoft Corporation'; Thumbprint = 'B835FC295FFB94EA2FCA23B0E9C1EDA3FBA4E07D' }
            }
            try { _MsixVerifyAuthenticodeFolder -Folder $Dir -ToolName 'probe'; $null } catch { $_ }
        }
        $err | Should -Not -BeNullOrEmpty
        $msg = $err.Exception.Message
        $msg | Should -BeLike '*1 of 2 binaries rejected*'
        $msg | Should -BeLike '*signers.json cannot fix these*tampered.dll: signature status HashMismatch*'
        $msg | Should -Not -BeLike '*add its CN prefix*' -Because 'trusting a publisher cannot repair a hash mismatch'
        @($err.Exception.Data['MsixAuthenticodeRejected'])[0].Reason | Should -Be 'InvalidSignature'
    }

    It 'passes when every binary is signed by a trusted publisher' {
        $dir = Join-Path -Path $TestDrive -ChildPath 'clean'
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        foreach ($f in 'one.exe', 'two.dll') {
            Set-Content -LiteralPath (Join-Path -Path $dir -ChildPath $f) -Value 'stub' -Encoding ascii
        }
        $threw = InModuleScope MSIX -Parameters @{ Dir = $dir } {
            param($Dir)
            $script:TestSigners = @{}
            try { _MsixVerifyAuthenticodeFolder -Folder $Dir -ToolName 'probe'; $false } catch { $true }
        }
        $threw | Should -BeFalse
    }
}

Describe 'Get-MsixToolsRoot' -Tag 'Toolchain' {

    AfterEach {
        InModuleScope MSIX {
            $script:ToolsRoot = $null
            $script:MsixLastSdkInstallError = $null
        }
    }

    It 'quotes the failed SDK install as the likely cause when MakeAppx.exe is missing' {
        $err = InModuleScope MSIX {
            $script:MsixLastSdkInstallError = "Microsoft.Windows.SDK.BuildTools 10.0.29000.100 (x64) was NOT installed: nothing was copied.`nSigner is NOT in the trusted-publisher allowlist"
            # No toolchain anywhere: every location Get-MsixToolsRoot probes is a Test-Path.
            Mock Test-Path { $false }
            try { $null = Get-MsixToolsRoot -Refresh; $null } catch { $_ }
        }
        $err | Should -Not -BeNullOrEmpty
        $msg = $err.Exception.Message
        $msg | Should -BeLike 'MakeAppx.exe not found. The last Install-MsixSdkTool attempt in this session failed*'
        $msg | Should -BeLike '*10.0.29000.100 (x64) was NOT installed*'
        $msg | Should -BeLike '*    Signer is NOT in the trusted-publisher allowlist*' -Because 'every line of the cause is quoted'
        $msg | Should -BeLike '*Install-MsixSdkTool*Initialize-MsixToolchain*MSIX_TOOLS_PATH*'
    }

    It 'keeps the plain remedies when no SDK install failed in this session' {
        $err = InModuleScope MSIX {
            $script:MsixLastSdkInstallError = $null
            Mock Test-Path { $false }
            try { $null = Get-MsixToolsRoot -Refresh; $null } catch { $_ }
        }
        $err | Should -Not -BeNullOrEmpty
        $err.Exception.Message | Should -BeLike 'MakeAppx.exe not found. Pick ONE of these:*Install-MsixSdkTool*'
        $err.Exception.Message | Should -Not -BeLike '*last Install-MsixSdkTool attempt*'
    }
}
