BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
    $script:D6Uri = 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/6'
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Manifest feature mutators from the v2 review (issues #108, #109, #112-#119)
# =============================================================================

Describe 'Manifest feature mutators (real packages, 0.71.4)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-feat-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    Context 'Add-MsixLegacyContextMenu -Schema (issue #108)' {
        It 'desktop9 emits the classic handler and raises MaxVersionTested to 22000' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'd9-base.msix')
            $out = Join-Path $script:Dir 'd9.msix'
            Add-MsixLegacyContextMenu -PackagePath $fx.PackagePath `
                -ShellExtDll 'VFS\ProgramFilesX64\App\Shell.dll' `
                -Clsid '11112222-3333-4444-5555-666677778888' -DisplayName 'Ctx' `
                -FileTypes '*', '.log' -Schema desktop9 -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $classic = $m.SelectSingleNode("//*[local-name()='FileExplorerClassicContextMenuHandler']")
            $classic | Should -Not -BeNullOrEmpty
            @($classic.ChildNodes).Count | Should -Be 2
            $m.SelectSingleNode("//*[local-name()='FileExplorerContextMenus']") | Should -BeNullOrEmpty
            $tdf = @($m.Package.Dependencies.TargetDeviceFamily) | Where-Object { $_.GetAttribute('Name') -eq 'Windows.Desktop' }
            [version]$tdf.GetAttribute('MaxVersionTested') | Should -BeGreaterOrEqual ([version]'10.0.22000.0')
        }

        It 'Both emits desktop4/5 AND desktop9 against the same CLSID' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'both-base.msix')
            $out = Join-Path $script:Dir 'both.msix'
            Add-MsixLegacyContextMenu -PackagePath $fx.PackagePath `
                -ShellExtDll 'VFS\ProgramFilesX64\App\Shell.dll' `
                -Clsid '11112222-3333-4444-5555-666677778888' -DisplayName 'Ctx' `
                -FileTypes '*' -Schema Both -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $m.SelectSingleNode("//*[local-name()='FileExplorerContextMenus']")               | Should -Not -BeNullOrEmpty
            $m.SelectSingleNode("//*[local-name()='FileExplorerClassicContextMenuHandler']")  | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Set-MsixBrandMetadata ms-resource warning (issue #109)' {
        It 'warns when the current DisplayName is pri-localized' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'pri-base.msix')
            # Give the fixture an ms-resource DisplayName first.
            $pri = Join-Path $script:Dir 'pri.msix'
            Set-MsixBrandMetadata -PackagePath $fx.PackagePath -DisplayName 'ms-resource:AppName' `
                -OutputPath $pri -SkipSigning
            $out = Join-Path $script:Dir 'pri-out.msix'
            $info = Set-MsixBrandMetadata -PackagePath $pri -DisplayName 'Literal Name' `
                        -OutputPath $out -SkipSigning 6>&1 | Out-String
            $info | Should -Match 'resources\.pri'
            [xml]$m = Get-MsixManifest -Path $out
            $m.Package.Properties.DisplayName | Should -Be 'Literal Name'
        }
    }

    Context 'Add-MsixService (issue #112)' {
        It 'declares the desktop6 service with the required restricted capabilities' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'svc-base.msix')
            $out = Join-Path $script:Dir 'svc.msix'
            Add-MsixService -PackagePath $fx.PackagePath `
                -Executable 'VFS\ProgramFilesX64\App\app.exe' -Name 'LabAgent' `
                -StartupType auto -StartAccount localSystem -Dependencies 'rpcss' `
                -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $svc = $m.SelectSingleNode("//*[local-name()='Service' and @Name='LabAgent']")
            $svc | Should -Not -BeNullOrEmpty
            $svc.GetAttribute('StartupType')  | Should -Be 'auto'
            $svc.GetAttribute('StartAccount') | Should -Be 'localSystem'
            $svc.ParentNode.GetAttribute('Category') | Should -Be 'windows.service'
            $caps = @($m.Package.Capabilities.ChildNodes | Where-Object { $_.LocalName -eq 'Capability' } | ForEach-Object { $_.GetAttribute('Name') })
            $caps | Should -Contain 'packagedServices'
            $caps | Should -Contain 'localSystemServices'
        }

        It 'is idempotent per service name' {
            $out  = Join-Path $script:Dir 'svc.msix'
            $out2 = Join-Path $script:Dir 'svc2.msix'
            Add-MsixService -PackagePath $out -Executable 'VFS\ProgramFilesX64\App\agent.exe' `
                -Name 'LabAgent' -OutputPath $out2 -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out2
            @($m.SelectNodes("//*[local-name()='Service' and @Name='LabAgent']")).Count | Should -Be 1
        }
    }

    Context 'Add-MsixPackageDependency (issue #115)' {
        It 'adds a known framework with the auto-filled publisher' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'dep-base.msix')
            $out = Join-Path $script:Dir 'dep.msix'
            Add-MsixPackageDependency -PackagePath $fx.PackagePath `
                -Name Microsoft.VCLibs.140.00.UWPDesktop -MinVersion 14.0.33321.0 `
                -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $dep = $m.SelectSingleNode("//*[local-name()='PackageDependency' and @Name='Microsoft.VCLibs.140.00.UWPDesktop']")
            $dep | Should -Not -BeNullOrEmpty
            $dep.GetAttribute('Publisher') | Should -Match 'CN=Microsoft Corporation'
        }

        It 'raises MinVersion but never lowers it' {
            $out  = Join-Path $script:Dir 'dep.msix'
            $up   = Join-Path $script:Dir 'dep-up.msix'
            Add-MsixPackageDependency -PackagePath $out -Name Microsoft.VCLibs.140.00.UWPDesktop `
                -MinVersion 14.0.40000.0 -OutputPath $up -SkipSigning
            [xml]$m = Get-MsixManifest -Path $up
            $m.SelectSingleNode("//*[local-name()='PackageDependency']").GetAttribute('MinVersion') | Should -Be '14.0.40000.0'

            $down = Join-Path $script:Dir 'dep-down.msix'
            $info = Add-MsixPackageDependency -PackagePath $up -Name Microsoft.VCLibs.140.00.UWPDesktop `
                        -MinVersion 14.0.1.0 -OutputPath $down -SkipSigning 6>&1 | Out-String
            $info | Should -Match 'skipping'
        }

        It 'throws a helpful error for an unknown framework without -Publisher' {
            $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'dep-unk.msix')
            { Add-MsixPackageDependency -PackagePath $fx.PackagePath -Name Contoso.Unknown `
                  -MinVersion 1.0.0.0 -SkipSigning -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*-Publisher*'
        }
    }

    Context 'Add-MsixShellHandlerExtension (issue #113)' {
        It 'declares preview/property/thumbnail handlers with their COM class' -TestCases @(
            @{ Kind = 'Preview';   Element = 'DesktopPreviewHandler';  Suffix = '000000000001' }
            @{ Kind = 'Property';  Element = 'DesktopPropertyHandler'; Suffix = '000000000002' }
            @{ Kind = 'Thumbnail'; Element = 'ThumbnailHandler';       Suffix = '000000000003' }
        ) {
            param($Kind, $Element, $Suffix)
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir "sh-$Kind-base.msix")
            $out = Join-Path $script:Dir "sh-$Kind.msix"
            $clsid = '11112222-3333-4444-5555-' + $Suffix
            Add-MsixShellHandlerExtension -PackagePath $fx.PackagePath -Kind $Kind `
                -Clsid $clsid -Dll 'VFS\ProgramFilesX64\App\h.dll' -FileTypes '.labh' `
                -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $handler = $m.SelectSingleNode("//*[local-name()='$Element']")
            $handler | Should -Not -BeNullOrEmpty
            $handler.GetAttribute('Clsid') | Should -Be $clsid.ToLowerInvariant()
            $m.SelectSingleNode("//*[local-name()='Class' and @Id='$($clsid.ToLowerInvariant())']") | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Add-MsixToastActivator (issue #114)' {
        It 'declares the toast activation extension + ExeServer COM class' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'toast-base.msix')
            $out = Join-Path $script:Dir 'toast.msix'
            Add-MsixToastActivator -PackagePath $fx.PackagePath `
                -Clsid '{ff1a2b3c-4d5e-6f70-8899-aabbccddeeff}' `
                -Executable 'VFS\ProgramFilesX64\App\app.exe' -Arguments '-Toast' `
                -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $toast = $m.SelectSingleNode("//*[local-name()='ToastNotificationActivation']")
            $toast.GetAttribute('ToastActivatorCLSID') | Should -Be 'ff1a2b3c-4d5e-6f70-8899-aabbccddeeff'
            $exe = $m.SelectSingleNode("//*[local-name()='ExeServer']")
            $exe.GetAttribute('Arguments') | Should -Be '-Toast'
        }
    }

    Context 'Set-MsixMutablePackageDirectory (issue #116)' {
        It 'declares the mutable directory extension + modifiableApp capability' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'mut-base.msix')
            $out = Join-Path $script:Dir 'mut.msix'
            Set-MsixMutablePackageDirectory -PackagePath $fx.PackagePath -Directory 'LabApp' `
                -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $dir = $m.SelectSingleNode("//*[local-name()='MutablePackageDirectory']")
            $dir.GetAttribute('Target') | Should -Be 'LabApp'
            $dir.ParentNode.ParentNode.GetAttribute('Category') | Should -Be 'windows.mutablePackageDirectories'
            @($m.Package.Capabilities.ChildNodes | Where-Object { $_.LocalName -eq 'Capability' } | ForEach-Object { $_.GetAttribute('Name') }) |
                Should -Contain 'modifiableApp'
        }
    }

    Context 'Add-MsixFileTypeAssociation richness (issue #119)' {
        It 'emits Logo, InfoTip, EditFlags and SupportedVerbs in schema order' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'fta-base.msix')
            $out = Join-Path $script:Dir 'fta.msix'
            Add-MsixFileTypeAssociation -PackagePath $fx.PackagePath -AppId 'App' `
                -Name labdoc -FileTypes '.labd' -DisplayName 'Lab Doc' `
                -InfoTip 'A lab document' -OpenIsSafe `
                -Verbs @(@{ Id = 'edit'; Parameters = '--edit "%1"'; DisplayName = 'Edit' }) `
                -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $fta = $m.SelectSingleNode("//*[local-name()='FileTypeAssociation' and @Name='labdoc']")
            $fta.SelectSingleNode("*[local-name()='InfoTip']").InnerText | Should -Be 'A lab document'
            $fta.SelectSingleNode("*[local-name()='EditFlags']").GetAttribute('OpenIsSafe') | Should -Be 'true'
            $verb = $fta.SelectSingleNode("*[local-name()='SupportedVerbs']/*[local-name()='Verb']")
            $verb.GetAttribute('Id')         | Should -Be 'edit'
            $verb.GetAttribute('Parameters') | Should -Be '--edit "%1"'
        }

        It 'rejects -OpenIsSafe together with -AlwaysUnsafe' {
            $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'fta-x.msix')
            { Add-MsixFileTypeAssociation -PackagePath $fx.PackagePath -AppId 'App' -Name x `
                  -FileTypes '.x' -OpenIsSafe -AlwaysUnsafe -SkipSigning -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*mutually exclusive*'
        }
    }

    Context 'New-MsixAppInstallerFile (issue #117)' {
        It 'emits a schema-shaped .appinstaller with the package identity and update policy' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'ai-base.msix')
            $r = New-MsixAppInstallerFile -PackagePath $fx.PackagePath `
                    -PackageUri 'https://dist.contoso.com/ai-base.msix' -OnLaunch -ShowPrompt `
                    -HoursBetweenUpdateChecks 12
            Test-Path -LiteralPath $r.Path | Should -BeTrue
            [xml]$ai = Get-Content -LiteralPath $r.Path -Raw
            $ai.AppInstaller.MainPackage.Uri | Should -Be 'https://dist.contoso.com/ai-base.msix'
            $ai.AppInstaller.MainPackage.Name | Should -Not -BeNullOrEmpty
            $ai.AppInstaller.UpdateSettings.OnLaunch.HoursBetweenUpdateChecks | Should -Be '12'
            $ai.AppInstaller.UpdateSettings.OnLaunch.ShowPrompt | Should -Be 'true'
        }

        It 'rejects -ShowPrompt without -OnLaunch' {
            $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'ai2.msix')
            { New-MsixAppInstallerFile -PackagePath $fx.PackagePath `
                  -PackageUri 'https://x/y.msix' -ShowPrompt -ErrorAction Stop } |
                Should -Throw -ExpectedMessage '*OnLaunch*'
        }
    }

    Context 'New-MsixModificationPackage (issue #118)' {
        It 'creates a MakeAppx-valid modification package with MainPackageDependency' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'main.msix')
            $content = Join-Path $script:Dir 'modcontent'
            New-Item -ItemType Directory -Path (Join-Path $content 'VFS\ProgramFilesX64\App\plugins') -Force | Out-Null
            Set-Content -Path (Join-Path $content 'VFS\ProgramFilesX64\App\plugins\lab.txt') -Value 'plugin'

            $r = New-MsixModificationPackage -MainPackagePath $fx.PackagePath `
                    -ContentPath $content -SkipSigning
            Test-Path -LiteralPath $r.PackagePath | Should -BeTrue

            [xml]$m = Get-MsixManifest -Path $r.PackagePath
            $dep = $m.SelectSingleNode("//*[local-name()='MainPackageDependency']")
            $dep.GetAttribute('Name') | Should -Be $r.MainPackageName
            $m.SelectSingleNode("//*[local-name()='Application']") | Should -BeNullOrEmpty
        }
    }
}
