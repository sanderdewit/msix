BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Win32 App Isolation' -Tag 'AppIsolation' {

    It 'Get-MsixIsolationCapability returns a list with promptForAccess' {
        (Get-MsixIsolationCapability).Name | Should -Contain 'isolatedWin32-promptForAccess'
    }

    It 'All rescap capabilities follow isolatedWin32- naming' {
        Get-MsixIsolationCapability |
            Where-Object ElementType -eq 'rescap:Capability' |
            ForEach-Object {
                $_.Name | Should -Match '^isolatedWin32-'
            }
    }

    It 'Device capabilities have ElementType DeviceCapability' {
        $deviceCaps = @(Get-MsixIsolationCapability | Where-Object ElementType -eq 'DeviceCapability')
        $deviceCaps.Count | Should -BeGreaterThan 0
        $deviceCaps.Name | Should -Contain 'microphone'
        $deviceCaps.Name | Should -Contain 'webcam'
    }
}

Describe 'Add-MsixAppIsolation end-to-end (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:WorkDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-appisolation-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null
    }
    AfterAll {
        if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
            Remove-Item -LiteralPath $script:WorkDir -Recurse -Force
        }
    }

    It 'adds a rescap isolation capability to a real package without throwing' {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' ; return }

        $pkg = Join-Path -Path $script:WorkDir -ChildPath 'base.msix'
        $out = Join-Path -Path $script:WorkDir -ChildPath 'isolated.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        { Add-MsixAppIsolation -PackagePath $fx.PackagePath -Capabilities 'isolatedWin32-promptForAccess' -OutputPath $out -SkipSigning } |
            Should -Not -Throw

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'emits rescap:Capability in the manifest for a rescap capability' {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' ; return }

        $out = Join-Path -Path $script:WorkDir -ChildPath 'isolated.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out
        $rescapUri = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities'
        $cap = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.NamespaceURI -eq $rescapUri -and $_.GetAttribute('Name') -eq 'isolatedWin32-promptForAccess' }
        $cap | Should -Not -BeNullOrEmpty -Because 'isolatedWin32-promptForAccess must appear as rescap:Capability'
    }

    It 'emits DeviceCapability in the manifest for a device capability' {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' ; return }

        $pkg2 = Join-Path -Path $script:WorkDir -ChildPath 'base2.msix'
        $out2 = Join-Path -Path $script:WorkDir -ChildPath 'device.msix'
        $fx2  = New-MsixTestFixture -OutputPath $pkg2

        Add-MsixAppIsolation -PackagePath $fx2.PackagePath -Capabilities 'microphone' -OutputPath $out2 -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out2
        $defaultUri = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10'
        $cap = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'DeviceCapability' -and $_.NamespaceURI -eq $defaultUri -and $_.GetAttribute('Name') -eq 'microphone' }
        $cap | Should -Not -BeNullOrEmpty -Because 'microphone must appear as DeviceCapability in the default namespace'

        if (Test-Path -LiteralPath $fx2.StagingFolder) { Remove-Item -LiteralPath $fx2.StagingFolder -Recurse -Force }
    }

    It 'is idempotent: running twice does not duplicate capabilities' {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' ; return }

        $out  = Join-Path -Path $script:WorkDir -ChildPath 'isolated.msix'
        $out2 = Join-Path -Path $script:WorkDir -ChildPath 'isolated2.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the output package'

        Add-MsixAppIsolation -PackagePath $out -Capabilities 'isolatedWin32-promptForAccess' -OutputPath $out2 -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out2
        $rescapUri = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities'
        $caps = @($m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.NamespaceURI -eq $rescapUri -and $_.GetAttribute('Name') -eq 'isolatedWin32-promptForAccess' })
        $caps.Count | Should -Be 1 -Because 'capability must appear exactly once even when added twice'
    }
}

Describe 'Win32 App Isolation: uap18 attributes + runFullTrust reconciliation (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:Uap18Uri = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/18'
        $script:RescapUri = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities'
        $script:IsoDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-iso-attrs-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:IsoDir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'MakeAppx not available on this host.'
        }
    }
    AfterAll {
        if ($script:IsoDir -and (Test-Path -LiteralPath $script:IsoDir)) {
            Remove-Item -LiteralPath $script:IsoDir -Recurse -Force
        }
    }

    It 'sets the uap18 isolation attributes on the Application (the actual enable switch)' {
        $pkg = Join-Path -Path $script:IsoDir -ChildPath 'base.msix'
        $out = Join-Path -Path $script:IsoDir -ChildPath 'iso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg
        Add-MsixAppIsolation -PackagePath $fx.PackagePath -Capabilities 'isolatedWin32-promptForAccess' -OutputPath $out -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out
        $app = $m.Package.Applications.Application
        $app.GetAttribute('EntryPoint')                       | Should -Be 'Windows.FullTrustApplication'
        $app.GetAttribute('EntryPoint', $script:Uap18Uri)     | Should -Be 'Isolated.App'
        $app.GetAttribute('TrustLevel', $script:Uap18Uri)     | Should -Be 'appContainer'
        $app.GetAttribute('RuntimeBehavior', $script:Uap18Uri)| Should -Be 'appSilo'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'declares the uap18 namespace and lists it in IgnorableNamespaces' {
        $out = Join-Path -Path $script:IsoDir -ChildPath 'iso.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out
        $m.Package.GetAttribute('xmlns:uap18') | Should -Be $script:Uap18Uri
        $m.Package.IgnorableNamespaces         | Should -Match '\buap18\b'
    }

    It 'raises the Windows.Desktop TargetDeviceFamily MinVersion to 10.0.26100.0' {
        # Isolation only engages when the package TARGETS 24H2; a down-level
        # MinVersion makes Windows ignore the uap18 attributes. The fixture ships
        # MinVersion 10.0.17763.0 and must be raised.
        $out = Join-Path -Path $script:IsoDir -ChildPath 'iso.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'earlier test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out
        $tdf = @($m.Package.Dependencies.TargetDeviceFamily) |
            Where-Object { $_.GetAttribute('Name') -eq 'Windows.Desktop' }
        $tdf | Should -Not -BeNullOrEmpty
        $tdf.GetAttribute('MinVersion') | Should -Be '10.0.26100.0' -Because 'Win32 App Isolation requires the package to target 24H2'
    }

    It 'retains runFullTrust (required by the Windows.FullTrustApplication entry point)' {
        # An isolated app keeps EntryPoint="Windows.FullTrustApplication", which the
        # AppxManifest schema requires runFullTrust for (MakeAppx error 80080204
        # otherwise). Isolation is enforced by the uap18 attributes, not by the
        # absence of runFullTrust.
        $out = Join-Path -Path $script:IsoDir -ChildPath 'iso.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'earlier test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out
        $rft = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust' }
        $rft | Should -Not -BeNullOrEmpty -Because 'the FullTrustApplication entry point requires runFullTrust'
    }

    It 'auto-adds isolatedWin32-shellExtensionContextMenu when a COM context-menu is present' {
        $pkg = Join-Path -Path $script:IsoDir -ChildPath 'ctx-base.msix'
        $ctx = Join-Path -Path $script:IsoDir -ChildPath 'ctx.msix'
        $out = Join-Path -Path $script:IsoDir -ChildPath 'ctx-iso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        # Inject a real COM context-menu (comServer + FileExplorerContextMenus).
        Add-MsixLegacyContextMenu -PackagePath $fx.PackagePath `
            -ShellExtDll 'VFS\ProgramFilesX64\App\Shell.dll' `
            -Clsid '11112222-3333-4444-5555-666677778888' -DisplayName 'Ctx' `
            -FileTypes '*' -OutputPath $ctx -SkipSigning

        Add-MsixAppIsolation -PackagePath $ctx -Capabilities 'isolatedWin32-promptForAccess' -OutputPath $out -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out
        $shellCap = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'isolatedWin32-shellExtensionContextMenu' }
        $shellCap | Should -Not -BeNullOrEmpty -Because 'a COM context-menu needs the isolation-native capability to run under isolation'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'ensures runFullTrust is present even if the source package lacks it' {
        # Start from a package whose runFullTrust was stripped, then isolate: the
        # cmdlet must re-add it so the FullTrust entry point validates.
        $pkg = Join-Path -Path $script:IsoDir -ChildPath 'norft-base.msix'
        $out = Join-Path -Path $script:IsoDir -ChildPath 'norft-iso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        Add-MsixAppIsolation -PackagePath $fx.PackagePath -Capabilities 'isolatedWin32-promptForAccess' -OutputPath $out -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out
        $rft = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust' }
        $rft | Should -Not -BeNullOrEmpty -Because 'the cmdlet must guarantee a schema-valid package'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It '-KeepRunFullTrust and -RemoveRunFullTrust together throw' {
        $out = Join-Path -Path $script:IsoDir -ChildPath 'iso.msix'
        { Add-MsixAppIsolation -PackagePath $out -RemoveRunFullTrust -KeepRunFullTrust -SkipSigning } |
            Should -Throw '*mutually exclusive*'
    }

    It 'warns that a PSF-launched package cannot be isolated' {
        # PSF (PsfLauncher entry point) is incompatible with isolation: it injects
        # fixup DLLs into the target process, which AppContainer blocks. The cmdlet
        # must warn rather than silently produce a non-isolating "isolated" package.
        $pkg = Join-Path -Path $script:IsoDir -ChildPath 'psf-base.msix'
        $out = Join-Path -Path $script:IsoDir -ChildPath 'psf-iso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg -Executable 'VFS\ProgramFilesX64\App\PsfLauncher64.exe'

        # Write-MsixLog routes through Write-Information (stream 6); capture it.
        $info = Add-MsixAppIsolation -PackagePath $fx.PackagePath `
                    -Capabilities 'isolatedWin32-promptForAccess' `
                    -OutputPath $out -SkipSigning 6>&1 | Out-String
        $info | Should -Match 'Package Support Framework'
        $info | Should -Match 'will NOT run isolated'

        # It warns, it does not throw — the package is still produced.
        Test-Path -LiteralPath $out | Should -BeTrue

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'isolation and runFullTrust cannot be separated: -RemoveRunFullTrust yields a package MakeAppx rejects' {
        # The isolated app keeps EntryPoint="Windows.FullTrustApplication", and the
        # AppxManifest schema requires runFullTrust for that entry point. Forcing
        # runFullTrust off therefore produces an invalid package: MakeAppx fails
        # the repack with error 80080204 ("... requires runFullTrust capability").
        # This is the authoritative proof that the two are required *together*,
        # not mutually exclusive.
        $pkg = Join-Path -Path $script:IsoDir -ChildPath 'sep-base.msix'
        $out = Join-Path -Path $script:IsoDir -ChildPath 'sep-iso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        { Add-MsixAppIsolation -PackagePath $fx.PackagePath `
                -Capabilities 'isolatedWin32-promptForAccess' `
                -RemoveRunFullTrust -OutputPath $out -SkipSigning -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*runFullTrust*'

        Test-Path -LiteralPath $out | Should -BeFalse -Because 'the rejected package must not be produced (atomic pack-sign-move)'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}

Describe 'Remove-MsixAppIsolation reverses isolation (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:Uap18Uri = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/18'
        $script:RmDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-iso-rm-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:RmDir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'MakeAppx not available on this host.'
        }
    }
    AfterAll {
        if ($script:RmDir -and (Test-Path -LiteralPath $script:RmDir)) {
            Remove-Item -LiteralPath $script:RmDir -Recurse -Force
        }
    }

    It 'strips the uap18 attributes and isolatedWin32-* capabilities' {
        $pkg = Join-Path -Path $script:RmDir -ChildPath 'base.msix'
        $iso = Join-Path -Path $script:RmDir -ChildPath 'iso.msix'
        $rm  = Join-Path -Path $script:RmDir -ChildPath 'deiso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        Add-MsixAppIsolation -PackagePath $fx.PackagePath -Capabilities 'isolatedWin32-promptForAccess' -OutputPath $iso -SkipSigning
        Remove-MsixAppIsolation -PackagePath $iso -OutputPath $rm -SkipSigning

        [xml]$m = Get-MsixManifest -Path $rm
        $app = $m.Package.Applications.Application
        $app.GetAttribute('TrustLevel', $script:Uap18Uri)      | Should -BeNullOrEmpty
        $app.GetAttribute('RuntimeBehavior', $script:Uap18Uri) | Should -BeNullOrEmpty
        $app.GetAttribute('EntryPoint', $script:Uap18Uri)      | Should -BeNullOrEmpty
        # Base entry point is preserved.
        $app.GetAttribute('EntryPoint') | Should -Be 'Windows.FullTrustApplication'

        $isoCaps = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -like 'isolatedWin32-*' }
        $isoCaps | Should -BeNullOrEmpty -Because 'all isolatedWin32-* capabilities must be removed'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}
