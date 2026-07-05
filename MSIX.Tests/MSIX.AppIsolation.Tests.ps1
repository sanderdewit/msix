BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
    $script:Uap10Uri  = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
    $script:Uap18Uri  = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/18'
    $script:RescapUri = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities'
    $script:FoundationUri = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10'
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Win32 App Isolation capability list' -Tag 'AppIsolation' {

    It 'Get-MsixIsolationCapability returns a list with promptForAccess' {
        (Get-MsixIsolationCapability).Name | Should -Contain 'isolatedWin32-promptForAccess'
    }

    It 'All rescap capabilities follow isolatedWin32- naming' {
        Get-MsixIsolationCapability |
            Where-Object ElementType -eq 'rescap:Capability' |
            ForEach-Object { $_.Name | Should -Match '^isolatedWin32-' }
    }

    It 'Device capabilities have ElementType DeviceCapability' {
        $deviceCaps = @(Get-MsixIsolationCapability | Where-Object ElementType -eq 'DeviceCapability')
        $deviceCaps.Count | Should -BeGreaterThan 0
        $deviceCaps.Name | Should -Contain 'microphone'
        $deviceCaps.Name | Should -Contain 'webcam'
    }
}

Describe 'Add-MsixAppIsolation — AppContainer (default, GA)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-ac-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force } }

    It 'switches to PartialTrustApplication + uap10 appContainer/packagedClassicApp and removes runFullTrust' {
        $pkg = Join-Path $script:Dir 'base.msix'
        $out = Join-Path $script:Dir 'ac.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg
        { Add-MsixAppIsolation -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning } | Should -Not -Throw

        [xml]$m = Get-MsixManifest -Path $out
        $app = $m.Package.Applications.Application
        $app.GetAttribute('EntryPoint')                          | Should -Be 'Windows.PartialTrustApplication'
        $app.GetAttribute('TrustLevel', $script:Uap10Uri)        | Should -Be 'appContainer'
        $app.GetAttribute('RuntimeBehavior', $script:Uap10Uri)   | Should -Be 'packagedClassicApp'

        $rft = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust' }
        $rft | Should -BeNullOrEmpty -Because 'runFullTrust must be removed so the app can fall into the AppContainer'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'does not write any uap18 / appSilo attributes in AppContainer mode' {
        $out = Join-Path $script:Dir 'ac.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test produced it'
        [xml]$m = Get-MsixManifest -Path $out
        $app = $m.Package.Applications.Application
        $app.GetAttribute('RuntimeBehavior', $script:Uap18Uri) | Should -BeNullOrEmpty
        $app.GetAttribute('EntryPoint', $script:Uap18Uri)      | Should -BeNullOrEmpty
    }

    It 'adds a requested standard capability (internetClient) resolved to its namespace' {
        $pkg = Join-Path $script:Dir 'base2.msix'
        $out = Join-Path $script:Dir 'ac-cap.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg
        Add-MsixAppIsolation -PackagePath $fx.PackagePath -Capabilities internetClient -OutputPath $out -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out
        $cap = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'internetClient' }
        $cap | Should -Not -BeNullOrEmpty
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'ignores isolatedWin32-* capabilities in AppContainer mode (not emitted)' {
        $pkg = Join-Path $script:Dir 'base3.msix'
        $out = Join-Path $script:Dir 'ac-iso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg
        Add-MsixAppIsolation -PackagePath $fx.PackagePath -Capabilities 'isolatedWin32-promptForAccess' -OutputPath $out -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out
        $iso = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -like 'isolatedWin32-*' }
        $iso | Should -BeNullOrEmpty -Because 'isolatedWin32-* belong to AppSilo mode, not AppContainer'
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'is idempotent: running twice keeps exactly one set of attributes' {
        $out  = Join-Path $script:Dir 'ac.msix'
        $out2 = Join-Path $script:Dir 'ac-again.msix'
        Test-Path -LiteralPath $out | Should -BeTrue
        Add-MsixAppIsolation -PackagePath $out -OutputPath $out2 -SkipSigning
        [xml]$m = Get-MsixManifest -Path $out2
        $app = $m.Package.Applications.Application
        @($app.Attributes | Where-Object { $_.LocalName -eq 'TrustLevel' }).Count | Should -Be 1
        $app.GetAttribute('TrustLevel', $script:Uap10Uri) | Should -Be 'appContainer'
    }
}

Describe 'Add-MsixAppIsolation — AppSilo (preview)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-silo-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force } }

    It 'sets PartialTrust + uap18 Isolated.App/appContainer/appSilo, removes runFullTrust, raises MinVersion to 26100' {
        $pkg = Join-Path $script:Dir 'base.msix'
        $out = Join-Path $script:Dir 'silo.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg
        Add-MsixAppIsolation -PackagePath $fx.PackagePath -Mode AppSilo -OutputPath $out -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out
        $app = $m.Package.Applications.Application
        $app.GetAttribute('EntryPoint')                        | Should -Be 'Windows.PartialTrustApplication'
        $app.GetAttribute('EntryPoint', $script:Uap18Uri)      | Should -Be 'Isolated.App'
        $app.GetAttribute('TrustLevel', $script:Uap18Uri)      | Should -Be 'appContainer'
        $app.GetAttribute('RuntimeBehavior', $script:Uap18Uri) | Should -Be 'appSilo'

        $rft = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust' }
        $rft | Should -BeNullOrEmpty

        $tdf = @($m.Package.Dependencies.TargetDeviceFamily) | Where-Object { $_.GetAttribute('Name') -eq 'Windows.Desktop' }
        $tdf.GetAttribute('MinVersion') | Should -Be '10.0.26100.0'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'emits the default isolatedWin32-promptForAccess as a rescap:Capability' {
        $out = Join-Path $script:Dir 'silo.msix'
        Test-Path -LiteralPath $out | Should -BeTrue
        [xml]$m = Get-MsixManifest -Path $out
        $cap = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.NamespaceURI -eq $script:RescapUri -and $_.GetAttribute('Name') -eq 'isolatedWin32-promptForAccess' }
        $cap | Should -Not -BeNullOrEmpty
    }

    It 'throws for a package with a windows.comServer extension (incompatible with partial trust)' {
        # A COM shell extension can't be declared with a partial-trust entry point,
        # so such a package cannot be isolated; the cmdlet must fail fast with guidance.
        $pkg = Join-Path $script:Dir 'ctx-base.msix'
        $ctx = Join-Path $script:Dir 'ctx.msix'
        $out = Join-Path $script:Dir 'ctx-silo.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg
        Add-MsixLegacyContextMenu -PackagePath $fx.PackagePath `
            -ShellExtDll 'VFS\ProgramFilesX64\App\Shell.dll' `
            -Clsid '11112222-3333-4444-5555-666677778888' -DisplayName 'Ctx' -FileTypes '*' `
            -OutputPath $ctx -SkipSigning

        { Add-MsixAppIsolation -PackagePath $ctx -Mode AppSilo -OutputPath $out -SkipSigning -ErrorAction Stop } |
            Should -Throw -ExpectedMessage '*comServer*'
        Test-Path -LiteralPath $out | Should -BeFalse -Because 'the un-isolatable package must not be produced'
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}

Describe 'Add-MsixAppIsolation — PSF detection' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-psf-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force } }

    It 'warns that a PSF-launched package cannot be isolated' {
        $pkg = Join-Path $script:Dir 'psf-base.msix'
        $out = Join-Path $script:Dir 'psf-iso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg -Executable 'VFS\ProgramFilesX64\App\PsfLauncher64.exe'
        $info = Add-MsixAppIsolation -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning 6>&1 | Out-String
        $info | Should -Match 'Package Support Framework'
        $info | Should -Match 'will NOT run isolated'
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}

Describe 'Remove-MsixAppIsolation reverses isolation (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Uap10Uri  = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
        $script:Uap18Uri  = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/18'
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-rm-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force } }

    It 'restores Windows.FullTrustApplication + runFullTrust and strips the isolation attributes' {
        $pkg = Join-Path $script:Dir 'base.msix'
        $iso = Join-Path $script:Dir 'iso.msix'
        $rm  = Join-Path $script:Dir 'deiso.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg
        Add-MsixAppIsolation -PackagePath $fx.PackagePath -OutputPath $iso -SkipSigning
        Remove-MsixAppIsolation -PackagePath $iso -OutputPath $rm -SkipSigning

        [xml]$m = Get-MsixManifest -Path $rm
        $app = $m.Package.Applications.Application
        $app.GetAttribute('EntryPoint')                        | Should -Be 'Windows.FullTrustApplication'
        $app.GetAttribute('TrustLevel', $script:Uap10Uri)      | Should -BeNullOrEmpty
        $app.GetAttribute('RuntimeBehavior', $script:Uap10Uri) | Should -BeNullOrEmpty

        $rft = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust' }
        $rft | Should -Not -BeNullOrEmpty -Because 'a full-trust packaged app needs runFullTrust restored'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}

Describe 'Invoke-MsixPipeline AppIsolation stage (real package, issue #97)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Uap10Uri = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
        $script:Uap18Uri = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/18'
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-pipe-iso-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force } }

    It 'default AppContainer mode: PartialTrust + uap10 attrs + runFullTrust removed (not the old capability-only shape)' {
        $pkg = Join-Path $script:Dir 'base.msix'
        $out = Join-Path $script:Dir 'pipe-ac.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        Invoke-MsixPipeline -PackagePath $fx.PackagePath -OutputPath $out -Config @{
            AppIsolation = @{ Mode = 'AppContainer' }
            Signing      = @{ Skip = $true }
        }

        [xml]$m = Get-MsixManifest -Path $out
        $app = $m.Package.Applications.Application
        $app.GetAttribute('EntryPoint')                        | Should -Be 'Windows.PartialTrustApplication'
        $app.GetAttribute('TrustLevel', $script:Uap10Uri)      | Should -Be 'appContainer'
        $app.GetAttribute('RuntimeBehavior', $script:Uap10Uri) | Should -Be 'packagedClassicApp'

        $rft = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'runFullTrust' }
        $rft | Should -BeNullOrEmpty -Because 'the pipeline must apply the same model as Add-MsixAppIsolation'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'AppSilo mode: uap18 silo attrs + default isolatedWin32-promptForAccess + MinVersion 26100' {
        $pkg = Join-Path $script:Dir 'base2.msix'
        $out = Join-Path $script:Dir 'pipe-silo.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        Invoke-MsixPipeline -PackagePath $fx.PackagePath -OutputPath $out -Config @{
            AppIsolation = @{ Mode = 'AppSilo' }
            Signing      = @{ Skip = $true }
        }

        [xml]$m = Get-MsixManifest -Path $out
        $app = $m.Package.Applications.Application
        $app.GetAttribute('EntryPoint')                        | Should -Be 'Windows.PartialTrustApplication'
        $app.GetAttribute('RuntimeBehavior', $script:Uap18Uri) | Should -Be 'appSilo'
        $app.GetAttribute('EntryPoint', $script:Uap18Uri)      | Should -Be 'Isolated.App'

        $cap = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'isolatedWin32-promptForAccess' }
        $cap | Should -Not -BeNullOrEmpty -Because 'AppSilo default capability must be applied by the pipeline too'

        $tdf = @($m.Package.Dependencies.TargetDeviceFamily) | Where-Object { $_.GetAttribute('Name') -eq 'Windows.Desktop' }
        $tdf.GetAttribute('MinVersion') | Should -Be '10.0.26100.0'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}
