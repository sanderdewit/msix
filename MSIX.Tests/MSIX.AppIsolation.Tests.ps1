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
