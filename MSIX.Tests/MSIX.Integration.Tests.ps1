BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')

    $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
    if (-not $script:ToolingAvailable) {
        Write-Warning 'Integration tests SKIPPED: the SDK toolchain (MakeAppx) could not be resolved on this host. Run Install-MsixSdkTool / Initialize-MsixToolchain, or run on the Windows CI runner.'
    }
    $script:FixtureDir = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "msix-int-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:FixtureDir -Force | Out-Null
}
AfterAll {
    if ($script:FixtureDir -and (Test-Path -LiteralPath $script:FixtureDir)) {
        Remove-Item -LiteralPath $script:FixtureDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Module MSIX -ErrorAction SilentlyContinue
}

Describe 'MSIX integration (real packages via MakeAppx)' -Tag 'Integration' {

    BeforeEach {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'SDK toolchain (MakeAppx) not available on this host.'
        }
    }

    It 'builds a real .msix and round-trips its manifest back out' {
        $pkg = Join-Path -Path $script:FixtureDir -ChildPath 'roundtrip.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg
        Test-Path -LiteralPath $fx.PackagePath | Should -BeTrue

        # Read the manifest straight back out of the packed file.
        [xml]$m = Get-MsixManifest -Path $fx.PackagePath
        $m.Package.Identity.Name | Should -Be 'MSIX.IntegrationTest'

        Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'raises MaxVersionTested on every TargetDeviceFamily of a real multi-TDF package (#57)' {
        $pkg = Join-Path -Path $script:FixtureDir -ChildPath 'multitdf.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg -TargetDeviceFamilies @(
            @{ Name = 'Windows.Desktop';   MinVersion = '10.0.17763.0'; MaxVersionTested = '10.0.17763.0' },
            @{ Name = 'Windows.Universal'; MinVersion = '10.0.17763.0'; MaxVersionTested = '10.0.19041.0' }
        )
        [xml]$m = Get-MsixManifest -Path $fx.PackagePath
        Set-MsixManifestMaxVersionTested -Manifest $m -MinBuild 22000
        $builds = @($m.Package.Dependencies.TargetDeviceFamily) |
            ForEach-Object { ($_.GetAttribute('MaxVersionTested') -split '\.')[2] }
        ($builds -join ',') | Should -Be '22000,22000'

        Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'unpacks a real package exactly once during a heuristic finding sweep (#58 guard)' {
        $pkg = Join-Path -Path $script:FixtureDir -ChildPath 'scan.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        # End-to-end smoke test on a real package. The exact unpack-once count
        # assertion for #58 lives in MSIX.Heuristics.Tests.ps1 (mock-based, runs
        # without the SDK); here we confirm the shared-workspace sweep runs
        # cleanly against a genuinely-packed .msix.
        { Get-MsixHeuristicFinding -PackagePath $fx.PackagePath } | Should -Not -Throw

        Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
}
