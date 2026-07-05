BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# .msixbundle handling (#125) + resources.pri regeneration (#124)
# =============================================================================

Describe 'msixbundle handling (issue #125)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-bndl-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'New-MsixBundle + Get-MsixBundleInfo round-trips the identity' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'app.msix')
        $bundle = Join-Path $script:Dir 'app.msixbundle'
        $r = New-MsixBundle -PackagePaths $fx.PackagePath -OutputPath $bundle -SkipSigning
        $r.PackageCount | Should -Be 1
        Test-Path -LiteralPath $bundle | Should -BeTrue

        $info = @(Get-MsixBundleInfo -BundlePath $bundle)
        $info.Count | Should -Be 1
        $info[0].Architecture | Should -Be 'x64'
        $info[0].Version      | Should -Match '^\d+\.\d+\.\d+\.\d+$'
    }

    It 'Expand-MsixBundle extracts the inner packages' {
        $bundle = Join-Path $script:Dir 'app.msixbundle'
        Test-Path -LiteralPath $bundle | Should -BeTrue
        $x = Expand-MsixBundle -BundlePath $bundle -Destination (Join-Path $script:Dir 'exp')
        @($x.Packages).Count | Should -BeGreaterThan 0
        $x.Packages[0] | Should -Match '\.(msix|appx)$'
    }

    It 'Invoke-MsixBundleOperation mutates every inner package and rebundles' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'op-base.msix')
        $bundle = Join-Path $script:Dir 'op.msixbundle'
        New-MsixBundle -PackagePaths $fx.PackagePath -OutputPath $bundle -SkipSigning | Out-Null

        $r = Invoke-MsixBundleOperation -BundlePath $bundle -Operation {
            param($pkg)
            Add-MsixCapability -PackagePath $pkg -Names internetClient -SkipSigning
        } -SkipSigning
        $r.PackagesProcessed | Should -Be 1

        $x = Expand-MsixBundle -BundlePath $bundle -Destination (Join-Path $script:Dir 'op-verify')
        [xml]$m = Get-MsixManifest -Path $x.Packages[0]
        $cap = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.GetAttribute('Name') -eq 'internetClient' }
        $cap | Should -Not -BeNullOrEmpty
    }

    It 'Invoke-MsixBundleOperation -Architecture passes through non-matching packages' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'arch-base.msix')
        $bundle = Join-Path $script:Dir 'arch.msixbundle'
        New-MsixBundle -PackagePaths $fx.PackagePath -OutputPath $bundle -SkipSigning | Out-Null

        # Fixture is x64; restricting to arm64 must process nothing.
        $r = Invoke-MsixBundleOperation -BundlePath $bundle -Architecture arm64 -Operation {
            param($pkg) Add-MsixCapability -PackagePath $pkg -Names internetClient -SkipSigning
        } -SkipSigning
        $r.PackagesProcessed     | Should -Be 0
        $r.PackagesPassedThrough | Should -Be 1
    }

    It 'writes to -OutputPath without touching the original bundle' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'out-base.msix')
        $bundle = Join-Path $script:Dir 'out.msixbundle'
        $out    = Join-Path $script:Dir 'out-modified.msixbundle'
        New-MsixBundle -PackagePaths $fx.PackagePath -OutputPath $bundle -SkipSigning | Out-Null
        $before = (Get-Item -LiteralPath $bundle).Length

        Invoke-MsixBundleOperation -BundlePath $bundle -OutputPath $out -Operation {
            param($pkg) Add-MsixCapability -PackagePath $pkg -Names internetClient -SkipSigning
        } -SkipSigning | Out-Null

        Test-Path -LiteralPath $out | Should -BeTrue
        (Get-Item -LiteralPath $bundle).Length | Should -Be $before -Because 'the original bundle must be left untouched'
    }
}

Describe 'resources.pri regeneration (issue #124)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:MakePriAvailable = $false
        if ($script:ToolingAvailable) {
            $tr = & (Get-Module MSIX) { Get-MsixToolsRoot }
            $script:MakePriAvailable = [bool](Test-Path -LiteralPath (Join-Path -Path $tr -ChildPath 'Tools\MakePri.exe'))
        }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-pri-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' }
        elseif (-not $script:MakePriAvailable) { Set-ItResult -Skipped -Because 'MakePri.exe not available.' }
    }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'Update-MsixResourcePri regenerates resources.pri and repacks a valid package' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'pri-base.msix')
        $out = Join-Path $script:Dir 'pri.msix'
        { Update-MsixResourcePri -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning } | Should -Not -Throw
        Test-Path -LiteralPath $out | Should -BeTrue
        # Package still valid + openable.
        { $null = [xml](Get-MsixManifest -Path $out) } | Should -Not -Throw
    }

    It 'Set-MsixBrandMetadata -RegeneratePri replaces the ms-resource literal and rebuilds pri' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'brand-base.msix')
        $pri = Join-Path $script:Dir 'brand-pri.msix'
        # Seed an ms-resource DisplayName.
        Set-MsixBrandMetadata -PackagePath $fx.PackagePath -DisplayName 'ms-resource:AppName' `
            -OutputPath $pri -SkipSigning
        $out = Join-Path $script:Dir 'brand-out.msix'
        { Set-MsixBrandMetadata -PackagePath $pri -DisplayName 'Literal Brand' `
            -RegeneratePri -OutputPath $out -SkipSigning } | Should -Not -Throw
        [xml]$m = Get-MsixManifest -Path $out
        $m.Package.Properties.DisplayName | Should -Be 'Literal Brand'
    }
}
