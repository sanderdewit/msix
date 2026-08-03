BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Behavioural coverage for mutators the coverage ratchet only *thought* it had
# (issue #152)
# -----------------------------------------------------------------------------
# MSIX.Contract.CoverageMap.Tests.ps1 used a regex over test source text to
# decide whether a mutator was "invoked". `Get-Command Add-MsixFoo -Module MSIX`
# matched, and so did Context/It TITLE strings - so these six were certified as
# covered while never actually being called. Switching that ratchet to AST
# CommandAst detection exposed them; these are the real tests.
# =============================================================================

Describe 'Mutators previously certified by regex only (#152)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-uncov-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'Add-MsixFirewallRule declares the rule in the manifest' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'fw-base.msix')
        $out = Join-Path $script:Dir 'fw.msix'
        # -Direction In (capitalised) binds because ValidateSet is case-insensitive;
        # the desktop2 schema requires lowercase, so this also pins the normalisation.
        Add-MsixFirewallRule -PackagePath $fx.PackagePath -AppId 'App' `
            -Executable 'VFS\ProgramFilesX64\App\app.exe' `
            -Direction In -Protocol TCP -OutputPath $out -SkipSigning
        [xml]$m = Get-MsixManifest -Path $out
        $m.OuterXml | Should -Match 'firewallRules'
        $m.OuterXml | Should -Match 'Direction="in"'
    }

    It 'Add-MsixLoaderSearchPathOverride adds the uap6 override' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'loader-base.msix')
        $out = Join-Path $script:Dir 'loader.msix'
        # The package must actually pack: the emitted attribute has to be
        # FolderPath, per CT_LoaderSearchPathOverride in UapManifestSchema_v6.xsd.
        Add-MsixLoaderSearchPathOverride -PackagePath $fx.PackagePath `
            -Paths 'VFS\ProgramFilesX64\App\lib' -OutputPath $out -SkipSigning
        [xml]$m = Get-MsixManifest -Path $out
        $m.OuterXml | Should -Match 'LoaderSearchPathOverride'
        $m.OuterXml | Should -Match 'FolderPath='
    }

    It 'Add-MsixStartupTask declares windows.startupTask with the requested id' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'startup-base.msix')
        $out = Join-Path $script:Dir 'startup.msix'
        Add-MsixStartupTask -PackagePath $fx.PackagePath -AppId 'App' -TaskId 'LabTask' `
            -DisplayName 'Lab Startup' -OutputPath $out -SkipSigning
        [xml]$m = Get-MsixManifest -Path $out
        $m.OuterXml | Should -Match 'windows\.startupTask'
        $m.OuterXml | Should -Match 'LabTask'
    }

    It 'Set-MsixInstalledLocationVirtualization sets the manifest property' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'ilv-base.msix')
        $out = Join-Path $script:Dir 'ilv.msix'
        Set-MsixInstalledLocationVirtualization -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning
        [xml]$m = Get-MsixManifest -Path $out
        $m.OuterXml | Should -Match 'installedLocationVirtualization'
    }

    It 'Update-MsixPackageVersion rewrites the Identity version' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'ver-base.msix')
        $out = Join-Path $script:Dir 'ver.msix'
        Update-MsixPackageVersion -PackagePath $fx.PackagePath -NewVersion '9.8.7.6' `
            -OutputPath $out -SkipSigning
        [xml]$m = Get-MsixManifest -Path $out
        $m.Package.Identity.Version | Should -Be '9.8.7.6'
    }

    It 'Remove-MsixUpdaterArtifact runs the real scan/mutate path without throwing' {
        # A clean fixture has no updater artefacts, so this exercises the scan +
        # no-op decision end to end (the previous "coverage" never called it).
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'upd-base.msix')
        { Remove-MsixUpdaterArtifact -PackagePath $fx.PackagePath -SkipSigning } | Should -Not -Throw
    }
}
