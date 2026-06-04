BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Regression coverage for the mutator-scriptblock scope bug: a -Mutator /
# -Transform scriptblock dispatched through _MsixMutatePackage /
# _MsixMutateManifest must be able to resolve module-PRIVATE helpers such as
# _MsixOpenOfflineHive. Before the fix this threw:
#   "_MsixOpenOfflineHive is not recognized as a name of a cmdlet ..."
# when Remove-MsixShellRegistryArtifact's mutator ran (e.g. via
# Invoke-MsixAutoFixFromAnalysis StripLegacyShellRegistry).

Describe 'Mutator scriptblocks resolve module-private functions' -Tag 'Mutator' {

    It 'a scriptblock invoked via NewBoundScriptBlock can see module-private helpers' {
        # This mirrors exactly what _MsixMutatePackage / _MsixMutateManifest do:
        # bind a caller scriptblock to the module session state, then invoke it.
        $result = InModuleScope MSIX {
            $block = { Get-Command -Name _MsixOpenOfflineHive -CommandType Function -ErrorAction SilentlyContinue }
            $bound = $ExecutionContext.SessionState.Module.NewBoundScriptBlock($block)
            & $bound
        }
        $result | Should -Not -BeNullOrEmpty -Because 'the module-private offreg helper must resolve inside a bound mutator block'
        $result.Name | Should -Be '_MsixOpenOfflineHive'
    }

    It '_MsixMutatePackage binds the mutator to the module session state (source guard)' {
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Pipeline.ps1')) -Raw
        $src | Should -Match 'NewBoundScriptBlock\(\$Mutator\)'
    }

    It 'Invoke-MsixManifestTransform binds the transform to the module session state (source guard)' {
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.ManifestExtensions.ps1')) -Raw
        $src | Should -Match 'NewBoundScriptBlock\(\$Transform\)'
    }
}

Describe 'Remove-MsixShellRegistryArtifact end-to-end (real package + hive)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration test SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:WorkDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-shellreg-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null
    }
    AfterAll {
        if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
            Remove-Item -LiteralPath $script:WorkDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'runs the mutator (offreg) path without an unresolved-function error' {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'MakeAppx not available.'
            return
        }

        # Build a real Registry.dat carrying a shellex ContextMenuHandler, then a
        # real .msix that contains it. This exercises the exact path that broke:
        # Remove-MsixShellRegistryArtifact -> _MsixMutatePackage -> & $Mutator ->
        # _MsixOpenOfflineHive.
        $clsid   = '{12345678-1234-1234-1234-1234567890ab}'
        $datPath = Join-Path -Path $script:WorkDir -ChildPath 'Registry.dat'
        & (Get-Module MSIX) {
            param($DatPath, $Clsid)
            $h = _MsixCreateOfflineHive
            try {
                # offreg's ORCreateKey does not create intermediate keys, so
                # build the path one segment at a time (same pattern as the
                # offreg/Issue28 tests).
                $cur = $h
                foreach ($seg in @('REGISTRY','MACHINE','SOFTWARE','Classes','Folder','shellex','ContextMenuHandlers','7-Zip')) {
                    $cur = _MsixOfflineCreateKey -Parent $cur -SubKey $seg
                }
                _MsixOfflineSetValueString -Key $cur -Name '' -Value $Clsid
                if (Test-Path -LiteralPath $DatPath) { Remove-Item -LiteralPath $DatPath -Force }
                if (-not (_MsixOfflineSaveHive -Hive $h -Path $DatPath)) { throw 'ORSaveHive failed.' }
            } finally { _MsixCloseOfflineHive -Hive $h }
        } $datPath $clsid

        $pkg = Join-Path -Path $script:WorkDir -ChildPath 'app.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg -Files @(
            @{ Path = 'Registry.dat'; Bytes = [IO.File]::ReadAllBytes($datPath) }
        )

        $entries = @([pscustomobject]@{ Clsid = $clsid; Target = 'Folder'; HandlerName = '7-Zip' })
        # The bug manifested as a thrown RuntimeException; assert it does NOT throw
        # an unresolved-function error. (-WhatIf would skip the mutator, so run real.)
        $out = Join-Path -Path $script:WorkDir -ChildPath 'app-clean.msix'
        { Remove-MsixShellRegistryArtifact -PackagePath $fx.PackagePath -Entries $entries -OutputPath $out -SkipSigning } |
            Should -Not -Throw

        Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force -ErrorAction SilentlyContinue
    }
}
