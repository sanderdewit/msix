BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
    $script:SrcPath = (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.SparseShell.ps1')).Path
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Import-MsixSparseShellExtension' -Tag 'SparseShell' {

    It 'Is exported from the module' {
        $cmd = Get-Command Import-MsixSparseShellExtension -Module MSIX -ErrorAction Stop
        $cmd | Should -Not -BeNullOrEmpty
    }

    It 'Exposes the documented parameters' {
        $cmd = Get-Command Import-MsixSparseShellExtension -Module MSIX
        $cmd.Parameters.Keys | Should -Contain 'PackagePath'
        $cmd.Parameters.Keys | Should -Contain 'NestedPackagePath'
        $cmd.Parameters.Keys | Should -Contain 'KeepInnerPackage'
        $cmd.Parameters.Keys | Should -Contain 'SkipSigning'
        $cmd.Parameters['PackagePath'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory } |
            Should -Not -BeNullOrEmpty
        $cmd.Parameters['KeepInnerPackage'].ParameterType.FullName |
            Should -Be 'System.Management.Automation.SwitchParameter'
    }

    It 'Supports ShouldProcess (SupportsShouldProcess)' {
        $cmd = Get-Command Import-MsixSparseShellExtension -Module MSIX
        $cmd.Parameters.Keys | Should -Contain 'WhatIf'
        $cmd.Parameters.Keys | Should -Contain 'Confirm'
    }

    Context 'Source-level guards' {
        BeforeAll { $script:Src = Get-Content -Raw -LiteralPath $script:SrcPath }

        It 'Uses ImportNode (deep clone) for foreign-namespace extension nodes' {
            $script:Src | Should -Match 'ImportNode\('
        }

        It 'Rewrites com:Class @Path attributes' {
            $script:Src | Should -Match "LocalName -eq 'Class'"
            $script:Src | Should -Match "Attributes\['Path'\]"
        }

        It 'Deletes the inner .msix by default (unless -KeepInnerPackage)' {
            $script:Src | Should -Match 'KeepInnerPackage'
            $script:Src | Should -Match 'Remove-Item -LiteralPath \$innerPkg'
        }

        It 'Reads manifests via Get-MsixManifest (XML-safe loader)' {
            $script:Src | Should -Match 'Get-MsixManifest -Path \$outerManifestPath'
            $script:Src | Should -Match 'Get-MsixManifest -Path \$innerManifestPath'
        }

        It 'Uses atomic scratch-sign-move repack pattern' {
            $script:Src | Should -Match 'msix-sparse-'
            $script:Src | Should -Match 'Move-Item -LiteralPath \$scratch'
        }

        It 'Bumps MaxVersionTested to at least 17763 for desktop4 context menus' {
            $script:Src | Should -Match 'Set-MsixManifestMaxVersionTested -Manifest \$outerXml -MinBuild 17763'
        }

        It 'Skips gracefully (no throw) when the nested package is not present' {
            # A missing nested package must not abort the whole auto-fix run.
            $script:Src | Should -Not -Match 'throw "Nested package not found'
            $script:Src | Should -Match 'skipping the sparse-shell merge'
        }

        It 'Resolves a bare nested-package filename by searching the workspace' {
            $script:Src | Should -Match 'Split-Path -Path \$NestedPackagePath -Leaf'
            $script:Src | Should -Match 'Get-ChildItem -LiteralPath \$workspace -Recurse -File -Filter \$leaf'
        }
    }
}

Describe 'Import-MsixSparseShellExtension missing nested package (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:WorkDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-sparse-miss-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:WorkDir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'MakeAppx not available on this host.'
        }
    }
    AfterAll {
        if ($script:WorkDir -and (Test-Path -LiteralPath $script:WorkDir)) {
            Remove-Item -LiteralPath $script:WorkDir -Recurse -Force
        }
    }

    It 'does not throw when the named nested package is absent (warns and returns)' {
        $pkg = Join-Path -Path $script:WorkDir -ChildPath 'base.msix'
        $out = Join-Path -Path $script:WorkDir -ChildPath 'merged.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        $info = Import-MsixSparseShellExtension -PackagePath $fx.PackagePath `
                    -NestedPackagePath 'NppShell.msix' -OutputPath $out -SkipSigning 6>&1 | Out-String
        # No throw is the contract; assert the graceful-skip message surfaced.
        $info | Should -Match 'not present inside the package'

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}

Describe 'Invoke-MsixAutoFixFromAnalysis NestedPackage stage' -Tag 'SparseShell' {

    It 'Emits an ImportSparseShellExtension stage when a NestedPackage finding is present' {
        $report = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{
                    Severity       = 'Warning'
                    Category       = 'NestedPackage'
                    Symptom        = 'Package contains a nested .msix.'
                    Recommendation = 'Merge into outer manifest'
                    Evidence       = 'VFS\ProgramFilesX64\App\contextMenu\Inner.msix'
                }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
        $stage = @($r.Plan | Where-Object Stage -eq 'ImportSparseShellExtension') | Select-Object -First 1
        $stage | Should -Not -BeNullOrEmpty
        $stage.Reason | Should -Match 'Inner\.msix'
    }

    It 'Omits the stage when -IgnoreNestedPackages is supplied' {
        $report = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{
                    Severity       = 'Warning'
                    Category       = 'NestedPackage'
                    Symptom        = 'Package contains a nested .msix.'
                    Recommendation = 'Merge into outer manifest'
                    Evidence       = 'VFS\ProgramFilesX64\App\contextMenu\Inner.msix'
                }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun -IgnoreNestedPackages
        ($r.Plan | Where-Object Stage -eq 'ImportSparseShellExtension') | Should -BeNullOrEmpty
    }

    It 'Invoke-MsixAutoFixFromAnalysis exposes the -IgnoreNestedPackages switch' {
        $cmd = Get-Command Invoke-MsixAutoFixFromAnalysis -Module MSIX
        $cmd.Parameters.Keys | Should -Contain 'IgnoreNestedPackages'
        $cmd.Parameters['IgnoreNestedPackages'].ParameterType.FullName |
            Should -Be 'System.Management.Automation.SwitchParameter'
    }
}
