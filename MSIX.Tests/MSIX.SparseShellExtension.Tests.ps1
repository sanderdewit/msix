BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
    $script:SrcPath = (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.SparseShell.ps1')).Path
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
