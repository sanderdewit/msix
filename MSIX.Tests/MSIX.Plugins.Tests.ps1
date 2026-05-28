BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    function New-SamplePluginReport {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions','',
            Justification = 'Pure constructor for a test fixture — produces a pscustomobject, no IO, no state change.')]
        param([string[]]$Dirs, [string[]]$ExtraCategories)
        $findings = @()
        foreach ($d in $Dirs) {
            $findings += [pscustomobject]@{
                Severity       = 'Info'
                Category       = 'PluginDirectory'
                Symptom        = "Likely runtime extension folder: $($d.Split('\')[-1])"
                Recommendation = 'Set-MsixFileSystemWriteVirtualization ...'
                Evidence       = $d
                AppId          = $null
            }
        }
        foreach ($c in @($ExtraCategories)) {
            $findings += [pscustomobject]@{
                Severity = 'Warning'
                Category = $c
                Symptom  = '.'; Recommendation = '.'; Evidence = '.'; AppId = $null
            }
        }
        [pscustomobject]@{
            PackagePath     = 'C:\nope.msix'
            Findings        = $findings
            SuggestedFixups = @()
        }
    }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Plugin / extension-point detection + autofix' -Tag 'Plugins' {

    Context 'Get-MsixPluginExtensionPoint' {
        It 'Is exported with the expected parameters and alias' {
            $cmd = Get-Command Get-MsixPluginExtensionPoint -Module MSIX
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.Parameters.Keys | Should -Contain 'PackagePath'
            $cmd.Parameters.Keys | Should -Contain 'MinFiles'
            (Get-Alias Get-MsixPluginExtensionPoints -ErrorAction SilentlyContinue).Definition | Should -Be 'Get-MsixPluginExtensionPoint'
        }
    }

    Context 'Invoke-MsixAutoFixFromAnalysis PluginDirectory stage' {
        It 'Adds the PluginDirectory stage for PluginDirectory findings' {
            $report = New-SamplePluginReport -Dirs 'VFS\ProgramFilesX64\App\plugins','VFS\ProgramFilesX64\App\themes' -ExtraCategories @()
            $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
            $stage = @($r.Plan | Where-Object Stage -eq 'PluginDirectory') | Select-Object -First 1
            $stage | Should -Not -BeNullOrEmpty
            $stage.Reason | Should -Match 'Selective virtualization'
            $stage.Reason | Should -Match 'plugins'
            $stage.Reason | Should -Match 'themes'
        }

        It '-LegacyPluginFix switches to the PSF FileRedirection route' {
            $report = New-SamplePluginReport -Dirs 'VFS\ProgramFilesX64\App\plugins' -ExtraCategories @()
            $r = Invoke-MsixAutoFixFromAnalysis -Report $report -LegacyPluginFix -DryRun
            $stage = @($r.Plan | Where-Object Stage -eq 'PluginDirectory') | Select-Object -First 1
            $stage | Should -Not -BeNullOrEmpty
            $stage.Reason | Should -Match 'PSF FileRedirection'
        }

        It '-IgnorePluginDirectories omits the stage entirely' {
            $report = New-SamplePluginReport -Dirs 'VFS\ProgramFilesX64\App\plugins' -ExtraCategories @()
            $r = Invoke-MsixAutoFixFromAnalysis -Report $report -IgnorePluginDirectories -DryRun
            ($r.Plan | Where-Object Stage -eq 'PluginDirectory' | Measure-Object).Count | Should -Be 0
        }

        It 'Omits the stage when there are no PluginDirectory findings' {
            $report = New-SamplePluginReport -Dirs @() -ExtraCategories 'VcRuntime'
            $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
            ($r.Plan | Where-Object Stage -eq 'PluginDirectory' | Measure-Object).Count | Should -Be 0
        }

        It 'Deduplicates plugin directories across findings' {
            $report = New-SamplePluginReport -Dirs `
                'VFS\ProgramFilesX64\App\plugins',`
                'VFS\ProgramFilesX64\App\plugins',`
                'VFS\ProgramFilesX64\App\themes' -ExtraCategories @()
            $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
            $stage = @($r.Plan | Where-Object Stage -eq 'PluginDirectory') | Select-Object -First 1
            $stage | Should -Not -BeNullOrEmpty
            $stage.Reason | Should -Match '2 extension folder\(s\)'
        }
    }

    Context 'Source-level regression guards' {
        It 'Get-MsixHeuristicFindings emits PluginDirectory findings' {
            # Issue #38: Get-MsixHeuristicFinding moved to MSIX.Scanners.ps1.
            $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Scanners.ps1')) -Raw
            $src | Should -Match "Category = 'PluginDirectory'"
            $src | Should -Match 'Get-MsixPluginExtensionPoint -PackagePath'
        }
        It 'Detection.ps1 declares the plugin directory-name list' {
            $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Detection.ps1')) -Raw
            $src | Should -Match 'MsixPluginDirectoryNames'
            $src | Should -Match 'function Get-MsixPluginExtensionPoint'
        }
    }
}
