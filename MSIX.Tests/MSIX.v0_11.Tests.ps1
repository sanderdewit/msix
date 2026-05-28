BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'PSF builders added in v0.11' -Tag 'Builders' {

    Context 'New-MsixPsfDynamicLibraryConfig' {
        It 'Returns DynamicLibraryFixup.dll' {
            $r = New-MsixPsfDynamicLibraryConfig -Mappings @(
                @{ name='liba.dll'; filepath='VFS/ProgramFilesX64/App/lib/liba.dll' }
            )
            $r.dll | Should -Be 'DynamicLibraryFixup.dll'
        }
        It 'Throws on missing fields' {
            { New-MsixPsfDynamicLibraryConfig -Mappings @(@{ name='liba.dll' }) } |
                Should -Throw '*filepath*'
            { New-MsixPsfDynamicLibraryConfig -Mappings @(@{ filepath='x' }) } |
                Should -Throw '*name*'
        }
        It 'Preserves order in relativePaths' {
            $r = New-MsixPsfDynamicLibraryConfig -Mappings @(
                @{ name='a.dll'; filepath='lib/a.dll' }
                @{ name='b.dll'; filepath='lib/b.dll' }
            )
            $r.config.relativePaths.Count | Should -Be 2
            $r.config.relativePaths[0].name | Should -Be 'a.dll'
        }
    }

    Context 'New-MsixPsfWaitForDebuggerConfig' {
        It 'Returns WaitForDebuggerFixup.dll' {
            (New-MsixPsfWaitForDebuggerConfig).dll | Should -Be 'WaitForDebuggerFixup.dll'
        }
        It 'Includes processes when given' {
            $r = New-MsixPsfWaitForDebuggerConfig -Processes 'app','launcher'
            $r.config.processes.Count | Should -Be 2
            $r.config.processes[0].executable | Should -Be 'app'
        }
        It 'Empty config when no processes' {
            $r = New-MsixPsfWaitForDebuggerConfig
            $r.config.Keys | Should -Not -Contain 'processes'
        }
    }
}

Describe '-NoSign alias: <Name>' -Tag 'NoSign' -ForEach @(
    @{ Name = 'Add-MsixPsfV2' }
    @{ Name = 'Add-MsixCapability' }
    @{ Name = 'Remove-MsixUninstallerArtifact' }
    @{ Name = 'Add-MsixSplashScreen' }
    @{ Name = 'Update-MsixPackageVersion' }
    @{ Name = 'Add-MsixVcRuntimeBundle' }
    @{ Name = 'Set-MsixFileSystemWriteVirtualization' }
    @{ Name = 'Set-MsixRegistryWriteVirtualization' }
    @{ Name = 'Set-MsixInstalledLocationVirtualization' }
    @{ Name = 'Add-MsixLoaderSearchPathOverride' }
    @{ Name = 'Add-MsixFirewallRule' }
    @{ Name = 'Add-MsixProtocolHandler' }
    @{ Name = 'Add-MsixFileTypeAssociation' }
    @{ Name = 'Add-MsixStartupTask' }
    @{ Name = 'Add-MsixFontExtension' }
    @{ Name = 'Set-MsixBrandMetadata' }
    @{ Name = 'Remove-MsixDesktopShortcut' }
) {
    It 'has -NoSign alias' {
        $cmd = Get-Command -Name $Name -Module MSIX -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
        $skip = $cmd.Parameters['SkipSigning']
        $skip | Should -Not -BeNullOrEmpty
        $skip.Aliases | Should -Contain 'NoSign'
    }
}

Describe 'Get-MsixManifest is polymorphic (v0.11)' -Tag 'Manifest' {
    BeforeAll {
        $script:Tmp = Join-Path $env:TEMP "msix-mf-poly-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item $script:Tmp -ItemType Directory -Force | Out-Null
    }
    AfterAll { Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }

    It 'Reads an XML file directly' {
        $xmlPath = Join-Path $script:Tmp 'AppxManifest.xml'
        @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="A" Publisher="CN=X" Version="1.0.0.0" />
  <Applications><Application Id="A" Executable="x.exe" /></Applications>
</Package>
'@ | Set-Content $xmlPath
        $m = Get-MsixManifest -Path $xmlPath
        $m.Package.Identity.Name | Should -Be 'A'
    }

    It 'Reads a folder containing AppxManifest.xml' {
        $m = Get-MsixManifest -Path $script:Tmp
        $m.Package.Identity.Name | Should -Be 'A'
    }

    It 'Throws cleanly on a non-existent path' {
        { Get-MsixManifest -Path (Join-Path $script:Tmp 'no-such-thing.xml') } |
            Should -Throw '*Path not found*'
    }
}

Describe 'Auto-fix planner (v0.11)' -Tag 'AutoFix' {

    It 'Invoke-MsixAutoFixFromAnalysis -DryRun returns an empty plan when there are no findings' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @()
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun
        $r.Plan.Count | Should -Be 0
    }

    It 'Plans RemoveUninstallers when an UninstallerArtifact finding exists' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Warning'; Category='UninstallerArtifact'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun
        $r.Plan.Stage | Should -Contain 'RemoveUninstallers'
    }

    It 'Plans manifest fixes from ManifestFix:* findings' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:FileSystemWriteVirtualization'; Symptom='x'; Recommendation='y'; Evidence='z' }
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:RegistryWriteVirtualization';   Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun
        $r.Plan.Stage | Should -Contain 'FileSystemWriteVirtualization'
        $r.Plan.Stage | Should -Contain 'RegistryWriteVirtualization'
    }

    It 'Skips PSF when -PreferManifestOverPsf and a manifest fix covers the same symptom' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:FileSystemWriteVirtualization'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' )
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun -PreferManifestOverPsf $true
        $r.Plan.Stage | Should -Not -Contain 'InjectPsf'
    }

    It 'Includes PSF when -PreferManifestOverPsf $false' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:FileSystemWriteVirtualization'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' )
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun -PreferManifestOverPsf $false
        $r.Plan.Stage | Should -Contain 'InjectPsf'
    }

    It 'Skips StartupTask when -StartupTaskAppId / -StartupTaskName missing' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:StartupTask'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun
        $r.Plan.Stage | Should -Not -Contain 'StartupTask'
    }

    It 'Plans StartupTask when params supplied' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings    = @(
                [pscustomobject]@{ Severity='Info'; Category='ManifestFix:StartupTask'; Symptom='x'; Recommendation='y'; Evidence='z' }
            )
            SuggestedFixups = @()
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun `
            -StartupTaskAppId 'App' -StartupTaskName 'Demo'
        $r.Plan.Stage | Should -Contain 'StartupTask'
    }
}
