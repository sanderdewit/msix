BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Manifest namespace registry (v0.10)' -Tag 'Manifest' {

    It 'Knows uap5 / uap6 / uap10 / desktop2 / desktop6' {
        foreach ($p in 'uap5','uap6','uap10','desktop2','desktop6') {
            (Get-MsixManifestNamespaceUri $p) | Should -Not -BeNullOrEmpty
        }
    }

    It 'Returns the documented uap10 URI' {
        Get-MsixManifestNamespaceUri -Prefix 'uap10' |
            Should -Be 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
    }

    It 'Returns the documented desktop6 URI' {
        Get-MsixManifestNamespaceUri -Prefix 'desktop6' |
            Should -Be 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/6'
    }

    It 'Add-MsixManifestNamespace works for all the new prefixes' {
        $xml = [xml]@'
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         IgnorableNamespaces="">
  <Identity Name="A" Publisher="CN=X" Version="1.0.0.0" />
  <Applications><Application Id="A" Executable="x.exe" /></Applications>
</Package>
'@
        foreach ($p in 'uap5','uap6','uap10','desktop2','desktop6') {
            Add-MsixManifestNamespace -Manifest $xml -Prefix $p
        }
        foreach ($p in 'uap5','uap6','uap10','desktop2','desktop6') {
            $xml.Package.IgnorableNamespaces | Should -Match "\b$p\b"
        }
    }
}

Describe 'Manifest-only fixer cmdlets are exported (v0.10)' -Tag 'Manifest' {
    It 'Set-MsixFileSystemWriteVirtualization is exported' {
        Get-Command Set-MsixFileSystemWriteVirtualization -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Set-MsixRegistryWriteVirtualization is exported' {
        Get-Command Set-MsixRegistryWriteVirtualization -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Set-MsixInstalledLocationVirtualization is exported' {
        Get-Command Set-MsixInstalledLocationVirtualization -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Add-MsixLoaderSearchPathOverride is exported and validates 1..5 paths' {
        $cmd = Get-Command Add-MsixLoaderSearchPathOverride -Module MSIX -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
        $param = $cmd.Parameters['Paths']
        $vc = $param.Attributes |
              Where-Object { $_ -is [System.Management.Automation.ValidateCountAttribute] } |
              Select-Object -First 1
        $vc.MinLength | Should -Be 1
        $vc.MaxLength | Should -Be 5
    }
    It 'Add-MsixFirewallRule is exported with proper Direction enum' {
        $cmd = Get-Command Add-MsixFirewallRule -Module MSIX -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
        $vs = $cmd.Parameters['Direction'].Attributes |
              Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
              Select-Object -First 1
        $vs.ValidValues | Should -Contain 'in'
        $vs.ValidValues | Should -Contain 'out'
    }
    It 'Add-MsixStartupTask, Add-MsixProtocolHandler, Add-MsixFileTypeAssociation are exported' {
        foreach ($n in 'Add-MsixStartupTask','Add-MsixProtocolHandler','Add-MsixFileTypeAssociation') {
            Get-Command -Name $n -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Set-MsixInstalledLocationVirtualization parameter validation' -Tag 'Manifest' {
    It 'Rejects invalid ModifiedItems values' {
        $cmd = Get-Command Set-MsixInstalledLocationVirtualization
        $vs  = $cmd.Parameters['ModifiedItems'].Attributes |
               Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
               Select-Object -First 1
        $vs.ValidValues | Should -Be @('keep','reset')
    }
}


# Regression coverage for #81 — MakeAppx schema failure (error C00CE169): an
# install-relative VFS path was emitted as virtualization:ExcludedDirectory,
# which only accepts $(KnownFolder:Name)[\subpath] tokens.

Describe 'ExcludedDirectory KnownFolder validation (Set-MsixFileSystemWriteVirtualization)' -Tag 'Manifest', 'Security' {

    It 'the KnownFolder schema pattern accepts tokens but rejects VFS/install paths' {
        # This mirrors the MSIX virtualization schema constraint that MakeAppx
        # enforces (error C00CE169). The fix validates against exactly this.
        $rx = [regex]'^\$\(KnownFolder:[A-Za-z0-9]{1,32}\)(\\.+)?$'

        '$(KnownFolder:LocalAppData)'            | Should -Match $rx
        '$(KnownFolder:RoamingAppData)'          | Should -Match $rx
        '$(KnownFolder:ProgramFilesX64)\App\Sub' | Should -Match $rx

        # The exact value from issue #81 and its variants must be rejected.
        'c6/VFS/ProgramFilesX64/7-Zip/Lang' | Should -Not -Match $rx
        'c6\VFS\ProgramFilesX64\7-Zip\Lang' | Should -Not -Match $rx
        'VFS\ProgramFilesX64\App\plugins'   | Should -Not -Match $rx
    }

    It 'Set-MsixFileSystemWriteVirtualization filters non-KnownFolder ExcludedDirectory entries' {
        # Source guard: the cmdlet must validate each entry against the
        # KnownFolder pattern and skip invalid ones (rather than emit
        # schema-invalid XML that MakeAppx then rejects).
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.ManifestExtensions.ps1')) -Raw
        $src | Should -Match 'KnownFolder:\[A-Za-z0-9\]\{1,32\}'
        $src | Should -Match 'Skipping ExcludedDirectory'
    }

    It 'the PluginDirectory autofix routes install-dir folders via PSF, not -ExcludedDirectories' {
        # A plugin dir under the install location (the 7-Zip Lang case) must be
        # redirected via PSF FileRedirection; it must NOT be handed to
        # Set-MsixFileSystemWriteVirtualization -ExcludedDirectories.
        $report = [pscustomobject]@{
            PackagePath     = 'C:\nope.msix'
            SuggestedFixups = @()
            Findings        = @(
                [pscustomobject]@{
                    Severity = 'Info'; Category = 'PluginDirectory'
                    Symptom = 'x'; Recommendation = 'x'
                    Evidence = 'VFS\ProgramFilesX64\7-Zip\Lang'; AppId = $null
                }
            )
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun
        $stage = @($r.Plan | Where-Object Stage -eq 'PluginDirectory') | Select-Object -First 1
        $stage | Should -Not -BeNullOrEmpty

        $actionSrc = $stage.Action.ToString()
        $actionSrc | Should -Match 'New-MsixPsfFileRedirectionConfig'
        # The plugin path must not be appended to the excluded-dirs argument.
        $actionSrc | Should -Not -Match 'capturedPluginDirs[^\r\n]*ExcludedDirectories'
        $actionSrc | Should -Not -Match 'ExcludedDirectories\s+\$excluded'
    }

    It 'the legacy plugin fix continues to use PSF FileRedirection' {
        $report = [pscustomobject]@{
            PackagePath     = 'C:\nope.msix'
            SuggestedFixups = @()
            Findings        = @(
                [pscustomobject]@{
                    Severity = 'Info'; Category = 'PluginDirectory'
                    Symptom = 'x'; Recommendation = 'x'
                    Evidence = 'VFS\ProgramFilesX64\7-Zip\Lang'; AppId = $null
                }
            )
        }
        $r = Invoke-MsixAutoFixFromAnalysis -Report $report -LegacyPluginFix -DryRun
        $stage = @($r.Plan | Where-Object Stage -eq 'PluginDirectory') | Select-Object -First 1
        $stage.Reason | Should -Match 'PSF FileRedirection'
    }
}
