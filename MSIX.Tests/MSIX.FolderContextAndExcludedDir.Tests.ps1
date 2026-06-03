BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Regression coverage for:
#   #80 — folder context menus (e.g. 7-Zip) were missing: the scanner did not
#         walk the 'Folder' shell class, and the context-menu cmdlets rejected
#         folder/container -FileTypes targets.
#   #81 — MakeAppx schema failure (error C00CE169): an install-relative VFS path
#         was emitted as virtualization:ExcludedDirectory, which only accepts
#         $(KnownFolder:Name)[\subpath] tokens.

Describe 'Folder context-menu support (#80)' -Tag 'ContextMenu' {

    # -FileTypes is validated at parameter-binding time (before any MakeAppx
    # work). A valid value passes binding and the body then fails on the bogus
    # package path; an invalid value fails binding with the "Invalid file type"
    # ValidateScript message. We therefore assert only on that message.
    function script:Invoke-FileTypeBinding {
        param([string]$Type)
        try {
            Add-MsixLegacyContextMenu -PackagePath 'C:\nope.msix' `
                -Clsid '12345678-1234-1234-1234-1234567890ab' -DisplayName 'X' `
                -ShellExtDll 'x.dll' -FileTypes $Type -SkipSigning -WhatIf -ErrorAction Stop
            return $null
        } catch { return $_.Exception.Message }
    }

    It 'accepts folder/container targets (Folder, Directory\Background, Drive, ...)' {
        foreach ($t in 'Folder', 'Directory', 'Directory\Background', 'Drive', 'DesktopBackground', 'AllFilesystemObjects', '*', '.txt') {
            (Invoke-FileTypeBinding -Type $t) | Should -Not -Match 'Invalid file type' -Because "'$t' should be accepted"
        }
    }

    It 'still rejects a clearly bogus target' {
        (Invoke-FileTypeBinding -Type 'not a target!!') | Should -Match 'Invalid file type'
    }

    It 'the shell context-menu scanner walks the Folder class target' {
        # 'Folder' must be in the scanner's target list or folder handlers
        # (7-Zip) are never detected.
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Scanners.ps1')) -Raw
        $src | Should -Match "\`$target in @\([^)]*'Folder'"
    }
}

Describe 'ExcludedDirectory KnownFolder validation (#81)' -Tag 'Manifest', 'Security' {

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
