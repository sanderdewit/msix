BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Shared runtime framework packages (#130) + modification-package completion (#131)
# =============================================================================

Describe 'Framework packages + runtime dependencies (issue #130)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:PsfAvailable = $false
        if ($script:ToolingAvailable) {
            $tr = & (Get-Module MSIX) { Get-MsixToolsRoot }
            $script:PsfAvailable = [bool](Test-Path -LiteralPath (Join-Path -Path $tr -ChildPath 'psf\PsfLauncher64.exe'))
        }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-fw-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        # A fake JRE runtime folder.
        $script:Jre = Join-Path $script:Dir 'jre17'
        New-Item -ItemType Directory -Path (Join-Path $script:Jre 'bin') -Force | Out-Null
        Set-Content -Path (Join-Path $script:Jre 'bin\java.exe') -Value 'stub'
        Set-Content -Path (Join-Path $script:Jre 'lib.txt') -Value 'runtime'
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'New-MsixFrameworkPackage emits Framework=true with no Applications element' {
        $fw = New-MsixFrameworkPackage -RuntimeFolder $script:Jre -Name 'Contoso.Java.17' `
                  -Version 17.0.11.0 -Publisher 'CN=Contoso' -SkipSigning `
                  -OutputPath (Join-Path $script:Dir 'fw.msix')
        [xml]$m = Get-MsixManifest -Path $fw.PackagePath
        $m.Package.Properties.Framework | Should -Be 'true'
        $m.Package.Identity.Name        | Should -Be 'Contoso.Java.17'
        $m.SelectSingleNode("//*[local-name()='Application']") | Should -BeNullOrEmpty
    }

    It 'Add-MsixRuntimeDependency (dep-only) declares the PackageDependency without PSF' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'dep-base.msix')
        $out = Join-Path $script:Dir 'dep.msix'
        $r = Add-MsixRuntimeDependency -PackagePath $fx.PackagePath `
                -FrameworkName 'Contoso.Java.17' -FrameworkMinVersion 17.0.11.0 `
                -FrameworkPublisher 'CN=Contoso' -Runtime None -OutputPath $out -SkipSigning
        $r.EnvironmentWired | Should -BeFalse
        [xml]$m = Get-MsixManifest -Path $out
        $dep = $m.SelectSingleNode("//*[local-name()='PackageDependency' and @Name='Contoso.Java.17']")
        $dep.GetAttribute('MinVersion') | Should -Be '17.0.11.0'
        $dep.GetAttribute('Publisher')  | Should -Be 'CN=Contoso'
    }

    It 'Add-MsixRuntimeDependency -Runtime Java wires JAVA_HOME to the computed framework root (PSF)' {
        if (-not $script:PsfAvailable) { Set-ItResult -Skipped -Because 'PSF binaries not available.'; return }
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'env-base.msix')
        $r = Add-MsixRuntimeDependency -PackagePath $fx.PackagePath `
                -FrameworkName 'Contoso.Java.17' -FrameworkMinVersion 17.0.11.0 `
                -FrameworkPublisher 'CN=Contoso' -Runtime Java -SkipSigning 3>$null
        $r.EnvironmentWired | Should -BeTrue
        $r.FrameworkRoot | Should -Match '^C:\\Program Files\\WindowsApps\\Contoso\.Java\.17_17\.0\.11\.0_x64__[a-z0-9]{13}$'
        # config.json inside the package carries the env fixup with JAVA_HOME.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($fx.PackagePath)
        try {
            $entry = $zip.Entries | Where-Object { $_.FullName -like '*config.json' } | Select-Object -First 1
            $entry | Should -Not -BeNullOrEmpty
            $reader = [IO.StreamReader]::new($entry.Open())
            try { $cfg = $reader.ReadToEnd() } finally { $reader.Dispose() }
            $cfg | Should -Match 'JAVA_HOME'
        } finally { $zip.Dispose() }
    }

    It 'Get-MsixBundledRuntime detects a private JRE by trait, not by name' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'bloat.msix') -Files @(
            @{ Path = 'VFS\ProgramFilesX64\App\jre\bin\java.exe'; Bytes = [byte[]](0x4D, 0x5A) },
            @{ Path = 'VFS\ProgramFilesX64\App\jre\lib\rt.txt';   Bytes = [byte[]](1..32) }
        )
        $rts = @(Get-MsixBundledRuntime -PackagePath $fx.PackagePath)
        $rts.Count | Should -Be 1
        $rts[0].Kind        | Should -Be 'Java'
        $rts[0].RuntimeRoot | Should -Be 'VFS\ProgramFilesX64\App\jre'
        $rts[0].CanAutoFix  | Should -BeTrue
    }

    It 'autofix plans DeduplicateBundledRuntime only with the opt-in switch AND identity' {
        $stub = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'
            Findings = @([pscustomobject]@{
                Severity = 'Info'; Category = 'BundledRuntime'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'VFS\App\jre'
                RuntimeEntries = @([pscustomobject]@{ Kind = 'Java'; RuntimeRoot = 'VFS\App\jre'; Evidence = 'jre\bin\java.exe'; SizeMB = 120; CanAutoFix = $true })
            })
            SuggestedFixups = @()
        }
        $without = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun
        @($without.Plan | Where-Object Stage -eq 'DeduplicateBundledRuntime') | Should -BeNullOrEmpty

        $withSwitchOnly = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun -DeduplicateBundledRuntime
        @($withSwitchOnly.Plan | Where-Object Stage -eq 'DeduplicateBundledRuntime') | Should -BeNullOrEmpty -Because 'the framework identity must be explicit'

        $full = Invoke-MsixAutoFixFromAnalysis -Report $stub -DryRun -DeduplicateBundledRuntime `
                    -RuntimeFrameworkName 'Contoso.Java.17' -RuntimeFrameworkMinVersion 17.0.11.0 `
                    -RuntimeFrameworkPublisher 'CN=Contoso'
        $full.Plan.Stage | Should -Contain 'DeduplicateBundledRuntime'
    }
}

Describe 'Modification packages: registry + diff (issue #131)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-mod2-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'New-MsixModificationPackage -RegistryContent builds readable Registry.dat + User.dat' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'main.msix')
        $content = Join-Path $script:Dir 'content'
        New-Item -ItemType Directory -Path $content -Force | Out-Null
        Set-Content -Path (Join-Path $content 'readme.txt') -Value 'settings pack'

        $mod = New-MsixModificationPackage -MainPackagePath $fx.PackagePath -ContentPath $content `
                   -RegistryContent @{
                       'HKLM\SOFTWARE\Contoso\App' = @{ 'LicenseServer' = 'lic01.contoso.com'; 'Port' = 27000 }
                       'HKCU\Software\Contoso\App' = @{ 'Theme' = 'dark' }
                   } -OutputPath (Join-Path $script:Dir 'settings.msix') -SkipSigning

        $ws = Join-Path $script:Dir 'verify'
        $null = & (Get-Module MSIX) { param($p, $o)
            Invoke-MsixProcess -FilePath (Join-Path (Get-MsixToolsRoot) 'Tools\MakeAppx.exe') -ArgumentList @('unpack', '/p', $p, '/d', $o, '/o')
        } $mod.PackagePath $ws
        Test-Path -LiteralPath (Join-Path $ws 'Registry.dat') | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $ws 'User.dat')     | Should -BeTrue

        # The value must be readable back through the offline-registry helpers.
        $val = & (Get-Module MSIX) { param($dat)
            $h = _MsixOpenOfflineHive -Path $dat
            try { _MsixOfflineGetValue -Parent $h -SubKey 'REGISTRY\MACHINE\SOFTWARE\Contoso\App' -Name 'LicenseServer' }
            finally { _MsixCloseOfflineHive -Hive $h }
        } (Join-Path $ws 'Registry.dat')
        $val | Should -Be 'lic01.contoso.com'
    }

    It 'ConvertTo-MsixModificationPackage productizes the delta between vendor and customized' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'vendor.msix')

        # Build the "customized" copy: unpack, add two files, repack.
        $cw = Join-Path $script:Dir 'custws'
        $null = & (Get-Module MSIX) { param($p, $o)
            Invoke-MsixProcess -FilePath (Join-Path (Get-MsixToolsRoot) 'Tools\MakeAppx.exe') -ArgumentList @('unpack', '/p', $p, '/d', $o, '/o')
        } $fx.PackagePath $cw
        New-Item -ItemType Directory -Path (Join-Path $cw 'VFS\ProgramFilesX64\App\plugins') -Force | Out-Null
        Set-Content -Path (Join-Path $cw 'VFS\ProgramFilesX64\App\plugins\corp.dll') -Value 'plugin'
        Set-Content -Path (Join-Path $cw 'VFS\ProgramFilesX64\App\app.ini') -Value 'customized=true'
        $cust = Join-Path $script:Dir 'customized.msix'
        $null = & (Get-Module MSIX) { param($s, $o)
            Invoke-MsixProcess -FilePath (Join-Path (Get-MsixToolsRoot) 'Tools\MakeAppx.exe') -ArgumentList @('pack', '/p', $o, '/d', $s, '/o')
        } $cw $cust

        $delta = ConvertTo-MsixModificationPackage -MainPackagePath $fx.PackagePath `
                     -CustomizedPackagePath $cust -OutputPath (Join-Path $script:Dir 'delta.msix') `
                     -SkipSigning 3>$null
        $delta.FilesAdded | Should -Be 2
        [xml]$m = Get-MsixManifest -Path $delta.PackagePath
        $mpd = $m.SelectSingleNode("//*[local-name()='MainPackageDependency']")
        $mpd.GetAttribute('Name') | Should -Be $m.SelectSingleNode("//*[local-name()='Identity']").GetAttribute('Name').Replace('.Modification', '')
        # The delta payload carries ONLY the changes.
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($delta.PackagePath)
        try { $names = @($zip.Entries.FullName) } finally { $zip.Dispose() }
        ($names -join ';') | Should -Match 'corp.dll'
        ($names -join ';') | Should -Match 'app.ini'
        ($names -join ';') | Should -Not -Match 'app\.exe' -Because 'unchanged vendor payload must not be in the delta'
    }

    It 'ConvertTo-MsixModificationPackage returns null (with warning) when nothing differs' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'same.msix')
        $copy = Join-Path $script:Dir 'same-copy.msix'
        Copy-Item -LiteralPath $fx.PackagePath -Destination $copy
        $r = ConvertTo-MsixModificationPackage -MainPackagePath $fx.PackagePath `
                 -CustomizedPackagePath $copy -OutputPath (Join-Path $script:Dir 'never.msix') `
                 -SkipSigning 3>$null
        $r | Should -BeNullOrEmpty
        Test-Path -LiteralPath (Join-Path $script:Dir 'never.msix') | Should -BeFalse
    }
}
