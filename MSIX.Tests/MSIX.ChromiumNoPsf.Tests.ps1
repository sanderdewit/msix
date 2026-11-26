BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem

    function script:New-TestManifest {
        # Applications: @( @{ Id = 'App'; Exe = 'VFS\...\app.exe' }, ... )
        param([object[]]$Applications)
        $apps = ($Applications | ForEach-Object {
            "    <Application Id=`"$($_.Id)`" Executable=`"$($_.Exe)`" EntryPoint=`"Windows.FullTrustApplication`">`n" +
            "      <uap:VisualElements DisplayName=`"$($_.Id)`" Description=`"x`" BackgroundColor=`"transparent`" Square150x150Logo=`"Assets\logo.png`" Square44x44Logo=`"Assets\logo.png`" />`n" +
            "    </Application>"
        }) -join "`n"
@"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap rescap">
  <Identity Name="Chromium.Test" Publisher="CN=Chromium Test" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties><DisplayName>Chromium.Test</DisplayName><PublisherDisplayName>Chromium Test</PublisherDisplayName><Logo>Assets\logo.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" /></Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
$apps
  </Applications>
  <Capabilities><rescap:Capability Name="runFullTrust" /></Capabilities>
</Package>
"@
    }

    # A zip with the shape of an .msix (manifest + payload; OPC-style encoded
    # names): enough for the zip-directory checks, no MakeAppx needed.
    function script:New-TestZipPackage {
        param([string]$Path, [string]$ManifestXml, [string[]]$Files)
        if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
        $zip = [System.IO.Compression.ZipFile]::Open($Path, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            $writer = [IO.StreamWriter]::new($zip.CreateEntry('AppxManifest.xml').Open())
            try { $writer.Write($ManifestXml) } finally { $writer.Dispose() }
            foreach ($f in $Files) {
                $stream = $zip.CreateEntry(($f -replace '\\', '/').Replace(' ', '%20')).Open()
                try { $stream.WriteByte(0x4D) } finally { $stream.Dispose() }
            }
        } finally { $zip.Dispose() }
        return $Path
    }

    $script:ChromeApp = 'VFS\ProgramFilesX64\Google\Chrome\Application'
    $script:ChromeFiles = @(
        "$script:ChromeApp\chrome.exe", "$script:ChromeApp\chrome_proxy.exe"
        "$script:ChromeApp\158.0.8127.89\chrome.dll", "$script:ChromeApp\158.0.8127.89\chrome_elf.dll"
        "$script:ChromeApp\158.0.8127.89\v8_context_snapshot.bin", "$script:ChromeApp\158.0.8127.89\icudtl.dat"
        "$script:ChromeApp\158.0.8127.89\resources.pak", "$script:ChromeApp\158.0.8127.89\Locales\en-US.pak"
        "$script:ChromeApp\158.0.8127.89\Extensions\external_extensions.json"
    )
    $script:ChromeManifest = New-TestManifest -Applications @(@{ Id = 'GOOGLE.CHROME'; Exe = "$script:ChromeApp\chrome.exe" })

    function script:New-PluginReport {
        param([string]$PackagePath, [object[]]$Extra = @())
        [pscustomobject]@{
            PackagePath     = $PackagePath
            Findings        = @(
                [pscustomobject]@{ Severity = 'Info'; Category = 'PluginDirectory'; Symptom = 'x'; Recommendation = 'y'; AppId = $null
                                   Evidence = "$script:ChromeApp\158.0.8127.89\Extensions" }
                [pscustomobject]@{ Severity = 'Info'; Category = 'PluginDirectory'; Symptom = 'x'; Recommendation = 'y'; AppId = $null
                                   Evidence = "$script:ChromeApp\158.0.8127.89\Locales" }
            ) + @($Extra)
            SuggestedFixups = @( New-MsixPsfFileRedirectionConfig -Base 'VFS/ProgramFilesX64/Google/Chrome/Application' -Patterns '.*\.log' )
        }
    }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# No PSF for Chromium-based apps.
# A captured Chrome got PSF through PluginDirectory (its Extensions and Locales
# folders - a false positive: Chrome never writes there). Launch-tested in
# Windows Sandbox: with PSF the window appeared after 50.5 s (74 s CPU) and one
# chrome.exe exited 0x1; without PSF after 9.3 s (26 s CPU), every process 0x0.
# Chromium's sandboxed children (renderer, GPU, utility) refuse injected DLLs.
# =============================================================================

Describe 'Chromium detection (_MsixFindChromiumMarker)' -Tag 'AutoFix' {

    It 'detects <Name>' -TestCases @(
        @{ Name = 'Chrome (markers in Application\<version>)'; Exe = 'VFS\ProgramFilesX64\Google\Chrome\Application\chrome.exe'
           Files = @('VFS\ProgramFilesX64\Google\Chrome\Application\158.0.8127.89\chrome_elf.dll'); Marker = 'VFS\ProgramFilesX64\Google\Chrome\Application\158.0.8127.89\chrome_elf.dll' }
        @{ Name = 'Edge (msedge_elf.dll)'; Exe = 'VFS\ProgramFilesX86\Microsoft\Edge\Application\msedge.exe'
           Files = @('VFS\ProgramFilesX86\Microsoft\Edge\Application\131.0.2903.70\msedge_elf.dll'); Marker = 'VFS\ProgramFilesX86\Microsoft\Edge\Application\131.0.2903.70\msedge_elf.dll' }
        @{ Name = 'Electron with app.asar (Mattermost)'; Exe = 'VFS\ProgramFilesX64\Mattermost\Mattermost.exe'
           Files = @('VFS\ProgramFilesX64\Mattermost\resources\app.asar', 'VFS\ProgramFilesX64\Mattermost\icudtl.dat'); Marker = 'VFS\ProgramFilesX64\Mattermost\resources\app.asar' }
        @{ Name = 'bare Electron (V8 snapshot next to icudtl.dat)'; Exe = 'VFS\ProgramFilesX64\Electron\electron.exe'
           Files = @('VFS\ProgramFilesX64\Electron\v8_context_snapshot.bin', 'VFS\ProgramFilesX64\Electron\icudtl.dat'); Marker = 'VFS\ProgramFilesX64\Electron\v8_context_snapshot.bin' }
        @{ Name = 'Squirrel Electron (app-<version> next to a stub, Figma)'; Exe = 'VFS\ProgramFilesX86\Figma\Figma.exe'
           Files = @('VFS\ProgramFilesX86\Figma\app-126.12.8\Figma.exe', 'VFS\ProgramFilesX86\Figma\app-126.12.8\resources\app.asar'); Marker = 'VFS\ProgramFilesX86\Figma\app-126.12.8\resources\app.asar' }
        @{ Name = 'CEF (libcef.dll)'; Exe = 'VFS\ProgramFilesX64\Spot\Spot.exe'
           Files = @('VFS\ProgramFilesX64\Spot\libcef.dll'); Marker = 'VFS\ProgramFilesX64\Spot\libcef.dll' }
        @{ Name = 'Opera (snapshot_blob.bin next to icudtl.dat)'; Exe = 'VFS\ProgramFilesX64\Opera\opera.exe'
           Files = @('VFS\ProgramFilesX64\Opera\snapshot_blob.bin', 'VFS\ProgramFilesX64\Opera\icudtl.dat'); Marker = 'VFS\ProgramFilesX64\Opera\snapshot_blob.bin' }
        @{ Name = 'an executable at the package root'; Exe = 'app.exe'; Files = @('libcef.dll'); Marker = 'libcef.dll' }
    ) {
        param($Name, $Exe, $Files, $Marker)
        $r = InModuleScope MSIX -Parameters @{ E = $Exe; F = $Files } {
            param($E, $F)
            $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($p in @($F) + $E) { [void]$set.Add($p) }
            _MsixFindChromiumMarker -Payload $set -Executable $E
        }
        $r | Should -BeExactly $Marker -Because "$Name is Chromium-based"
    }

    It 'does not flag <Name>' -TestCases @(
        @{ Name = 'a Qt app (Telegram)'; Exe = 'VFS\ProgramFilesX64\Telegram Desktop\Telegram.exe'
           Files = @('VFS\ProgramFilesX64\Telegram Desktop\Qt6Core.dll') }
        @{ Name = 'a V8 snapshot without Chromium ICU data'; Exe = 'VFS\ProgramFilesX64\Engine\engine.exe'
           Files = @('VFS\ProgramFilesX64\Engine\snapshot_blob.bin') }
        @{ Name = 'CEF in a helper subfolder (Steam-like)'; Exe = 'VFS\ProgramFilesX86\Steam\steam.exe'
           Files = @('VFS\ProgramFilesX86\Steam\bin\cef\cef.win7x64\libcef.dll', 'VFS\ProgramFilesX86\Steam\bin\cef\cef.win7x64\icudtl.dat') }
        @{ Name = 'markers in a sibling application folder'; Exe = 'VFS\ProgramFilesX64\Vendor\Tool\tool.exe'
           Files = @('VFS\ProgramFilesX64\Vendor\Browser\chrome_elf.dll') }
    ) {
        param($Name, $Exe, $Files)
        $r = InModuleScope MSIX -Parameters @{ E = $Exe; F = $Files } {
            param($E, $F)
            $set = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
            foreach ($p in @($F) + $E) { [void]$set.Add($p) }
            _MsixFindChromiumMarker -Payload $set -Executable $E
        }
        $r | Should -BeNullOrEmpty -Because "$Name is not Chromium-based"
    }
}

Describe '_MsixGetChromiumPsfTarget' -Tag 'AutoFix' {

    It 'returns the Application PSF would wrap when it runs Chrome' {
        $zip = New-TestZipPackage -Path (Join-Path $TestDrive 'chrome.msix') -ManifestXml $script:ChromeManifest -Files $script:ChromeFiles
        $t = InModuleScope MSIX -Parameters @{ P = $zip } { param($P) _MsixGetChromiumPsfTarget -PackagePath $P }
        $t.AppId  | Should -Be 'GOOGLE.CHROME'
        $t.Marker | Should -Match 'chrome_elf\.dll$'
    }

    It 'checks the first Application, the one PSF wraps' {
        $manifest = New-TestManifest -Applications @(
            @{ Id = 'Tool';   Exe = 'VFS\ProgramFilesX64\Vendor\Tool\tool.exe' }
            @{ Id = 'Chrome'; Exe = "$script:ChromeApp\chrome.exe" }
        )
        $zip = New-TestZipPackage -Path (Join-Path $TestDrive 'tool-first.msix') -ManifestXml $manifest -Files (@($script:ChromeFiles) + 'VFS\ProgramFilesX64\Vendor\Tool\tool.exe')
        InModuleScope MSIX -Parameters @{ P = $zip } { param($P) _MsixGetChromiumPsfTarget -PackagePath $P } | Should -BeNullOrEmpty
    }

    It 'leaves a package that already carries PSF alone (<Case>)' -TestCases @(
        @{ Case = 'launcher'; ExeLeaf = 'PsfLauncher64.exe'; ExtraLeaf = 'PsfLauncher64.exe' }
        @{ Case = 'runtime';  ExeLeaf = 'chrome.exe';        ExtraLeaf = 'PsfRuntime64.dll' }
    ) {
        param($Case, $ExeLeaf, $ExtraLeaf)
        $manifest = New-TestManifest -Applications @(@{ Id = 'GOOGLE.CHROME'; Exe = "$script:ChromeApp\$ExeLeaf" })
        $zip = New-TestZipPackage -Path (Join-Path $TestDrive "psf-$Case.msix") -ManifestXml $manifest -Files (@($script:ChromeFiles) + "$script:ChromeApp\$ExtraLeaf")
        InModuleScope MSIX -Parameters @{ P = $zip } { param($P) _MsixGetChromiumPsfTarget -PackagePath $P } | Should -BeNullOrEmpty
    }

    It 'returns nothing for a package path that does not exist' {
        InModuleScope MSIX { _MsixGetChromiumPsfTarget -PackagePath 'C:\nope.msix' } | Should -BeNullOrEmpty
    }
}

Describe 'Auto-fix stages leave PSF out for a Chromium-based target' -Tag 'AutoFix' {

    BeforeAll {
        $script:ChromeZip = New-TestZipPackage -Path (Join-Path $TestDrive 'chrome-plan.msix') -ManifestXml $script:ChromeManifest -Files $script:ChromeFiles
        $plain = New-TestManifest -Applications @(@{ Id = 'App'; Exe = 'VFS\ProgramFilesX64\App\app.exe' })
        $script:PlainZip = New-TestZipPackage -Path (Join-Path $TestDrive 'plain-plan.msix') -ManifestXml $plain -Files @('VFS\ProgramFilesX64\App\app.exe')
        $psf = New-TestManifest -Applications @(@{ Id = 'GOOGLE.CHROME'; Exe = "$script:ChromeApp\PsfLauncher64.exe" })
        $script:PsfChromeZip = New-TestZipPackage -Path (Join-Path $TestDrive 'chrome-psf.msix') -ManifestXml $psf -Files (@($script:ChromeFiles) + "$script:ChromeApp\PsfLauncher64.exe" + "$script:ChromeApp\PsfRuntime64.dll")
    }

    BeforeEach {
        Mock -ModuleName MSIX Set-MsixFileSystemWriteVirtualization { }
        Mock -ModuleName MSIX Add-MsixPsfV2 { }
    }

    It 'PluginDirectory keeps only its manifest change, InjectPsf is skipped, both with the reason' {
        $out = @(Invoke-MsixAutoFixFromAnalysis -Report (New-PluginReport -PackagePath $script:ChromeZip) -SkipSigning -Confirm:$false 6>&1)
        $log = $out | Out-String -Width 4096
        $log | Should -Match "\[Warning\] PluginDirectory: not injecting PSF: Application 'GOOGLE\.CHROME' runs a Chromium-based executable .*chrome_elf\.dll.*Chromium's sandboxed child processes \(renderer, GPU, utility\) don't take the injected PSF runtime, which slows or breaks the start\."
        $log | Should -Match "\[Warning\] InjectPsf: not injecting PSF: Application 'GOOGLE\.CHROME'"
        $plan = @(($out | Where-Object { $_.PSObject.Properties['Plan'] }).Plan)
        @($plan.Stage) | Should -Be @('PluginDirectory')
        $plan[0].Reason | Should -Match 'manifest only'
        Should -Invoke -ModuleName MSIX Set-MsixFileSystemWriteVirtualization -Times 1 -Exactly
        Should -Invoke -ModuleName MSIX Add-MsixPsfV2 -Times 0 -Exactly
    }

    It 'a non-Chromium package still gets PSF as before' {
        $out = @(Invoke-MsixAutoFixFromAnalysis -Report (New-PluginReport -PackagePath $script:PlainZip) -SkipSigning -Confirm:$false 6>$null)
        @(($out | Where-Object { $_.PSObject.Properties['Plan'] }).Plan.Stage) | Should -Be @('PluginDirectory', 'InjectPsf')
        Should -Invoke -ModuleName MSIX Add-MsixPsfV2 -Times 2 -Exactly
    }

    It 'a Chromium package that already carries PSF is not touched by the rule' {
        $out = @(Invoke-MsixAutoFixFromAnalysis -Report (New-PluginReport -PackagePath $script:PsfChromeZip) -SkipSigning -Confirm:$false 6>$null)
        @(($out | Where-Object { $_.PSObject.Properties['Plan'] }).Plan.Stage) | Should -Be @('PluginDirectory', 'InjectPsf')
        Should -Invoke -ModuleName MSIX Add-MsixPsfV2 -Times 2 -Exactly
    }

    It '-LegacyPluginFix (PSF only) plans no PluginDirectory stage for Chrome' {
        $log = Invoke-MsixAutoFixFromAnalysis -Report (New-PluginReport -PackagePath $script:ChromeZip) -LegacyPluginFix -DryRun 6>&1 | Out-String -Width 4096
        $log | Should -Match 'PluginDirectory: not injecting PSF'
        $log | Should -Not -Match '==> PluginDirectory'
        $r = Invoke-MsixAutoFixFromAnalysis -Report (New-PluginReport -PackagePath $script:ChromeZip) -LegacyPluginFix -DryRun 6>$null
        @($r.Plan | Where-Object Stage -eq 'PluginDirectory') | Should -BeNullOrEmpty
    }

    It 'DeduplicateBundledRuntime declares the framework without the PSF env wiring' {
        Mock -ModuleName MSIX _MsixMutatePackage { }
        Mock -ModuleName MSIX Add-MsixRuntimeDependency { }
        $report = [pscustomobject]@{
            PackagePath = $script:ChromeZip; SuggestedFixups = @()
            Findings    = @([pscustomobject]@{
                Severity = 'Info'; Category = 'BundledRuntime'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'jre'
                RuntimeEntries = @([pscustomobject]@{ Kind = 'Java'; RuntimeRoot = 'VFS\ProgramFilesX64\Google\jre'; Evidence = 'jre\bin\java.exe'; SizeMB = 1; CanAutoFix = $true })
            })
        }
        $log = Invoke-MsixAutoFixFromAnalysis -Report $report -SkipSigning -Confirm:$false -DeduplicateBundledRuntime `
                   -RuntimeFrameworkName 'Contoso.Jre' -RuntimeFrameworkMinVersion '17.0.0.0' -RuntimeFrameworkPublisher 'CN=Contoso' 6>&1 | Out-String -Width 4096
        $log | Should -Match 'DeduplicateBundledRuntime: not injecting PSF'
        Should -Invoke -ModuleName MSIX Add-MsixRuntimeDependency -Times 1 -Exactly -ParameterFilter { $Runtime -eq 'None' }
    }

    It 'Invoke-MsixAutoFix skips its InjectPsf and splash stages for Chrome, not for a plain app' {
        $splash = Join-Path $TestDrive 'splash.png'
        [IO.File]::WriteAllBytes($splash, [byte[]](0x89, 0x50))
        $fixups = @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' )
        $chrome = Invoke-MsixAutoFix -PackagePath $script:ChromeZip -PsfFixups $fixups -SplashImagePath $splash -SplashAppId 'GOOGLE.CHROME' -DryRun 6>$null
        @($chrome.Stages) | Should -Not -Contain 'Recommended:InjectPsf'
        @($chrome.Stages) | Should -Not -Contain 'Optional:AddSplashImage'
        $plain = Invoke-MsixAutoFix -PackagePath $script:PlainZip -PsfFixups $fixups -SplashImagePath $splash -SplashAppId 'App' -DryRun 6>$null
        @($plain.Stages) | Should -Contain 'Recommended:InjectPsf'
        @($plain.Stages) | Should -Contain 'Optional:AddSplashImage'
    }
}

Describe 'A Chrome-like package on real MakeAppx' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path $TestDrive -ChildPath 'chrome-real'
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }

    It 'the post-process gets its write-virtualization change and no PsfLauncher' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'chrome.msix') -Executable "$script:ChromeApp\chrome.exe" `
                -Files @($script:ChromeFiles | Where-Object { $_ -notlike '*\chrome.exe' } | ForEach-Object { @{ Path = $_; Bytes = [byte[]](0x4D, 0x5A) } })
        $out = Join-Path $script:Dir 'chrome-fixed.msix'
        $report = New-PluginReport -PackagePath $fx.PackagePath -Extra @(
            [pscustomobject]@{ Severity = 'Info'; Category = 'ManifestFix:FileSystemWriteVirtualization'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'z' })

        $null = Invoke-MsixAutoFixFromAnalysis -Report $report -OutputPath $out -SkipSigning -Confirm:$false 6>$null

        $zip = [IO.Compression.ZipFile]::OpenRead($out)
        try { $names = @($zip.Entries | ForEach-Object { $_.FullName }) } finally { $zip.Dispose() }
        @($names | Where-Object { $_ -match 'PsfLauncher|PsfRuntime|FileRedirectionFixup' }) | Should -BeNullOrEmpty
        [xml]$m = Get-MsixManifest -Path $out
        $m.SelectSingleNode("//*[local-name()='Application']").GetAttribute('Executable') | Should -BeExactly "$script:ChromeApp\chrome.exe"
        $m.SelectSingleNode("//*[local-name()='Properties']/*[local-name()='FileSystemWriteVirtualization']").InnerText | Should -Be 'disabled'
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}
