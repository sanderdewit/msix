BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')

    # The shape the converter now emits: one Application per Start-menu
    # shortcut, several of them on ONE executable with their own
    # uap10:Parameters. Mirrors the captured Java 8 package: "About Java" and
    # "Check For Updates" (javacpl.exe -tab ...) plus "Configure Java"
    # (javacpl.exe, no parameters); the first one already carries a javaws.exe
    # alias. Python adds python.exe twice (plain and -m pydoc -b) and
    # pythonw.exe once (with parameters).
    $script:SharedExeManifest = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
         xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
         xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap uap3 uap10 desktop rescap">
  <Identity Name="Alias.Shared" Publisher="CN=Alias Test" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Alias.Shared</DisplayName>
    <PublisherDisplayName>Alias Test</PublisherDisplayName>
    <Logo>Assets\logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.22000.1" />
  </Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="AboutJava" Executable="VFS\ProgramFilesX64\Java\bin\javacpl.exe" EntryPoint="Windows.FullTrustApplication" uap10:Parameters="-tab about">
      <uap:VisualElements DisplayName="About Java" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
      <Extensions>
        <uap3:Extension Category="windows.appExecutionAlias" Executable="VFS\ProgramFilesX64\Java\bin\javaws.exe" EntryPoint="Windows.FullTrustApplication">
          <uap3:AppExecutionAlias><desktop:ExecutionAlias Alias="javaws.exe" /></uap3:AppExecutionAlias>
        </uap3:Extension>
      </Extensions>
    </Application>
    <Application Id="CheckForUpdates" Executable="VFS\ProgramFilesX64\Java\bin\javacpl.exe" EntryPoint="Windows.FullTrustApplication" uap10:Parameters="-tab update">
      <uap:VisualElements DisplayName="Check For Updates" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
    <Application Id="ConfigureJava" Executable="VFS\ProgramFilesX64\Java\bin\javacpl.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Configure Java" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
    <Application Id="Idle" Executable="VFS\ProgramFilesX64\Python313\pythonw.exe" EntryPoint="Windows.FullTrustApplication" uap10:Parameters="idle.pyw">
      <uap:VisualElements DisplayName="IDLE" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
    <Application Id="ModuleDocs" Executable="VFS\ProgramFilesX64\Python313\python.exe" EntryPoint="Windows.FullTrustApplication" uap10:Parameters="-m pydoc -b">
      <uap:VisualElements DisplayName="Module Docs" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
    <Application Id="Python" Executable="VFS\ProgramFilesX64\Python313\python.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Python" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
    <Application Id="JavaWs" Executable="VFS\ProgramFilesX64\Java\bin\javaws.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Java Web Start" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
'@

    function script:Get-AliasMap([xml]$Manifest) {
        # alias name -> the Application Id(s) that declare it
        $map = [ordered]@{}
        foreach ($a in @($Manifest.SelectNodes("//*[local-name()='ExecutionAlias']"))) {
            $owner = $a
            while ($owner -and $owner.LocalName -ne 'Application') { $owner = $owner.ParentNode }
            $name = $a.GetAttribute('Alias').ToLowerInvariant()
            $map[$name] = @(@($map[$name]) + $owner.GetAttribute('Id') | Where-Object { $_ })
        }
        return $map
    }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Two Applications on one executable must not both get its alias.
# The converter declares an Application per Start-menu shortcut; Java has
# "Configure Java" and "About Java" on javacpl.exe, Python "Python 3.13" and
# "Module Docs" on python.exe. AddAliases gave each the same alias and MakeAppx
# refused the package: "'javacpl.exe' is a duplicate key for the unique
# Identity Constraint ...Extension_AppExecutionAlias...".
# =============================================================================

Describe 'Get-MsixAliasCandidate: one candidate per executable' -Tag 'Heuristics' {

    BeforeAll {
        $script:Ws = Join-Path -Path $TestDrive -ChildPath 'alias-ws'
        New-Item -ItemType Directory -Path $script:Ws -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $script:Ws 'AppxManifest.xml'), $script:SharedExeManifest, [Text.UTF8Encoding]::new($true))
        $script:Cands = @(Get-MsixAliasCandidate -PackagePath 'C:\nope.msix' -WorkspacePath $script:Ws)
    }

    It 'emits one candidate per alias name, not one per Application' {
        @($script:Cands | ForEach-Object { $_.SuggestAlias }) | Should -Be @('javacpl.exe', 'pythonw.exe', 'python.exe', 'javaws.exe')
    }

    It 'picks the Application without uap10:Parameters, passing over one that already has an alias' {
        ($script:Cands | Where-Object SuggestAlias -eq 'javacpl.exe').AppId | Should -Be 'ConfigureJava'
        ($script:Cands | Where-Object SuggestAlias -eq 'python.exe').AppId  | Should -Be 'Python'
        @(($script:Cands | Where-Object SuggestAlias -eq 'javacpl.exe').SharedWith) | Should -Be @('AboutJava', 'CheckForUpdates')
    }

    It 'falls back to the first Application when every one has parameters' {
        ($script:Cands | Where-Object SuggestAlias -eq 'pythonw.exe').AppId | Should -Be 'Idle'
        ($script:Cands | Where-Object SuggestAlias -eq 'pythonw.exe').AlreadyHasAlias | Should -BeFalse
    }

    It 'reports a name another Application already declares as taken' {
        $ws = ($script:Cands | Where-Object SuggestAlias -eq 'javaws.exe')
        $ws.AppId | Should -Be 'JavaWs'
        $ws.AlreadyHasAlias | Should -BeTrue -Because 'AboutJava already declares javaws.exe'
    }

    It 'feeds Get-MsixHeuristicFinding-style consumers only unique names' {
        $open = @($script:Cands | Where-Object { -not $_.AlreadyHasAlias })
        @($open.AppId) | Should -Be @('ConfigureJava', 'Idle', 'Python')
    }
}

Describe 'Add-MsixAlias never declares an alias name twice' -Tag 'Mutator' {

    BeforeAll {
        $script:AliasFile = Join-Path -Path $TestDrive -ChildPath 'AppxManifest.xml'
    }

    BeforeEach {
        [IO.File]::WriteAllText($script:AliasFile, $script:SharedExeManifest, [Text.UTF8Encoding]::new($true))
        # Stand-in for unpack/mutate/repack: one load-transform-save of the file.
        Mock -ModuleName MSIX _MsixMutateManifest {
            [xml]$m = Get-MsixManifest -Path $script:AliasFile
            $m = Invoke-MsixManifestTransform -Manifest $m -Transform $Mutate
            Save-MsixManifest -Manifest $m -Path $script:AliasFile
        }
    }

    It '-All gives each executable''s alias to ONE Application and logs the others' {
        $log = Add-MsixAlias -PackagePath 'C:\nope.msix' -All -SkipSigning 6>&1 | Out-String -Width 4096
        $map = Get-AliasMap -Manifest (Get-MsixManifest -Path $script:AliasFile)

        foreach ($name in $map.Keys) { @($map[$name]) | Should -HaveCount 1 -Because "'$name' may be declared only once" }
        @($map['javacpl.exe']) | Should -Be 'ConfigureJava'
        @($map['python.exe'])  | Should -Be 'Python'
        @($map['pythonw.exe']) | Should -Be 'Idle'
        @($map['javaws.exe'])  | Should -Be 'AboutJava' -Because 'the existing alias stays where it was'

        $log | Should -Match "AppExecutionAlias 'javacpl\.exe' goes to ConfigureJava, which runs the same executable; skipped for CheckForUpdates"
        $log | Should -Match "AppExecutionAlias 'python\.exe' goes to Python, which runs the same executable; skipped for ModuleDocs"
        $log | Should -Match "AppExecutionAlias 'javaws\.exe' is already declared in the package; skipped for JavaWs"
    }

    It 'with explicit AppIds that share an executable, still declares the name once' {
        $null = Add-MsixAlias -PackagePath 'C:\nope.msix' -AppIds 'ModuleDocs', 'CheckForUpdates' -SkipSigning 6>$null
        $map = Get-AliasMap -Manifest (Get-MsixManifest -Path $script:AliasFile)
        @($map['python.exe'])  | Should -Be 'ModuleDocs'
        @($map['javacpl.exe']) | Should -Be 'CheckForUpdates'

        # A later call for the plain app must not add the name again.
        $null = Add-MsixAlias -PackagePath 'C:\nope.msix' -AppIds 'Python', 'ConfigureJava' -SkipSigning 6>$null
        $map = Get-AliasMap -Manifest (Get-MsixManifest -Path $script:AliasFile)
        @($map['python.exe'])  | Should -Be 'ModuleDocs'
        @($map['javacpl.exe']) | Should -Be 'CheckForUpdates'
    }
}

Describe 'Shared-executable aliases on a real package' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path $TestDrive -ChildPath 'alias-real'
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }

    It 'the AutoFix AddAliases stage packs a Java/Python-style package' {
        $files = foreach ($p in 'VFS\ProgramFilesX64\Java\bin\javacpl.exe', 'VFS\ProgramFilesX64\Java\bin\javaws.exe',
                               'VFS\ProgramFilesX64\Python313\python.exe', 'VFS\ProgramFilesX64\Python313\pythonw.exe') {
            @{ Path = $p; Bytes = [byte[]](0x4D, 0x5A) }
        }
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'shared.msix') -ManifestXml $script:SharedExeManifest `
            -Executable 'VFS\ProgramFilesX64\Java\bin\javacpl.exe' -Files $files
        $out = Join-Path $script:Dir 'shared-alias.msix'

        # The planner's input exactly as Get-MsixHeuristicFinding builds it.
        $findings = @(Get-MsixAliasCandidate -PackagePath $fx.PackagePath | Where-Object { -not $_.AlreadyHasAlias } | ForEach-Object {
            [pscustomobject]@{ Severity = 'Info'; Category = 'AppExecutionAlias'; Symptom = 'x'; Recommendation = 'y'; Evidence = $_.Executable; AppId = $_.AppId }
        })
        $report = [pscustomobject]@{ PackagePath = $fx.PackagePath; Findings = $findings; SuggestedFixups = @() }

        { $null = Invoke-MsixAutoFixFromAnalysis -Report $report -OutputPath $out -SkipSigning -Confirm:$false 6>$null } | Should -Not -Throw

        $map = Get-AliasMap -Manifest (Get-MsixManifest -Path $out)
        foreach ($name in $map.Keys) { @($map[$name]) | Should -HaveCount 1 }
        @($map.Keys) | Should -Be @('javaws.exe', 'javacpl.exe', 'pythonw.exe', 'python.exe')
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'a PSF-launched app gets its config.json target''s name (pythonw.exe) and the package packs' {
        $apps = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap10="http://schemas.microsoft.com/appx/manifest/uap/windows10/10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap uap10 rescap">
  <Identity Name="Alias.Psf" Publisher="CN=Alias Test" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties><DisplayName>Alias.Psf</DisplayName><PublisherDisplayName>Alias Test</PublisherDisplayName><Logo>Assets\logo.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.19041.0" MaxVersionTested="10.0.22000.1" /></Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="PYTHON.A3.A13.A17.A64.BIT" Executable="VFS\ProgramFilesX64\Python313\PsfLauncher64.exe" EntryPoint="Windows.FullTrustApplication" uap10:Parameters="idle.pyw">
      <uap:VisualElements DisplayName="IDLE" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
  </Applications>
  <Capabilities><rescap:Capability Name="runFullTrust" /></Capabilities>
</Package>
'@
        $config = '{"applications":[{"id":"PYTHON.A3.A13.A17.A64.BIT","executable":"VFS/ProgramFilesX64/Python313/pythonw.exe"}],"processes":[{"executable":".*","fixups":[]}]}'
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'psf.msix') -ManifestXml $apps `
            -Executable 'VFS\ProgramFilesX64\Python313\PsfLauncher64.exe' -Files @(
                @{ Path = 'VFS\ProgramFilesX64\Python313\pythonw.exe'; Bytes = [byte[]](0x4D, 0x5A) }
                @{ Path = 'VFS\ProgramFilesX64\Python313\config.json'; Content = $config }
            )
        $out = Join-Path $script:Dir 'psf-alias.msix'

        Add-MsixAlias -PackagePath $fx.PackagePath -All -OutputPath $out -SkipSigning 6>$null

        $map = Get-AliasMap -Manifest (Get-MsixManifest -Path $out)
        @($map.Keys) | Should -Be @('pythonw.exe')
        @($map['pythonw.exe']) | Should -Be 'PYTHON.A3.A13.A17.A64.BIT'
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}

Describe 'Add-MsixAlias names a PSF-launched app after its config.json target' -Tag 'Mutator' {

    BeforeAll {
        # PSF (the PluginDirectory stage) runs before AddAliases and points the
        # app at PsfLauncher64.exe; the alias used to be named after the AppId
        # ('python.a3.a13.a17.a64.bit.exe') instead of the program it starts.
        $script:PsfWs = Join-Path -Path $TestDrive -ChildPath 'psf-ws'
        $appDir = Join-Path -Path $script:PsfWs -ChildPath 'VFS\ProgramFilesX64\Python313'
        New-Item -ItemType Directory -Path $appDir -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $appDir 'config.json'),
            '{"applications":[{"id":"PsfIdle","executable":"VFS/ProgramFilesX64/Python313/pythonw.exe"},{"id":"PsfDocs","executable":"VFS/ProgramFilesX64/Python313/python.exe"}],"processes":[]}')
        # An app's own config.json without PSF's 'applications' list must not confuse the lookup.
        [IO.File]::WriteAllText((Join-Path $script:PsfWs 'config.json'), '{"theme":"dark"}')
        $script:PsfFile = Join-Path -Path $script:PsfWs -ChildPath 'AppxManifest.xml'
        $script:PsfManifest = $script:SharedExeManifest.Replace('<Applications>', @'
<Applications>
    <Application Id="PsfIdle" Executable="VFS\ProgramFilesX64\Python313\PsfLauncher64.exe" EntryPoint="Windows.FullTrustApplication" uap10:Parameters="idle.pyw">
      <uap:VisualElements DisplayName="IDLE (PSF)" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
    <Application Id="PsfDocs" Executable="VFS\ProgramFilesX64\Python313\PsfLauncher64_2.exe" EntryPoint="Windows.FullTrustApplication" uap10:Parameters="-m pydoc -b">
      <uap:VisualElements DisplayName="Docs (PSF)" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
    <Application Id="Unmapped" Executable="VFS\ProgramFilesX64\Other\PsfLauncher64.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Unmapped (PSF)" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
'@)
    }

    BeforeEach {
        [IO.File]::WriteAllText($script:PsfFile, $script:PsfManifest, [Text.UTF8Encoding]::new($true))
        # One load-transform-save, handing the transform the unpacked folder as
        # _MsixMutateManifest does.
        Mock -ModuleName MSIX _MsixMutateManifest {
            [xml]$m = Get-MsixManifest -Path $script:PsfFile
            $m = Invoke-MsixManifestTransform -Manifest $m -Transform $Mutate -ArgumentList @($script:PsfWs)
            Save-MsixManifest -Manifest $m -Path $script:PsfFile
        }
    }

    It 'names the alias after the PSF config.json target, not the AppId' {
        $null = Add-MsixAlias -PackagePath 'C:\nope.msix' -AppIds 'PsfIdle' -SkipSigning 6>$null
        $map = Get-AliasMap -Manifest (Get-MsixManifest -Path $script:PsfFile)
        @($map['pythonw.exe']) | Should -Be 'PsfIdle'
        $map.Contains('psfidle.exe') | Should -BeFalse
    }

    It 'keeps the once-per-package rule across PSF and plain apps' {
        # python.exe: PsfDocs (PSF, parameters), ModuleDocs (parameters) and
        # Python (plain) -> Python. pythonw.exe: PsfIdle and Idle, both with
        # parameters -> the first, PsfIdle.
        $log = Add-MsixAlias -PackagePath 'C:\nope.msix' -All -SkipSigning 6>&1 | Out-String -Width 4096
        $map = Get-AliasMap -Manifest (Get-MsixManifest -Path $script:PsfFile)
        foreach ($name in $map.Keys) { @($map[$name]) | Should -HaveCount 1 -Because "'$name' may be declared only once" }
        @($map['python.exe'])  | Should -Be 'Python'
        @($map['pythonw.exe']) | Should -Be 'PsfIdle'
        $log | Should -Match "AppExecutionAlias 'python\.exe' goes to Python, which runs the same executable; skipped for PsfDocs"
        $log | Should -Match "AppExecutionAlias 'pythonw\.exe' goes to PsfIdle, which runs the same executable; skipped for Idle"
    }

    It 'falls back to the AppId only when no config.json maps the app' {
        $log = Add-MsixAlias -PackagePath 'C:\nope.msix' -AppIds 'Unmapped' -SkipSigning 6>&1 | Out-String -Width 4096
        $map = Get-AliasMap -Manifest (Get-MsixManifest -Path $script:PsfFile)
        @($map['unmapped.exe']) | Should -Be 'Unmapped'
        $log | Should -Match 'Unmapped runs PsfLauncher but no PSF config.json maps it'
    }
}
