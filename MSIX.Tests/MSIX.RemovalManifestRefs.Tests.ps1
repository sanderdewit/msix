BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')

    $script:Ns = @'
xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:uap3="http://schemas.microsoft.com/appx/manifest/uap/windows10/3"
         xmlns:uap6="http://schemas.microsoft.com/appx/manifest/uap/windows10/6"
         xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10"
         xmlns:desktop2="http://schemas.microsoft.com/appx/manifest/desktop/windows10/2"
         xmlns:desktop4="http://schemas.microsoft.com/appx/manifest/desktop/windows10/4"
         xmlns:desktop5="http://schemas.microsoft.com/appx/manifest/desktop/windows10/5"
         xmlns:desktop6="http://schemas.microsoft.com/appx/manifest/desktop/windows10/6"
         xmlns:desktop7="http://schemas.microsoft.com/appx/manifest/desktop/windows10/7"
         xmlns:com="http://schemas.microsoft.com/appx/manifest/com/windows10"
         xmlns:com4="http://schemas.microsoft.com/appx/manifest/com/windows10/4"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap uap3 uap6 desktop desktop2 desktop4 desktop5 desktop6 desktop7 com com4 rescap"
'@

    # Every kind of reference a removal can leave dangling, next to ones that
    # must survive. updater.exe, WinSparkle.dll and the 'updater' folder go;
    # setup.exe is an Application's entry point and has to stay.
    $script:RichManifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package $script:Ns>
  <Identity Name="Removal.Test" Publisher="CN=Removal Test" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Removal.Test</DisplayName>
    <PublisherDisplayName>Removal Test</PublisherDisplayName>
    <Logo>Assets\logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" />
  </Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="App" Executable="VFS\ProgramFilesX64\App\app.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="App" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
      <Extensions>
        <desktop7:Extension Category="windows.shortcut">
          <desktop7:Shortcut File="[{Common Programs}]\App.lnk" Icon="[{Package}]\VFS\ProgramFilesX64\App\app.exe" />
        </desktop7:Extension>
        <desktop6:Extension Category="windows.service" Executable="VFS\ProgramFilesX64\App\updater.exe" EntryPoint="Windows.FullTrustApplication">
          <desktop6:Service Name="AppUpdater" StartupType="auto" StartAccount="localSystem" />
        </desktop6:Extension>
        <desktop6:Extension Category="windows.service" Executable="VFS\ProgramFilesX64\App\agent.exe" EntryPoint="Windows.FullTrustApplication">
          <desktop6:Service Name="AppAgent" StartupType="auto" StartAccount="localService" />
        </desktop6:Extension>
        <uap3:Extension Category="windows.appExecutionAlias" Executable="VFS/ProgramFilesX64/App/UPDATER.EXE" EntryPoint="Windows.FullTrustApplication">
          <uap3:AppExecutionAlias><desktop:ExecutionAlias Alias="appupdate.exe" /></uap3:AppExecutionAlias>
        </uap3:Extension>
        <uap3:Extension Category="windows.appExecutionAlias" Executable="VFS\ProgramFilesX64\App\app.exe" EntryPoint="Windows.FullTrustApplication">
          <uap3:AppExecutionAlias><desktop:ExecutionAlias Alias="app.exe" /></uap3:AppExecutionAlias>
        </uap3:Extension>
        <desktop:Extension Category="windows.startupTask" Executable="VFS\ProgramFilesX64\App\updater.exe" EntryPoint="Windows.FullTrustApplication">
          <desktop:StartupTask TaskId="UpdaterTask" Enabled="true" DisplayName="Updater" />
        </desktop:Extension>
        <com:Extension Category="windows.comServer">
          <com:ComServer>
            <com:ExeServer Executable="VFS\ProgramFilesX64\App\updater.exe" DisplayName="Update COM">
              <com:Class Id="aaaaaaaa-0000-0000-0000-000000000001" />
            </com:ExeServer>
            <com:SurrogateServer DisplayName="Shell">
              <com:Class Id="bbbbbbbb-0000-0000-0000-000000000002" Path="VFS\ProgramFilesX64\App\WinSparkle.dll" ThreadingModel="STA" />
              <com:Class Id="cccccccc-0000-0000-0000-000000000003" Path="VFS\ProgramFilesX64\App\shell.dll" ThreadingModel="STA" />
            </com:SurrogateServer>
          </com:ComServer>
        </com:Extension>
        <desktop:Extension Category="windows.toastNotificationActivation">
          <desktop:ToastNotificationActivation ToastActivatorCLSID="{AAAAAAAA-0000-0000-0000-000000000001}" />
        </desktop:Extension>
        <desktop4:Extension Category="windows.fileExplorerContextMenus">
          <desktop4:FileExplorerContextMenus>
            <desktop5:ItemType Type="*">
              <desktop5:Verb Id="ContextMenuHandlers" Clsid="bbbbbbbb-0000-0000-0000-000000000002" />
            </desktop5:ItemType>
            <desktop5:ItemType Type="Directory">
              <desktop5:Verb Id="ContextMenuHandlers" Clsid="cccccccc-0000-0000-0000-000000000003" />
            </desktop5:ItemType>
          </desktop4:FileExplorerContextMenus>
        </desktop4:Extension>
        <uap:Extension Category="windows.fileTypeAssociation">
          <uap:FileTypeAssociation Name="labthumbnail">
            <uap:SupportedFileTypes><uap:FileType>.lab</uap:FileType></uap:SupportedFileTypes>
            <desktop2:ThumbnailHandler Clsid="bbbbbbbb-0000-0000-0000-000000000002" />
          </uap:FileTypeAssociation>
        </uap:Extension>
      </Extensions>
    </Application>
    <Application Id="Setup" Executable="VFS\ProgramFilesX64\App\setup.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Setup" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
  <Extensions>
    <desktop2:Extension Category="windows.firewallRules">
      <desktop2:FirewallRules Executable="VFS\ProgramFilesX64\App\updater.exe">
        <desktop2:Rule Direction="out" IPProtocol="TCP" Profile="all" />
      </desktop2:FirewallRules>
    </desktop2:Extension>
    <uap6:Extension Category="windows.loaderSearchPathOverride">
      <uap6:LoaderSearchPathOverride>
        <uap6:LoaderSearchPathEntry FolderPath="VFS\ProgramFilesX64\App\updater" />
        <uap6:LoaderSearchPathEntry FolderPath="VFS\ProgramFilesX64\App" />
      </uap6:LoaderSearchPathOverride>
    </uap6:Extension>
    <com4:Extension Category="windows.comServer">
      <com4:ComServer>
        <com4:InProcessServer>
          <com4:Path>VFS\ProgramFilesX64\App\WinSparkle.dll</com4:Path>
          <com4:Class Id="dddddddd-0000-0000-0000-000000000004" ThreadingModel="Both" />
        </com4:InProcessServer>
      </com4:ComServer>
    </com4:Extension>
  </Extensions>
</Package>
"@

    function script:New-TestWorkspace {
        param([string]$Name, [string]$Manifest, [string[]]$Files)
        $ws = Join-Path -Path $TestDrive -ChildPath $Name
        New-Item -ItemType Directory -Path $ws -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $ws 'AppxManifest.xml'), $Manifest, [Text.UTF8Encoding]::new($true))
        foreach ($f in $Files) {
            $p = Join-Path $ws $f
            New-Item -ItemType Directory -Path (Split-Path -Path $p -Parent) -Force | Out-Null
            [IO.File]::WriteAllBytes($p, [byte[]](0x4D, 0x5A))
        }
        return $ws
    }

    $script:RichFiles = @(
        'AppxBlockMap.xml', 'Assets\logo.png',
        'VFS\ProgramFilesX64\App\app.exe', 'VFS\ProgramFilesX64\App\agent.exe', 'VFS\ProgramFilesX64\App\setup.exe',
        'VFS\ProgramFilesX64\App\updater.exe', 'VFS\ProgramFilesX64\App\WinSparkle.dll', 'VFS\ProgramFilesX64\App\shell.dll',
        'VFS\ProgramFilesX64\App\updater\helper.dll'
    )
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Removal stages must not leave the manifest pointing at removed files.
# RemoveUpdaters deleted a captured Chrome's GoogleUpdater\...\updater.exe but
# kept the two desktop6 windows.service extensions that start it; MakeAppx then
# refused the package: "0x80080204 - The specified package format is not
# valid: The package manifest is not valid". Every file-removal stage now goes
# through _MsixRemoveWorkspaceFile.
# =============================================================================

Describe '_MsixRemoveWorkspaceFile' -Tag 'Mutator' {

    BeforeAll {
        $script:Ws = New-TestWorkspace -Name 'rich' -Manifest $script:RichManifest -Files $script:RichFiles
        $script:Result = & (Get-Module MSIX) {
            param($Workspace)
            _MsixRemoveWorkspaceFile -Workspace $Workspace -RelativePath @(
                'VFS\ProgramFilesX64\App\updater.exe'
                'VFS\ProgramFilesX64\App\WinSparkle.dll'
                'VFS\ProgramFilesX64\App\setup.exe'
                'VFS\ProgramFilesX64\App\updater\helper.dll'
                'AppxBlockMap.xml'
                'VFS\ProgramFilesX64\App\missing.exe'
            )
        } $script:Ws 6>$null
        [xml]$script:M = Get-MsixManifest -Path (Join-Path $script:Ws 'AppxManifest.xml')
        function script:Select-TestNode([string]$XPath) { @($script:M.SelectNodes($XPath)) }
    }

    It 'deletes the files nothing needs and reports them' {
        @($script:Result.Removed) | Should -Be @(
            'VFS\ProgramFilesX64\App\updater.exe'
            'VFS\ProgramFilesX64\App\WinSparkle.dll'
            'VFS\ProgramFilesX64\App\updater\helper.dll'
        )
        foreach ($f in $script:Result.Removed) { Join-Path $script:Ws $f | Should -Not -Exist }
        Join-Path $script:Ws 'VFS\ProgramFilesX64\App\updater' | Should -Not -Exist -Because 'a folder the removal emptied goes too'
    }

    It 'keeps an Application''s own Executable (the Application is never removed)' {
        @($script:Result.Kept) | Should -Be @('VFS\ProgramFilesX64\App\setup.exe')
        Join-Path $script:Ws 'VFS\ProgramFilesX64\App\setup.exe' | Should -Exist
        Select-TestNode "//*[local-name()='Application' and @Id='Setup']" | Should -HaveCount 1
        Select-TestNode "//*[local-name()='Application']" | Should -HaveCount 2
    }

    It 'never deletes a package-format file' {
        Join-Path $script:Ws 'AppxBlockMap.xml' | Should -Exist
    }

    It 'removes every Extension whose Executable was removed (service, alias, startup task)' {
        Select-TestNode "//*[local-name()='Service' and @Name='AppUpdater']" | Should -BeNullOrEmpty
        Select-TestNode "//*[local-name()='ExecutionAlias' and @Alias='appupdate.exe']" | Should -BeNullOrEmpty -Because 'the match is case- and slash-insensitive'
        Select-TestNode "//*[local-name()='Extension' and @Category='windows.startupTask']" | Should -BeNullOrEmpty
        Select-TestNode "//*[local-name()='Service' and @Name='AppAgent']" | Should -HaveCount 1
        Select-TestNode "//*[local-name()='ExecutionAlias' and @Alias='app.exe']" | Should -HaveCount 1
        Select-TestNode "//*[local-name()='Shortcut']" | Should -HaveCount 1
    }

    It 'removes desktop2 FirewallRules, and the Extension it leaves empty' {
        Select-TestNode "//*[local-name()='Extension' and @Category='windows.firewallRules']" | Should -BeNullOrEmpty
    }

    It 'removes a com ExeServer and a SurrogateServer class whose files were removed, keeping the rest of the server' {
        Select-TestNode "//*[local-name()='ExeServer']" | Should -BeNullOrEmpty
        Select-TestNode "//*[local-name()='Class' and @Id='bbbbbbbb-0000-0000-0000-000000000002']" | Should -BeNullOrEmpty
        Select-TestNode "//*[local-name()='Class' and @Id='cccccccc-0000-0000-0000-000000000003']" | Should -HaveCount 1
        Select-TestNode "//*[local-name()='Extension' and @Category='windows.comServer']" | Should -HaveCount 1
    }

    It 'removes what named a removed COM class by CLSID (MakeAppx requires the class to resolve)' {
        Select-TestNode "//*[local-name()='Extension' and @Category='windows.toastNotificationActivation']" | Should -BeNullOrEmpty
        Select-TestNode "//*[local-name()='Verb' and @Clsid='bbbbbbbb-0000-0000-0000-000000000002']" | Should -BeNullOrEmpty
        Select-TestNode "//*[local-name()='ItemType' and @Type='*']" | Should -BeNullOrEmpty -Because 'an ItemType left without a Verb goes too'
        Select-TestNode "//*[local-name()='ItemType' and @Type='Directory']" | Should -HaveCount 1
        Select-TestNode "//*[local-name()='ThumbnailHandler']" | Should -BeNullOrEmpty
        Select-TestNode "//*[local-name()='FileTypeAssociation' and @Name='labthumbnail']" | Should -HaveCount 1 -Because 'the FTA itself is still valid'
    }

    It 'removes a com4 InProcessServer, a now-missing loader folder, and the containers they leave empty' {
        Select-TestNode "//*[local-name()='InProcessServer']" | Should -BeNullOrEmpty
        Select-TestNode "//*[local-name()='LoaderSearchPathEntry']" | ForEach-Object { $_.GetAttribute('FolderPath') } |
            Should -Be 'VFS\ProgramFilesX64\App'
        Select-TestNode "/*[local-name()='Package']/*[local-name()='Extensions']/*" | Should -HaveCount 1
        Select-TestNode "//*[local-name()='Extensions'][not(*)]" | Should -BeNullOrEmpty -Because 'an empty <Extensions> is not schema-valid'
    }

    It 'logs one line per removed declaration' {
        @($script:Result.ManifestChanges) | Should -HaveCount 11
        @($script:Result.ManifestChanges)[0] | Should -Match "^Removed <desktop6:Extension Category='windows.service'> \(Service 'AppUpdater'\) from the manifest: it named 'VFS\\ProgramFilesX64\\App\\updater\.exe'"
        @($script:Result.ManifestChanges) | Where-Object { $_ -match 'COM class aaaaaaaa-0000-0000-0000-000000000001' } | Should -HaveCount 1
    }

    It 'never deletes outside the workspace' {
        $ws = New-TestWorkspace -Name 'escape' -Manifest $script:RichManifest -Files @('VFS\ProgramFilesX64\App\app.exe')
        $outside = Join-Path -Path $TestDrive -ChildPath 'outside.txt'
        [IO.File]::WriteAllText($outside, 'keep me')
        $r = & (Get-Module MSIX) {
            param($Workspace)
            _MsixRemoveWorkspaceFile -Workspace $Workspace -RelativePath @('..\outside.txt', 'VFS\..\..\outside.txt')
        } $ws 6>$null
        $r.Removed | Should -BeNullOrEmpty
        $outside | Should -Exist
    }

    It 'leaves the manifest byte-identical when nothing was removed' {
        $ws = New-TestWorkspace -Name 'untouched' -Manifest $script:RichManifest -Files $script:RichFiles
        $before = [IO.File]::ReadAllBytes((Join-Path $ws 'AppxManifest.xml'))
        $r = & (Get-Module MSIX) {
            param($Workspace)
            _MsixRemoveWorkspaceFile -Workspace $Workspace -RelativePath @('VFS\ProgramFilesX64\App\setup.exe', 'nope.exe')
        } $ws 6>$null
        $r.Removed | Should -BeNullOrEmpty
        $r.ManifestChanges | Should -BeNullOrEmpty
        [IO.File]::ReadAllBytes((Join-Path $ws 'AppxManifest.xml')) | Should -Be $before
    }
}

Describe 'Removal stages keep the manifest valid on a real package' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path $TestDrive -ChildPath 'real'
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null

        function script:New-ExtensionManifest {
            param([string]$AppsXml, [string]$Capabilities = '')
@"
<?xml version="1.0" encoding="utf-8"?>
<Package $script:Ns>
  <Identity Name="Removal.Real" Publisher="CN=Removal Test" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Removal.Real</DisplayName>
    <PublisherDisplayName>Removal Test</PublisherDisplayName>
    <Logo>Assets\logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" />
  </Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
$AppsXml
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
$Capabilities
  </Capabilities>
</Package>
"@
        }
        $script:Visual = '<uap:VisualElements DisplayName="App" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />'
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }

    It 'Remove-MsixUpdaterArtifact: a Chrome-like package still packs, without the updater''s services' {
        $apps = @"
    <Application Id="App" Executable="VFS\ProgramFilesX64\App\app.exe" EntryPoint="Windows.FullTrustApplication">
      $script:Visual
      <Extensions>
        <desktop6:Extension Category="windows.service" Executable="VFS\ProgramFilesX64\App\agent.exe" EntryPoint="Windows.FullTrustApplication">
          <desktop6:Service Name="AppAgent" StartupType="manual" StartAccount="localSystem" />
        </desktop6:Extension>
        <desktop6:Extension Category="windows.service" Executable="VFS\ProgramFilesX86\Google\GoogleUpdater\159.0.8140.0\updater.exe" EntryPoint="Windows.FullTrustApplication">
          <desktop6:Service Name="GoogleUpdaterInternalService159.0.8140.0" StartupType="auto" StartAccount="localSystem" />
        </desktop6:Extension>
        <desktop6:Extension Category="windows.service" Executable="VFS\ProgramFilesX86\Google\GoogleUpdater\159.0.8140.0\updater.exe" EntryPoint="Windows.FullTrustApplication">
          <desktop6:Service Name="GoogleUpdaterService159.0.8140.0" StartupType="auto" StartAccount="localSystem" />
        </desktop6:Extension>
        <desktop:Extension Category="windows.startupTask" Executable="VFS\ProgramFilesX86\Google\Update\GoogleUpdate.exe" EntryPoint="Windows.FullTrustApplication">
          <desktop:StartupTask TaskId="GoogleUpdateTask" Enabled="true" DisplayName="Google Update" />
        </desktop:Extension>
        <uap3:Extension Category="windows.appExecutionAlias" Executable="VFS\ProgramFilesX64\App\app.exe" EntryPoint="Windows.FullTrustApplication">
          <uap3:AppExecutionAlias><desktop:ExecutionAlias Alias="app.exe" /></uap3:AppExecutionAlias>
        </uap3:Extension>
      </Extensions>
    </Application>
"@
        $manifest = (New-ExtensionManifest -AppsXml $apps -Capabilities '    <rescap:Capability Name="packagedServices" />
    <rescap:Capability Name="localSystemServices" />').Replace('</Package>', @'
  <Extensions>
    <desktop2:Extension Category="windows.firewallRules">
      <desktop2:FirewallRules Executable="VFS\ProgramFilesX86\Google\Update\GoogleUpdate.exe">
        <desktop2:Rule Direction="out" IPProtocol="TCP" Profile="all" />
      </desktop2:FirewallRules>
    </desktop2:Extension>
  </Extensions>
</Package>
'@)
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'chrome-like.msix') -ManifestXml $manifest -Files @(
            @{ Path = 'VFS\ProgramFilesX64\App\agent.exe'; Bytes = [byte[]](0x4D, 0x5A) }
            @{ Path = 'VFS\ProgramFilesX86\Google\GoogleUpdater\159.0.8140.0\updater.exe'; Bytes = [byte[]](0x4D, 0x5A) }
            @{ Path = 'VFS\ProgramFilesX86\Google\Update\GoogleUpdate.exe'; Bytes = [byte[]](0x4D, 0x5A) }
        )
        $out = Join-Path $script:Dir 'chrome-like-clean.msix'

        $r = Remove-MsixUpdaterArtifact -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning 6>$null

        $r.FilesRemoved | Should -HaveCount 2
        $r.ManifestElementsRemoved | Should -HaveCount 4
        [xml]$m = Get-MsixManifest -Path $out
        @($m.SelectNodes("//*[@Executable]") | ForEach-Object { $_.GetAttribute('Executable') } | Where-Object { $_ -match 'Google' }) |
            Should -BeNullOrEmpty -Because 'nothing may name a removed updater'
        @($m.SelectNodes("//*[local-name()='Service']") | ForEach-Object { $_.GetAttribute('Name') }) | Should -Be 'AppAgent'
        $m.SelectSingleNode("//*[local-name()='ExecutionAlias' and @Alias='app.exe']") | Should -Not -BeNullOrEmpty
        $m.SelectSingleNode("/*[local-name()='Package']/*[local-name()='Extensions']") | Should -BeNullOrEmpty -Because 'the firewall rule was its only extension'
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'Remove-MsixUninstallerArtifact keeps an Application''s setup.exe and drops the alias on the uninstaller' {
        $apps = @"
    <Application Id="App" Executable="VFS\ProgramFilesX64\App\app.exe" EntryPoint="Windows.FullTrustApplication">
      $script:Visual
      <Extensions>
        <uap3:Extension Category="windows.appExecutionAlias" Executable="VFS\ProgramFilesX64\App\unins000.exe" EntryPoint="Windows.FullTrustApplication">
          <uap3:AppExecutionAlias><desktop:ExecutionAlias Alias="appuninstall.exe" /></uap3:AppExecutionAlias>
        </uap3:Extension>
      </Extensions>
    </Application>
    <Application Id="Setup" Executable="VFS\ProgramFilesX64\App\setup.exe" EntryPoint="Windows.FullTrustApplication">
      $($script:Visual.Replace('DisplayName="App"', 'DisplayName="Setup"'))
    </Application>
"@
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'uninst.msix') -ManifestXml (New-ExtensionManifest -AppsXml $apps) -Files @(
            @{ Path = 'VFS\ProgramFilesX64\App\setup.exe';    Bytes = [byte[]](0x4D, 0x5A) }
            @{ Path = 'VFS\ProgramFilesX64\App\unins000.exe'; Bytes = [byte[]](0x4D, 0x5A) }
        )
        $out = Join-Path $script:Dir 'uninst-clean.msix'

        $log = Remove-MsixUninstallerArtifact -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning -KeepRegistry 6>&1 | Out-String -Width 4096

        $log | Should -Match "\[Warning\] Kept 'VFS\\ProgramFilesX64\\App\\setup\.exe' in the package: it is the Executable of Application 'Setup'"
        [xml]$m = Get-MsixManifest -Path $out
        $m.SelectSingleNode("//*[local-name()='Application' and @Id='Setup']") | Should -Not -BeNullOrEmpty
        $m.SelectSingleNode("//*[local-name()='ExecutionAlias' and @Alias='appuninstall.exe']") | Should -BeNullOrEmpty
        $m.SelectSingleNode("//*[local-name()='Application' and @Id='App']/*[local-name()='Extensions']") | Should -BeNullOrEmpty -Because 'the emptied <Extensions> goes too'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($out)
        try { $names = @($zip.Entries | ForEach-Object { $_.FullName }) } finally { $zip.Dispose() }
        $names | Should -Contain 'VFS/ProgramFilesX64/App/setup.exe'
        $names | Should -Not -Contain 'VFS/ProgramFilesX64/App/unins000.exe'
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'Remove-MsixPsf re-points an alias that named the launcher instead of leaving it dangling' {
        $apps = @"
    <Application Id="App" Executable="VFS\ProgramFilesX64\App\PsfLauncher64.exe" EntryPoint="Windows.FullTrustApplication">
      $script:Visual
      <Extensions>
        <uap3:Extension Category="windows.appExecutionAlias" Executable="VFS\ProgramFilesX64\App\PsfLauncher64.exe" EntryPoint="Windows.FullTrustApplication">
          <uap3:AppExecutionAlias><desktop:ExecutionAlias Alias="app.exe" /></uap3:AppExecutionAlias>
        </uap3:Extension>
      </Extensions>
    </Application>
"@
        $config = '{"applications":[{"id":"App","executable":"VFS/ProgramFilesX64/App/app.exe"}],"processes":[{"executable":".*","fixups":[]}]}'
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'psf.msix') -ManifestXml (New-ExtensionManifest -AppsXml $apps) `
            -Executable 'VFS\ProgramFilesX64\App\PsfLauncher64.exe' -Files @(
                @{ Path = 'VFS\ProgramFilesX64\App\app.exe';         Bytes = [byte[]](0x4D, 0x5A) }
                @{ Path = 'VFS\ProgramFilesX64\App\PsfRuntime64.dll'; Bytes = [byte[]](0x4D, 0x5A) }
                @{ Path = 'VFS\ProgramFilesX64\App\config.json';      Content = $config }
            )
        $out = Join-Path $script:Dir 'psf-clean.msix'

        Remove-MsixPsf -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning 6>$null

        [xml]$m = Get-MsixManifest -Path $out
        $m.SelectSingleNode("//*[local-name()='Application']").GetAttribute('Executable') | Should -Be 'VFS\ProgramFilesX64\App\app.exe'
        $alias = $m.SelectSingleNode("//*[local-name()='ExecutionAlias' and @Alias='app.exe']")
        $alias | Should -Not -BeNullOrEmpty
        $alias.ParentNode.ParentNode.GetAttribute('Executable') | Should -Be 'VFS\ProgramFilesX64\App\app.exe'
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'DeduplicateBundledRuntime strips the runtime and every declaration that named it' {
        $apps = @"
    <Application Id="App" Executable="VFS\ProgramFilesX64\App\app.exe" EntryPoint="Windows.FullTrustApplication">
      $script:Visual
      <Extensions>
        <uap3:Extension Category="windows.appExecutionAlias" Executable="VFS\ProgramFilesX64\App\jre\bin\java.exe" EntryPoint="Windows.FullTrustApplication">
          <uap3:AppExecutionAlias><desktop:ExecutionAlias Alias="appjava.exe" /></uap3:AppExecutionAlias>
        </uap3:Extension>
      </Extensions>
    </Application>
"@
        $manifest = (New-ExtensionManifest -AppsXml $apps).Replace('</Package>', @'
  <Extensions>
    <uap6:Extension Category="windows.loaderSearchPathOverride">
      <uap6:LoaderSearchPathOverride>
        <uap6:LoaderSearchPathEntry FolderPath="VFS\ProgramFilesX64\App\jre\bin" />
      </uap6:LoaderSearchPathOverride>
    </uap6:Extension>
  </Extensions>
</Package>
'@)
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'jre.msix') -ManifestXml $manifest -Files @(
            @{ Path = 'VFS\ProgramFilesX64\App\jre\bin\java.exe';   Bytes = [byte[]](0x4D, 0x5A) }
            @{ Path = 'VFS\ProgramFilesX64\App\jre\bin\jvm.dll';    Bytes = [byte[]](0x4D, 0x5A) }
            @{ Path = 'VFS\ProgramFilesX64\App\jre\lib\rt.jar';     Bytes = [byte[]](0x50, 0x4B) }
        )
        $out = Join-Path $script:Dir 'jre-dedup.msix'
        $report = [pscustomobject]@{
            PackagePath     = $fx.PackagePath
            Findings        = @([pscustomobject]@{
                Severity = 'Info'; Category = 'BundledRuntime'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'jre'
                RuntimeEntries = @([pscustomobject]@{ Kind = 'Java'; RuntimeRoot = 'VFS\ProgramFilesX64\App\jre'; Evidence = 'jre\bin\java.exe'; SizeMB = 1; CanAutoFix = $true })
            })
            SuggestedFixups = @()
        }
        # Only the strip is under test; the framework wiring has its own tests.
        Mock -ModuleName MSIX Add-MsixRuntimeDependency { }

        $null = Invoke-MsixAutoFixFromAnalysis -Report $report -OutputPath $out -SkipSigning -Confirm:$false `
            -DeduplicateBundledRuntime -RuntimeFrameworkName 'Contoso.Jre' -RuntimeFrameworkMinVersion '17.0.0.0' `
            -RuntimeFrameworkPublisher 'CN=Contoso' 6>$null

        [xml]$m = Get-MsixManifest -Path $out
        $m.SelectSingleNode("//*[local-name()='ExecutionAlias' and @Alias='appjava.exe']") | Should -BeNullOrEmpty
        $m.SelectSingleNode("//*[local-name()='LoaderSearchPathEntry']") | Should -BeNullOrEmpty
        $m.SelectSingleNode("/*[local-name()='Package']/*[local-name()='Extensions']") | Should -BeNullOrEmpty
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($out)
        try { $names = @($zip.Entries | ForEach-Object { $_.FullName }) } finally { $zip.Dispose() }
        @($names | Where-Object { $_ -like 'VFS/ProgramFilesX64/App/jre/*' }) | Should -BeNullOrEmpty
        Should -Invoke -ModuleName MSIX Add-MsixRuntimeDependency -Times 1 -Exactly
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}
