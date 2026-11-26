BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')

    # Builds a Registry.dat from @{ 'REGISTRY\MACHINE\...' = @{ '' = 'value'; 'Start' = [int]2 } }.
    # offreg's ORCreateKey makes one level at a time, so every path is created
    # segment by segment.
    function script:New-TestHive {
        param([string]$Path, [hashtable]$Keys)
        & (Get-Module MSIX) {
            param($Path, $Keys)
            $hive = _MsixCreateOfflineHive
            try {
                foreach ($keyPath in $Keys.Keys) {
                    $cur = $hive
                    foreach ($seg in ($keyPath -split '\\')) { $cur = _MsixOfflineCreateKey -Parent $cur -SubKey $seg }
                    $values = $Keys[$keyPath]
                    foreach ($name in $values.Keys) {
                        if ($values[$name] -is [int]) { _MsixOfflineSetValueDword -Key $cur -Name $name -Value $values[$name] }
                        else { _MsixOfflineSetValueString -Key $cur -Name $name -Value ([string]$values[$name]) }
                    }
                }
                if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
                if (-not (_MsixOfflineSaveHive -Hive $hive -Path $Path)) { throw 'ORSaveHive failed.' }
            } finally { _MsixCloseOfflineHive -Hive $hive }
        } $Path $Keys
    }

    function script:New-TestFile {
        param([string]$Root, [string[]]$Files)
        foreach ($f in $Files) {
            $p = Join-Path -Path $Root -ChildPath $f
            New-Item -ItemType Directory -Path (Split-Path -Path $p -Parent) -Force | Out-Null
            [IO.File]::WriteAllBytes($p, [byte[]](0x4D, 0x5A))
        }
    }

    $script:Thumb   = 'shellex\{e357fccd-a995-4576-b01f-234630154e96}'
    $script:Classes = 'REGISTRY\MACHINE\SOFTWARE\Classes'
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Registry.dat folder tokens map to the canonical MSIX VFS folders.
# [{ProgramFilesX86}] was mapped to VFS\ProgramFiles(x86) - a folder MSIX does
# not have - and the path was returned even when nothing was there, so K-Lite
# Codec Pack's shell handlers were declared on DLLs that were not in the package
# (the payload is under VFS\ProgramFilesX86). A path that is not in the package
# now maps to nothing, and the auto-fix stage skips that entry with a warning.
# =============================================================================

Describe 'Folder-token mapping (_MsixConvertRegPathToVfs)' -Tag 'Heuristics' {

    It '[{<Token>}] maps to VFS\<Folder>' -TestCases @(
        @{ Token = 'ProgramFilesX64';       Folder = 'ProgramFilesX64' }
        @{ Token = 'ProgramFilesX86';       Folder = 'ProgramFilesX86' }
        @{ Token = 'ProgramFilesCommonX64'; Folder = 'ProgramFilesCommonX64' }
        @{ Token = 'ProgramFilesCommonX86'; Folder = 'ProgramFilesCommonX86' }
        @{ Token = 'SystemX64';             Folder = 'SystemX64' }
        @{ Token = 'SystemX86';             Folder = 'SystemX86' }
        @{ Token = 'Windows';               Folder = 'Windows' }
        @{ Token = 'Fonts';                 Folder = 'Fonts' }
        @{ Token = 'Common AppData';        Folder = 'Common AppData' }
        @{ Token = 'AppData';               Folder = 'AppData' }
        @{ Token = 'Local AppData';         Folder = 'Local AppData' }
        @{ Token = 'LocalAppDataLow';       Folder = 'LocalAppDataLow' }
        # Older spellings resolve to the same canonical folders.
        @{ Token = 'ProgramFiles6432';      Folder = 'ProgramFilesX64' }
        @{ Token = 'System';                Folder = 'SystemX64' }
        @{ Token = 'CommonAppData';         Folder = 'Common AppData' }
        @{ Token = 'LocalAppData';          Folder = 'Local AppData' }
        @{ Token = 'programfilesx86';       Folder = 'ProgramFilesX86' }
    ) {
        param($Token, $Folder)
        $r = InModuleScope MSIX -Parameters @{ T = $Token } { param($T) _MsixConvertRegPathToVfs -RegPath "[{$T}]\Vendor\App\x.dll" }
        $r | Should -BeExactly "VFS\$Folder\Vendor\App\x.dll"
    }

    It 'never produces one of the old non-MSIX folder names' {
        $r = InModuleScope MSIX {
            foreach ($t in 'ProgramFilesX86', 'SystemX86', 'CommonAppData', 'AppData', 'LocalAppData') {
                _MsixConvertRegPathToVfs -RegPath "[{$t}]\x.dll"
            }
        }
        $r | Should -Not -Contain 'VFS\ProgramFiles(x86)\x.dll'
        $r | Should -Not -Contain 'VFS\System\x.dll'
        $r | Should -Not -Contain 'VFS\ProgramData\x.dll'
        $r | Should -Not -Contain 'VFS\AppData\Roaming\x.dll'
        $r | Should -Not -Contain 'VFS\AppData\Local\x.dll'
    }

    It 'maps the package root token, quotes and forward slashes' {
        InModuleScope MSIX { _MsixConvertRegPathToVfs -RegPath '[{AppVPackageRoot}]\bin\x.dll' } | Should -BeExactly 'bin\x.dll'
        InModuleScope MSIX { _MsixConvertRegPathToVfs -RegPath '"[{ProgramFilesX86}]/App/x.dll"' } | Should -BeExactly 'VFS\ProgramFilesX86\App\x.dll'
    }

    It 'returns nothing for an unknown token, a plain path or traversal' {
        InModuleScope MSIX { _MsixConvertRegPathToVfs -RegPath '[{AppVCurrentUserSID}]\x.dll' } | Should -BeNullOrEmpty
        InModuleScope MSIX { _MsixConvertRegPathToVfs -RegPath 'C:\Program Files\App\x.dll' } | Should -BeNullOrEmpty
        InModuleScope MSIX { _MsixConvertRegPathToVfs -RegPath '[{ProgramFilesX86}]\..\..\evil.dll' } | Should -BeNullOrEmpty
    }
}

Describe '_MsixRegPathToVfsRelative / _MsixAbsoluteToVfsRelativeDirect only return files in the package' -Tag 'Heuristics' {

    BeforeAll {
        $script:Ws = Join-Path -Path $TestDrive -ChildPath 'map-ws'
        New-TestFile -Root $script:Ws -Files @(
            'VFS\ProgramFilesX86\K-Lite Codec Pack\Icaros\64-bit\IcarosThumbnailProvider.dll'
            'VFS\ProgramFiles(x86)\Legacy\only-here.dll'
            'VFS\ProgramFilesX64\App\x64.dll'
            'VFS\ProgramFilesCommonX64\Vendor\common.dll'
            'VFS\ProgramFilesX64\Common Files\Other\other.dll'
            'VFS\Common AppData\Vendor\data.dll'
            'VFS\SystemX64\sys64.dll'
            'VFS\Windows\winonly.dll'
        )
    }

    It 'maps K-Lite''s token path to the file that is in the package' {
        InModuleScope MSIX -Parameters @{ Ws = $script:Ws } {
            param($Ws)
            _MsixRegPathToVfsRelative -RegPath '[{ProgramFilesX86}]\K-Lite Codec Pack\Icaros\64-bit\IcarosThumbnailProvider.dll' -WorkspacePath $Ws
        } | Should -BeExactly 'VFS\ProgramFilesX86\K-Lite Codec Pack\Icaros\64-bit\IcarosThumbnailProvider.dll'
    }

    It 'returns nothing when the mapped file is not in the package' {
        InModuleScope MSIX -Parameters @{ Ws = $script:Ws } {
            param($Ws)
            _MsixRegPathToVfsRelative -RegPath '[{ProgramFilesX86}]\K-Lite Codec Pack\missing.dll' -WorkspacePath $Ws
        } | Should -BeNullOrEmpty
        # A file only under the old, non-MSIX folder name is not the token's file.
        InModuleScope MSIX -Parameters @{ Ws = $script:Ws } {
            param($Ws)
            _MsixRegPathToVfsRelative -RegPath '[{ProgramFilesX86}]\Legacy\only-here.dll' -WorkspacePath $Ws
        } | Should -BeNullOrEmpty
    }

    It 'maps host absolute paths, longest folder first, with a fallback to the parent VFS folder' {
        $r = InModuleScope MSIX -Parameters @{ Ws = $script:Ws } {
            param($Ws)
            $pf  = $env:ProgramW6432; if (-not $pf) { $pf = [Environment]::GetFolderPath('ProgramFiles') }
            $cpf = $env:CommonProgramW6432; if (-not $cpf) { $cpf = [Environment]::GetFolderPath('CommonProgramFiles') }
            $win = [Environment]::GetFolderPath('Windows')
            [ordered]@{
                X86     = _MsixAbsoluteToVfsRelativeDirect -AbsPath (Join-Path ([Environment]::GetFolderPath('ProgramFilesX86')) 'K-Lite Codec Pack\Icaros\64-bit\IcarosThumbnailProvider.dll') -WorkspacePath $Ws
                X64     = _MsixAbsoluteToVfsRelativeDirect -AbsPath "`"$pf\App\x64.dll`"" -WorkspacePath $Ws
                Common  = _MsixAbsoluteToVfsRelativeDirect -AbsPath "$cpf\Vendor\common.dll" -WorkspacePath $Ws
                Nested  = _MsixAbsoluteToVfsRelativeDirect -AbsPath "$cpf\Other\other.dll" -WorkspacePath $Ws
                Data    = _MsixAbsoluteToVfsRelativeDirect -AbsPath (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Vendor\data.dll') -WorkspacePath $Ws
                Sys     = _MsixAbsoluteToVfsRelativeDirect -AbsPath "$win\System32\sys64.dll" -WorkspacePath $Ws
                Env     = _MsixAbsoluteToVfsRelativeDirect -AbsPath '%SystemRoot%\winonly.dll' -WorkspacePath $Ws
                Missing = _MsixAbsoluteToVfsRelativeDirect -AbsPath "$pf\App\nope.dll" -WorkspacePath $Ws
            }
        }
        $r.X86     | Should -BeExactly 'VFS\ProgramFilesX86\K-Lite Codec Pack\Icaros\64-bit\IcarosThumbnailProvider.dll'
        $r.X64     | Should -BeExactly 'VFS\ProgramFilesX64\App\x64.dll'
        $r.Common  | Should -BeExactly 'VFS\ProgramFilesCommonX64\Vendor\common.dll'
        $r.Nested  | Should -BeExactly 'VFS\ProgramFilesX64\Common Files\Other\other.dll'
        $r.Data    | Should -BeExactly 'VFS\Common AppData\Vendor\data.dll'
        $r.Sys     | Should -BeExactly 'VFS\SystemX64\sys64.dll'
        $r.Env     | Should -BeExactly 'VFS\Windows\winonly.dll'
        $r.Missing | Should -BeNullOrEmpty
    }
}

Describe 'Scanners report only files that are in the package' -Tag 'Heuristics' {

    BeforeAll {
        $script:ScanWs = Join-Path -Path $TestDrive -ChildPath 'scan-ws'
        New-TestFile -Root $script:ScanWs -Files @(
            'VFS\ProgramFilesX86\App\thumbs.dll'
            'VFS\ProgramFilesX86\App\shell.dll'
            'VFS\ProgramFilesX86\App\labsvc.exe'
        )
        New-TestHive -Path (Join-Path $script:ScanWs 'Registry.dat') -Keys @{
            "$script:Classes\.lab\$script:Thumb"  = @{ '' = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}' }
            "$script:Classes\.miss\$script:Thumb" = @{ '' = '{11112222-3333-4444-5555-000000000009}' }
            "$script:Classes\CLSID\{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}\InProcServer32" = @{ '' = '[{ProgramFilesX86}]\App\thumbs.dll' }
            "$script:Classes\CLSID\{11112222-3333-4444-5555-000000000009}\InProcServer32" = @{ '' = '[{ProgramFilesX86}]\App\missing.dll' }
            "$script:Classes\*\shellex\ContextMenuHandlers\LabMenu"  = @{ '' = '{22223333-4444-5555-6666-000000000001}' }
            "$script:Classes\*\shellex\ContextMenuHandlers\GoneMenu" = @{ '' = '{22223333-4444-5555-6666-000000000002}' }
            "$script:Classes\CLSID\{22223333-4444-5555-6666-000000000001}\InProcServer32" = @{ '' = '[{ProgramFilesX86}]\App\shell.dll' }
            "$script:Classes\CLSID\{22223333-4444-5555-6666-000000000002}\InProcServer32" = @{ '' = '[{ProgramFilesX86}]\App\gone.dll' }
            'REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\LabSvc'  = @{ 'ImagePath' = '"[{ProgramFilesX86}]\App\labsvc.exe" -run'; 'Start' = [int]2; 'ObjectName' = 'LocalSystem' }
            'REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\GoneSvc' = @{ 'ImagePath' = '[{ProgramFilesX86}]\App\gonesvc.exe'; 'Start' = [int]2; 'ObjectName' = 'LocalSystem' }
        }
    }

    It 'shell handlers: VFS\ProgramFilesX86 for the DLL that exists, nothing for the one that does not' {
        $h = @(Get-MsixShellHandlerEntry -PackagePath 'C:\nope.msix' -WorkspacePath $script:ScanWs)
        ($h | Where-Object FileType -eq '.lab').VfsDllPath  | Should -BeExactly 'VFS\ProgramFilesX86\App\thumbs.dll'
        ($h | Where-Object FileType -eq '.lab').CanAutoFix  | Should -BeTrue
        ($h | Where-Object FileType -eq '.miss').VfsDllPath | Should -BeNullOrEmpty
        ($h | Where-Object FileType -eq '.miss').CanAutoFix | Should -BeFalse
    }

    It 'context menus: same rule' {
        $c = @(Get-MsixShellContextMenuEntry -PackagePath 'C:\nope.msix' -WorkspacePath $script:ScanWs)
        ($c | Where-Object HandlerName -eq 'LabMenu').VfsDllPath  | Should -BeExactly 'VFS\ProgramFilesX86\App\shell.dll'
        ($c | Where-Object HandlerName -eq 'GoneMenu').VfsDllPath | Should -BeNullOrEmpty
    }

    It 'services: same rule' {
        $s = @(Get-MsixServiceEntry -PackagePath 'C:\nope.msix' -WorkspacePath $script:ScanWs)
        ($s | Where-Object Name -eq 'LabSvc').VfsExecutable  | Should -BeExactly 'VFS\ProgramFilesX86\App\labsvc.exe'
        ($s | Where-Object Name -eq 'LabSvc').CanAutoFix     | Should -BeTrue
        ($s | Where-Object Name -eq 'GoneSvc').VfsExecutable | Should -BeNullOrEmpty
        ($s | Where-Object Name -eq 'GoneSvc').CanAutoFix    | Should -BeFalse
    }
}

Describe 'Auto-fix stages skip an entry whose file is not in the package, with a warning' -Tag 'AutoFix' {

    It 'shell handlers: an unresolved entry is warned about, a resolved one is declared' {
        Mock -ModuleName MSIX Add-MsixShellHandlerExtension { }
        Mock -ModuleName MSIX _MsixGetPackagePayloadPath { 'VFS\ProgramFilesX86\App\thumbs.dll' }
        $report = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'; SuggestedFixups = @()
            Findings    = @([pscustomobject]@{
                Severity = 'Warning'; Category = 'ManifestFix:ShellHandlerExtension'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'z'
                ShellHandlerEntries = @(
                    [pscustomobject]@{ Kind = 'Thumbnail'; FileType = '.lab'; FtaName = 'labthumbnail'; Clsid = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}'; VfsDllPath = 'VFS\ProgramFilesX86\App\thumbs.dll'; CanAutoFix = $true }
                    # Was in the package at analysis time; an earlier stage removed it.
                    [pscustomobject]@{ Kind = 'Thumbnail'; FileType = '.gone'; FtaName = 'gonethumbnail'; Clsid = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa001}'; VfsDllPath = 'VFS\ProgramFilesX86\App\gone.dll'; CanAutoFix = $true }
                )
                UnresolvedShellHandlerEntries = @(
                    [pscustomobject]@{ Kind = 'Thumbnail'; FileType = '.miss'; FtaName = 'missthumbnail'; Clsid = '{11112222-3333-4444-5555-000000000009}'; DllPath = '[{ProgramFilesX86}]\App\missing.dll'; VfsDllPath = $null; CanAutoFix = $false }
                )
            })
        }
        $log = Invoke-MsixAutoFixFromAnalysis -Report $report -SkipSigning -Confirm:$false 6>&1 | Out-String -Width 4096
        $log | Should -Match "\[Warning\] AddShellHandlerExtensions: skipping the Thumbnail handler for '\.miss': Registry\.dat names its DLL '\[\{ProgramFilesX86\}\]\\App\\missing\.dll', which is not in the package"
        $log | Should -Match "\[Warning\] AddShellHandlerExtensions: skipping the Thumbnail handler for '\.gone': its DLL 'VFS\\ProgramFilesX86\\App\\gone\.dll' is no longer in the package"
        Should -Invoke -ModuleName MSIX Add-MsixShellHandlerExtension -Times 1 -Exactly -ParameterFilter {
            (@($Handlers | ForEach-Object { @($_.FileTypes) }) -join ',') -eq '.lab'
        }
    }

    It 'shell handlers: only unresolved entries means no stage, just the warning' {
        $report = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'; SuggestedFixups = @()
            Findings    = @([pscustomobject]@{
                Severity = 'Warning'; Category = 'ManifestFix:ShellHandlerExtension'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'z'
                ShellHandlerEntries = @()
                UnresolvedShellHandlerEntries = @([pscustomobject]@{ Kind = 'Preview'; FileType = '.miss'; Clsid = '{11112222-3333-4444-5555-000000000009}'; DllPath = $null; VfsDllPath = $null; CanAutoFix = $false })
            })
        }
        $out = @(Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun 6>&1)
        ($out | Out-String -Width 4096) | Should -Match "skipping the Preview handler for '\.miss': Registry\.dat registers no DLL for its CLSID"
        @(($out | Where-Object { $_.PSObject.Properties['Plan'] }).Plan | Where-Object Stage -eq 'AddShellHandlerExtensions') | Should -BeNullOrEmpty
    }

    It 'services and context menus warn about an executable or DLL that is not in the package' {
        $report = [pscustomobject]@{
            PackagePath = 'C:\nope.msix'; SuggestedFixups = @()
            Findings    = @(
                [pscustomobject]@{
                    Severity = 'Info'; Category = 'ManifestFix:PackagedService'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'z'
                    ServiceEntries = @([pscustomobject]@{ Name = 'GoneSvc'; Executable = '[{ProgramFilesX86}]\App\gonesvc.exe'; VfsExecutable = $null; StartupType = 'auto'; StartAccount = 'localSystem'; CanAutoFix = $false })
                }
                [pscustomobject]@{
                    Severity = 'Error'; Category = 'ShellExt'; Symptom = 'x'; Recommendation = ''; Evidence = ''; AppId = $null
                    ShellEntries = @([pscustomobject]@{ Type = 'ShellExt'; Target = '*'; HandlerName = 'GoneMenu'; Clsid = '{22223333-4444-5555-6666-000000000002}'; DllPath = '[{ProgramFilesX86}]\App\gone.dll'; VfsDllPath = $null })
                }
            )
        }
        $log = Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun 6>&1 | Out-String -Width 4096
        $log | Should -Match "AddPackagedServices: skipping service 'GoneSvc': Registry\.dat starts it from '\[\{ProgramFilesX86\}\]\\App\\gonesvc\.exe', which is not in the package"
        $log | Should -Match "AddLegacyContextMenu: skipping the 'GoneMenu' handler on '\*': Registry\.dat names its DLL '\[\{ProgramFilesX86\}\]\\App\\gone\.dll', which is not in the package"
    }
}

Describe 'Add-MsixLegacyContextMenu maps a raw token DLL path with the canonical table' -Tag 'ContextMenu' {

    It '[{ProgramFilesX86}] becomes VFS\ProgramFilesX86 in the com:Class Path' {
        $file = Join-Path -Path $TestDrive -ChildPath 'ctx-AppxManifest.xml'
        $script:CtxFile = $file
        $manifest = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10" xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10" IgnorableNamespaces="uap">
  <Identity Name="Ctx.Test" Publisher="CN=Ctx" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties><DisplayName>Ctx</DisplayName><PublisherDisplayName>Ctx</PublisherDisplayName><Logo>Assets\logo.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.19041.0" /></Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="App" Executable="VFS\ProgramFilesX86\App\app.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Ctx" Description="x" BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
  </Applications>
</Package>
'@
        [IO.File]::WriteAllText($file, $manifest, [Text.UTF8Encoding]::new($true))
        Mock -ModuleName MSIX _MsixMutateManifest {
            [xml]$m = Get-MsixManifest -Path $script:CtxFile
            $m = Invoke-MsixManifestTransform -Manifest $m -Transform $Mutate
            Save-MsixManifest -Manifest $m -Path $script:CtxFile
        }
        Add-MsixLegacyContextMenu -PackagePath 'C:\nope.msix' -ShellExtDll '[{ProgramFilesX86}]\App\Shell.dll' `
            -Clsid '22223333-4444-5555-6666-000000000001' -DisplayName 'Lab' -SkipSigning 6>$null
        [xml]$m = Get-MsixManifest -Path $file
        $m.SelectSingleNode("//*[local-name()='Class']").GetAttribute('Path') | Should -BeExactly 'VFS\ProgramFilesX86\App\Shell.dll'
    }
}

Describe 'A K-Lite-shaped package: every declared handler DLL is in the package' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path $TestDrive -ChildPath 'klite'
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }

    It 'analysis + auto-fix declare the x86 handler DLLs under VFS\ProgramFilesX86 and pack' {
        $dat = Join-Path $script:Dir 'Registry.dat'
        $prop = 'REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\PropertySystem\PropertyHandlers'
        New-TestHive -Path $dat -Keys @{
            "$script:Classes\.mkv\$script:Thumb" = @{ '' = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}' }
            "$script:Classes\.mka\$script:Thumb" = @{ '' = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}' }
            "$script:Classes\.miss\$script:Thumb" = @{ '' = '{11112222-3333-4444-5555-000000000009}' }
            "$prop\.mkv" = @{ '' = '{0c08e3bb-d10b-4cc9-b1b3-701f5be9d6ec}' }
            "$script:Classes\CLSID\{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}\InProcServer32" = @{ '' = '[{ProgramFilesX86}]\K-Lite Codec Pack\Icaros\64-bit\IcarosThumbnailProvider.dll' }
            "$script:Classes\CLSID\{0c08e3bb-d10b-4cc9-b1b3-701f5be9d6ec}\InProcServer32" = @{ '' = '[{ProgramFilesX86}]\K-Lite Codec Pack\Icaros\64-bit\IcarosPropertyHandler.dll' }
            "$script:Classes\CLSID\{11112222-3333-4444-5555-000000000009}\InProcServer32" = @{ '' = '[{ProgramFilesX86}]\K-Lite Codec Pack\missing.dll' }
        }
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'klite.msix') -Executable 'VFS\ProgramFilesX86\K-Lite Codec Pack\Tools\CodecTweakTool.exe' -Files @(
            @{ Path = 'Registry.dat'; Bytes = [IO.File]::ReadAllBytes($dat) }
            @{ Path = 'VFS\ProgramFilesX86\K-Lite Codec Pack\Icaros\64-bit\IcarosThumbnailProvider.dll'; Bytes = [byte[]](0x4D, 0x5A) }
            @{ Path = 'VFS\ProgramFilesX86\K-Lite Codec Pack\Icaros\64-bit\IcarosPropertyHandler.dll';   Bytes = [byte[]](0x4D, 0x5A) }
        )
        $out = Join-Path $script:Dir 'klite-fixed.msix'

        $findings = @(Get-MsixHeuristicFinding -PackagePath $fx.PackagePath 6>$null)
        $handlerFinding = @($findings | Where-Object Category -eq 'ManifestFix:ShellHandlerExtension')[0]
        @($handlerFinding.ShellHandlerEntries).Count            | Should -Be 3
        @($handlerFinding.UnresolvedShellHandlerEntries).Count  | Should -Be 1
        $report = [pscustomobject]@{ PackagePath = $fx.PackagePath; Findings = $findings; SuggestedFixups = @() }
        $log = Invoke-MsixAutoFixFromAnalysis -Report $report -OutputPath $out -SkipSigning -Confirm:$false 6>&1 | Out-String -Width 4096
        $log | Should -Match "skipping the Thumbnail handler for '\.miss'"

        [xml]$m = Get-MsixManifest -Path $out
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $zip = [IO.Compression.ZipFile]::OpenRead($out)
        try { $payload = @($zip.Entries | ForEach-Object { [Uri]::UnescapeDataString($_.FullName).Replace('/', '\') }) } finally { $zip.Dispose() }
        $paths = @($m.SelectNodes("//*[local-name()='Class' and @Path]") | ForEach-Object { $_.GetAttribute('Path') })
        $paths | Should -HaveCount 2
        foreach ($p in $paths) { $payload | Should -Contain $p -Because 'a declared handler DLL must be in the package' }
        @($m.SelectNodes("//*[local-name()='FileType']") | ForEach-Object { $_.InnerText }) | Should -Be @('.mka', '.mkv')
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}
