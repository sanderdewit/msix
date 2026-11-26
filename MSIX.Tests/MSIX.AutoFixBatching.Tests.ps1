BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')

    # A report with N thumbnail handlers on one CLSID - the K-Lite Codec Pack
    # shape (Icaros: one thumbnail handler CLSID across dozens of file types).
    function script:New-ShellHandlerReport {
        param([int]$Count, [object[]]$Extra = @())
        $entries = @(for ($i = 1; $i -le $Count; $i++) {
            [pscustomobject]@{
                Kind = 'Thumbnail'; FileType = ".t$i"; FtaName = "t${i}thumbnail"
                Clsid = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}'
                VfsDllPath = 'VFS\ProgramFilesX86\App\thumbs.dll'; CanAutoFix = $true
            }
        }) + @($Extra)
        [pscustomobject]@{
            PackagePath     = 'C:\nope.msix'
            Findings        = @([pscustomobject]@{
                Severity = 'Warning'; Category = 'ManifestFix:ShellHandlerExtension'
                Symptom = 'x'; Recommendation = 'y'; Evidence = 'z'
                ShellHandlerEntries = $entries
            })
            SuggestedFixups = @()
        }
    }

    $script:ManifestText = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap rescap">
  <Identity Name="Batch.Test" Publisher="CN=Batch Test" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Batch.Test</DisplayName>
    <PublisherDisplayName>Batch Test</PublisherDisplayName>
    <Logo>Assets\logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.17763.0" />
  </Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="App" Executable="VFS\ProgramFilesX64\App\app.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Batch.Test" Description="x" BackgroundColor="transparent"
        Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
'@

    # Single-handler parameters for five handlers that exercise every path of
    # the per-handler logic: two kinds on one file type (the property handler
    # joins the thumbnail FTA - a type may be declared once per package), a
    # second CLSID landing on an FTA that already carries that kind (class
    # added, handler skipped), a default FtaName, a forward-slash DLL path and
    # an upper-case extension.
    $script:HandlerSet = @(
        @{ Kind = 'Thumbnail'; Clsid = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}'; Dll = 'VFS\ProgramFilesX86\App\thumbs.dll'; FileTypes = @('.mpv2'); FtaName = 'mpv2thumbnail' }
        @{ Kind = 'Thumbnail'; Clsid = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}'; Dll = 'VFS\ProgramFilesX86\App\thumbs.dll'; FileTypes = @('.mkv'); FtaName = 'mkvthumbnail' }
        @{ Kind = 'Property';  Clsid = '11112222-3333-4444-5555-000000000002';   Dll = 'VFS/ProgramFilesX86/App/props.dll';  FileTypes = @('.mkv'); FtaName = 'mkvproperty' }
        @{ Kind = 'Preview';   Clsid = '11112222-3333-4444-5555-000000000003';   Dll = 'VFS\ProgramFilesX86\App\prev.dll';   FileTypes = @('.MKA') }
        @{ Kind = 'Thumbnail'; Clsid = '11112222-3333-4444-5555-000000000004';   Dll = 'VFS\ProgramFilesX86\App\other.dll';  FileTypes = @('.mkv'); FtaName = 'mkvthumbnail' }
    )
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# One manifest mutation per stage, not one per item.
# Invoke-MsixAutoFixFromAnalysis's AddShellHandlerExtensions stage called
# Add-MsixShellHandlerExtension once per file type, and every call unpacked and
# repacked the whole package (~30 s for 40 MB). K-Lite Codec Pack's 83
# thumbnail/property handlers ran past 40 minutes and were killed.
# =============================================================================

Describe 'AddShellHandlerExtensions stage: one mutation for every handler' -Tag 'AutoFix' {

    BeforeEach {
        # The stage checks each handler DLL is still in the package.
        Mock -ModuleName MSIX _MsixGetPackagePayloadPath { 'AppxManifest.xml', 'VFS\ProgramFilesX86\App\thumbs.dll' }
    }

    It 'calls Add-MsixShellHandlerExtension ONCE with all 100 handlers' {
        Mock -ModuleName MSIX Add-MsixShellHandlerExtension { }
        $null = Invoke-MsixAutoFixFromAnalysis -Report (New-ShellHandlerReport -Count 100) -SkipSigning -Confirm:$false
        Should -Invoke -ModuleName MSIX Add-MsixShellHandlerExtension -Times 1 -Exactly
        Should -Invoke -ModuleName MSIX Add-MsixShellHandlerExtension -Times 1 -Exactly -ParameterFilter {
            $PackagePath -eq 'C:\nope.msix' -and $SkipSigning -and @($Handlers).Count -eq 100
        }
    }

    It 'passes every entry through with its FtaName, file type, CLSID and DLL' {
        $script:seen = $null
        Mock -ModuleName MSIX Add-MsixShellHandlerExtension { $script:seen = @($Handlers) }
        $null = Invoke-MsixAutoFixFromAnalysis -Report (New-ShellHandlerReport -Count 3) -SkipSigning -Confirm:$false
        $script:seen.Count | Should -Be 3
        @($script:seen | ForEach-Object { $_.FtaName })      | Should -Be @('t1thumbnail', 't2thumbnail', 't3thumbnail')
        @($script:seen | ForEach-Object { @($_.FileTypes) }) | Should -Be @('.t1', '.t2', '.t3')
        @($script:seen | ForEach-Object { $_.Kind } | Select-Object -Unique) | Should -Be 'Thumbnail'
        @($script:seen | ForEach-Object { $_.Dll } | Select-Object -Unique)  | Should -Be 'VFS\ProgramFilesX86\App\thumbs.dll'
    }

    It 'skips an entry the cmdlet would reject (with a warning) instead of failing the rest' {
        Mock -ModuleName MSIX Add-MsixShellHandlerExtension { }
        $bad = [pscustomobject]@{
            Kind = 'Thumbnail'; FileType = '.c++'; FtaName = 'c++thumbnail'
            Clsid = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}'; VfsDllPath = 'VFS\ProgramFilesX86\App\thumbs.dll'; CanAutoFix = $true
        }
        $log = Invoke-MsixAutoFixFromAnalysis -Report (New-ShellHandlerReport -Count 3 -Extra $bad) -SkipSigning -Confirm:$false 6>&1 | Out-String -Width 4096
        $log | Should -Match "\[Warning\] AddShellHandlerExtensions: skipping the Thumbnail handler for '\.c\+\+'"
        Should -Invoke -ModuleName MSIX Add-MsixShellHandlerExtension -Times 1 -Exactly -ParameterFilter { @($Handlers).Count -eq 3 }
    }
}

Describe 'Add-MsixShellHandlerExtension -Handlers' -Tag 'ManifestExtensions' {

    BeforeAll {
        # Stand-in for the unpack/mutate/repack cycle: the manifest lives in a
        # file and every _MsixMutateManifest call is one load-transform-save,
        # exactly what one repack does to it.
        $script:MutateCalls = 0
        $script:ManifestFile = Join-Path -Path $TestDrive -ChildPath 'AppxManifest.xml'
        function script:Reset-TestManifest {
            [IO.File]::WriteAllText($script:ManifestFile, $script:ManifestText, [Text.UTF8Encoding]::new($true))
            $script:MutateCalls = 0
        }
    }

    BeforeEach {
        Mock -ModuleName MSIX _MsixMutateManifest {
            $script:MutateCalls++
            [xml]$m = Get-MsixManifest -Path $script:ManifestFile
            $m = Invoke-MsixManifestTransform -Manifest $m -Transform $Mutate
            Save-MsixManifest -Manifest $m -Path $script:ManifestFile
        }
    }

    It 'gives the same manifest as one call per handler, in ONE mutation instead of five' {
        Reset-TestManifest
        foreach ($h in $script:HandlerSet) {
            Add-MsixShellHandlerExtension -PackagePath 'C:\nope.msix' @h -SkipSigning
        }
        $script:MutateCalls | Should -Be 5
        $perCall = Get-Content -LiteralPath $script:ManifestFile -Raw

        Reset-TestManifest
        Add-MsixShellHandlerExtension -PackagePath 'C:\nope.msix' -Handlers $script:HandlerSet -SkipSigning
        $script:MutateCalls | Should -Be 1
        $batch = Get-Content -LiteralPath $script:ManifestFile -Raw

        $batch | Should -BeExactly $perCall
    }

    It 'declares the expected FTAs, handler elements and COM classes' {
        Reset-TestManifest
        Add-MsixShellHandlerExtension -PackagePath 'C:\nope.msix' -Handlers $script:HandlerSet -SkipSigning
        [xml]$m = Get-MsixManifest -Path $script:ManifestFile

        $ftas = @($m.SelectNodes("//*[local-name()='FileTypeAssociation']") | ForEach-Object { $_.GetAttribute('Name') })
        $ftas | Should -Be @('mpv2thumbnail', 'mkvthumbnail', 'previewhandler')
        @($m.SelectNodes("//*[local-name()='ThumbnailHandler']")).Count       | Should -Be 2
        @($m.SelectNodes("//*[local-name()='DesktopPropertyHandler']")).Count | Should -Be 1
        @($m.SelectNodes("//*[local-name()='DesktopPreviewHandler']")).Count  | Should -Be 1
        # .mkv is declared once; its FTA carries the thumbnail AND the property handler.
        @($m.SelectNodes("//*[local-name()='FileType' and text()='.mkv']")).Count | Should -Be 1
        $mkv = $m.SelectSingleNode("//*[local-name()='FileTypeAssociation' and @Name='mkvthumbnail']")
        $mkv.SelectSingleNode("*[local-name()='DesktopPropertyHandler']").GetAttribute('Clsid') | Should -Be '11112222-3333-4444-5555-000000000002'
        # Four distinct CLSIDs, each declared once; the second thumbnail CLSID
        # gets its class even though its FTA already had a thumbnail handler.
        @($m.SelectNodes("//*[local-name()='Class']")).Count | Should -Be 4
        $m.SelectSingleNode("//*[local-name()='FileTypeAssociation' and @Name='previewhandler']//*[local-name()='FileType']").InnerText |
            Should -Be '.mka'
        $m.SelectSingleNode("//*[local-name()='Class' and @Id='11112222-3333-4444-5555-000000000002']").GetAttribute('Path') |
            Should -Be 'VFS\ProgramFilesX86\App\props.dll'
    }

    It 'accepts the entry shape Get-MsixShellHandlerEntry emits (VfsDllPath, FileType)' {
        Reset-TestManifest
        $entries = @([pscustomobject]@{
            Kind = 'Thumbnail'; FileType = '.lab'; FtaName = 'labthumbnail'
            Clsid = '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}'; VfsDllPath = 'VFS\ProgramFilesX86\App\thumbs.dll'; CanAutoFix = $true
        })
        Add-MsixShellHandlerExtension -PackagePath 'C:\nope.msix' -Handlers $entries -SkipSigning
        [xml]$m = Get-MsixManifest -Path $script:ManifestFile
        $m.SelectSingleNode("//*[local-name()='FileTypeAssociation' and @Name='labthumbnail']") | Should -Not -BeNullOrEmpty
    }

    It 'never declares a file type twice: a handler for a type another FTA already holds with other types is skipped' {
        Reset-TestManifest
        [xml]$seed = Get-MsixManifest -Path $script:ManifestFile
        $uap = 'http://schemas.microsoft.com/appx/manifest/uap/windows10'
        $app = $seed.SelectSingleNode("//*[local-name()='Application']")
        $ext = $seed.CreateElement('Extensions', $seed.Package.NamespaceURI)
        $ftaExt = $seed.CreateElement('uap:Extension', $uap); $ftaExt.SetAttribute('Category', 'windows.fileTypeAssociation')
        $fta = $seed.CreateElement('uap:FileTypeAssociation', $uap); $fta.SetAttribute('Name', 'videos')
        $sft = $seed.CreateElement('uap:SupportedFileTypes', $uap)
        foreach ($t in '.mkv', '.mp4') { $n = $seed.CreateElement('uap:FileType', $uap); $n.InnerText = $t; $null = $sft.AppendChild($n) }
        $null = $fta.AppendChild($sft); $null = $ftaExt.AppendChild($fta); $null = $ext.AppendChild($ftaExt); $null = $app.AppendChild($ext)
        Save-MsixManifest -Manifest $seed -Path $script:ManifestFile

        $log = Add-MsixShellHandlerExtension -PackagePath 'C:\nope.msix' -Kind Thumbnail -Clsid '{c5aec3ec-e812-4677-a9a7-4fee1f9aa000}' `
                   -Dll 'VFS\ProgramFilesX86\App\thumbs.dll' -FileTypes '.MKV' -FtaName 'mkvthumbnail' -SkipSigning 6>&1 | Out-String -Width 4096
        $log | Should -Match "\[Warning\] Thumbnail handler .* not declared for \.MKV: FTA 'videos' already declares"
        [xml]$m = Get-MsixManifest -Path $script:ManifestFile
        @($m.SelectNodes("//*[local-name()='FileTypeAssociation']")).Count | Should -Be 1
        $m.SelectSingleNode("//*[local-name()='Class']") | Should -BeNullOrEmpty -Because 'nothing is half-declared when the handler is skipped'
    }

    It 'validates every entry before the package is touched' {
        Reset-TestManifest
        $bad = @($script:HandlerSet[0], @{ Kind = 'Icon'; Clsid = '11112222-3333-4444-5555-000000000009'; Dll = 'x.dll'; FileTypes = @('.x') })
        { Add-MsixShellHandlerExtension -PackagePath 'C:\nope.msix' -Handlers $bad -SkipSigning } |
            Should -Throw -ExpectedMessage "*Shell handler #2*Kind 'Icon'*"
        $script:MutateCalls | Should -Be 0
    }
}

Describe 'AddPackagedServices stage: one mutation, and no service on a removed executable' -Tag 'AutoFix' {

    BeforeAll {
        $script:ServiceReport = [pscustomobject]@{
            PackagePath     = 'C:\nope.msix'
            Findings        = @(
                foreach ($svc in @(
                    @{ Name = 'ContosoAgent';       Exe = 'VFS\ProgramFilesX64\App\agent.exe';          Account = 'localService' }
                    @{ Name = 'ContosoLicense';     Exe = 'VFS\ProgramFilesX64\App\licsvc.exe';         Account = 'localSystem' }
                    @{ Name = 'MozillaMaintenance'; Exe = 'VFS\ProgramFilesX86\App\maintenanceservice.exe'; Account = 'localSystem' }
                )) {
                    [pscustomobject]@{
                        Severity = 'Warning'; Category = 'ManifestFix:PackagedService'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'z'
                        ServiceEntries = @([pscustomobject]@{
                            Name = $svc.Name; VfsExecutable = $svc.Exe; StartupType = 'auto'
                            StartAccount = $svc.Account; Dependencies = @(); CanAutoFix = $true
                        })
                    }
                }
            )
            SuggestedFixups = @()
        }
    }

    It 'declares the services in ONE call, skipping the one whose executable an earlier stage removed' {
        Mock -ModuleName MSIX Add-MsixService { }
        # The package as RemoveUpdaters left it: maintenanceservice.exe is gone.
        Mock -ModuleName MSIX _MsixGetPackagePayloadPath {
            'AppxManifest.xml', 'VFS\ProgramFilesX64\App\agent.exe', 'VFS\ProgramFilesX64\App\LICSVC.EXE'
        }
        $log = Invoke-MsixAutoFixFromAnalysis -Report $script:ServiceReport -SkipSigning -Confirm:$false 6>&1 | Out-String -Width 4096

        Should -Invoke -ModuleName MSIX Add-MsixService -Times 1 -Exactly
        Should -Invoke -ModuleName MSIX Add-MsixService -Times 1 -Exactly -ParameterFilter {
            (@($Services | ForEach-Object { $_.Name }) -join ',') -eq 'ContosoAgent,ContosoLicense'
        }
        $log | Should -Match "skipping service 'MozillaMaintenance': its executable 'VFS\\ProgramFilesX86\\App\\maintenanceservice\.exe' is no longer in the package"
    }

    It 'does not call Add-MsixService at all when no service is left' {
        Mock -ModuleName MSIX Add-MsixService { }
        Mock -ModuleName MSIX _MsixGetPackagePayloadPath { 'AppxManifest.xml' }
        $null = Invoke-MsixAutoFixFromAnalysis -Report $script:ServiceReport -SkipSigning -Confirm:$false
        Should -Invoke -ModuleName MSIX Add-MsixService -Times 0 -Exactly
    }

    It 'Add-MsixService -Services gives the same manifest as one call per service, in one mutation' {
        $file = Join-Path -Path $TestDrive -ChildPath 'svc-AppxManifest.xml'
        $script:SvcFile = $file
        $script:SvcCalls = 0
        Mock -ModuleName MSIX _MsixMutateManifest {
            $script:SvcCalls++
            [xml]$m = Get-MsixManifest -Path $script:SvcFile
            $m = Invoke-MsixManifestTransform -Manifest $m -Transform $Mutate
            Save-MsixManifest -Manifest $m -Path $script:SvcFile
        }
        $services = @(
            @{ Executable = 'VFS\ProgramFilesX64\App\agent.exe';  Name = 'ContosoAgent' }
            @{ Executable = 'VFS\ProgramFilesX64\App\licsvc.exe'; Name = 'ContosoLicense'; StartAccount = 'localSystem'; Dependencies = @('rpcss') }
            @{ Executable = 'VFS\ProgramFilesX64\App\agent.exe';  Name = 'ContosoAgent' }   # idempotent repeat
        )

        [IO.File]::WriteAllText($file, $script:ManifestText, [Text.UTF8Encoding]::new($true))
        foreach ($s in $services) { Add-MsixService -PackagePath 'C:\nope.msix' @s -SkipSigning }
        $script:SvcCalls | Should -Be 3
        $perCall = Get-Content -LiteralPath $file -Raw

        [IO.File]::WriteAllText($file, $script:ManifestText, [Text.UTF8Encoding]::new($true))
        $script:SvcCalls = 0
        Add-MsixService -PackagePath 'C:\nope.msix' -Services $services -SkipSigning
        $script:SvcCalls | Should -Be 1
        (Get-Content -LiteralPath $file -Raw) | Should -BeExactly $perCall

        [xml]$m = Get-MsixManifest -Path $file
        @($m.SelectNodes("//*[local-name()='Service']")).Count | Should -Be 2
        @($m.Package.Capabilities.ChildNodes | Where-Object { $_.LocalName -eq 'Capability' } | ForEach-Object { $_.GetAttribute('Name') }) |
            Should -Contain 'localSystemServices'
    }
}

Describe 'DeclarePackageCertificates stage: one mutation for every certificate' -Tag 'AutoFix' {

    It 'calls Add-MsixPackageCertificate ONCE with every certificate path' {
        Mock -ModuleName MSIX Add-MsixPackageCertificate { }
        $report = [pscustomobject]@{
            PackagePath     = 'C:\nope.msix'
            Findings        = @([pscustomobject]@{
                Severity = 'Info'; Category = 'ManifestFix:PackageCertificate'; Symptom = 'x'; Recommendation = 'y'; Evidence = 'Certs'
                CertificateEntries = @(
                    [pscustomobject]@{ RelativePath = 'Certs\root.cer';    FileName = 'root.cer';    SizeBytes = 10; AlreadyDeclared = $false; CanAutoFix = $true }
                    [pscustomobject]@{ RelativePath = 'Certs\issuing.cer'; FileName = 'issuing.cer'; SizeBytes = 10; AlreadyDeclared = $false; CanAutoFix = $true }
                )
            })
            SuggestedFixups = @()
        }
        $null = Invoke-MsixAutoFixFromAnalysis -Report $report -DeclarePackageCertificates -PackageCertificateStore CA -SkipSigning -Confirm:$false
        Should -Invoke -ModuleName MSIX Add-MsixPackageCertificate -Times 1 -Exactly
        Should -Invoke -ModuleName MSIX Add-MsixPackageCertificate -Times 1 -Exactly -ParameterFilter {
            $StoreName -eq 'CA' -and (@($CertificatePath) -join ',') -eq 'Certs\root.cer,Certs\issuing.cer'
        }
    }
}

Describe 'Batched mutators on a real package' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path $TestDrive -ChildPath 'batch-real'
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }

    It 'Add-MsixShellHandlerExtension -Handlers packs, with the manifest one call per handler gives' {
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'base.msix')
        $perCall = Join-Path $script:Dir 'per-call.msix'
        Copy-Item -LiteralPath $fx.PackagePath -Destination $perCall
        foreach ($h in $script:HandlerSet) {
            Add-MsixShellHandlerExtension -PackagePath $perCall @h -SkipSigning
        }
        $batch = Join-Path $script:Dir 'batch.msix'
        Add-MsixShellHandlerExtension -PackagePath $fx.PackagePath -Handlers $script:HandlerSet -OutputPath $batch -SkipSigning

        (Get-MsixManifest -Path $batch).OuterXml | Should -BeExactly (Get-MsixManifest -Path $perCall).OuterXml
        @((Get-MsixManifest -Path $batch).SelectNodes("//*[local-name()='FileTypeAssociation']") | ForEach-Object { $_.GetAttribute('Name') }) |
            Should -Be @('mpv2thumbnail', 'mkvthumbnail', 'previewhandler')
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'Add-MsixPackageCertificate declares several payload certificates in one call' {
        # Real DER certificates, made in memory (no certificate store involved).
        $der = foreach ($cn in 'CN=Batch Root', 'CN=Batch Issuing') {
            $rsa = [System.Security.Cryptography.RSA]::Create(2048)
            try {
                $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
                    $cn, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,
                    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                $cert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(30))
                , $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            } finally { $rsa.Dispose() }
        }
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'cert-base.msix') -Files @(
            @{ Path = 'Certs\root.cer';    Bytes = $der[0] }
            @{ Path = 'Certs\issuing.cer'; Bytes = $der[1] }
        )
        $out = Join-Path $script:Dir 'cert.msix'
        Add-MsixPackageCertificate -PackagePath $fx.PackagePath -CertificatePath 'Certs\root.cer', 'Certs\issuing.cer' `
            -StoreName TrustedPeople -OutputPath $out -SkipSigning
        [xml]$m = Get-MsixManifest -Path $out
        @($m.SelectNodes("//*[local-name()='Certificate']") | ForEach-Object { $_.GetAttribute('Content') }) |
            Should -Be @('Certs\root.cer', 'Certs\issuing.cer')
        @($m.SelectNodes("//*[local-name()='Extension' and @Category='windows.certificates']")).Count | Should -Be 1
        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }
}
