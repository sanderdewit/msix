# =============================================================================
# Build-MsixTestFixture — synthesize a real .msix at test time
# -----------------------------------------------------------------------------
# Dot-sourced by the Integration-tagged tests. Produces a genuine MSIX package
# (via the SDK MakeAppx on the runner) from a declarative spec, so integration
# tests can exercise the real unpack/scan/repack paths instead of mocks.
#
# Binaries are NOT committed to the repo; each fixture is built fresh into a
# temp folder and removed by the caller. Requires the Windows SDK tools
# (MakeAppx), resolved through the module's own Get-MsixToolsRoot.
# =============================================================================

# A 1x1 transparent PNG — the smallest valid asset MakeAppx will accept for the
# manifest's logo references.
$script:MsixFixturePngBytes = [byte[]]@(
    0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A,0x00,0x00,0x00,0x0D,0x49,0x48,0x44,0x52,
    0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x08,0x06,0x00,0x00,0x00,0x1F,0x15,0xC4,
    0x89,0x00,0x00,0x00,0x0D,0x49,0x44,0x41,0x54,0x78,0x9C,0x62,0x00,0x01,0x00,0x00,
    0x05,0x00,0x01,0x0D,0x0A,0x2D,0xB4,0x00,0x00,0x00,0x00,0x49,0x45,0x4E,0x44,0xAE,
    0x42,0x60,0x82
)

function Test-MsixFixtureToolingAvailable {
    <#
    .SYNOPSIS
        Returns $true if MakeAppx can be resolved on this host, else $false.
        Used by Integration tests to skip (loudly) rather than fail when the
        SDK toolchain is not present (e.g. a non-Windows dev box).
    #>
    [OutputType([bool])]
    param()
    try {
        $root = & (Get-Module MSIX) { Get-MsixToolsRoot -ErrorAction Stop }
        return [bool]($root -and (Test-Path -LiteralPath (Join-Path -Path $root -ChildPath 'Tools\MakeAppx.exe')))
    } catch {
        return $false
    }
}

function New-MsixTestFixture {
    <#
    .SYNOPSIS
        Builds a real .msix package from a declarative spec and returns its path.

    .PARAMETER OutputPath
        Where to write the .msix. The staging folder is a sibling temp dir.

    .PARAMETER Publisher
        Identity/Publisher DN. Default 'CN=MSIX Integration Test'.

    .PARAMETER Name
        Identity/Name. Default 'MSIX.IntegrationTest'.

    .PARAMETER Version
        Identity/Version. Default '1.0.0.0'.

    .PARAMETER TargetDeviceFamilies
        Array of @{ Name=...; MinVersion=...; MaxVersionTested=... }. When omitted,
        a single Windows.Desktop TDF is emitted. Pass two to exercise multi-TDF.

    .PARAMETER Files
        Extra files to lay into the package: @{ Path='VFS\ProgramFilesX64\App\foo.txt'; Content='...' }.
        Path is package-relative; parent folders are created.

    .PARAMETER Sign
        Self-sign the packed .msix with a cert matching Publisher.

    .OUTPUTS
        [pscustomobject] with PackagePath, StagingFolder, Signed, CertPath.
    #>
    [OutputType([pscustomobject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [string]$Publisher = 'CN=MSIX Integration Test',
        [string]$Name      = 'MSIX.IntegrationTest',
        [string]$Version   = '1.0.0.0',
        [hashtable[]]$TargetDeviceFamilies,
        [hashtable[]]$Files,
        [switch]$Sign
    )

    $stage = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "msix-fixture-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $stage -Force | Out-Null

    # --- TargetDeviceFamily element(s) ---------------------------------------
    if (-not $TargetDeviceFamilies) {
        $TargetDeviceFamilies = @(@{ Name = 'Windows.Desktop'; MinVersion = '10.0.17763.0'; MaxVersionTested = '10.0.19041.0' })
    }
    $tdfXml = ($TargetDeviceFamilies | ForEach-Object {
        "    <TargetDeviceFamily Name=`"$($_.Name)`" MinVersion=`"$($_.MinVersion)`" MaxVersionTested=`"$($_.MaxVersionTested)`" />"
    }) -join "`n"

    # --- AppxManifest.xml -----------------------------------------------------
    $manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10"
         xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
         IgnorableNamespaces="uap rescap">
  <Identity Name="$Name" Publisher="$Publisher" Version="$Version" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>$Name</DisplayName>
    <PublisherDisplayName>Integration Test</PublisherDisplayName>
    <Logo>Assets\logo.png</Logo>
  </Properties>
  <Dependencies>
$tdfXml
  </Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
  <Applications>
    <Application Id="App" Executable="VFS\ProgramFilesX64\App\app.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="$Name" Description="Integration test package"
        BackgroundColor="transparent" Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png" />
    </Application>
  </Applications>
  <Capabilities>
    <rescap:Capability Name="runFullTrust" />
  </Capabilities>
</Package>
"@
    $manifestPath = Join-Path -Path $stage -ChildPath 'AppxManifest.xml'
    # UTF-8 BOM so Windows PowerShell 5.1 round-trips it identically.
    [IO.File]::WriteAllText($manifestPath, $manifest, [Text.UTF8Encoding]::new($true))

    # --- Assets + a stub executable so the manifest references resolve --------
    $assets = Join-Path -Path $stage -ChildPath 'Assets'
    New-Item -ItemType Directory -Path $assets -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path -Path $assets -ChildPath 'logo.png'), $script:MsixFixturePngBytes)

    $appDir = Join-Path -Path $stage -ChildPath 'VFS\ProgramFilesX64\App'
    New-Item -ItemType Directory -Path $appDir -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path -Path $appDir -ChildPath 'app.exe'), [byte[]]@(0x4D,0x5A))  # 'MZ' stub

    # --- Caller-specified extra files ----------------------------------------
    foreach ($f in $Files) {
        $dest = Join-Path -Path $stage -ChildPath $f.Path
        $destDir = Split-Path -Path $dest -Parent
        if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
        if ($f.ContainsKey('Bytes')) {
            [IO.File]::WriteAllBytes($dest, [byte[]]$f.Bytes)
        } else {
            [IO.File]::WriteAllText($dest, [string]$f.Content)
        }
    }

    # --- Pack via the SDK MakeAppx (resolved through the module) --------------
    $toolsRoot = & (Get-Module MSIX) { Get-MsixToolsRoot }
    $makeappx  = Join-Path -Path $toolsRoot -ChildPath 'Tools\MakeAppx.exe'
    $r = & (Get-Module MSIX) {
        param($exe, $stageDir, $out)
        Invoke-MsixProcess -FilePath $exe -ArgumentList @('pack', '/d', $stageDir, '/p', $out, '/o')
    } $makeappx $stage $OutputPath
    if ($r.ExitCode -ne 0) {
        throw "MakeAppx pack failed (exit $($r.ExitCode)): $($r.StdErr)$($r.StdOut)"
    }

    $certPath = $null
    if ($Sign) {
        $signed = & (Get-Module MSIX) {
            param($pkg)
            Invoke-MsixSelfSignAndDebug -PackagePath $pkg -Force
        } $OutputPath
        if ($signed) { $certPath = $signed.CertPath }
    }

    return [pscustomobject]@{
        PackagePath   = $OutputPath
        StagingFolder = $stage
        Signed        = [bool]$Sign
        CertPath      = $certPath
    }
}
