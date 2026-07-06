BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Writes a minimal AppxManifest.xml with the given Identity Name + a marker
    # so we can tell which manifest a reader returned.
    function script:New-TestManifestXml {
        param([string]$Name, [string]$Executable, [string]$Marker)
        @"
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="$Name" Publisher="CN=Test" Version="1.0.0.0" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>$Marker</DisplayName><PublisherDisplayName>t</PublisherDisplayName><Logo>l.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/></Dependencies>
  <Resources><Resource Language="en-us"/></Resources>
  <Applications>
    <Application Id="App" Executable="$Executable" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="$Marker" Description="d" BackgroundColor="transparent" Square150x150Logo="l.png" Square44x44Logo="l.png"/>
    </Application>
  </Applications>
</Package>
"@
    }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Nested / sparse package regression tests (0.73.1)
# -----------------------------------------------------------------------------
# Three latent bugs fixed here, all reproduced by Notepad++-8.9.4.msix:
#   1. MakeAppx VALIDATES the inner manifest on unpack; a sparse inner package
#      legitimately references an external exe, so unpack crashed (0x80080204).
#   2. An 8.3 short-path segment in the inner temp dir corrupted the payload
#      copy's relative paths, mis-filing the inner AppxManifest.xml under a
#      'NN\AppxManifest.xml' path inside the outer VFS.
#   3. Get-MsixManifest matched AppxManifest.xml by BASENAME (-First 1), so on a
#      package carrying a nested manifest it could return the wrong one.
# =============================================================================

Describe 'Get-MsixManifest picks the package-root manifest (bug 3)' -Tag 'NestedPackage' {

    It 'returns the ROOT AppxManifest.xml even when a nested one exists under VFS' {
        $pkg = Join-Path -Path $TestDrive -ChildPath 'twomanifests.msix'
        $zip = [IO.Compression.ZipFile]::Open($pkg, 'Create')
        try {
            # Nested manifest FIRST in the archive (so a naive -First 1 grabs it).
            $nested = $zip.CreateEntry('VFS/ProgramFilesX64/App/sub/AppxManifest.xml')
            $w = [IO.StreamWriter]::new($nested.Open())
            try { $w.Write((New-TestManifestXml -Name 'Inner.Sub' -Executable 'x.exe' -Marker 'INNER')) } finally { $w.Dispose() }
            # Real root manifest second.
            $root = $zip.CreateEntry('AppxManifest.xml')
            $w2 = [IO.StreamWriter]::new($root.Open())
            try { $w2.Write((New-TestManifestXml -Name 'Outer.Real' -Executable 'app.exe' -Marker 'ROOT')) } finally { $w2.Dispose() }
        } finally { $zip.Dispose() }

        $m = Get-MsixManifest -Path $pkg
        $m.Package.Identity.Name        | Should -Be 'Outer.Real'
        $m.Package.Properties.DisplayName | Should -Be 'ROOT'
    }
}

Describe 'Import-MsixSparseShellExtension handles a real sparse nested package (bugs 1 & 2)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-nest-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'unpacks a validation-rejecting inner package and produces exactly one manifest, no corruption' {
        # Outer fixture with a nested folder for the sparse package.
        $outer = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'outer.msix') -Files @(
            @{ Path = 'VFS\ProgramFilesX64\App\contextMenu\ShellExt.dll'; Bytes = [byte[]](0x4D, 0x5A, 1, 2, 3) }
        )

        # Build a SPARSE inner .msix by ZIP (MakeAppx pack would itself reject
        # the external-exe reference). Its Application Executable points at a
        # file that lives in the OUTER package, exactly like NppShell.
        $innerMsix = Join-Path $script:Dir 'Nested.msix'
        $z = [IO.Compression.ZipFile]::Open($innerMsix, 'Create')
        try {
            $me = $z.CreateEntry('AppxManifest.xml')
            $w = [IO.StreamWriter]::new($me.Open())
            try { $w.Write((New-TestManifestXml -Name 'Nested.Sparse' -Executable 'notepad++.exe' -Marker 'NESTED')) } finally { $w.Dispose() }
            $de = $z.CreateEntry('ExtraPayload.dll')
            $w2 = [IO.StreamWriter]::new($de.Open())
            try { $w2.Write('MZ-stub') } finally { $w2.Dispose() }
        } finally { $z.Dispose() }

        # Place the inner .msix inside the outer package payload.
        $withNested = Join-Path $script:Dir 'outer-nested.msix'
        & (Get-Module MSIX) { param($p, $d) Invoke-MsixProcess -FilePath (Join-Path (Get-MsixToolsRoot) 'Tools\MakeAppx.exe') -ArgumentList @('unpack', '/p', $p, '/d', $d, '/o') | Out-Null } $outer.PackagePath (Join-Path $script:Dir 'stage')
        $ctxDir = Join-Path $script:Dir 'stage\VFS\ProgramFilesX64\App\contextMenu'
        Copy-Item -LiteralPath $innerMsix -Destination (Join-Path $ctxDir 'Nested.msix') -Force
        & (Get-Module MSIX) { param($s, $o) Invoke-MsixProcess -FilePath (Join-Path (Get-MsixToolsRoot) 'Tools\MakeAppx.exe') -ArgumentList @('pack', '/p', $o, '/d', $s, '/o') } (Join-Path $script:Dir 'stage') $withNested | Out-Null

        $out = Join-Path $script:Dir 'merged.msix'
        # Bug 1: this used to throw on the inner unpack (MakeAppx validation).
        { Import-MsixSparseShellExtension -PackagePath $withNested `
              -NestedPackagePath 'VFS\ProgramFilesX64\App\contextMenu\Nested.msix' `
              -OutputPath $out -SkipSigning } | Should -Not -Throw

        # Bug 2: exactly one AppxManifest.xml (no stray nested copy under VFS).
        $zip = [IO.Compression.ZipFile]::OpenRead($out)
        try {
            $manifests = @($zip.Entries | Where-Object { $_.Name -eq 'AppxManifest.xml' })
            $manifests.Count | Should -Be 1
            $manifests[0].FullName | Should -Be 'AppxManifest.xml'
            # inner payload was lifted into the outer VFS
            @($zip.Entries | Where-Object { $_.Name -eq 'ExtraPayload.dll' }).Count | Should -BeGreaterThan 0
            # the redundant nested .msix is gone
            @($zip.Entries | Where-Object { $_.Name -eq 'Nested.msix' }).Count | Should -Be 0
        } finally { $zip.Dispose() }

        # Bug 3: the reader returns the real root identity.
        $m = Get-MsixManifest -Path $out
        $m.Package.Identity.Name | Should -Not -Be 'Nested.Sparse'
    }
}
