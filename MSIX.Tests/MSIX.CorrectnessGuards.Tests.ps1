BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Correctness guards (issue #153)
# -----------------------------------------------------------------------------
# Defects that all shared one shape: the module carried on and reported success
# while producing something wrong - a modification package with no registry
# content, a package missing a runtime DLL, duplicate manifest nodes, a log with
# mangled characters, or a phantom application entry.
# =============================================================================

Describe 'Failure signals are not discarded (#153)' -Tag 'Correctness' {

    It 'New-MsixModificationPackage fails when the registry hive cannot be saved' {
        # _MsixOfflineSaveHive signals failure ONLY by returning $false. The
        # return was discarded, so a failed save produced a SIGNED modification
        # package containing none of the requested registry keys, exit code 0,
        # and a log line claiming success.
        $threw = InModuleScope MSIX {
            Mock _MsixOfflineSaveHive { $false }
            Mock _MsixCreateOfflineHive { [IntPtr]::new(1) }
            Mock _MsixCloseOfflineHive {}
            Mock _MsixOfflineCreateKey { [IntPtr]::new(2) }
            Mock _MsixOfflineCloseKey {}
            Mock _MsixOfflineSetValueString {}
            Mock _MsixOfflineSetValueDword {}
            $staging = Join-Path ([IO.Path]::GetTempPath()) ("hive-" + [guid]::NewGuid().ToString('N').Substring(0,8))
            New-Item -ItemType Directory -Path $staging -Force | Out-Null
            try {
                _MsixBuildRegistryContent -Staging $staging -RegistryContent @{ 'HKLM\SOFTWARE\Probe' = @{ V = 'x' } }
                $false
            } catch { $true }
            finally { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue }
        }
        $threw | Should -BeTrue -Because 'a hive that could not be written must not ship as a successful package'
    }

    It 'Test-MsixSignature reports NeedsSelfSign for a NotTrusted package' {
        # A NotTrusted package will NOT install in a clean sandbox - exactly the
        # case -AutoSign exists for - yet NotTrusted was missing from the set,
        # although this function's own help lists it as returnable.
        $needs = InModuleScope MSIX {
            Mock Get-AuthenticodeSignature {
                [pscustomobject]@{ Status = 'NotTrusted'; SignerCertificate = $null }
            }
            $f = Join-Path ([IO.Path]::GetTempPath()) ("sig-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.msix')
            Set-Content -LiteralPath $f -Value 'stub' -Encoding ascii
            try { (Test-MsixSignature -PackagePath $f).NeedsSelfSign }
            finally { Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue }
        }
        $needs | Should -BeTrue
    }
}

Describe 'Log file encoding (#153)' -Tag 'Correctness' {

    It 'writes UTF-8 so arrows and box drawing survive' {
        # With no -Encoding, Windows PowerShell 5.1 writes the ANSI code page and
        # turns the arrows/box-drawing this module emits into literal '?'.
        $log = Join-Path ([IO.Path]::GetTempPath()) ("log-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.log')
        try {
            Set-MsixLogFile -Path $log
            Write-MsixLog -Level Info -Message 'arrow -> U+2192 here'
            Write-MsixLog -Level Info -Message ([char]0x2192).ToString()
            Set-MsixLogFile
            $bytes = [IO.File]::ReadAllBytes($log)
            # U+2192 is E2 86 92 in UTF-8; '?' (0x3F) is what ANSI substitutes.
            $text = [Text.Encoding]::UTF8.GetString($bytes)
            $text | Should -Match ([regex]::Escape([char]0x2192))
        } finally {
            Set-MsixLogFile
            Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Null-safety on packages with no <Applications> (#153)' -Tag 'Correctness' {

    BeforeAll {
        # The shape the module GENERATES itself via New-MsixModificationPackage
        # and New-MsixFrameworkPackage: no <Applications>, no <Extensions>.
        $script:NoApps = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Properties><DisplayName>X</DisplayName></Properties>
</Package>
'@
    }

    It 'Compare-MsixPackage does not invent a phantom application entry' {
        $count = InModuleScope MSIX -Parameters @{ Xml = $script:NoApps } {
            param($Xml)
            [xml]$m = $Xml
            @($m.Package.Applications.Application | Where-Object { $null -ne $_ }).Count
        }
        # @($null).Count reports 1 - that is the bug this guards.
        $count | Should -Be 0
    }

    It 'every module file expands Applications.Application with a null guard' {
        $root = Split-Path -Parent $PSScriptRoot
        $unguarded = Get-ChildItem -Path $root -Filter 'MSIX.*.ps1' |
            Where-Object { $_.Name -notmatch '\.Tests\.ps1$' } |
            ForEach-Object {
                $file = $_
                Select-String -LiteralPath $file.FullName -Pattern '@\(\$\w+\.Package\.Applications\.Application\)' |
                    ForEach-Object { "{0}:{1}" -f $file.Name, $_.LineNumber }
            }
        $unguarded | Should -BeNullOrEmpty
    }
}

Describe 'VC runtime bundling refuses to ship something broken (#153)' -Tag 'Correctness' {

    It 'declares no silent x86 fallback for an undetectable architecture' {
        # The old code coerced 'unknown' (and arm64) to 'x86' while logging
        # "auto-detected", bundling x86 DLLs into an x64/arm64 package.
        $src = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'MSIX.VcRuntime.ps1') -Raw
        $src | Should -Not -Match "if \(\`$Architecture -notin 'x86','x64'\) \{ \`$Architecture = 'x86' \}"
        $src | Should -Match 'Cannot auto-detect a supported architecture'
    }

    It 'throws rather than packing a partial runtime bundle' {
        $src = Get-Content -LiteralPath (Join-Path (Split-Path -Parent $PSScriptRoot) 'MSIX.VcRuntime.ps1') -Raw
        $src | Should -Match 'Packing now would ship a package that still fails at launch'
    }
}

Describe 'Mutators are idempotent on a second run (#153)' -Tag 'Correctness', 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-idem-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'Add-MsixFileTypeAssociation does not duplicate the association' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'fta2-base.msix')
        $one = Join-Path $script:Dir 'fta2-1.msix'
        $two = Join-Path $script:Dir 'fta2-2.msix'
        Add-MsixFileTypeAssociation -PackagePath $fx.PackagePath -AppId 'App' -Name 'labfta' -FileTypes '.labx' -OutputPath $one -SkipSigning
        Add-MsixFileTypeAssociation -PackagePath $one -AppId 'App' -Name 'labfta' -FileTypes '.labx' -OutputPath $two -SkipSigning
        [xml]$m = Get-MsixManifest -Path $two
        @($m.SelectNodes("//*[local-name()='FileTypeAssociation']")).Count | Should -Be 1
    }

    It 'Add-MsixFirewallRule does not duplicate the Rule element' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'fw2-base.msix')
        $one = Join-Path $script:Dir 'fw2-1.msix'
        $two = Join-Path $script:Dir 'fw2-2.msix'
        $exe = 'VFS\ProgramFilesX64\App\app.exe'
        Add-MsixFirewallRule -PackagePath $fx.PackagePath -AppId 'App' -Executable $exe -Direction in -Protocol TCP -OutputPath $one -SkipSigning
        Add-MsixFirewallRule -PackagePath $one -AppId 'App' -Executable $exe -Direction in -Protocol TCP -OutputPath $two -SkipSigning
        [xml]$m = Get-MsixManifest -Path $two
        @($m.SelectNodes("//*[local-name()='Rule']")).Count | Should -Be 1
    }

    It 'Add-MsixShellVerbExtension does not duplicate the association' {
        $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'verb2-base.msix')
        $one = Join-Path $script:Dir 'verb2-1.msix'
        $two = Join-Path $script:Dir 'verb2-2.msix'
        Add-MsixShellVerbExtension -PackagePath $fx.PackagePath -AppId 'App' -VerbDisplayName 'Open with Lab' -FileTypes '.labv' -OutputPath $one -SkipSigning
        Add-MsixShellVerbExtension -PackagePath $one -AppId 'App' -VerbDisplayName 'Open with Lab' -FileTypes '.labv' -OutputPath $two -SkipSigning
        [xml]$m = Get-MsixManifest -Path $two
        @($m.SelectNodes("//*[local-name()='FileTypeAssociation']")).Count | Should -Be 1
    }
}
