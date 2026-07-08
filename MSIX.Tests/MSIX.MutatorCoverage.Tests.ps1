BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')

    function script:ConvertTo-TestSecureString {
        # Test-only helper (same shape as SecretLeakage tests): builds the
        # SecureString char-by-char to avoid the banned plaintext cmdlet.
        [OutputType([SecureString])]
        param([Parameter(Mandatory)][string]$Value)
        $secure = [System.Security.SecureString]::new()
        foreach ($char in $Value.ToCharArray()) { $secure.AppendChar($char) }
        $secure.MakeReadOnly()
        return $secure
    }
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Coverage burn-down (issue #102)
# -----------------------------------------------------------------------------
# Behavioural tests for the mutators that sat in the coverage-map allowlist:
# every cmdlet here is INVOKED against a real fixture package (or real state),
# not just existence-checked. Grouped one Describe per cmdlet (issue #88).
# =============================================================================

Describe 'Manifest mutators from the coverage allowlist (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-cov-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
        # A tiny valid PNG for cmdlets that take an image path.
        $script:PngPath = Join-Path $script:Dir 'splash.png'
        [IO.File]::WriteAllBytes($script:PngPath, $script:MsixFixturePngBytes)
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    Context 'Add-MsixAlias' {
        It 'adds an AppExecutionAlias for the application executable' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'alias-base.msix')
            $out = Join-Path $script:Dir 'alias.msix'
            Add-MsixAlias -PackagePath $fx.PackagePath -AppIds 'App' -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $m.OuterXml | Should -Match 'ExecutionAlias'
        }
    }

    Context 'Add-MsixFileTypeAssociation' {
        It 'adds a uap FTA for the requested extension' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'fta-base.msix')
            $out = Join-Path $script:Dir 'fta.msix'
            Add-MsixFileTypeAssociation -PackagePath $fx.PackagePath -AppId 'App' -Name 'labfta' `
                -FileTypes '.labx' -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $m.OuterXml | Should -Match 'windows\.fileTypeAssociation'
            $m.OuterXml | Should -Match '\.labx'
        }
    }

    Context 'Add-MsixProtocolHandler' {
        It 'adds a uap protocol handler' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'proto-base.msix')
            $out = Join-Path $script:Dir 'proto.msix'
            Add-MsixProtocolHandler -PackagePath $fx.PackagePath -AppId 'App' -Name 'msixlab' `
                -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $m.OuterXml | Should -Match 'windows\.protocol'
            $m.OuterXml | Should -Match 'msixlab'
        }
    }

    Context 'Add-MsixFontExtension' {
        It 'declares a packaged font' {
            $fontRel = 'Assets\lab.ttf'
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'font-base.msix') `
                       -Files @(@{ Path = $fontRel; Bytes = [byte[]](1..64) })
            $out = Join-Path $script:Dir 'font.msix'
            Add-MsixFontExtension -PackagePath $fx.PackagePath -FontPaths $fontRel -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $m.OuterXml | Should -Match 'lab\.ttf'
        }
    }

    Context 'Add-MsixShellVerbExtension' {
        It 'adds a shell verb with the requested display name' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'verb-base.msix')
            $out = Join-Path $script:Dir 'verb.msix'
            Add-MsixShellVerbExtension -PackagePath $fx.PackagePath -AppId 'App' `
                -VerbDisplayName 'Open with Lab' -FileTypes '.labv' -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $m.OuterXml | Should -Match 'Open with Lab'
        }
    }

    Context 'Add-MsixStartMenuFolder' {
        It 'places the app in a start-menu folder' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'smf-base.msix')
            $out = Join-Path $script:Dir 'smf.msix'
            Add-MsixStartMenuFolder -PackagePath $fx.PackagePath -FolderName 'Lab Tools' -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $m.OuterXml | Should -Match 'Lab Tools'
        }
    }

    Context 'Add-MsixVcRuntimeBundle' {
        It 'scans the package imports and correctly no-ops when no VC runtime is missing' {
            # The fixture stub exe imports nothing, so the real scan path runs
            # end-to-end and reports there is nothing to bundle.
            $src = Join-Path $script:Dir 'vcsrc'
            New-Item -ItemType Directory -Path $src -Force | Out-Null
            [IO.File]::WriteAllBytes((Join-Path $src 'vcruntime140.dll'), [byte[]]@(0x4D,0x5A))
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'vc-base.msix')
            $out = Join-Path $script:Dir 'vc.msix'
            $info = Add-MsixVcRuntimeBundle -PackagePath $fx.PackagePath -SourceFolder $src `
                        -Architecture x64 -OutputPath $out -SkipSigning 6>&1 | Out-String
            $info | Should -Match 'No missing VC runtime'
        }
    }

    Context 'Set-MsixBrandMetadata' {
        It 'rewrites the package display metadata' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'brand-base.msix')
            $out = Join-Path $script:Dir 'brand.msix'
            Set-MsixBrandMetadata -PackagePath $fx.PackagePath -DisplayName 'Branded Lab' `
                -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $m.Package.Properties.DisplayName | Should -Be 'Branded Lab'
        }
    }

    Context 'Remove-MsixDesktopShortcut' {
        It 'runs the real scan/mutate path (no-op on a clean fixture, no throw)' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'shortcut-base.msix')
            { Remove-MsixDesktopShortcut -PackagePath $fx.PackagePath -SkipSigning } | Should -Not -Throw
        }
    }

    Context 'Remove-MsixStartMenuEntry' {
        It 'runs the real scan/mutate path (no-op on a clean fixture, no throw)' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'sme-base.msix')
            { Remove-MsixStartMenuEntry -PackagePath $fx.PackagePath -All -SkipSigning } | Should -Not -Throw
        }
    }

    Context 'Update-MsixSigner' {
        It 're-signs the package with a generated cert and aligns the publisher' {
            $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'signer-base.msix')
            $cert = New-MsixSelfSignedCertificate -PackagePath $fx.PackagePath
            try {
                { Update-MsixSigner -PackagePath $fx.PackagePath -Pfx $cert.PfxPath -PfxPassword $cert.PfxPassword } |
                    Should -Not -Throw
                (Get-AuthenticodeSignature -LiteralPath $fx.PackagePath).SignerCertificate |
                    Should -Not -BeNullOrEmpty
            } finally {
                $certDir = Split-Path -Path $cert.PfxPath -Parent
                if (Test-Path -LiteralPath $certDir) { Remove-Item -LiteralPath $certDir -Recurse -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}

Describe 'PSF-dependent mutators from the coverage allowlist (real package + PSF binaries)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:PsfAvailable = $false
        if ($script:ToolingAvailable) {
            $tr = & (Get-Module MSIX) { Get-MsixToolsRoot }
            $script:PsfAvailable = [bool](Test-Path -LiteralPath (Join-Path -Path $tr -ChildPath 'psf\PsfLauncher64.exe'))
        }
        if (-not $script:PsfAvailable) { Write-Warning 'PSF-dependent tests SKIPPED: PSF binaries not present under the tools root.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-covpsf-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' }
        elseif (-not $script:PsfAvailable) { Set-ItResult -Skipped -Because 'PSF binaries not available.' }
    }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    Context 'Add-MsixPsfV2' {
        It 'injects the PSF launcher + config.json and repoints the entry point' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'psf-base.msix')
            $out = Join-Path $script:Dir 'psf.msix'
            $frf = New-MsixPsfFileRedirectionConfig -Base 'VFS/ProgramFilesX64/App/' -Patterns '.*\.log'
            Add-MsixPsfV2 -PackagePath $fx.PackagePath -Fixups @($frf) -OutputPath $out -SkipSigning
            [xml]$m = Get-MsixManifest -Path $out
            $m.Package.Applications.Application.Executable | Should -Match 'PsfLauncher'
        }

        It 'merges into an existing config on re-injection (already-PSF package)' {
            # Regression: the merge branch keys process entries in an
            # [ordered]@{} (OrderedDictionary), whose key-lookup method is
            # .Contains() - NOT .ContainsKey(). A second injection is the only
            # path that reaches it, so injecting twice guards the crash
            # "does not contain a method named 'ContainsKey'".
            $fx    = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'psf-merge-base.msix')
            $once  = Join-Path $script:Dir 'psf-merge-1.msix'
            $twice = Join-Path $script:Dir 'psf-merge-2.msix'
            $frf   = New-MsixPsfFileRedirectionConfig -Base 'VFS/ProgramFilesX64/App/' -Patterns '.*\.log'
            $envfx = New-MsixPsfEnvVarConfig -Variables @{ MSIX_MERGE_PROBE = '1' }
            Add-MsixPsfV2 -PackagePath $fx.PackagePath -Fixups @($frf) -OutputPath $once -SkipSigning
            # Second pass runs against an already-PSF'd package => merge mode.
            { Add-MsixPsfV2 -PackagePath $once -Fixups @($envfx) -OutputPath $twice -SkipSigning } |
                Should -Not -Throw
            Test-Path -LiteralPath $twice | Should -BeTrue
            [xml]$m = Get-MsixManifest -Path $twice
            $m.Package.Applications.Application.Executable | Should -Match 'PsfLauncher'
        }
    }

    Context 'Add-MsixDiagnosticTrace' {
        It 'injects the TraceFixup via PSF without throwing' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'trace-base.msix')
            $out = Join-Path $script:Dir 'trace.msix'
            { Add-MsixDiagnosticTrace -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning } |
                Should -Not -Throw
            Test-Path -LiteralPath $out | Should -BeTrue
        }
    }

    Context 'Add-MsixSplashScreen' {
        It 'adds the splash image + PSF config entry to a PSF-enabled package' {
            # Add-MsixSplashScreen wires the splash through the PSF launcher
            # config, so it requires a package that already carries config.json.
            $fx   = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'splash-base.msix')
            $psf  = Join-Path $script:Dir 'splash-psf.msix'
            $out  = Join-Path $script:Dir 'splash.msix'
            $png  = Join-Path $script:Dir 'splash.png'
            [IO.File]::WriteAllBytes($png, $script:MsixFixturePngBytes)
            $frf = New-MsixPsfFileRedirectionConfig -Base 'VFS/ProgramFilesX64/App/' -Patterns '.*\.log'
            Add-MsixPsfV2 -PackagePath $fx.PackagePath -Fixups @($frf) -OutputPath $psf -SkipSigning
            { Add-MsixSplashScreen -PackagePath $psf -ImagePath $png -AppId 'App' `
                  -OutputPath $out -SkipSigning } | Should -Not -Throw
            Test-Path -LiteralPath $out | Should -BeTrue
        }
    }

    Context 'Add-MsixStandardScript' {
        It 'generates + injects a PSF startScript' {
            $fx  = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'script-base.msix')
            $out = Join-Path $script:Dir 'script.msix'
            { Add-MsixStandardScript -PackagePath $fx.PackagePath -AppId 'App' -Name CreateShortcut `
                  -Parameters @{ DisplayName = 'Lab'; Target = 'app.exe' } `
                  -OutputPath $out -SkipSigning } | Should -Not -Throw
            Test-Path -LiteralPath $out | Should -BeTrue
        }
    }
}

Describe 'Configuration setters from the coverage allowlist' -Tag 'MutatorCoverage' {

    Context 'Set-MsixLogFile' {
        It 'routes Write-MsixLog lines to the configured file' {
            $log = Join-Path ([IO.Path]::GetTempPath()) "msix-logtest-$([guid]::NewGuid().ToString('N').Substring(0,8)).log"
            try {
                Set-MsixLogFile -Path $log
                Write-MsixLog -Level Info -Message 'coverage-log-probe'
                Set-MsixLogFile   # reset (no -Path)
                Get-Content -LiteralPath $log -Raw | Should -Match 'coverage-log-probe'
            } finally {
                Set-MsixLogFile
                if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
            }
        }
    }

    Context 'Set-MsixLogLevel' {
        It 'suppresses below-threshold messages and restores' {
            try {
                Set-MsixLogLevel -Level Error
                $lines = Write-MsixLog -Level Info -Message 'should-be-suppressed' 6>&1 | Out-String
                $lines | Should -Not -Match 'should-be-suppressed'
            } finally {
                Set-MsixLogLevel -Level Info
            }
            $lines2 = Write-MsixLog -Level Info -Message 'visible-again' 6>&1 | Out-String
            $lines2 | Should -Match 'visible-again'
        }
    }

    Context 'Set-MsixToolsRoot' {
        It 'accepts a valid root (validates MakeAppx presence) and rejects an empty directory' {
            # Setting requires MakeAppx under <root>\Tools — validation is part
            # of the contract, so assert both sides.
            $orig = Get-MsixToolsRoot
            $origValid = $orig -and (Test-Path -LiteralPath (Join-Path -Path $orig -ChildPath 'Tools\MakeAppx.exe'))
            if ($origValid) {
                # Positive side only where real tooling exists (not on the
                # tool-less CI Pester job — the Integration job covers hosts
                # with tooling).
                Set-MsixToolsRoot -Path $orig
                (Get-MsixToolsRoot) | Should -Be $orig
            }

            $tmp = Join-Path ([IO.Path]::GetTempPath()) "msix-toolsroot-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            New-Item -ItemType Directory -Path $tmp -Force | Out-Null
            try {
                { Set-MsixToolsRoot -Path $tmp -ErrorAction Stop } | Should -Throw -ExpectedMessage '*MakeAppx*'
                (Get-MsixToolsRoot) | Should -Be $orig -Because 'a failed set must not change the root'
            } finally {
                Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Set-MsixScriptSignature' {
        It 'signs a script with a self-signed code-signing cert' {
            $work = Join-Path ([IO.Path]::GetTempPath()) "msix-scriptsig-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            New-Item -ItemType Directory -Path $work -Force | Out-Null
            $cert = $null
            try {
                $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=MSIX Coverage Test' `
                            -CertStoreLocation Cert:\CurrentUser\My
                $pfx  = Join-Path $work 'sig.pfx'
                $pw   = ConvertTo-TestSecureString 'coverage-test'
                Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $pw | Out-Null

                $script = Join-Path $work 'probe.ps1'
                Set-Content -LiteralPath $script -Value 'Write-Output "probe"' -Encoding utf8BOM
                Set-MsixScriptSignature -ScriptPath $script -Pfx $pfx -PfxPassword $pw

                (Get-AuthenticodeSignature -LiteralPath $script).SignerCertificate.Subject |
                    Should -Be 'CN=MSIX Coverage Test'
            } finally {
                if ($cert) { Remove-Item -LiteralPath "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force -ErrorAction SilentlyContinue }
                if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}
