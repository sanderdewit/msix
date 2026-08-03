BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Data-loss guards (issue #145)
# -----------------------------------------------------------------------------
# Three paths could silently destroy or corrupt the operator's package:
#   1. Remove-MsixPsf deleted 'config.json' / '*Fixup*.dll' from packages that
#      never had PSF, then repacked and moved over the original.
#   2. Add-MsixVcRuntimeBundle packed and signed directly over the input file,
#      so a signing failure left an unsigned repack where a signed package was.
#   3. New-MsixWorkspace honoured the inherited $WhatIfPreference, returned an
#      empty string, and broke -WhatIf for every mutator.
# These are the assertions that were missing; each fails against the old code.
# =============================================================================

Describe 'New-MsixWorkspace under -WhatIf (issue #145)' -Tag 'DataLoss' {

    It 'still creates a real scratch directory when WhatIfPreference is set' {
        # The workspace is private scratch, not a user-visible side effect. If
        # New-Item honours -WhatIf the directory is missing, Get-Item fails and
        # the function returns '' - which broke every mutator's -WhatIf.
        $result = InModuleScope MSIX {
            $WhatIfPreference = $true
            try {
                $ws = New-MsixWorkspace -PackageName 'whatif-guard'
                [pscustomobject]@{ Path = $ws; Exists = [bool]($ws -and (Test-Path -LiteralPath $ws)) }
            } finally {
                $WhatIfPreference = $false
                if ($ws -and (Test-Path -LiteralPath $ws)) { Remove-Item -LiteralPath $ws -Recurse -Force -ErrorAction SilentlyContinue }
            }
        }
        $result.Path   | Should -Not -BeNullOrEmpty
        $result.Exists | Should -BeTrue
    }
}

Describe 'Remove-MsixPsf payload guard (issue #145)' -Tag 'DataLoss', 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-dlguard-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'does NOT delete an app''s own config.json from a package that never had PSF' {
        # The exact data-loss case: an Electron/.NET style app shipping its own
        # config.json and a DLL whose name happens to contain "Fixup".
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'nopsf-base.msix') -Files @(
            @{ Path = 'app\config.json';      Bytes = [Text.Encoding]::UTF8.GetBytes('{"appSetting":true}') }
            @{ Path = 'app\ContosoFixup.dll'; Bytes = [byte[]]@(0x4D,0x5A,0x90,0x00) }
        )
        $before = (Get-FileHash -LiteralPath $fx.PackagePath -Algorithm SHA256).Hash

        Remove-MsixPsf -PackagePath $fx.PackagePath -SkipSigning

        # The operator's package must be byte-identical: nothing to remove.
        (Get-FileHash -LiteralPath $fx.PackagePath -Algorithm SHA256).Hash | Should -Be $before

        # And prove the payload survives inside the package.
        $probe = Join-Path $script:Dir 'nopsf-probe'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [IO.Compression.ZipFile]::ExtractToDirectory($fx.PackagePath, $probe)
        Test-Path -LiteralPath (Join-Path $probe 'app\config.json')      | Should -BeTrue
        Test-Path -LiteralPath (Join-Path $probe 'app\ContosoFixup.dll') | Should -BeTrue
    }
}

Describe 'Add-MsixVcRuntimeBundle atomic repack (issue #145)' -Tag 'DataLoss' {

    It 'declares -UnsignedOutputPath so a signing failure is recoverable' {
        (Get-Command Add-MsixVcRuntimeBundle).Parameters.ContainsKey('UnsignedOutputPath') | Should -BeTrue
    }

    It 'packs to scratch and moves, never over the input path' {
        # Behavioural proxy: assert MakeAppx pack is never handed the caller's
        # own package path as its /p destination.
        $packTargets = InModuleScope MSIX {
            $script:targets = @()
            Mock Get-MsixToolsRoot { 'C:\fake-tools' }
            Mock Test-MsixManifest { $true }
            Mock Get-MsixManifestApplication { @([pscustomobject]@{ Executable = 'app\app.exe' }) }
            Mock Get-MsixManifest {
                $x = New-Object System.Xml.XmlDocument
                $x.LoadXml('<Package><Applications><Application Id="A" Executable="app\app.exe"/></Applications></Package>')
                $x
            }
            Mock Invoke-MsixProcess {
                if ($ArgumentList -contains 'pack') {
                    $i = [array]::IndexOf($ArgumentList, '/p')
                    $script:targets += $ArgumentList[$i + 1]
                }
                if ($ArgumentList -contains 'unpack') {
                    $i = [array]::IndexOf($ArgumentList, '/d')
                    New-Item -ItemType Directory -Path $ArgumentList[$i + 1] -Force | Out-Null
                }
                [pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' }
            }
            Mock Assert-MsixProcessSuccess {}
            Mock Invoke-MsixSigning {}
            Mock Move-Item {}
            Mock _GetPeArchitecture { 'x64' }

            $src = Join-Path ([IO.Path]::GetTempPath()) ("vcsrc-" + [guid]::NewGuid().ToString('N').Substring(0,8))
            New-Item -ItemType Directory -Path $src -Force | Out-Null
            [IO.File]::WriteAllBytes((Join-Path $src 'msvcp140.dll'), [byte[]]@(0x4D,0x5A))
            $pkg = Join-Path ([IO.Path]::GetTempPath()) ("vcpkg-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.msix')
            Set-Content -LiteralPath $pkg -Value 'stub' -Encoding ascii
            try {
                Add-MsixVcRuntimeBundle -PackagePath $pkg -SourceFolder $src -Architecture x64 `
                    -Names 'msvcp140.dll' -SkipSigning -ErrorAction SilentlyContinue | Out-Null
            } catch { }
            [pscustomobject]@{ Targets = $script:targets; Pkg = $pkg }
        }
        @($packTargets.Targets).Count | Should -BeGreaterThan 0
        foreach ($t in $packTargets.Targets) {
            $t | Should -Not -Be $packTargets.Pkg
        }
    }
}

Describe '_MsixPreserveUnsigned honesty (issue #145)' -Tag 'DataLoss' {

    It 'logs at Error - not a false "preserved" Warning - when the copy fails' {
        $msgs = InModuleScope MSIX {
            $script:captured = @()
            Mock Write-MsixLog { $script:captured += [pscustomobject]@{ Level = $Level; Message = $Message } }
            # Destination on a drive that cannot exist => copy must fail.
            _MsixPreserveUnsigned -Scratch 'C:\definitely\missing\scratch.msix' -Destination 'Q:\nope\out.msix'
            $script:captured
        }
        @($msgs | Where-Object { $_.Level -eq 'Error' }).Count | Should -BeGreaterThan 0
        @($msgs | Where-Object { $_.Message -match 'preserved at' -and $_.Level -eq 'Warning' }).Count | Should -Be 0
    }

    It 'creates a missing destination directory and reports success truthfully' {
        $res = InModuleScope MSIX {
            $root    = Join-Path ([IO.Path]::GetTempPath()) ("preserve-" + [guid]::NewGuid().ToString('N').Substring(0,8))
            $scratch = Join-Path ([IO.Path]::GetTempPath()) ("scratch-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.msix')
            Set-Content -LiteralPath $scratch -Value 'payload' -Encoding ascii
            $dest = Join-Path $root 'nested\out.msix'
            $script:captured = @()
            Mock Write-MsixLog { $script:captured += [pscustomobject]@{ Level = $Level; Message = $Message } }
            _MsixPreserveUnsigned -Scratch $scratch -Destination $dest
            $out = [pscustomobject]@{ Exists = (Test-Path -LiteralPath $dest); Levels = @($script:captured.Level) }
            Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue
            Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
            $out
        }
        $res.Exists | Should -BeTrue
        $res.Levels | Should -Not -Contain 'Error'
    }
}
