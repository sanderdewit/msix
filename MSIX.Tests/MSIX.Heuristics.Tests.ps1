BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Heuristic catalogues (v0.9)' -Tag 'Heuristics' {

    Context 'Get-MsixKnownCapability' {
        It 'Returns at least 10 entries' {
            (Get-MsixKnownCapability).Count | Should -BeGreaterOrEqual 10
        }
        It 'Tags rescap entries correctly' {
            $rescap = Get-MsixKnownCapability | Where-Object Name -eq 'runFullTrust'
            $rescap.Namespace | Should -Be 'rescap'
        }
        It 'Tags standard entries correctly' {
            $std = Get-MsixKnownCapability | Where-Object Name -eq 'internetClient'
            $std.Namespace | Should -Be 'standard'
        }
    }

    Context 'Invoke-MsixAutoFix DryRun' {
        It 'Returns DryRun=true and lists planned stages without mutating' {
            # Use a path that need not exist; DryRun shouldn't unpack anything.
            $r = Invoke-MsixAutoFix -PackagePath 'C:\does-not-exist.msix' `
                                    -RemoveUninstallers `
                                    -VersionBumpComponent Build `
                                    -Capabilities runFullTrust `
                                    -DryRun
            $r.DryRun  | Should -BeTrue
            $r.Stages  | Should -Contain 'PrePsf:RemoveUninstallers'
            $r.Stages  | Should -Contain 'PrePsf:BumpVersion'
            $r.Stages  | Should -Contain 'Recommended:AddCapabilities'
        }
        It 'Skips PSF stage when no fixups provided' {
            $r = Invoke-MsixAutoFix -PackagePath 'C:\nope.msix' -RemoveUninstallers -DryRun
            $r.Stages | Should -Not -Contain 'Recommended:InjectPsf'
        }
    }

    Context 'Get-MsixHeuristicFinding unpacks once (#58)' {
        It 'invokes MakeAppx unpack exactly once for a full heuristic sweep' {
            $pkg = Join-Path -Path $TestDrive -ChildPath 'count.msix'
            Set-Content -LiteralPath $pkg -Value 'stub' -Encoding utf8

            $result = InModuleScope MSIX -Parameters @{ Pkg = $pkg } {
                param($Pkg)
                $script:unpackCount = 0
                Mock Get-MsixToolsRoot { 'C:\fake-tools' }
                # New-MsixWorkspace returns a real temp dir we populate with a
                # minimal manifest so the scanners have something to read.
                Mock New-MsixWorkspace {
                    $d = Join-Path ([IO.Path]::GetTempPath()) ("hf-" + [guid]::NewGuid().ToString('N').Substring(0,8))
                    New-Item -ItemType Directory -Path $d -Force | Out-Null
                    $d
                }
                Mock Invoke-MsixProcess {
                    if ($ArgumentList -contains 'unpack') {
                        $script:unpackCount++
                        # Lay down a minimal manifest in the unpack destination so
                        # downstream scanners don't error.
                        $idx  = [array]::IndexOf($ArgumentList, '/d')
                        $dest = $ArgumentList[$idx + 1]
                        if ($dest -and -not (Test-Path -LiteralPath "$dest\AppxManifest.xml")) {
                            Set-Content -LiteralPath "$dest\AppxManifest.xml" -Encoding utf8 -Value @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Applications><Application Id="A" Executable="a.exe" /></Applications>
</Package>
'@
                        }
                    }
                    [pscustomobject]@{ ExitCode = 0; StdOut = ''; StdErr = '' }
                }
                $null = Get-MsixHeuristicFinding -PackagePath $Pkg
                $script:unpackCount
            }
            # Before #58 this was ~14 (one unpack per scanner + the manifest block).
            $result | Should -Be 1
        }
    }
}
