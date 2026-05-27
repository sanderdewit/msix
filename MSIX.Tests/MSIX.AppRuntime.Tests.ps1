BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Install-MsixAppRuntime fail-closed + Authenticode (issue #42)' -Tag 'AppRuntime' {

    # We cannot exercise the network/signature path in CI without a real
    # download, but we can pin the structural invariants that make the
    # fix work: bundle + every channel exe MUST be Authenticode-verified
    # before the marker is written, per-channel failures MUST NOT be
    # swallowed, and the marker MUST be the last write.

    BeforeAll {
        $script:Src = Get-Content -LiteralPath (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.PsfBinaries.ps1')) -Raw
        $idx = $script:Src.IndexOf('function Install-MsixAppRuntime')
        $idx | Should -BeGreaterThan -1
        $next = $script:Src.IndexOf("`nfunction ", $idx + 10)
        if ($next -lt 0) { $next = $script:Src.Length }
        $script:InstallBody = $script:Src.Substring($idx, $next - $idx)
    }

    It 'verifies the DesktopAppInstaller bundle' {
        $script:InstallBody | Should -Match '_MsixVerifyAuthenticodeMsixBundle.*DesktopAppInstaller'
    }

    It 'verifies every channel runtime exe' {
        $script:InstallBody | Should -Match '_MsixVerifyAuthenticode\s+-Path\s+\$rt'
    }

    It 'fails closed: no try/Write-Warning/continue around per-channel download' {
        # The OLD code wrapped the per-channel download in a try block whose
        # catch only emitted a Warning. That's exactly the failure mode the
        # issue forbids. The fixed code must NOT contain that pattern.
        $script:InstallBody | Should -Not -Match 'try\s*\{[\s\S]*?_MsixDownloadFile[\s\S]*?\}\s*catch\s*\{[\s\S]*?Write-MsixLog\s+Warning\s+"Channel'
    }

    It 'writes the install marker AFTER all downloads + verifications' {
        # Marker write must appear AFTER the channel-verify call. Find the
        # offset of each and assert ordering.
        $verifyIdx = $script:InstallBody.IndexOf('_MsixVerifyAuthenticode -Path $rt')
        $markerIdx = $script:InstallBody.IndexOf('Set-Content -LiteralPath $marker')
        $verifyIdx | Should -BeGreaterThan -1
        $markerIdx | Should -BeGreaterThan -1
        $markerIdx | Should -BeGreaterThan $verifyIdx
    }

    It 'rolls back files created in this call when verification fails' {
        # The catch block must iterate $createdThisRun and Remove-Item each
        # entry so a partial cache isn't left behind.
        $script:InstallBody | Should -Match 'createdThisRun'
        $script:InstallBody | Should -Match '(?s)catch\s*\{[\s\S]*?\$createdThisRun[\s\S]*?Remove-Item'
    }
}

Describe 'Get-MsixAppRuntimeVersion is channel-aware (issue #42)' -Tag 'AppRuntime' {

    # Stage a fake AppRuntime cache folder and prove the channel-aware
    # discovery reports the channels actually present on disk.

    BeforeAll {
        $script:Stage = Join-Path $env:TEMP "msix-apprt-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Stage -Force | Out-Null
    }
    AfterAll {
        if (Test-Path -LiteralPath $script:Stage) {
            Remove-Item -LiteralPath $script:Stage -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'reports an empty channel list when no installer exists' {
        $r = Get-MsixAppRuntimeVersion -Path $script:Stage
        $r.Installed         | Should -BeFalse
        @($r.Channels).Count | Should -Be 0
    }

    It 'discovers every WindowsAppRuntimeInstall-x64-<channel>.exe on disk' {
        # Stage the channel files (empty -- the discovery is filename-based).
        foreach ($ch in '1.4','1.5','1.7') {
            New-Item -ItemType File -Path (Join-Path $script:Stage "WindowsAppRuntimeInstall-x64-$ch.exe") -Force | Out-Null
        }
        # Touch the marker so Installed reports true.
        (Get-Date -Format o) | Set-Content -LiteralPath (Join-Path $script:Stage 'runtime.installed') -Encoding ascii

        $r = Get-MsixAppRuntimeVersion -Path $script:Stage
        $r.Installed | Should -BeTrue
        ($r.Channels | Sort-Object) -join ',' | Should -Be '1.4,1.5,1.7'
        @($r.WindowsAppRuntimeExes).Count | Should -Be 3
    }

    It 'ignores files that do not match the channel-suffix naming convention' {
        New-Item -ItemType File -Path (Join-Path $script:Stage 'WindowsAppRuntimeInstall-x64.exe') -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $script:Stage 'WindowsAppRuntimeInstall-arm64-1.4.exe') -Force | Out-Null
        $r = Get-MsixAppRuntimeVersion -Path $script:Stage
        # Should still have exactly 3 from the previous step
        @($r.Channels).Count | Should -Be 3
    }
}
