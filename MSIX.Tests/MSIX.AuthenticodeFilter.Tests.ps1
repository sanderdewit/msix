BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force

    $script:Sandbox = Join-Path $env:TEMP "msix-authenticode-filter-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:Sandbox -Force | Out-Null

    # Drop a mix of files into a fake toolchain extraction folder.
    # The folder MUST NOT contain any real signed binaries — the test only
    # exercises which files _MsixVerifyAuthenticodeFolder selects, not the
    # signature check itself (verified separately via the Throws case).
    @(
        'notepad.exe',                  # would be selected (but we never call it)
        'kernel32.dll',                 # would be selected
        'notepad.exe.manifest',         # MUST be skipped — XML side-by-side manifest
        'plain.manifest',               # MUST be skipped — XML manifest
        'data.json',                    # MUST be skipped
        'readme.txt',                   # MUST be skipped
        'libfoo.so',                    # MUST be skipped (non-Windows)
        'archive.zip'                   # MUST be skipped
    ) | ForEach-Object {
        # Empty files are enough — the filter inspects extensions, not contents.
        '' | Set-Content -LiteralPath (Join-Path $script:Sandbox $_) -Encoding ascii
    }
}

AfterAll {
    if (Test-Path $script:Sandbox) {
        Remove-Item -LiteralPath $script:Sandbox -Recurse -Force -ErrorAction SilentlyContinue
    }
    Remove-Module MSIX -ErrorAction SilentlyContinue
}

Describe 'Authenticode folder filter' -Tag 'PsfBinaries' {

    # The previous implementation used Get-ChildItem -Include '*.exe','*.dll'
    # which in some PowerShell versions matched 'app.exe.manifest' too,
    # producing bogus "not signed" failures during toolchain installs. The
    # current implementation filters on $_.Extension -in '.exe','.dll' which
    # is an exact suffix match. This test pins that behaviour.

    It 'Selects only .exe and .dll files, ignoring side-by-side .manifest files' {
        # Reach into the private helper logic — the filter is the only
        # thing we care about, and we can't mock Get-AuthenticodeSignature
        # cleanly across PS versions. Reproduce the filter expression here
        # and assert it picks exactly the .exe and .dll files.
        $picked = @(Get-ChildItem -LiteralPath $script:Sandbox -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.exe', '.dll' })

        $picked.Count    | Should -Be 2
        $picked.Name | Should -Contain 'notepad.exe'
        $picked.Name | Should -Contain 'kernel32.dll'

        $picked.Name | Should -Not -Contain 'notepad.exe.manifest'
        $picked.Name | Should -Not -Contain 'plain.manifest'
        $picked.Name | Should -Not -Contain 'data.json'
    }

    It 'Source: _MsixVerifyAuthenticodeFolder uses .Extension -in (not -Include glob)' {
        # Belt-and-braces guard so future edits don''t silently revert to
        # the wildcard form. The "$_.Extension -in '.exe', '.dll'" pattern
        # is what protects against the .exe.manifest false positive.
        # (We only positively assert the new form here; a negative match on
        # "-Include '*.exe','*.dll'" would false-fire on the explanatory
        # comment that documents why we no longer use it.)
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.PsfBinaries.ps1')) -Raw
        $src | Should -Match "\.Extension -in '\.exe', '\.dll'"
    }
}

Describe 'Install-MsixMgr Authenticode opt-out' -Tag 'PsfBinaries' {

    # Upstream microsoft/msix-packaging#710: the msixmgr archive ships
    # unsigned + test-signed binaries. We default to skipping Authenticode
    # verification ONLY for msixmgr so installs don''t fail on every
    # machine. The skip must be opt-out (user can pass -VerifyAuthenticode
    # to restore strict verification) and the skip must surface via
    # Write-Warning so high-assurance operators see it.

    It 'Install-MsixMgr exposes a -VerifyAuthenticode switch (default off)' {
        $cmd = Get-Command Install-MsixMgr -Module MSIX
        $p   = $cmd.Parameters['VerifyAuthenticode']
        $p | Should -Not -BeNullOrEmpty
        $p.ParameterType.FullName | Should -Be 'System.Management.Automation.SwitchParameter'
    }

    It 'Update-MsixMgr forwards -VerifyAuthenticode' {
        $cmd = Get-Command Update-MsixMgr -Module MSIX
        $p   = $cmd.Parameters['VerifyAuthenticode']
        $p | Should -Not -BeNullOrEmpty
        $p.ParameterType.FullName | Should -Be 'System.Management.Automation.SwitchParameter'
    }

    It 'Source: Install-MsixMgr only verifies when -VerifyAuthenticode is supplied' {
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.AppAttach.ps1')) -Raw
        # The verify call must be guarded by an if ($VerifyAuthenticode) check.
        $src | Should -Match "if \(\`$VerifyAuthenticode\) \{[^}]*_MsixVerifyAuthenticodeFolder"
        # And there must be a Write-Warning on the skip path mentioning the
        # upstream issue so the bypass isn''t silent.
        $src | Should -Match 'Write-Warning.+msixmgr.+710'
    }

    It 'Source: every NON-msixmgr toolchain downloader still verifies unconditionally' {
        # The skip must be scoped to Install-MsixMgr / Update-MsixMgr. The
        # other downloaders (PSF, Procmon, DebugView, SDK BuildTools) must
        # still call _MsixVerifyAuthenticodeFolder without a switch guard.
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.PsfBinaries.ps1')) -Raw
        $verifyCalls = [regex]::Matches($src, '_MsixVerifyAuthenticodeFolder -Folder')
        $verifyCalls.Count | Should -BeGreaterOrEqual 3
        # None of those calls in PsfBinaries.ps1 should be wrapped in a
        # 'if ($VerifyAuthenticode)' opt-in — that would silently weaken
        # security for the trusted downloaders.
        $src | Should -Not -Match 'if \(\$VerifyAuthenticode\)\s*\{\s*_MsixVerifyAuthenticodeFolder'
    }
}
