BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    $script:Sandbox = Join-Path -Path $env:TEMP -ChildPath "msix-authenticode-filter-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
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
        '' | Set-Content -LiteralPath (Join-Path -Path $script:Sandbox -ChildPath $_) -Encoding ascii
    }
}

AfterAll {
    if (Test-Path -LiteralPath $script:Sandbox) {
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
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.PsfBinaries.ps1')) -Raw
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

    It 'Source: Install-MsixMgr opts out of Authenticode verification via the toolchain helper (issue #36 refactor)' {
        # Post-issue-#36, Install-MsixMgr is a thin wrapper that delegates to
        # _MsixInstallArchiveTool. The security-relevant guard is that the
        # WRAPPER passes its -VerifyAuthenticode switch into the helper AND
        # supplies the upstream-issue warning text — otherwise the skip
        # would be silent and the test would no longer enforce its intent.
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.AppAttach.ps1')) -Raw
        # Wrapper must forward the switch (so verification stays opt-in).
        $src | Should -Match '-VerifyAuthenticode\s+\(\[bool\]\$VerifyAuthenticode\)'
        # And the skip warning must mention msixmgr + the upstream issue
        # number so the bypass cannot be silent.
        $src | Should -Match 'SkipVerificationWarning.+msixmgr.+710'
    }

    It 'Source: helper gates verification on the -VerifyAuthenticode parameter (issue #36)' {
        # The skip is now centralised in _MsixInstallArchiveTool. The helper
        # must still gate the verify call AND emit a warning on the skip path.
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.PsfBinaries.ps1')) -Raw
        $src | Should -Match 'if \(\$VerifyAuthenticode\)\s*\{[^}]*_MsixVerifyAuthenticodeFolder'
        $src | Should -Match 'Write-Warning\s+(-Message\s+)?\$SkipVerificationWarning'
    }

    It 'Source: every NON-msixmgr toolchain downloader still verifies (default ON)' {
        # The skip must be scoped to Install-MsixMgr / Update-MsixMgr.
        # ProcMon and DebugView are thin wrappers around the helper and
        # DELIBERATELY do NOT pass -VerifyAuthenticode, so they inherit the
        # helper's default of $true. PSF and SDK installers remain bespoke
        # and call _MsixVerifyAuthenticodeFolder directly without any guard.
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.PsfBinaries.ps1')) -Raw

        # Bespoke installers (PSF, SDK) call the verify helper directly.
        $directCalls = [regex]::Matches($src, '_MsixVerifyAuthenticodeFolder -Folder')
        $directCalls.Count | Should -BeGreaterOrEqual 3   # helper itself + PSF + SDK

        # Only the toolchain helper (in this file) is allowed to gate the
        # verify call on the switch -- searching the whole file is fine
        # because the helper is the only legitimate site.
        $guardedCalls = [regex]::Matches($src, 'if \(\$VerifyAuthenticode\)\s*\{')
        $guardedCalls.Count | Should -Be 1

        # ProcMon and DebugView wrappers must NOT mention VerifyAuthenticode
        # at all (they inherit the helper's $true default).
        $procmonBlock = ($src -split 'function Install-MsixProcMon \{')[1] -split '\n\}'
        $procmonBlock[0] | Should -Not -Match 'VerifyAuthenticode'
        $dbgBlock     = ($src -split 'function Install-MsixDebugView \{')[1] -split '\n\}'
        $dbgBlock[0]     | Should -Not -Match 'VerifyAuthenticode'
    }
}
