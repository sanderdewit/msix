BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Local surface coverage (issue #152)
# -----------------------------------------------------------------------------
# Exported functions that need neither the network, Hyper-V, Windows Sandbox,
# an installed package, nor elevation - so they can be covered honestly in CI.
# What remains uncovered after this file is genuinely environment-bound and is
# listed, with justification, in MSIX.Contract.CoverageMap.Tests.ps1.
# =============================================================================

Describe 'Toolchain version reporters' -Tag 'LocalSurface' {

    # These read a version marker from the tools root. The contract that matters
    # is that a MISSING toolchain reports absence instead of throwing - callers
    # use them to decide whether to install.
    It 'Get-MsixSdkToolsVersion does not throw' {
        { Get-MsixSdkToolsVersion | Out-Null } | Should -Not -Throw
    }
    It 'Get-MsixPsfBinariesVersion does not throw' {
        { Get-MsixPsfBinariesVersion | Out-Null } | Should -Not -Throw
    }
    It 'Get-MsixMgrVersion does not throw' {
        { Get-MsixMgrVersion | Out-Null } | Should -Not -Throw
    }
    It 'Get-MsixDebugViewVersion does not throw' {
        { Get-MsixDebugViewVersion | Out-Null } | Should -Not -Throw
    }
    It 'Resolve-MsixMgrPath returns a string or nothing, never throws' {
        $p = Resolve-MsixMgrPath -ErrorAction SilentlyContinue
        if ($null -ne $p) { $p | Should -BeOfType [string] }
    }
}

Describe 'Local queries against the live package store' -Tag 'LocalSurface' {

    # No package is installed in CI, so the contract under test is "reports
    # nothing" rather than "throws" - the same honesty rule as #140.
    It 'Get-MsixOrphanedAppData handles a machine with no matching packages' {
        { Get-MsixOrphanedAppData -ErrorAction Stop | Out-Null } | Should -Not -Throw
    }
    It 'Get-MsixPackageStorageSummary fails loudly for an unknown package name' {
        # Reporting "nothing" for a package that is not installed would read as
        # "this package uses no storage" - the honesty rule from #140.
        { Get-MsixPackageStorageSummary -PackageName 'Msix.NoSuch.Package.Test' -ErrorAction Stop | Out-Null } |
            Should -Throw '*No installed package matches*'
    }
    It 'Get-MsixContainerAppData fails loudly for an unknown package name' {
        { Get-MsixContainerAppData -PackageName 'Msix.NoSuch.Package.Test' -ErrorAction Stop | Out-Null } |
            Should -Throw '*No installed package matches*'
    }
}

Describe 'Generators that only write files' -Tag 'LocalSurface' {

    It 'New-MsixSandboxConfig writes a .wsb without a BOM' {
        $drop = Join-Path ([IO.Path]::GetTempPath()) ("wsb-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $drop -Force | Out-Null
        try {
            # The cmdlet requires the package to be present in the drop folder.
            Set-Content -LiteralPath (Join-Path $drop 'App.msix') -Value 'stub' -Encoding ascii
            $out = Join-Path $drop 'sandbox.wsb'
            New-MsixSandboxConfig -DropFolder $drop -PackageName 'App.msix' -OutputPath $out | Out-Null
            Test-Path -LiteralPath $out | Should -BeTrue
            # Windows Sandbox parses this as XML; a BOM must not be emitted (#146).
            $first3 = ([IO.File]::ReadAllBytes($out))[0..2] -join ' '
            $first3 | Should -Not -Be '239 187 191'
            # And it must be well-formed XML.
            { [xml](Get-Content -LiteralPath $out -Raw) } | Should -Not -Throw
        } finally { Remove-Item -LiteralPath $drop -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'New-MsixPsfJson builds a config from a manifest file and a fixup' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("psfjson-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $mp = Join-Path $dir 'AppxManifest.xml'
            [IO.File]::WriteAllText($mp, @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="A" Publisher="CN=B" Version="1.0.0.0" />
  <Applications><Application Id="App" Executable="app.exe" /></Applications>
</Package>
'@, [Text.UTF8Encoding]::new($true))
            # -Fixup takes a fixup NAME from a ValidateSet, not a config hashtable;
            # FileRedirectionFixup additionally needs -Base and -Patterns.
            $json = New-MsixPsfJson -AppxManifest $mp -Fixup 'FileRedirectionFixup' `
                        -Base 'logs' -Patterns '.*\.log'
            $json | Should -Not -BeNullOrEmpty
            { $json | ConvertFrom-Json } | Should -Not -Throw
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'Accelerator round-trip' -Tag 'LocalSurface' {

    It 'Import-MsixAccelerator parses a YAML accelerator into fixup objects' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("accel-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $yaml = Join-Path $dir 'accel.yaml'
            [IO.File]::WriteAllText($yaml, @'
name: probe
description: local surface coverage
fixups:
  - type: FileRedirection
    base: logs
    patterns:
      - .*\.log
'@, [Text.UTF8Encoding]::new($false))
            { Import-MsixAccelerator -Path $yaml | Out-Null } | Should -Not -Throw
        } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'Import-MsixAccelerator rejects a file that does not exist' {
        $missing = Join-Path ([IO.Path]::GetTempPath()) ("no-accel-" + [guid]::NewGuid().ToString('N') + '.yaml')
        { Import-MsixAccelerator -Path $missing -ErrorAction Stop | Out-Null } | Should -Throw
    }
}

Describe 'Self-signing a package end to end' -Tag 'LocalSurface', 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:Dir = Join-Path ([IO.Path]::GetTempPath()) ("selfsign-" + [guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'Invoke-MsixSelfSign signs a package with a generated certificate (no admin)' {
        # Uses CurrentUser cert store only - the module must never require
        # elevation, which is the same reason it parses hives via offreg.dll
        # instead of reg.exe load.
        $fx = New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'selfsign.msix')
        { Invoke-MsixSelfSign -PackagePath $fx.PackagePath -ErrorAction Stop | Out-Null } | Should -Not -Throw
        (Test-MsixSignature -PackagePath $fx.PackagePath).Status | Should -Not -Be 'NotSigned'
    }
}
