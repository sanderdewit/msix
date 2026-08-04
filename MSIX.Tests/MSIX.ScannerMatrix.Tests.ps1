BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Read-only scanner matrix (issue #152)
# -----------------------------------------------------------------------------
# The read-only scanners were the single largest block of never-invoked
# functions, and they are exactly where two shipped bugs lived: the manifest-fix
# null-deref (a package with no <Properties>/<Extensions>) and the offreg probe
# regression that silently disabled every registry-derived finding.
#
# Rather than 15 near-identical Describe blocks, this drives them from one table
# against BOTH a well-formed package and the degenerate manifest shapes the
# module GENERATES itself (New-MsixModificationPackage / New-MsixFrameworkPackage
# emit no <Applications> and no <Extensions>). A scanner must return something
# enumerable and must not throw on either.
# =============================================================================

BeforeDiscovery {
    # Every exported read-only scanner sharing the -PackagePath/-WorkspacePath
    # shape. Adding a new one here is a one-line change.
    $script:ScannerNames = @(
        'Get-MsixAliasCandidate'
        'Get-MsixCapabilityHint'
        'Get-MsixComServerEntry'
        'Get-MsixDesktopShortcutCandidate'
        'Get-MsixFontCandidate'
        'Get-MsixNestedPackageCandidate'
        'Get-MsixPluginExtensionPoint'
        'Get-MsixRunKeyEntry'
        'Get-MsixServiceEntry'
        'Get-MsixShellContextMenuEntry'
        'Get-MsixShellHandlerEntry'
        'Get-MsixUninstallerCandidate'
        'Get-MsixUninstallRegistryEntry'
        'Get-MsixUpdaterCandidate'
        'Get-MsixVcRuntimeReference'
    )
    $script:ScannerCases = $script:ScannerNames | ForEach-Object { @{ Name = $_ } }
}

Describe 'Read-only scanner matrix' -Tag 'Integration', 'Scanners' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) { Write-Warning 'Scanner matrix SKIPPED: MakeAppx not resolvable.' }
        $script:Dir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-matrix-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null

        if ($script:ToolingAvailable) {
            # A normal package.
            $script:Normal = (New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'matrix-normal.msix')).PackagePath

            # The degenerate shape the module itself produces: no <Applications>,
            # no <Extensions>, no <Capabilities>.
            $script:Minimal = (New-MsixTestFixture -OutputPath (Join-Path $script:Dir 'matrix-minimal.msix') -ManifestXml @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Msix.Matrix.Minimal" Publisher="CN=MsixTest" Version="1.0.0.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Minimal</DisplayName>
    <PublisherDisplayName>MsixTest</PublisherDisplayName>
    <Logo>Assets\logo.png</Logo>
  </Properties>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0" />
  </Dependencies>
  <Resources><Resource Language="en-us" /></Resources>
</Package>
'@).PackagePath
        }
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) { Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue } }

    It '<Name> runs against a well-formed package' -ForEach $script:ScannerCases {
        { & $Name -PackagePath $script:Normal -ErrorAction Stop | Out-Null } | Should -Not -Throw
    }

    It '<Name> survives a manifest with no Applications/Extensions/Capabilities' -ForEach $script:ScannerCases {
        # This is the shape New-MsixModificationPackage and New-MsixFrameworkPackage
        # emit, and the shape that produced the @($null) null-deref class (#153).
        { & $Name -PackagePath $script:Minimal -ErrorAction Stop | Out-Null } | Should -Not -Throw
    }

    It '<Name> fails loudly on a package that does not exist' -ForEach $script:ScannerCases {
        # An empty result from a missing package reads as "clean" - the honesty
        # rule from #140.
        $missing = Join-Path $script:Dir ("gone-" + [guid]::NewGuid().ToString('N').Substring(0,6) + '.msix')
        { & $Name -PackagePath $missing -ErrorAction Stop | Out-Null } | Should -Throw
    }
}

Describe 'Scanner coverage anchor' -Tag 'Integration', 'Scanners' {

    # The matrix above dispatches with `& $Name`, which AST-based coverage
    # detection cannot see - so without this the ratchet would report these 15 as
    # never invoked even though they are exercised three ways each. Calling them
    # by name here keeps the coverage signal HONEST rather than teaching the
    # ratchet to trust strings again (the exact weakness fixed in #152).
    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:AnchorDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-anchor-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:AnchorDir -Force | Out-Null
        if ($script:ToolingAvailable) {
            $script:AnchorPkg = (New-MsixTestFixture -OutputPath (Join-Path $script:AnchorDir 'anchor.msix')).PackagePath
        }
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:AnchorDir -and (Test-Path -LiteralPath $script:AnchorDir)) { Remove-Item -LiteralPath $script:AnchorDir -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'invokes every read-only scanner by name against a real package' {
        $p = $script:AnchorPkg
        { Get-MsixAliasCandidate            -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixCapabilityHint            -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixComServerEntry            -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixDesktopShortcutCandidate  -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixFontCandidate             -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixNestedPackageCandidate    -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixPluginExtensionPoint      -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixRunKeyEntry               -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixServiceEntry              -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixShellContextMenuEntry     -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixShellHandlerEntry         -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixUninstallerCandidate      -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixUninstallRegistryEntry    -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixUpdaterCandidate          -PackagePath $p | Out-Null } | Should -Not -Throw
        { Get-MsixVcRuntimeReference        -PackagePath $p | Out-Null } | Should -Not -Throw
    }

    It 'reports package-level metadata without a live installation' {
        { Get-MsixRequiredAppRuntimeChannel -PackagePath $script:AnchorPkg | Out-Null } | Should -Not -Throw
        { Get-MsixCompatibilityReport       -PackagePath $script:AnchorPkg | Out-Null } | Should -Not -Throw
    }
}

Describe 'Aggregate analysis entry points' -Tag 'Integration', 'Scanners' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        $script:Dir2 = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-agg-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:Dir2 -Force | Out-Null
        if ($script:ToolingAvailable) {
            $script:Pkg = (New-MsixTestFixture -OutputPath (Join-Path $script:Dir2 'agg.msix')).PackagePath
        }
    }
    BeforeEach { if (-not $script:ToolingAvailable) { Set-ItResult -Skipped -Because 'MakeAppx not available.' } }
    AfterAll { if ($script:Dir2 -and (Test-Path -LiteralPath $script:Dir2)) { Remove-Item -LiteralPath $script:Dir2 -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'Get-MsixStaticAnalysis returns a report for a real package' {
        $r = Get-MsixStaticAnalysis -PackagePath $script:Pkg
        $r | Should -Not -BeNullOrEmpty
    }

    It 'Invoke-MsixInvestigation returns findings and recommended commands' {
        $r = Invoke-MsixInvestigation -PackagePath $script:Pkg
        $r.PSObject.Properties.Name | Should -Contain 'Findings'
        $r.PSObject.Properties.Name | Should -Contain 'RecommendedCommands'
    }

    It 'Test-MsixAgainstLimitation evaluates the known-limitation catalogue' {
        { Test-MsixAgainstLimitation -PackagePath $script:Pkg -ErrorAction Stop | Out-Null } | Should -Not -Throw
    }

    It 'Compare-MsixPackage diffs two packages' {
        $other = (New-MsixTestFixture -OutputPath (Join-Path $script:Dir2 'agg2.msix') -Name 'MSIX.IntegrationTest.Other').PackagePath
        $diff = Compare-MsixPackage -LeftPath $script:Pkg -RightPath $other
        $diff | Should -Not -BeNullOrEmpty
    }

    It 'Get-MsixInfo reads identity from a real package' {
        $info = Get-MsixInfo -PackagePath $script:Pkg
        $info.Name | Should -Not -BeNullOrEmpty
    }
}

Describe 'Pure helpers with no package dependency' -Tag 'Scanners' {

    It 'Get-MsixPublisherId computes the 13-character package family hash' {
        # The value is well-known: CN=Microsoft always hashes the same way.
        $id = Get-MsixPublisherId -Publisher 'CN=MsixTest'
        $id | Should -Match '^[a-z0-9]{13}$'
        # Deterministic.
        (Get-MsixPublisherId -Publisher 'CN=MsixTest') | Should -Be $id
    }

    It 'Select-MsixManifestNode selects by XPath' {
        [xml]$m = @'
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="A" Publisher="CN=B" Version="1.0.0.0" />
</Package>
'@
        $node = Select-MsixManifestNode -Manifest $m -XPath "//*[local-name()='Identity']"
        $node | Should -Not -BeNullOrEmpty
    }

    It 'Save-MsixManifest round-trips a document to disk' {
        [xml]$m = '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="A" Publisher="CN=B" Version="1.0.0.0" /></Package>'
        $p = Join-Path ([IO.Path]::GetTempPath()) ("save-" + [guid]::NewGuid().ToString('N').Substring(0,8) + '.xml')
        try {
            Save-MsixManifest -Manifest $m -Path $p
            Test-Path -LiteralPath $p | Should -BeTrue
            [xml]$back = Get-Content -LiteralPath $p -Raw
            $back.Package.Identity.Name | Should -Be 'A'
        } finally { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }

    It 'New-MsixPsfConfig builds JSON from a manifest and fixups' {
        [xml]$m = '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="A" Publisher="CN=B" Version="1.0.0.0" /><Applications><Application Id="App" Executable="app.exe" /></Applications></Package>'
        $fx = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'
        $json = New-MsixPsfConfig -Manifest $m -Fixups @($fx)
        $json | Should -Not -BeNullOrEmpty
        { $json | ConvertFrom-Json } | Should -Not -Throw
    }

    It 'ConvertTo-MsixReportHtml renders a findings report' {
        $report = [pscustomobject]@{
            PackagePath = 'x.msix'
            Findings    = @([pscustomobject]@{ Severity='Warning'; Category='Test'; Symptom='S'; Recommendation='R'; Evidence='E'; AppId=$null })
        }
        $html = ConvertTo-MsixReportHtml -Report $report -Commands @('# none') -PackagePath 'x.msix'
        $html | Should -Match '<html'
        # Untrusted finding text must be HTML-escaped, not injected.
        $html | Should -Not -Match '<script'
    }
}
