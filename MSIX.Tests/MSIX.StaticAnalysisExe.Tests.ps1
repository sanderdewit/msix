BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Get-MsixStaticAnalysis robustness vs Application Executable shapes' -Tag 'Static' {

    # Regression: a package whose Application Executable attribute is a
    # bare leaf filename ("notepad++.exe", no path separator) blew up the
    # whole investigation pipeline with:
    #   Exception calling "Substring" with "2" argument(s): "length ('-1')
    #   must be a non-negative value."
    # The fix guards $exe.LastIndexOf('\') == -1 in BOTH places the
    # writable-hint heuristic uses it.
    #
    # We don't have a real MSIX with that exact shape to point at in
    # the test suite, so we exercise the source path with two static
    # checks: (a) the guard variable $hasDir exists and (b) both
    # references to LastIndexOf('\') sit behind it.

    It "Source guards LastIndexOf('\') with a presence check before Substring" {
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Investigation.ps1')) -Raw

        # Both usages must follow the $hasDir / $exe.Contains('\') guard.
        $src | Should -Match '\$hasDir = \$exe\.Contains'

        # The if-form Substring used to compute $appDir must read from
        # $hasDir (the central guard), not call .Contains('\') a second
        # time — that's how the bug crept in (only one call site
        # guarded).
        $src | Should -Match 'if \(\$hasDir\) \{ Join-Path (-Path )?\$workspace'

        # The $base assignment must also be conditional on $hasDir.
        $src | Should -Match '\$base = if \(\$hasDir\)'
    }

    It 'Recommendation falls back to no -Base when the executable is at the package root' {
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Investigation.ps1')) -Raw
        # The else branch must emit a -Base-less form.
        $src | Should -Match "Apply FileRedirectionFixup -Patterns"
    }
}


Describe 'Get-MsixStaticAnalysis idempotent ManifestFix detection' -Tag 'Static' {

    It 'Source guards the FileSystemWriteVirtualization finding with -not $hasFsVirt' {
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Investigation.ps1')) -Raw
        # The writable-file emission must be wrapped in an if (-not $hasFsVirt) block
        # so packages that already declare the desktop6 element don't get the noise.
        $src | Should -Match 'if \(-not \$hasFsVirt\)'
        $src | Should -Match "local-name\(\)='FileSystemWriteVirtualization'"
    }

    It 'Source guards the manifest-alternative entries the same way' {
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Investigation.ps1')) -Raw
        # Both alternatives must be suppressed when the corresponding fix
        # is already in <Properties>. Single-quoted regex so PowerShell
        # doesn't expand the literal $hasFsVirt / $hasRegVirt tokens.
        ($src -match '(?s)if \(-not \$hasFsVirt\).*?Set-MsixFileSystemWriteVirtualization') | Should -BeTrue
        ($src -match '(?s)if \(-not \$hasRegVirt\).*?Set-MsixRegistryWriteVirtualization') | Should -BeTrue
    }
}

Describe 'Static analysis coverage for new manifest/autofix features' -Tag 'Static' {

    It 'exports the new service and shell-handler scanners' {
        (Get-Command Get-MsixServiceEntry -Module MSIX -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        (Get-Command Get-MsixShellHandlerEntry -Module MSIX -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
        (Get-Alias Get-MsixServiceEntries -ErrorAction SilentlyContinue).Definition | Should -Be 'Get-MsixServiceEntry'
        (Get-Alias Get-MsixShellHandlerEntries -ErrorAction SilentlyContinue).Definition | Should -Be 'Get-MsixShellHandlerEntry'
    }

    It 'rolls new scanner categories into heuristic findings' {
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Scanners.ps1')) -Raw
        $src | Should -Match "Category\s+=\s+'ManifestFix:PackagedService'"
        $src | Should -Match "Category\s+=\s+'ManifestFix:ShellHandlerExtension'"
        $src | Should -Match 'Get-MsixServiceEntry -PackagePath \$PackagePath -WorkspacePath \$shared'
        $src | Should -Match 'Get-MsixShellHandlerEntry -PackagePath \$PackagePath -WorkspacePath \$shared'
    }

    It 'emits explicit isolation blocker categories for v0.71.3 tooling' {
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.Investigation.ps1')) -Raw
        $src | Should -Match "Category\s+=\s+'IsolationBlockedByPsf'"
        $src | Should -Match "Category\s+=\s+'IsolationBlockedByComServer'"
        $src | Should -Match 'Remove-MsixPsf before Add-MsixAppIsolation'
    }
}
