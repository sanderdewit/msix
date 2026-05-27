BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe '-LiteralPath consistency for user-supplied paths (issue #45)' -Tag 'LiteralPath' {

    # Functional regression: a temp file path that contains wildcard
    # characters like '[x]' must still be readable by helpers that the
    # public cmdlets eventually call. The classic failure mode is
    # `Get-Item $path` or `Get-Content $path` (positional) where the
    # provider's wildcard engine interprets the brackets and finds
    # nothing -- silently returning $null instead of the file content.

    BeforeAll {
        $script:Bracketed = Join-Path $env:TEMP "msix-litpath-[x]-$([guid]::NewGuid().ToString('N').Substring(0,6)).json"
        Set-Content -LiteralPath $script:Bracketed -Value '{"hello":"world"}' -Encoding utf8
    }
    AfterAll {
        if (Test-Path -LiteralPath $script:Bracketed) {
            Remove-Item -LiteralPath $script:Bracketed -Force -ErrorAction SilentlyContinue
        }
    }

    It 'A staged path containing wildcard chars exists and is readable via -LiteralPath' {
        # Sanity check the staging itself -- if this fails the rest of the
        # functional checks below are uninformative.
        Test-Path -LiteralPath $script:Bracketed | Should -BeTrue
        (Get-Content -LiteralPath $script:Bracketed -Raw).Trim() | Should -Be '{"hello":"world"}'
    }

    It 'Positional Get-Item against the bracketed path returns nothing (demonstrates the bug class)' {
        # This is the failure mode -LiteralPath protects against.
        $r = Get-Item $script:Bracketed -ErrorAction SilentlyContinue
        $r | Should -BeNullOrEmpty
    }

    It '-LiteralPath against the bracketed path resolves correctly' {
        $r = Get-Item -LiteralPath $script:Bracketed -ErrorAction Stop
        # Compare leaf names instead of full paths: $env:TEMP can return the
        # 8.3 short-name form (e.g. SANDER~1) while Get-Item returns the
        # expanded long-name form. Both refer to the same file.
        $r | Should -Not -BeNullOrEmpty
        # Use .NET GetFileName to avoid Split-Path's parameter-set quirks
        # when -LiteralPath + -Leaf are combined across PS versions.
        [IO.Path]::GetFileName($r.FullName) |
            Should -Be ([IO.Path]::GetFileName($script:Bracketed))
    }
}

Describe 'Source-level guard: user-facing provider calls use -LiteralPath' -Tag 'LiteralPath' {

    # Pin the convention with a source-level scan. Any positional
    # `Get-Item $foo` (where $foo is a parameter or workspace variable
    # rather than a literal) is a candidate for the wildcard-expansion
    # bug.  We don't claim 100% coverage -- the scan focuses on the
    # forms most exposed to user input: the provider cmdlets that
    # accept a path positional argument and a $-prefixed identifier
    # immediately after.

    BeforeAll {
        # Module source files (exclude tests).
        $script:ModuleSources = Get-ChildItem -LiteralPath (Resolve-Path (Join-Path $PSScriptRoot '..')) `
            -Filter 'MSIX.*.ps1' -File |
            Where-Object { $_.Name -notlike '*.Tests.ps1' }
    }

    # The regex below matches:  <whitespace>Verb-Noun $varName<space-or-end>
    # We accept it only when it is NOT preceded on the same line by
    # `-LiteralPath` (which would mean the call is already safe) and not
    # part of a string literal (anchoring at line start prevents the
    # latter).
    $cmdlets = @(
        'Get-Item','Get-ChildItem','Test-Path','Remove-Item',
        'Get-Content','Set-Content'
    )

    foreach ($cmdlet in $cmdlets) {
        It "$cmdlet never appears with a positional `$variable in module source" -TestCases @(@{ Cmd = $cmdlet }) {
            param($Cmd)
            $pattern = "(?m)^\s+$([regex]::Escape($Cmd))\s+\`$[A-Za-z_][A-Za-z0-9_]*(\s|$)"
            $rx = [regex]$pattern
            $offenders = @()
            foreach ($f in $script:ModuleSources) {
                $src = Get-Content -LiteralPath $f.FullName -Raw
                $matchSet = $rx.Matches($src)
                if ($matchSet.Count -gt 0) {
                    $offenders += "$($f.Name): $($matchSet.Count) match(es)"
                }
            }
            $offenders.Count | Should -Be 0 -Because (
                "Found positional $Cmd `$var calls without -LiteralPath:`n" +
                ($offenders -join "`n"))
        }
    }
}
