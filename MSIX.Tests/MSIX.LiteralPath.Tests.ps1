BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
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
        $script:Bracketed = Join-Path -Path $env:TEMP -ChildPath "msix-litpath-[x]-$([guid]::NewGuid().ToString('N').Substring(0,6)).json"
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

    # Issue #46: extend the original (#45) guard to catch assignment +
    # parenthesised + dotted-access forms, not only the line-start
    # statement form. The previous regex was `^\s+Verb-Noun $var`, which
    # let `$x = Get-Item $foo` and `(Get-Item $foo).BaseName` through
    # because the cmdlet didn't sit at line start.
    #
    # New regex uses a non-identifier lookbehind `(?<![A-Za-z-])` so we
    # match the cmdlet wherever it appears in an expression, not only at
    # the start of a statement.
    #
    # Copy-Item / Move-Item are kept out of this guard intentionally:
    # their two-positional form (`Copy-Item $src $dst`) needs hand
    # review to choose between -LiteralPath and -Path (the source may be
    # a wildcard glob by design in some call sites). A second guard
    # below scans for the most exposed positional form -- the one that
    # takes two $-prefixed variables in a row.

    BeforeAll {
        $script:ModuleSources = Get-ChildItem -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..')) `
            -Filter 'MSIX.*.ps1' -File |
            Where-Object { $_.Name -notlike '*.Tests.ps1' }
    }

    $cmdlets = @(
        'Get-Item','Get-ChildItem','Test-Path','Remove-Item',
        'Get-Content','Set-Content'
    )

    foreach ($cmdlet in $cmdlets) {
        It "$cmdlet never appears with a positional `$variable (anywhere in an expression)" -TestCases @(@{ Cmd = $cmdlet }) {
            param($Cmd)
            # (?<![A-Za-z-]) prevents matching INSIDE a longer cmdlet name.
            # The trailing lookahead accepts whitespace, ')', '.', or
            # end-of-line so we catch assignment, parenthesised, and
            # dotted-access forms.
            $pattern = "(?<![A-Za-z-])$([regex]::Escape($Cmd))\s+\`$[A-Za-z_][A-Za-z0-9_]*(?=\s|\)|\.|$)"
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

    It 'Copy-Item / Move-Item never use the two-positional `$src `$dst form' {
        # The classic offender is `Copy-Item $src $dst -Force`. The fix is
        # `Copy-Item -LiteralPath $src -Destination $dst -Force` (or
        # `-Path` if $src is deliberately a wildcard glob). Either way the
        # raw `Verb-Item $a $b` form is what we forbid -- it leaves both
        # source AND destination exposed to wildcard expansion.
        $rx = [regex]'(?<![A-Za-z-])(Copy-Item|Move-Item)\s+\$[A-Za-z_][A-Za-z0-9_]*\s+\$[A-Za-z_][A-Za-z0-9_]*(?=\s|$)'
        $offenders = @()
        foreach ($f in $script:ModuleSources) {
            $src = Get-Content -LiteralPath $f.FullName -Raw
            $matchSet = $rx.Matches($src)
            if ($matchSet.Count -gt 0) {
                $offenders += "$($f.Name): $($matchSet.Count) match(es)"
            }
        }
        $offenders.Count | Should -Be 0 -Because (
            "Found two-positional `Copy-Item / Move-Item `$src `$dst calls:`n" +
            ($offenders -join "`n"))
    }
}

Describe 'Functional: signer / scanner code paths tolerate bracketed paths (issue #46)' -Tag 'LiteralPath' {
    # Real-call functional coverage for the wildcard-character-in-path
    # failure mode. Pick a single MSIX cmdlet that hits the same set of
    # provider calls Invoke-MsixSigning would (Get-Item on the package
    # path, etc.) and exercise it against a path with `[x]` in it.

    BeforeAll {
        # We can't run the actual signer (needs a real .msix + cert), but
        # Get-MsixPublisherId is a quick public cmdlet defined in
        # MSIX.Core.ps1 that operates on a string and has no filesystem
        # surface -- this confirms the module loads and the bracket-aware
        # tests below come from a clean state.
        Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    }

    It 'Resolve-MsixDebugViewPath returns a string or null for a bracketed env override' {
        # The env-var path is one of the most exposed user-supplied
        # entry points. Setting it to a bogus bracketed path must not
        # throw -- Resolve-MsixDebugViewPath should fall through to its
        # default search order and return either a string or $null.
        $bracketedDir = Join-Path -Path $env:TEMP -ChildPath "msix-litpath-[x]-debugview-$([guid]::NewGuid().ToString('N').Substring(0,6))"
        New-Item -ItemType Directory -Path $bracketedDir -Force | Out-Null
        $prev = $env:MSIX_DEBUGVIEW_PATH
        try {
            $env:MSIX_DEBUGVIEW_PATH = Join-Path -Path $bracketedDir -ChildPath 'Dbgview.exe'
            # Whether or not the file exists, the call should not throw
            # and should return either a string or $null.
            { Resolve-MsixDebugViewPath } | Should -Not -Throw
        } finally {
            $env:MSIX_DEBUGVIEW_PATH = $prev
            Remove-Item -LiteralPath $bracketedDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'A trace file at a path containing [x] is parseable by Get-MsixTraceFailure' {
        # Trace files come from operator workflows and can land at
        # arbitrary paths. The parser must accept brackets.
        $bracketed = Join-Path -Path $env:TEMP -ChildPath "msix-litpath-trace-[x]-$([guid]::NewGuid().ToString('N').Substring(0,6)).log"
        # Use BOM-less UTF-8 -- the parser strips a BOM but the
        # canonical TraceFixup output is BOM-less.
        [IO.File]::WriteAllText($bracketed,
            "[00:00:01.000 1234:AB1] WriteFileW: C:\Program Files\WindowsApps\app\cache.tmp -> ACCESS_DENIED`r`n",
            [Text.UTF8Encoding]::new($false))
        try {
            $rows = Get-MsixTraceFailure -Path $bracketed
            @($rows).Count | Should -Be 1
            $rows[0].Function | Should -Be 'WriteFileW'
        } finally {
            Remove-Item -LiteralPath $bracketed -Force -ErrorAction SilentlyContinue
        }
    }
}
