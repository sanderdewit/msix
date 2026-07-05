BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Help contract (issue #98)
# -----------------------------------------------------------------------------
# PowerShell rejects an ENTIRE comment-based help block when it contains an
# invalid construct — e.g. a combined '.PARAMETER A / B' tag, or a description
# line that STARTS with '.msix ...' (parsed as an unknown '.msix' directive).
# The function then surfaces only auto-generated syntax: no synopsis, no
# examples. Before the #98 sweep, 62 of 166 exported functions were affected.
#
# Test 1 makes that class of regression fail CI: every exported function must
# have a real (non-auto-generated) synopsis.
#
# Test 2/3: every exported function should carry at least one .EXAMPLE.
# $KnownNoExample is the baseline debt — a ratchet like the coverage map:
# add an example -> remove the entry; the list may only shrink.
# =============================================================================

Describe 'Help contract: comment-based help parses for every exported function' -Tag 'Meta' {

    BeforeAll {
        # Burned down to EMPTY in issue #111. Any name added here is new debt
        # and needs a justification in the PR.
        $script:KnownNoExample = @()

        $script:Functions = @(Get-Command -Module MSIX -CommandType Function)
        $script:HelpMap = @{}
        foreach ($fn in $script:Functions) {
            $script:HelpMap[$fn.Name] = Get-Help -Name $fn.Name -ErrorAction SilentlyContinue
        }

        function script:Test-MsixHelpParsed {
            param([string]$Name)
            $h = $script:HelpMap[$Name]
            if (-not $h -or -not $h.Synopsis) { return $false }
            $syn = $h.Synopsis.Trim()
            if (-not $syn) { return $false }
            # Auto-generated fallback synopsis is the syntax line: "Name [-Param] ..."
            if ($syn -match ('^' + [regex]::Escape($Name) + '\b\s*\[')) { return $false }
            return $true
        }

        function script:Test-MsixHelpHasExample {
            param([string]$Name)
            $h = $script:HelpMap[$Name]
            if (-not $h) { return $false }
            if (-not $h.PSObject.Properties['examples']) { return $false }
            if (-not $h.examples -or -not $h.examples.PSObject.Properties['example']) { return $false }
            return (@($h.examples.example).Count -gt 0)
        }
    }

    It 'every exported function has a parsed (non-auto-generated) synopsis' {
        $rejected = @($script:Functions | Where-Object { -not (Test-MsixHelpParsed -Name $_.Name) } |
            ForEach-Object { $_.Name })
        $rejected | Should -BeNullOrEmpty -Because "these functions' comment-help blocks are being REJECTED by the help parser (check for combined '.PARAMETER A / B' tags or description lines starting with '.word'): $($rejected -join ', ')"
    }

    It 'every exported function has at least one example (or is grandfathered)' {
        $missing = @($script:Functions | Where-Object {
            -not (Test-MsixHelpHasExample -Name $_.Name) -and ($_.Name -notin $script:KnownNoExample)
        } | ForEach-Object { $_.Name })
        $missing | Should -BeNullOrEmpty -Because "these functions have no .EXAMPLE (add one, or grandfather deliberately): $($missing -join ', ')"
    }

    It 'has no stale no-example allowlist entries (the debt list only shrinks)' {
        $stale = @($script:KnownNoExample | Where-Object {
            ($script:HelpMap.ContainsKey($_)) -and (Test-MsixHelpHasExample -Name $_)
        })
        $stale | Should -BeNullOrEmpty -Because "these now have examples - remove them from `$KnownNoExample: $($stale -join ', ')"
    }

    It 'has no allowlist entries that are no longer exported' {
        $names = $script:Functions | ForEach-Object { $_.Name }
        $orphans = @($script:KnownNoExample | Where-Object { $_ -notin $names })
        $orphans | Should -BeNullOrEmpty -Because "not exported anymore - delete from the allowlist: $($orphans -join ', ')"
    }
}
