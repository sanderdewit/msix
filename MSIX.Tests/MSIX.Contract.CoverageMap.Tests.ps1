BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Coverage-map guardrail (issue #88)
# -----------------------------------------------------------------------------
# The Add-MsixAppIsolation `.ContainsKey()` bug shipped because the cmdlet was
# never *invoked* by any test — only Get-MsixIsolationCapability was. This
# meta-test makes that class of gap impossible to introduce silently: every
# exported Add/Remove/Set/Update mutator must be invoked (name followed by a
# parameter) in at least one test file.
#
# $KnownUncovered is the BASELINE DEBT as of issue #88 — mutators that today
# are only existence/parameter-checked. It is a ratchet, not a parking lot:
#   * Adding a NEW exported mutator without a test -> Test 1 fails.
#   * Adding real coverage for an allowlisted mutator -> Test 2 fails until you
#     REMOVE it from $KnownUncovered. The list may only shrink.
# Burn it down to empty over successive PRs.
# =============================================================================

Describe 'Coverage map: every mutator is exercised by a test' -Tag 'Meta' {

    BeforeAll {
        # Debt list — burned down to EMPTY in issue #102. Any name added here
        # is new debt and needs a justification in the PR.
        $script:KnownUncovered = @()

        # PERMANENT exclusions with justification (not debt): these cmdlets'
        # entire job is downloading/refreshing external toolchain binaries from
        # the internet (GitHub/Sysinternals/NuGet). A unit/integration test that
        # invokes them would hit the network on every CI run and pin external
        # availability to the build — deliberately out of scope. Manual coverage:
        # TEST-PLAN.md Scenario 12 (toolchain provisioning).
        $script:PermanentlyExcluded = @(
            'Update-MsixAppRuntime'
            'Update-MsixDebugView'
            'Update-MsixProcMon'
            'Update-MsixPsfBinary'
            # Added in #152: the AST-based detector below showed these two were
            # only ever "covered" by a Get-Command existence check. They are the
            # same network-updater class as the four above - their whole job is
            # downloading toolchain binaries - so they belong here rather than in
            # the debt list. Manual coverage: TEST-PLAN.md Scenario 12.
            'Update-MsixMgr'
            'Update-MsixSdkTool'
        )

        $psd1     = Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')
        $exported = (Import-PowerShellDataFile -Path $psd1).FunctionsToExport
        $script:Mutators = @($exported | Where-Object { $_ -match '^(Add|Remove|Set|Update)-Msix' })

        # AST-based invocation detection (issue #152).
        #
        # This ratchet used to define "invoked" as the regex
        #     [regex]::Escape($Name) + '\s+[-$@]'
        # over the concatenated test sources. That matched things which are not
        # invocations at all: `Get-Command Add-MsixFoo -Module MSIX`, and even
        # `Context`/`It` TITLE strings. Eight mutators were certified as covered
        # on exactly that basis while never being called, so the debt list read
        # empty while 12 mutators were genuinely uninvoked - the ratchet was
        # holding a number that was not real.
        #
        # Parsing each test file and collecting real CommandAst command names
        # cannot be fooled by a string, a comment, or an argument to Get-Command.
        $self  = $MyInvocation.MyCommand.Path
        $files = Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.Tests.ps1' |
            Where-Object { $_.FullName -ne $self }

        $invoked = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($file in $files) {
            $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                       $file.FullName, [ref]$null, [ref]$errors)
            if (-not $ast) { continue }
            foreach ($call in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $cmdName = $call.GetCommandName()
                if (-not $cmdName) { continue }
                # An MSIX cmdlet passed as an ARGUMENT (Get-Command Add-MsixFoo,
                # Should -Invoke Add-MsixFoo, Mock Add-MsixFoo) is not a call to
                # it. Only the command position counts.
                [void]$invoked.Add($cmdName)
            }
        }
        $script:InvokedCommands = $invoked

        function script:Test-MsixInvoked {
            param([string]$Name)
            return $script:InvokedCommands.Contains($Name)
        }
    }

    It 'introduces no NEW uncovered mutator (every mutator is invoked, or grandfathered)' {
        $uncovered = @($script:Mutators | Where-Object {
            -not (Test-MsixInvoked -Name $_) -and
            ($_ -notin $script:KnownUncovered) -and
            ($_ -notin $script:PermanentlyExcluded)
        })
        $uncovered | Should -BeNullOrEmpty -Because "these exported mutators are never invoked by a test (add a behavioural test, or — only if genuinely untestable — grandfather them in `$KnownUncovered): $($uncovered -join ', ')"
    }

    It 'permanent exclusions are still exported and still network-updater shaped' {
        foreach ($name in $script:PermanentlyExcluded) {
            $name | Should -BeIn $script:Mutators -Because 'a permanently-excluded name that is no longer exported should be deleted from the list'
            $name | Should -Match '^Update-Msix' -Because 'the permanent-exclusion rationale only covers toolchain updaters; anything else must be tested instead'
        }
    }

    It 'has no stale allowlist entries (the debt list only shrinks)' {
        $stale = @($script:KnownUncovered | Where-Object {
            ($_ -in $script:Mutators) -and (Test-MsixInvoked -Name $_)
        })
        $stale | Should -BeNullOrEmpty -Because "these are now covered by a test — remove them from `$KnownUncovered so the ratchet holds: $($stale -join ', ')"
    }

    It 'has no allowlist entries that are no longer exported' {
        $orphans = @($script:KnownUncovered | Where-Object { $_ -notin $script:Mutators })
        $orphans | Should -BeNullOrEmpty -Because "these allowlist names are not exported mutators anymore — delete them: $($orphans -join ', ')"
    }
}
