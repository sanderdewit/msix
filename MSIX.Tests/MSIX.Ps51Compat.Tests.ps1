BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
}

# =============================================================================
# Windows PowerShell 5.1 compatibility guard (issue #142)
# -----------------------------------------------------------------------------
# The module targets PowerShellVersion 5.1, but the Pester lane runs under
# pwsh 7 where PS7-only constructs work — so a 5.1-only break can pass every
# test. This is a fast STATIC guard for the specific regression from #142: the
# `ErrorMessage` named argument on validation attributes ([ValidatePattern],
# [ValidateSet], [ValidateScript], …) was added in PS 6.0 and throws
# "Property 'ErrorMessage' cannot be found" at parameter binding under 5.1.
# The compat-ps51 CI job is the broad runtime guard; this pins the exact class
# with a clear message at the pwsh unit-test altitude.
# =============================================================================

Describe 'PowerShell 5.1 source compatibility' -Tag 'Compat' {

    It 'no module .ps1 uses the PS7-only ErrorMessage validation-attribute argument' {
        $offenders = Get-ChildItem -Path $script:ModuleRoot -Filter 'MSIX.*.ps1' |
            Where-Object { $_.Name -notmatch '\.Tests\.ps1$' } |
            ForEach-Object {
                $file = $_
                Select-String -LiteralPath $file.FullName -Pattern 'ErrorMessage\s*=' |
                    ForEach-Object { "{0}:{1}: {2}" -f $file.Name, $_.LineNumber, $_.Line.Trim() }
            }
        # A non-empty list means someone re-introduced ErrorMessage = on an
        # attribute. Drop the argument (the Validate* regex/set still enforces
        # the rule) to keep the declared 5.1 floor honest.
        $offenders | Should -BeNullOrEmpty
    }
}
