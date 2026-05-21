BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Add-MsixPsfV2 alias-sync regression guard' -Tag 'PSF' {

    # When PSF replaces an Application's Executable with PsfLauncher.exe,
    # an earlier implementation also tried to "sync" any existing
    # uap3:Extension Category="windows.appExecutionAlias" by setting its
    # Executable attribute. That violated the AppX schema:
    #
    #   App manifest validation error: The attribute EntryPoint must be
    #   specified if the attribute Executable on the Extension element is
    #   specified.
    #
    # The sync block has been removed entirely — an AppExecutionAlias
    # without Executable/EntryPoint inherits its launch target from the
    # parent Application, which is the correct semantics for the one-alias-
    # per-app case Add-MsixAlias produces.

    It 'PSF.ps1 source does not contain the alias-sync SetAttribute call' {
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.PSF.ps1')) -Raw
        # The smoking-gun expression that produced the schema violation.
        $src | Should -Not -Match '\$aliasExt\.SetAttribute\(\s*''Executable'''
    }

    It 'PSF.ps1 does not set Executable on a windows.appExecutionAlias Extension element' {
        # Stronger structural check: search for any SetAttribute('Executable', ...)
        # call inside a block that filters Extensions by the appExecutionAlias category.
        $src = Get-Content (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.PSF.ps1')) -Raw
        # If the source mentions 'windows.appExecutionAlias' AND a SetAttribute
        # on Executable in close proximity, fail — that pattern was the bug.
        $hasCategoryRef = $src -match "windows\.appExecutionAlias"
        if ($hasCategoryRef) {
            # The only place we should reference the category now is in a
            # COMMENT explaining we intentionally do not touch it. Verify
            # there is no surviving SetAttribute('Executable', ...) within
            # 800 chars of the category reference.
            $idx = $src.IndexOf('windows.appExecutionAlias')
            $window = $src.Substring([Math]::Max(0, $idx - 100), [Math]::Min(900, $src.Length - $idx + 100))
            $window | Should -Not -Match "SetAttribute\(\s*'Executable'"
        }
    }
}
