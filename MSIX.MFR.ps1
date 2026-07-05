# =============================================================================
# Modern File Redirection (MFR) Fixup
# -----------------------------------------------------------------------------
# MFRFixup is the next-generation file redirection DLL shipped in Tim Mangan's
# PSF fork. It is broadly compatible with FileRedirectionFixup but supports
# four different override modes per redirected path, plus an ILV-aware mode
# that respects the package's installedLocationVirtualization extension.
#
# Override modes (matching common packaging-tool behaviour):
#   - Traditional   classic VFS folder name (Local AppData, AppData,
#                   ProgramFilesX64, Windows, Fonts, …) — default for VFS paths
#   - Local         user-shell folder (ThisPCDesktopFolder, Personal,
#                   Common Desktop, Common Documents)
#   - COW           copy-on-write behaviour for PE files: default | enablePe |
#                   disableAll
#   - IlvAware      true|false — defer to package's
#                   uap10:installedLocationVirtualization extension
# =============================================================================

# Documented values that mirror the documented MFR option set
$script:MfrTraditionalKnownFolders = @(
    'Local AppData','AppData','LocalAppDataLow','Common AppData',
    'FOLDERID_System\Catroot2','FOLDERID_System\Catroot',
    'FOLDERID_System\drivers\etc','FOLDERID_System\driverstore',
    'FOLDERID_System\logfiles','FOLDERID_System\spool',
    'SystemX86','UserProgramFiles','ProgramFilesCommonX86','ProgramFilesX86',
    'SystemX64','ProgramFilesCommonX64','ProgramFilesX64',
    'System','Fonts','Windows\Microsoft.NET','Windows',
    'Common AppData\Microsoft\Windows\AppRepository',
    'Local AppData\Microsoft\Windows','Common Programs','Profile',
    'AppVPackageDrive'
)
$script:MfrLocalKnownFolders = @(
    'ThisPCDesktopFolder','Personal','Common Desktop','Common Documents'
)
$script:MfrCowOptions  = @('default','enablePe','disableAll')

function Get-MsixMfrKnownFolder {
    <#
    .SYNOPSIS
        Returns the documented MFR override folders by mode.

    .DESCRIPTION
        MFRFixup classifies redirected paths into two folder families:
        'Traditional' VFS-style folders (Local AppData, ProgramFilesX64, …)
        and 'Local' user-shell folders (Personal, Common Desktop, …). This
        function returns those documented values so callers can validate
        their MFR rules against the documented option list rather
        than passing free-form strings.

        With -Mode Both (the default), an object with all three sets is
        returned (Traditional, Local, COW options).

    .PARAMETER Mode
        Which folder family to list. One of 'Traditional', 'Local', 'Both'
        (default).

    .OUTPUTS
        [string[]] when -Mode is Traditional or Local.
        [pscustomobject] with Traditional/Local/COW properties when -Mode
        is Both.

    .EXAMPLE
        Get-MsixMfrKnownFolder -Mode Traditional

    .EXAMPLE
        # Inspect all three sets in one go
        (Get-MsixMfrKnownFolder).COW
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [ValidateSet('Traditional','Local','Both')]
        [string]$Mode = 'Both'
    )
    switch ($Mode) {
        'Traditional' { $script:MfrTraditionalKnownFolders }
        'Local'       { $script:MfrLocalKnownFolders }
        default       {
            [pscustomobject]@{
                Traditional = $script:MfrTraditionalKnownFolders
                Local       = $script:MfrLocalKnownFolders
                COW         = $script:MfrCowOptions
            }
        }
    }
}

function New-MsixMfrTraditionalRule {
    <#
    .SYNOPSIS
        Build a single Traditional-mode MFR redirection rule.

    .DESCRIPTION
        Produces a hashtable in the shape MFRFixup expects under
        config.redirectedPaths.traditionalRedirectedPaths[]. The known folder
        is validated against the documented Traditional set. The result is
        intended to be fed to New-MsixPsfMfrConfig.

    .PARAMETER KnownFolder
        One of the values from Get-MsixMfrKnownFolder -Mode Traditional.

    .PARAMETER RelativePath
        Path relative to that known folder (forward slashes, no leading slash).

    .PARAMETER Patterns
        Filename regex patterns to match (e.g. '.*\.log').

    .PARAMETER Cow
        Copy-on-write behaviour for PE files: default | enablePe | disableAll.

    .PARAMETER IlvAware
        If true, this rule respects uap10:installedLocationVirtualization.

    .OUTPUTS
        [hashtable] (ordered) suitable for New-MsixPsfMfrConfig
        -TraditionalRules.

    .EXAMPLE
        New-MsixMfrTraditionalRule -KnownFolder 'ProgramFilesX64' `
            -RelativePath 'Contoso/logs' -Patterns '.*\.log' -Cow enablePe
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -in $script:MfrTraditionalKnownFolders) { $true }
            else { throw "Unknown traditional folder '$_'. Use Get-MsixMfrKnownFolder -Mode Traditional." }
        })]
        [string]$KnownFolder,
        [Parameter(Mandatory)]
        [string]$RelativePath,
        [Parameter(Mandatory)]
        [string[]]$Patterns,
        [ValidateSet('default','enablePe','disableAll')]
        [string]$Cow,
        [bool]$IlvAware
    )
    $r = [ordered]@{
        knownFolder    = $KnownFolder
        relativePath   = $RelativePath
        patterns       = [array]$Patterns
    }
    if ($Cow)               { $r['copyOnWrite']  = $Cow }
    if ($PSBoundParameters.ContainsKey('IlvAware')) { $r['ilvAware'] = $IlvAware }
    return $r
}


function New-MsixMfrLocalRule {
    <#
    .SYNOPSIS
        Build a single Local-mode MFR redirection rule (user-shell folders).

    .DESCRIPTION
        Produces a hashtable in the shape MFRFixup expects under
        config.redirectedPaths.localRedirectedPaths[]. Use this for redirected
        paths that live under user-shell folders (Desktop, Documents, …)
        instead of the classic VFS roots covered by
        New-MsixMfrTraditionalRule.

    .PARAMETER KnownFolder
        One of: ThisPCDesktopFolder, Personal, Common Desktop, Common Documents.

    .PARAMETER RelativePath
        Path relative to that known folder.

    .PARAMETER Patterns
        Filename regex patterns to match.

    .PARAMETER Cow
        Copy-on-write behaviour for PE files: default | enablePe | disableAll.

    .PARAMETER IlvAware
        If true, this rule respects uap10:installedLocationVirtualization.

    .OUTPUTS
        [hashtable] (ordered) suitable for New-MsixPsfMfrConfig -LocalRules.

    .EXAMPLE
        New-MsixMfrLocalRule -KnownFolder 'Personal' `
            -RelativePath 'Contoso' -Patterns '.*\.cfg'
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -in $script:MfrLocalKnownFolders) { $true }
            else { throw "Unknown local folder '$_'. Use Get-MsixMfrKnownFolder -Mode Local." }
        })]
        [string]$KnownFolder,
        [Parameter(Mandatory)]
        [string]$RelativePath,
        [Parameter(Mandatory)]
        [string[]]$Patterns,
        [ValidateSet('default','enablePe','disableAll')]
        [string]$Cow,
        [bool]$IlvAware
    )
    $r = [ordered]@{
        knownFolder  = $KnownFolder
        relativePath = $RelativePath
        patterns     = [array]$Patterns
    }
    if ($Cow)               { $r['copyOnWrite'] = $Cow }
    if ($PSBoundParameters.ContainsKey('IlvAware')) { $r['ilvAware'] = $IlvAware }
    return $r
}


function New-MsixPsfMfrConfig {
    <#
    .SYNOPSIS
        Builds an MFRFixup config hashtable for use with Add-MsixPsfV2.

    .DESCRIPTION
        MFRFixup ships in Tim Mangan's PSF fork (`MFRFixup64.dll` /
        `MFRFixup32.dll`) and is a drop-in replacement for FileRedirectionFixup
        with finer-grained controls. This helper produces the standard config
        block expected at config.json -> processes[].fixups[].

    .PARAMETER TraditionalRules
        Hashtables produced by New-MsixMfrTraditionalRule.

    .PARAMETER LocalRules
        Hashtables produced by New-MsixMfrLocalRule.

    .PARAMETER GlobalIlvAware
        Default value for the ilvAware flag at the top level (overridable per rule).

    .PARAMETER GlobalCow
        Default copyOnWrite mode at the top level.

    .OUTPUTS
        [hashtable] with keys 'dll' (always 'MFRFixup.dll') and 'config'
        (the ordered hashtable assembled from the supplied rules). Consumed
        by Add-MsixPsfV2 -Fixups.

    .EXAMPLE
        # Builder -> Add-MsixPsfV2 chain
        $rule = New-MsixMfrTraditionalRule -KnownFolder 'ProgramFilesX64' `
            -RelativePath 'Contoso/logs' -Patterns '.*\.log' -Cow enablePe

        $mfr = New-MsixPsfMfrConfig -TraditionalRules @($rule) -GlobalIlvAware $true

        Add-MsixPsfV2 -PackagePath .\app.msix -Fixups @($mfr) `
            -Pfx .\cert.pfx -PfxPassword (Read-Host -AsSecureString)
    #>
    [OutputType([hashtable])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [hashtable[]]$TraditionalRules,
        [hashtable[]]$LocalRules,
        [bool]$GlobalIlvAware,
        [ValidateSet('default','enablePe','disableAll')]
        [string]$GlobalCow
    )

    $config = [ordered]@{}
    if ($PSBoundParameters.ContainsKey('GlobalIlvAware')) { $config['ilvAware']    = $GlobalIlvAware }
    if ($GlobalCow)                                       { $config['copyOnWrite'] = $GlobalCow }

    $rules = @{}
    if ($TraditionalRules) { $rules['traditionalRedirectedPaths'] = @($TraditionalRules) }
    if ($LocalRules)       { $rules['localRedirectedPaths']       = @($LocalRules) }

    if ($rules.Count -gt 0) {
        $config['redirectedPaths'] = $rules
    }

    return @{
        dll    = 'MFRFixup.dll'
        config = $config
    }
}


# Backward-compatible plural aliases
Set-Alias Get-MsixMfrKnownFolders Get-MsixMfrKnownFolder
