# =============================================================================
# Modern File Redirection (MFR) Fixup
# -----------------------------------------------------------------------------
# MFRFixup is the next-generation file redirection DLL shipped in Tim Mangan's
# PSF fork. It is broadly compatible with FileRedirectionFixup but supports
# four different override modes per redirected path, plus an ILV-aware mode
# that respects the package's installedLocationVirtualization extension.
#
# Override modes (mirroring TMEditX):
#   - Traditional   classic VFS folder name (Local AppData, AppData,
#                   ProgramFilesX64, Windows, Fonts, …) — default for VFS paths
#   - Local         user-shell folder (ThisPCDesktopFolder, Personal,
#                   Common Desktop, Common Documents)
#   - COW           copy-on-write behaviour for PE files: default | enablePe |
#                   disableAll
#   - IlvAware      true|false — defer to package's
#                   uap10:installedLocationVirtualization extension
# =============================================================================

# Documented values that mirror the TMEditX UI
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

function Get-MsixMfrKnownFolders {
    <#
    .SYNOPSIS
        Returns the documented MFR override folders by mode.
    #>
    [CmdletBinding()]
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

    .PARAMETER KnownFolder
        One of the values from Get-MsixMfrKnownFolders -Mode Traditional.

    .PARAMETER RelativePath
        Path relative to that known folder (forward slashes, no leading slash).

    .PARAMETER Patterns
        Filename regex patterns to match (e.g. '.*\.log').

    .PARAMETER Cow
        Copy-on-write behaviour for PE files: default | enablePe | disableAll.

    .PARAMETER IlvAware
        If true, this rule respects uap10:installedLocationVirtualization.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -in $script:MfrTraditionalKnownFolders) { $true }
            else { throw "Unknown traditional folder '$_'. Use Get-MsixMfrKnownFolders -Mode Traditional." }
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

    .PARAMETER KnownFolder
        One of: ThisPCDesktopFolder, Personal, Common Desktop, Common Documents.

    .PARAMETER RelativePath / Patterns / Cow / IlvAware
        See New-MsixMfrTraditionalRule.
    #>
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -in $script:MfrLocalKnownFolders) { $true }
            else { throw "Unknown local folder '$_'. Use Get-MsixMfrKnownFolders -Mode Local." }
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

    .EXAMPLE
        $rule = New-MsixMfrTraditionalRule -KnownFolder 'ProgramFilesX64' `
            -RelativePath 'Contoso/logs' -Patterns '.*\.log' -Cow enablePe

        $mfr = New-MsixPsfMfrConfig -TraditionalRules @($rule) -GlobalIlvAware $true

        Add-MsixPsfV2 -PackagePath app.msix -Fixups @($mfr) -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [OutputType([hashtable])]
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
