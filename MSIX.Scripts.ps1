# =============================================================================
# Standard scripts (PSADT-flavoured)
# -----------------------------------------------------------------------------
# Renders parameterised .ps1 scripts from the templates\ folder, optionally
# signs them, and (via Add-MsixStandardScript) wires them into a package as a
# PSF startScript.
#
# Templates use <#PARAM:Name#> placeholders; replacements happen in-memory and
# the output goes to the path you choose.
# =============================================================================

$script:TemplateDir = Join-Path $PSScriptRoot 'templates'

# Catalogue: name -> { Template, Description, RequiredParams }
$script:StandardScriptCatalogue = [ordered]@{
    CreateShortcut = @{
        Template       = 'CreateShortcut.ps1.tmpl'
        Description    = 'Create a desktop / start-menu shortcut to the packaged app on first launch.'
        RequiredParams = @('DisplayName','Target')
        Defaults       = @{
            Arguments        = ''
            WorkingDirectory = ''
            IconPath         = ''
            Location         = 'Desktop'
        }
    }
    CopyIconToAppData = @{
        Template       = 'CopyIconToAppData.ps1.tmpl'
        Description    = 'Copy bundled icon(s) into %APPDATA% so shortcuts survive package updates.'
        RequiredParams = @('SourceFiles','DestSubfolder')
        Defaults       = @{}
    }
    CleanupOldUserData = @{
        Template       = 'CleanupOldUserData.ps1.tmpl'
        Description    = 'Idempotent removal of legacy user-state directories and registry keys.'
        RequiredParams = @()
        Defaults       = @{
            Paths            = ''
            RegistryKeys     = ''
            OnlyOlderThanDays= '0'
        }
    }
    RegisterFileAssociation = @{
        Template       = 'RegisterFileAssociation.ps1.tmpl'
        Description    = 'Register a host-side file association under HKCU pointing at an alias.'
        RequiredParams = @('Extensions','ProgId','Target')
        Defaults       = @{ Arguments = '' }
    }
    CustomerSettingsBootstrap = @{
        Template       = 'CustomerSettingsBootstrap.ps1.tmpl'
        Description    = 'Bake in customer-specific HKCU settings as JSON; written on first launch.'
        RequiredParams = @('HivePath','Settings')
        Defaults       = @{ Overwrite = 'false' }
    }
}


function Get-MsixStandardScripts {
    <#
    .SYNOPSIS
        Lists the standard-script templates this module ships with.
    #>
    [CmdletBinding()]
    param()
    foreach ($k in $script:StandardScriptCatalogue.Keys) {
        $v = $script:StandardScriptCatalogue[$k]
        [pscustomobject]@{
            Name           = $k
            Description    = $v.Description
            RequiredParams = $v.RequiredParams
            OptionalParams = @($v.Defaults.Keys)
            Template       = Join-Path $script:TemplateDir $v.Template
        }
    }
}


function _MsixRenderTemplate {
    param(
        [string]$TemplatePath,
        [hashtable]$Parameters
    )
    if (-not (Test-Path $TemplatePath)) { throw "Template not found: $TemplatePath" }
    $text = Get-Content $TemplatePath -Raw

    # Find every <#PARAM:Name#> in the template, replace from $Parameters,
    # complain about anything left unsubstituted.
    $pattern = '<#PARAM:([A-Za-z0-9_]+)#>'
    $needed  = [regex]::Matches($text, $pattern) | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique

    foreach ($name in $needed) {
        if (-not $Parameters.ContainsKey($name)) {
            throw "Template '$TemplatePath' requires -$name but it was not provided."
        }
        $value = [string]$Parameters[$name]
        # Literal (non-regex) substitution — values may contain backslashes,
        # quotes, regex metacharacters etc.
        $text = $text.Replace("<#PARAM:$name#>", $value)
    }

    return $text
}


function New-MsixStandardScript {
    <#
    .SYNOPSIS
        Generates a customised PowerShell script from a bundled template.

    .DESCRIPTION
        Picks one of the standard templates, substitutes parameters, writes
        the result to disk. Optionally signs the resulting .ps1 with a
        provided code-signing certificate so the package can run it under
        AllSigned/RemoteSigned execution policies.

        See Get-MsixStandardScripts for the list of templates.

    .PARAMETER Name
        Template name (e.g. 'CreateShortcut').

    .PARAMETER Parameters
        Hashtable of placeholder values (e.g. @{ DisplayName='Foo'; Target='foo.exe' }).

    .PARAMETER OutputPath
        Where to write the generated .ps1.

    .PARAMETER Pfx / PfxPassword
        Sign the output with this PFX. Omit to leave unsigned.

    .PARAMETER TimestampUrl
        RFC 3161 timestamp server. Default: DigiCert.

    .EXAMPLE
        New-MsixStandardScript -Name CreateShortcut `
            -Parameters @{ DisplayName='Contoso Expenses'; Target='contosoexpenses.exe' } `
            -OutputPath C:\src\createshortcut.ps1 `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({ $_ -in $script:StandardScriptCatalogue.Keys })]
        [string]$Name,
        [Parameter(Mandatory)]
        [hashtable]$Parameters,
        [Parameter(Mandatory)]
        [string]$OutputPath,
        [string]$Pfx,
        [string]$PfxPassword,
        [string]$TimestampUrl = 'http://timestamp.digicert.com'
    )

    $entry = $script:StandardScriptCatalogue[$Name]
    foreach ($req in $entry.RequiredParams) {
        if (-not $Parameters.ContainsKey($req) -or [string]::IsNullOrEmpty($Parameters[$req])) {
            throw "Template '$Name' requires -$req."
        }
    }
    # Apply defaults
    $merged = @{}
    foreach ($k in $entry.Defaults.Keys) { $merged[$k] = $entry.Defaults[$k] }
    foreach ($k in $Parameters.Keys)     { $merged[$k] = $Parameters[$k] }

    $tmpl    = Join-Path $script:TemplateDir $entry.Template
    $content = _MsixRenderTemplate -TemplatePath $tmpl -Parameters $merged

    if ($PSCmdlet.ShouldProcess($OutputPath, "Generate $Name from template")) {
        $dir = Split-Path $OutputPath -Parent
        if ($dir -and -not (Test-Path $dir)) { New-Item $dir -ItemType Directory -Force | Out-Null }
        Set-Content -Path $OutputPath -Value $content -Encoding utf8
        Write-MsixLog Info "Generated $Name -> $OutputPath"
    }

    if ($Pfx) {
        Set-MsixScriptSignature -ScriptPath $OutputPath -Pfx $Pfx -PfxPassword $PfxPassword -TimestampUrl $TimestampUrl
    }

    return Get-Item $OutputPath
}


function Set-MsixScriptSignature {
    <#
    .SYNOPSIS
        Signs a PowerShell script (Authenticode + RFC 3161 timestamp) using the
        same certificate the rest of the module uses for package signing.

    .DESCRIPTION
        Wraps Set-AuthenticodeSignature so callers don't have to deal with
        certificate loading / timestamp server arguments.

    .PARAMETER ScriptPath
        .ps1 (or .psm1) file to sign.

    .PARAMETER Pfx / PfxPassword
        PFX certificate. Required.

    .PARAMETER TimestampUrl
        RFC 3161 server. Default: DigiCert.

    .EXAMPLE
        Set-MsixScriptSignature -ScriptPath createshortcut.ps1 -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ScriptPath,
        [Parameter(Mandatory)]
        [string]$Pfx,
        [Parameter(Mandatory)]
        [string]$PfxPassword,
        [string]$TimestampUrl = 'http://timestamp.digicert.com'
    )

    if (-not (Test-Path $ScriptPath)) { throw "Script not found: $ScriptPath" }
    if (-not (Test-Path $Pfx))        { throw "PFX not found: $Pfx" }

    $sec  = ConvertTo-SecureString $PfxPassword -AsPlainText -Force
    $cert = Get-PfxCertificate -FilePath $Pfx -Password $sec -ErrorAction Stop

    $sig = Set-AuthenticodeSignature -FilePath $ScriptPath -Certificate $cert `
                                     -TimestampServer $TimestampUrl `
                                     -HashAlgorithm SHA256 -ErrorAction Stop
    if ($sig.Status -ne 'Valid') {
        Write-MsixLog Warning "Script signature status: $($sig.Status) ($($sig.StatusMessage))"
    } else {
        Write-MsixLog Info "Signed: $ScriptPath  ($($sig.SignerCertificate.Thumbprint))"
    }
    return $sig
}


function Add-MsixStandardScript {
    <#
    .SYNOPSIS
        High-level: generate a standard script, sign it, and inject it into an
        MSIX package as a PSF startScript in one call.

    .DESCRIPTION
        Combines New-MsixStandardScript + Add-MsixPsfV2 -AppOptions /
        -AdditionalFiles. The signing certificate is shared between the script
        and the package so they form a coherent signed artefact.

    .PARAMETER PackagePath
        .msix file to modify.

    .PARAMETER AppId
        Application Id to attach the startScript to.

    .PARAMETER Name
        Standard-script template name (see Get-MsixStandardScripts).

    .PARAMETER Parameters
        Hashtable of values to substitute into the template.

    .PARAMETER ScriptFileName
        Name of the .ps1 inside the package (default: <Name>.ps1).

    .PARAMETER RunOnce / WaitForScriptToFinish / ShowWindow / RunInVirtualEnvironment / StopOnScriptError / Timeout / EndScript
        Forwarded to New-MsixPsfStartScriptConfig.

    .PARAMETER Pfx / PfxPassword
        Signing certificate (used for both the script and the repacked .msix).

    .PARAMETER OutputPath / SkipSigning
        Forwarded to Add-MsixPsfV2.

    .EXAMPLE
        Add-MsixStandardScript -PackagePath app.msix -AppId 'App' `
            -Name CreateShortcut `
            -Parameters @{ DisplayName='Contoso'; Target='contoso.exe' } `
            -RunOnce -WaitForScriptToFinish `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidateScript({ $_ -in $script:StandardScriptCatalogue.Keys })]
        [string]$Name,
        [Parameter(Mandatory)]
        [hashtable]$Parameters,
        [string]$ScriptFileName,
        [switch]$RunOnce,
        [switch]$WaitForScriptToFinish,
        [switch]$ShowWindow,
        [switch]$RunInVirtualEnvironment,
        [switch]$StopOnScriptError,
        [int]$Timeout = 0,
        [switch]$EndScript,
        [string]$Pfx,
        [string]$PfxPassword,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning
    )

    if (-not $ScriptFileName) { $ScriptFileName = "$Name.ps1" }

    # Stage script in a workspace so cleanup is easy
    $stage      = New-MsixWorkspace "$AppId-$Name"
    $scriptPath = Join-Path $stage $ScriptFileName

    try {
        $genArgs = @{
            Name       = $Name
            Parameters = $Parameters
            OutputPath = $scriptPath
        }
        if ($Pfx -and -not $SkipSigning) {
            $genArgs['Pfx']         = $Pfx
            $genArgs['PfxPassword'] = $PfxPassword
        }
        New-MsixStandardScript @genArgs | Out-Null

        $startBlock = New-MsixPsfStartScriptConfig -AppId $AppId `
            -ScriptPath              $ScriptFileName `
            -RunOnce:$RunOnce `
            -WaitForScriptToFinish:$WaitForScriptToFinish `
            -ShowWindow:$ShowWindow `
            -RunInVirtualEnvironment:$RunInVirtualEnvironment `
            -StopOnScriptError:$StopOnScriptError `
            -Timeout $Timeout `
            -EndScript:$EndScript

        $psfArgs = @{
            PackagePath     = $PackagePath
            Fixups          = @()
            AppOptions      = @($startBlock)
            AdditionalFiles = @($scriptPath)
        }
        if ($Pfx)         { $psfArgs['Pfx']         = $Pfx }
        if ($PfxPassword) { $psfArgs['PfxPassword'] = $PfxPassword }
        if ($OutputPath)  { $psfArgs['OutputPath']  = $OutputPath }
        if ($SkipSigning) { $psfArgs['SkipSigning'] = $true }

        Add-MsixPsfV2 @psfArgs

    } finally {
        Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
    }
}

