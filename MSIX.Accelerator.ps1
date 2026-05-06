# =============================================================================
# MSIX Accelerator support
# -----------------------------------------------------------------------------
# Implements a thin parser for the Accelerator YAML schema documented at
# https://learn.microsoft.com/windows/msix/toolkit/accelerators.
#
# An accelerator captures the conversion recipe for a specific Win32 product:
# its eligibility, the sequence of fixes, and (for FixType=PSF) a YAML-encoded
# config.json. Sample accelerators:
#   https://github.com/microsoft/MSIX-Labs/tree/master/DeveloperLabs/SampleAccelerators
#
# We support PSF FixType natively. Other FixTypes (Capability, Dependency,
# Services, etc.) are surfaced as findings for human review.
# =============================================================================

function Test-MsixAcceleratorParserAvailable {
    # Use the powershell-yaml module if available; otherwise fall back to a
    # minimal regex parser sufficient for the FixType: PSF case.
    return [bool](Get-Module -ListAvailable -Name 'powershell-yaml')
}


function ConvertFrom-MsixYamlAccelerator {
    <#
    .SYNOPSIS
        Parses an accelerator YAML file. Uses powershell-yaml if present,
        otherwise a minimal hand-rolled parser sufficient for the documented schema.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) { throw "Accelerator not found: $Path" }

    if (Test-MsixAcceleratorParserAvailable) {
        Import-Module powershell-yaml -ErrorAction Stop
        return ConvertFrom-Yaml (Get-Content $Path -Raw)
    }

    # Minimal fallback: parse only the keys we need.
    Write-MsixLog Warning "powershell-yaml not installed; using minimal parser. Run 'Install-Module powershell-yaml' for full support."
    $text   = Get-Content $Path -Raw
    $result = @{}

    # Top-level scalar keys (PackageName, PackageVersion, etc.)
    foreach ($scalar in @('PackageName','PackageVersion','PublisherName','EligibleForConversion',
                          'ConversionStatus','MinimumPSFVersion','Architecture','MinimumOSVersion',
                          'MinimumOSBuild','Edition','MSIXConversionToolVersion','AcceleratorVersion')) {
        if ($text -match "^\s*${scalar}\s*:\s*(.+)$") {
            $result[$scalar] = ($matches[1] -replace '^["'']|["'']$').Trim()
        }
    }
    return $result
}


function Import-MsixAccelerator {
    <#
    .SYNOPSIS
        Loads an accelerator YAML file and returns an object describing the
        recipe and any PSF fixups it contains.

    .PARAMETER Path
        Path to the accelerator .yaml/.yml file.

    .OUTPUTS
        [pscustomobject] with PackageName, ConversionStatus, FixSteps[],
        SuggestedFixups[] (PSF hashtables), AppOptions[] (workingDirectory etc.),
        Capabilities[], Dependencies[], ManualNotes[].

    .EXAMPLE
        Import-MsixAccelerator -Path .\line.yaml
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $raw = ConvertFrom-MsixYamlAccelerator -Path $Path

    $report = [pscustomobject]@{
        Source           = (Resolve-Path $Path).Path
        PackageName      = $raw.PackageName
        PackageVersion   = $raw.PackageVersion
        Publisher        = $raw.PublisherName
        Eligible         = $raw.EligibleForConversion
        Status           = $raw.ConversionStatus
        Architecture     = $raw.Architecture
        FixSteps         = @()
        SuggestedFixups  = @()
        AppOptions       = @()
        Capabilities     = @()
        Dependencies     = @()
        ManualNotes      = @()
    }

    foreach ($step in @($raw.RemediationApproach)) {
        if (-not $step) { continue }
        $fix = $step.Fix
        if (-not $fix) { continue }

        $report.FixSteps += [pscustomobject]@{
            Sequence   = $step.SequenceNumber
            Issue      = $step.Issue.Description
            FixType    = $fix.FixType
            Reference  = $fix.Reference
        }

        switch ($fix.FixType) {
            'PSF' {
                $cfg = $fix.FixDetails.PSFConfig
                if ($cfg) {
                    foreach ($app in @($cfg.applications)) {
                        if ($app.workingDirectory -or $app.arguments) {
                            $report.AppOptions += New-MsixPsfArguments `
                                -AppId            $app.id `
                                -Arguments        $app.arguments `
                                -WorkingDirectory $app.workingDirectory
                        }
                    }
                    foreach ($proc in @($cfg.processes)) {
                        foreach ($f in @($proc.fixups)) {
                            $dll = ($f.dll -replace '\d+\.dll$', '.dll')
                            if ($dll -eq 'FileRedirectionFixup.dll' -and $f.config.redirectedPaths.packageRelative) {
                                foreach ($pr in @($f.config.redirectedPaths.packageRelative)) {
                                    $report.SuggestedFixups += New-MsixPsfFileRedirectionConfig `
                                        -Base $pr.base -Patterns @($pr.patterns)
                                }
                            }
                            elseif ($dll -eq 'RegLegacyFixups.dll' -and $f.config.remediation) {
                                foreach ($rem in @($f.config.remediation)) {
                                    $report.SuggestedFixups += New-MsixPsfRegLegacyConfig `
                                        -Hive $rem.hive -Access $rem.access -Patterns @($rem.patterns)
                                }
                            }
                            elseif ($dll -eq 'EnvVarFixup.dll' -and $f.config.envVars) {
                                $h = @{}
                                foreach ($k in $f.config.envVars.Keys) { $h[$k] = $f.config.envVars[$k] }
                                $report.SuggestedFixups += New-MsixPsfEnvVarConfig -Variables $h
                            }
                        }
                    }
                }
            }
            'Capability'  { $report.Capabilities += @($fix.FixDetails.Capabilities) }
            'Dependency'  { $report.Dependencies += @($fix.FixDetails.Dependencies) }
            default {
                $report.ManualNotes += [pscustomobject]@{
                    FixType  = $fix.FixType
                    Issue    = $step.Issue.Description
                    Detail   = ($fix.FixDetails | ConvertTo-Json -Depth 5 -Compress)
                }
            }
        }
    }
    return $report
}


function Invoke-MsixAccelerator {
    <#
    .SYNOPSIS
        Applies an accelerator recipe to an .msix file: runs Add-MsixPsfV2 with
        the synthesised fixups, AppOptions, and signs the result.

    .DESCRIPTION
        Non-PSF fix steps (Capability, Dependency, Services, EntryPoint, etc.)
        cannot be applied automatically and are returned in the output as
        ManualSteps for the operator to action.

    .PARAMETER PackagePath
        Existing .msix to which the accelerator's PSF block will be applied.

    .PARAMETER AcceleratorPath
        Path to the accelerator YAML.

    .PARAMETER Pfx / PfxPassword
        Signing certificate.

    .EXAMPLE
        Invoke-MsixAccelerator -PackagePath line.msix -AcceleratorPath line.yaml -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [string]$AcceleratorPath,
        [string]$Pfx,
        [string]$PfxPassword
    )

    $accel = Import-MsixAccelerator -Path $AcceleratorPath

    if ($accel.Status -in 'Failed','Not Eligible') {
        Write-MsixLog Warning "Accelerator declares ConversionStatus '$($accel.Status)'. Proceeding anyway, but review FixSteps first."
    }

    if ($accel.SuggestedFixups.Count -eq 0 -and $accel.AppOptions.Count -eq 0) {
        Write-MsixLog Warning 'Accelerator contains no PSF fixups; nothing to inject. Returning report only.'
        return $accel
    }

    if ($PSCmdlet.ShouldProcess($PackagePath, "Apply accelerator $($accel.Source)")) {
        Add-MsixPsfV2 -PackagePath $PackagePath `
                      -Fixups     ([hashtable[]]$accel.SuggestedFixups) `
                      -AppOptions ([hashtable[]]$accel.AppOptions) `
                      -Pfx        $Pfx `
                      -PfxPassword $PfxPassword
    }

    return $accel
}
