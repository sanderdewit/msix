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

function ConvertFrom-MsixYamlAccelerator {
    <#
    .SYNOPSIS
        Parses an accelerator YAML file using an intentionally-restricted
        scalar parser.

    .DESCRIPTION
        Reads an accelerator YAML file from -Path and returns a hashtable of
        the top-level keys. Only flat scalar (key: value) and inline list
        (key: [a, b, c]) forms are recognised. Quoting with single or double
        quotes around scalar values is honoured (stripped); everything else
        is treated as a literal string.

        Nested mappings, anchors/aliases, tags (e.g. !!python/object/apply,
        !!binary, !!set), multi-document streams, flow mappings, and any
        other YAML feature that could instantiate a .NET object are NOT
        supported. By design, hostile constructs degrade to literal text
        rather than causing object instantiation.

    .PARAMETER Path
        Path to the accelerator .yaml / .yml file.

    .OUTPUTS
        [hashtable] with one entry per recognised top-level key. Inline-list
        values are returned as string arrays; everything else is a string.

    .EXAMPLE
        $raw = ConvertFrom-MsixYamlAccelerator -Path .\line.yaml
        $raw.PackageName

    .NOTES
        SECURITY: Accelerator YAML is parsed by an intentionally-restricted scalar
        parser. Only flat key:value and key:[value1,value2] forms are supported. Tags,
        references, multi-document streams, and any YAML feature that could
        instantiate .NET objects are NOT supported -- by design. Do not switch to a
        full third-party YAML library for this input: accelerator files are
        user-supplied and a full YAML parser would be a code-execution vector on
        untrusted accelerator authors.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not (Test-Path $Path)) { throw "Accelerator not found: $Path" }

    # SECURITY (H5): We deliberately do NOT invoke any external YAML
    # deserialiser here, even if one is installed. Full YAML parsers honour
    # YAML type tags such as !!python/object/apply or .NET type tags that
    # can instantiate arbitrary objects during deserialisation -- a
    # well-known code-execution vector when the YAML comes from an
    # untrusted source. Accelerator files ARE untrusted (third-party
    # authors publish them), so we parse with a tiny purpose-built scalar
    # parser instead. Do not "improve" this by routing through a real YAML
    # library.
    $text   = Get-Content -LiteralPath $Path -Raw
    $result = @{}

    # Match: <indent><key>: <value>   (one line, no nested mappings).
    # The key is restricted to a conservative identifier set so we never
    # accidentally capture a tag like "!!python/object/apply:os.system".
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_\-]*)\s*:\s*(.*)$') {
            $key = $matches[1]
            $val = $matches[2].Trim()

            # Strip a trailing comment that is clearly outside a quoted string.
            if ($val -notmatch '^["''].*["'']$' -and $val -match '^(.*?)\s+#') {
                $val = $matches[1].Trim()
            }

            if ($val -match '^\[(.*)\]\s*$') {
                # Inline list:  key: [a, b, c]
                $items = @()
                foreach ($item in ($matches[1] -split ',')) {
                    $t = $item.Trim()
                    if ($t -match '^"(.*)"$' -or $t -match "^'(.*)'$") { $t = $matches[1] }
                    $items += $t
                }
                $result[$key] = $items
            }
            elseif ($val -match '^"(.*)"$' -or $val -match "^'(.*)'$") {
                $result[$key] = $matches[1]
            }
            else {
                # Everything else -- including hostile YAML tag syntax such as
                # "!!python/object/apply:os.system [`"whoami`"]" -- is kept as a
                # literal string. No tag resolution, no object instantiation.
                $result[$key] = $val
            }
        }
    }
    return $result
}


function Import-MsixAccelerator {
    <#
    .SYNOPSIS
        Loads an accelerator YAML file and returns an object describing the
        recipe and any PSF fixups it contains.

    .DESCRIPTION
        Parses an Accelerator YAML file via ConvertFrom-MsixYamlAccelerator,
        then translates the recipe into the module's PSF builder shapes:
        FileRedirectionFixup, RegLegacyFixups, EnvVarFixup configs, plus
        any per-app arguments / working directory. The resulting object
        feeds Invoke-MsixAccelerator (or can be inspected and applied
        manually).

        Non-PSF fix types (Capability, Dependency, anything unrecognised)
        are surfaced under ManualNotes so the operator can action them.

        LIMITATION: The underlying parser is intentionally restricted to
        flat scalars and inline lists (see ConvertFrom-MsixYamlAccelerator
        .NOTES). Accelerators that express their RemediationApproach as a
        nested YAML mapping tree -- the format generated by some authoring
        tools -- will NOT be walked correctly here. Support for nested
        trees is deferred to issue #18. For now, supply accelerators whose
        RemediationApproach is provided in flat-key form, or pre-process
        the YAML into that shape.

    .PARAMETER Path
        Path to the accelerator .yaml / .yml file.

    .OUTPUTS
        [pscustomobject] with Source, PackageName, PackageVersion, Publisher,
        Eligible, Status, Architecture, FixSteps[], SuggestedFixups[] (PSF
        hashtables ready for Add-MsixPsfV2), AppOptions[] (workingDirectory /
        arguments), Capabilities[], Dependencies[], ManualNotes[].

    .EXAMPLE
        $accel = Import-MsixAccelerator -Path .\line.yaml
        $accel.SuggestedFixups
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
                            $report.AppOptions += New-MsixPsfArgument `
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

    .PARAMETER Pfx
        Path to the signing PFX. Forwarded to Add-MsixPsfV2.

    .PARAMETER PfxPassword
        SecureString password for -Pfx.

    .OUTPUTS
        [pscustomobject] the same report shape produced by
        Import-MsixAccelerator. When the accelerator contained nothing
        applicable, the report is returned without modifying the package.

    .EXAMPLE
        Invoke-MsixAccelerator -PackagePath .\line.msix `
            -AcceleratorPath .\line.yaml `
            -Pfx .\cert.pfx -PfxPassword (Read-Host -AsSecureString)

    .EXAMPLE
        # Dry-run via -WhatIf to see what would be applied
        Invoke-MsixAccelerator -PackagePath .\line.msix `
            -AcceleratorPath .\line.yaml -WhatIf
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [string]$AcceleratorPath,
        [string]$Pfx,
        [SecureString]$PfxPassword
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
