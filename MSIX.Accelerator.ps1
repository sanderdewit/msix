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

    if (-not (Test-Path -LiteralPath $Path)) { throw "Accelerator not found: $Path" }

    # Thin file wrapper over the string parser (ConvertFrom-MsixAcceleratorYaml),
    # which now understands nested maps + block lists in addition to the original
    # flat scalars / inline lists (issue #18). The same safe, value-only parsing
    # guarantees apply: no type tags, anchors, or object instantiation.
    $text = Get-Content -LiteralPath $Path -Raw
    return ConvertFrom-MsixAcceleratorYaml -Yaml $text
}


function _MsixConvertAcceleratorScalar {
    <#
    Converts a single YAML scalar value (the right-hand side of "key: value", or
    a "- item" list element) into a [string] or [string[]]. Inline lists
    [a, b, c] become string arrays; quotes are stripped. NEVER resolves YAML
    tags, anchors, or aliases — hostile constructs (e.g. "!!python/object/...")
    are returned verbatim as inert strings. Value-only by design.
    #>
    param([string]$Value)

    $v = $Value
    # Strip a trailing comment that is clearly outside a quoted string.
    if ($v -notmatch '^["''].*["'']$' -and $v -match '^(.*?)\s+#') {
        $v = $matches[1]
    }
    $v = $v.Trim()

    if ($v -match '^\[(.*)\]\s*$') {
        # Inline list:  [a, b, c]
        $items = [System.Collections.Generic.List[string]]::new()
        foreach ($item in ($matches[1] -split ',')) {
            $t = $item.Trim()
            if ($t -match '^"(.*)"$' -or $t -match "^'(.*)'$") { $t = $matches[1] }
            if ($t -ne '') { $items.Add($t) }
        }
        return [string[]]$items.ToArray()
    }
    if ($v -match '^"(.*)"$' -or $v -match "^'(.*)'$") {
        return [string]$matches[1]
    }
    # Everything else — including hostile YAML tag syntax — is kept literal.
    return [string]$v
}

function _MsixParseAcceleratorMap {
    <#
    Recursive-descent map parser. $Lines is an [object[]] of @($indent,$content)
    tuples (blank/comment/doc-marker lines already stripped). $Cursor is a
    @{ Index = <int> } hashtable threaded through the recursion (a plain int
    would not mutate across calls, and [ref] double-wraps awkwardly in PS 5.1).
    Consumes consecutive "key: value" lines at exactly $MapIndent and returns a
    [hashtable]. A key with an empty value followed by deeper-indented lines
    recurses into a nested map or block list.
    #>
    param(
        [object[]]$Lines,
        [hashtable]$Cursor,
        [int]$MapIndent
    )
    $map = @{}
    while ($Cursor.Index -lt $Lines.Count) {
        $ln = $Lines[$Cursor.Index]
        if ($ln[0] -ne $MapIndent) { break }
        if ($ln[1].StartsWith('- ')) { break }
        $m = [regex]::Match($ln[1], '^([A-Za-z0-9_\-]+):\s*(.*)$')
        if (-not $m.Success) { break }
        $key = $m.Groups[1].Value
        $val = $m.Groups[2].Value
        $Cursor.Index++
        if ($val -ne '') {
            $map[$key] = _MsixConvertAcceleratorScalar -Value $val
        } elseif ($Cursor.Index -lt $Lines.Count -and $Lines[$Cursor.Index][0] -gt $MapIndent) {
            $childIndent = $Lines[$Cursor.Index][0]
            if ($Lines[$Cursor.Index][1].StartsWith('- ')) {
                $map[$key] = _MsixParseAcceleratorList -Lines $Lines -Cursor $Cursor -ListIndent $childIndent
            } else {
                $map[$key] = _MsixParseAcceleratorMap -Lines $Lines -Cursor $Cursor -MapIndent $childIndent
            }
        } else {
            $map[$key] = ''
        }
    }
    return $map
}

function _MsixParseAcceleratorList {
    <#
    Recursive-descent block-list parser. Consumes consecutive "- ..." lines at
    exactly $ListIndent and returns an [object[]]. A "- key: value" element
    starts a nested map (the "- " is rewritten to spaces so the element's keys
    align at ListIndent+2); a plain "- scalar" element becomes a scalar value.
    #>
    param(
        [object[]]$Lines,
        [hashtable]$Cursor,
        [int]$ListIndent
    )
    $items = [System.Collections.Generic.List[object]]::new()
    while ($Cursor.Index -lt $Lines.Count) {
        $ln = $Lines[$Cursor.Index]
        if ($ln[0] -ne $ListIndent) { break }
        if (-not $ln[1].StartsWith('- ')) { break }
        $after = $ln[1].Substring(2)
        if ([regex]::IsMatch($after, '^([A-Za-z0-9_\-]+):\s*(.*)$')) {
            # Map element: rewrite this line so its first key sits at ListIndent+2,
            # then let the map parser consume it plus its indented continuation.
            $itemIndent = $ListIndent + 2
            $Lines[$Cursor.Index] = @($itemIndent, $after)
            $items.Add((_MsixParseAcceleratorMap -Lines $Lines -Cursor $Cursor -MapIndent $itemIndent))
        } else {
            $Cursor.Index++
            $items.Add((_MsixConvertAcceleratorScalar -Value $after))
        }
    }
    return ,$items.ToArray()
}

function ConvertFrom-MsixAcceleratorYaml {
    <#
    .SYNOPSIS
        Parses accelerator YAML text into nested hashtables / arrays using a
        safe, value-only recursive-descent parser.

    .DESCRIPTION
        Supports the YAML subset accelerators actually use: scalars, inline
        lists ([a, b, c]), indentation-based nested maps, and block lists
        (including block-lists-of-maps for RemediationApproach trees).

        SECURITY: this is NOT a general YAML parser and never will be. Every
        leaf is a [string] or [string[]]; containers are [hashtable] /
        [object[]]. It NEVER instantiates .NET/CLR types, so YAML type tags
        (e.g. !!python/object/apply, !!net/object), anchors/aliases (&/*), and
        multi-document/directive markers (---, ..., %) are treated as inert
        literal text or skipped — closing the deserialisation code-execution
        vector that full YAML libraries expose on untrusted accelerator files.
        Tabs in indentation are rejected (YAML forbids them; mixing tabs/spaces
        silently corrupts structure).

    .PARAMETER Yaml
        The accelerator YAML document as a string.

    .OUTPUTS
        [hashtable] for a mapping document, or [object[]] for a top-level list.

    .EXAMPLE
        ConvertFrom-MsixAcceleratorYaml -Yaml (Get-Content acc.yaml -Raw)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Yaml
    )

    # Tokenize: drop blank/comment/doc-marker lines, capture (indent, content).
    $tokens = [System.Collections.Generic.List[object]]::new()
    foreach ($raw in ($Yaml -split "`r?`n")) {
        if ($raw -match '^[ ]*\t') {
            throw "Accelerator YAML uses a tab character in indentation, which is not allowed. Use spaces only."
        }
        $trimmedEnd = $raw -replace '\s+$', ''
        if ($trimmedEnd -eq '') { continue }
        $content = $trimmedEnd.TrimStart(' ')
        if ($content.StartsWith('#')) { continue }
        # Multi-document / directive markers: single-document parser ignores them.
        if ($content -eq '---' -or $content -eq '...' -or $content.StartsWith('%')) { continue }
        $indent = $trimmedEnd.Length - $content.Length
        # Store the [indent, content] pair as one element. List[object].Add does
        # not enumerate its argument, so add the 2-element array directly — a
        # leading unary comma would double-wrap it (@(@(indent,content))) and
        # make $ln[0] an array instead of the indent int.
        $tokens.Add([object[]]@($indent, $content))
    }

    if ($tokens.Count -eq 0) { return @{} }

    $lines  = [object[]]$tokens.ToArray()
    $cursor = @{ Index = 0 }
    if ($lines[0][1].StartsWith('- ')) {
        return _MsixParseAcceleratorList -Lines $lines -Cursor $cursor -ListIndent $lines[0][0]
    }
    return _MsixParseAcceleratorMap -Lines $lines -Cursor $cursor -MapIndent $lines[0][0]
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
        Source           = (Resolve-Path -LiteralPath $Path).Path
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
        Write-MsixLog -Level Warning -Message "Accelerator declares ConversionStatus '$($accel.Status)'. Proceeding anyway, but review FixSteps first."
    }

    if ($accel.SuggestedFixups.Count -eq 0 -and $accel.AppOptions.Count -eq 0) {
        Write-MsixLog -Level Warning -Message 'Accelerator contains no PSF fixups; nothing to inject. Returning report only.'
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
