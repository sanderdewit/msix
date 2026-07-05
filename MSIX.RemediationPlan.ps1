# =============================================================================
# Remediation plan round-trip
# -----------------------------------------------------------------------------
# Serialise, validate, and replay a structured remediation plan so operators
# can persist the plan, route it through change-control, and apply it
# deterministically against a later package build.
#
# Schema (YAML, all keys under a top-level `remediation:` block):
#
#   version:        1
#   generatedAt:    <ISO-8601>
#   generatedBy:    MSIX.PowerShell <version>
#   packageFingerprint:
#     identityName: <string>
#     publisher:    <string>
#     sha256:       <string>
#   findings:
#     - category:   <string>
#       confidence: <double>
#       symptom:    <string>
#   appliedFixes:
#     - cmdlet:     <cmdlet-name>
#       args:
#         <key>:    <value>
#   approval:
#     requiredBy:   <string>
#     notes:        <string>
#
# SECURITY: only cmdlets exported by this module may appear in appliedFixes.
# The same defence-in-depth guard used by the playbook bus is applied here.
# =============================================================================

$script:_MsixPlanVersion = 1


# ---------------------------------------------------------------------------
# Private: minimal YAML scalar helpers
# ---------------------------------------------------------------------------

function _MsixYamlScalar([object]$val) {
    if ($null -eq $val) { return 'null' }
    if ($val -is [bool]) { return $val.ToString().ToLower() }
    if ($val -is [datetime])             { return $val.ToString('o') }
    if ($val -is [System.DateTimeOffset]) { return $val.ToString('o') }
    if ($val -is [System.ValueType]) { return [string]$val }
    $s = [string]$val
    # Quote strings that contain YAML special chars, leading/trailing space,
    # or that look like YAML booleans/nulls to avoid ambiguity.
    if ($s -match '[:#\[\]{}|>&*!,]' -or
        $s -match '^\s|\s$' -or
        $s -match '^(true|false|yes|no|null|~)$' -or
        $s -eq '') {
        return "'" + $s.Replace("'", "''") + "'"
    }
    return $s
}

# Emit a hashtable/pscustomobject as YAML with the given indentation.
# Returns a string (with trailing newline per line).
function _MsixYamlBlock([object]$obj, [int]$indent) {
    $pad = ' ' * $indent
    $sb  = [System.Text.StringBuilder]::new()

    $props = if ($obj -is [System.Collections.IDictionary]) {
        $obj.GetEnumerator() | ForEach-Object { [pscustomobject]@{ Key = $_.Key; Value = $_.Value } }
    } else {
        $obj.PSObject.Properties | Where-Object MemberType -eq 'NoteProperty' |
            ForEach-Object { [pscustomobject]@{ Key = $_.Name; Value = $_.Value } }
    }

    foreach ($p in $props) {
        $k = $p.Key
        $v = $p.Value

        if ($null -eq $v) {
            $sb.AppendLine("${pad}${k}: null") | Out-Null

        } elseif ($v -is [array] -or ($v -is [System.Collections.IEnumerable] -and $v -isnot [string])) {
            $sb.AppendLine("${pad}${k}:") | Out-Null
            $items = @($v)
            foreach ($item in $items) {
                if ($item -is [System.Collections.IDictionary] -or $item -is [pscustomobject]) {
                    # First key of the nested object gets the list bullet.
                    $inner = _MsixYamlBlock -Obj $item -Indent ($indent + 4)
                    $lines = @($inner -split "`r?`n" | Where-Object { $_ -ne '' })
                    if ($lines.Count -gt 0) {
                        $sb.AppendLine("$pad  - $($lines[0].TrimStart())") | Out-Null
                        for ($i = 1; $i -lt $lines.Count; $i++) {
                            $sb.AppendLine("$pad    $($lines[$i].TrimStart())") | Out-Null
                        }
                    }
                } else {
                    $sb.AppendLine("$pad  - $(_MsixYamlScalar -Val $item)") | Out-Null
                }
            }

        } elseif ($v -is [System.Collections.IDictionary] -or $v -is [pscustomobject]) {
            $sb.AppendLine("${pad}${k}:") | Out-Null
            $sb.Append((_MsixYamlBlock -Obj $v -Indent ($indent + 2))) | Out-Null

        } else {
            $sb.AppendLine("${pad}${k}: $(_MsixYamlScalar -Val $v)") | Out-Null
        }
    }

    return $sb.ToString()
}


# ---------------------------------------------------------------------------
# Private: minimal YAML parser
# Handles: scalar key: value, nested mappings (indented), and sequences (-).
# Intentionally restricted — no tags, anchors, multi-doc, or object
# instantiation. Same security stance as ConvertFrom-MsixYamlAccelerator.
# ---------------------------------------------------------------------------

function _MsixParseYaml([string[]]$Lines, [ref]$Pos, [int]$MinIndent) {
    $result = [ordered]@{}

    while ($Pos.Value -lt $Lines.Count) {
        $rawLine = $Lines[$Pos.Value]
        $trimmed = $rawLine.TrimStart()

        # Skip blank lines and comments.
        if ($trimmed -eq '' -or $trimmed.StartsWith('#')) { $Pos.Value++; continue }

        $currentIndent = $rawLine.Length - $trimmed.Length

        # Dedent means we've left this block — return to caller.
        if ($currentIndent -lt $MinIndent) { break }

        # Sequence item at this level.
        if ($trimmed.StartsWith('- ')) {
            # Caller handles sequence items; break so the sequence loop in the
            # caller can collect them.
            break
        }

        $Pos.Value++

        # Key: value
        if ($trimmed -match '^([^:]+):\s*(.*)$') {
            $key   = $matches[1].Trim()
            $value = $matches[2].Trim()

            if ($value -eq '' -or $value -eq 'null') {
                # Could be a nested mapping or sequence — peek ahead.
                if ($Pos.Value -lt $Lines.Count) {
                    $nextRaw = $Lines[$Pos.Value]
                    $nextTrimmed = $nextRaw.TrimStart()
                    $nextIndent  = $nextRaw.Length - $nextTrimmed.Length

                    if ($nextIndent -gt $currentIndent -and $nextTrimmed.StartsWith('- ')) {
                        # Sequence.
                        $seq = @()
                        while ($Pos.Value -lt $Lines.Count) {
                            $seqRaw  = $Lines[$Pos.Value]
                            $seqTrim = $seqRaw.TrimStart()
                            $seqInd  = $seqRaw.Length - $seqTrim.Length
                            if ($seqInd -lt $nextIndent -or -not $seqTrim.StartsWith('- ')) { break }
                            $Pos.Value++
                            $firstVal = $seqTrim.Substring(2).Trim()
                            # Peek for nested block after the '- ' line.
                            if ($Pos.Value -lt $Lines.Count) {
                                $peekRaw  = $Lines[$Pos.Value]
                                $peekInd  = $peekRaw.Length - $peekRaw.TrimStart().Length
                                if ($peekInd -gt $seqInd) {
                                    # The '-' introduced a nested mapping. Parse it.
                                    $itemObj = [ordered]@{}
                                    # First key may be on the same line as '-'.
                                    if ($firstVal -match '^([^:]+):\s*(.*)$') {
                                        $fk = $matches[1].Trim(); $fv = $matches[2].Trim()
                                        $itemObj[$fk] = if ($fv -eq '' -or $fv -eq 'null') { $null } else { _MsixUnquoteYaml -S $fv }
                                    }
                                    $nested = _MsixParseYaml -Lines $Lines -Pos $Pos -MinIndent ($seqInd + 1)
                                    foreach ($nk in $nested.Keys) { $itemObj[$nk] = $nested[$nk] }
                                    $seq += [pscustomobject]$itemObj
                                } else {
                                    $seq += if ($firstVal -eq 'null') { $null } else { _MsixUnquoteYaml -S $firstVal }
                                }
                            } else {
                                $seq += if ($firstVal -eq 'null') { $null } else { _MsixUnquoteYaml -S $firstVal }
                            }
                        }
                        $result[$key] = $seq
                        continue
                    } elseif ($nextIndent -gt $currentIndent) {
                        # Nested mapping.
                        $result[$key] = _MsixParseYaml -Lines $Lines -Pos $Pos -MinIndent $nextIndent
                        continue
                    }
                }
                $result[$key] = $null
            } else {
                $result[$key] = _MsixUnquoteYaml -S $value
            }
        }
    }
    return $result
}

function _MsixUnquoteYaml([string]$s) {
    $s = $s.Trim()
    if ($s.StartsWith("'") -and $s.EndsWith("'")) {
        return $s.Substring(1, $s.Length - 2).Replace("''", "'")
    }
    if ($s.StartsWith('"') -and $s.EndsWith('"')) {
        return $s.Substring(1, $s.Length - 2).Replace('\"', '"')
    }
    if ($s -eq 'null' -or $s -eq '~') { return $null }
    if ($s -match '^\d+\.\d+$') { return [double]$s }
    if ($s -match '^\d+$') { return [int]$s }
    if ($s -in 'true','yes') { return $true }
    if ($s -in 'false','no') { return $false }
    return $s
}


# ---------------------------------------------------------------------------
# Private: cmdlet safety guard — same pattern as Invoke-MsixPlaybook.
# ---------------------------------------------------------------------------
function _MsixGuardPlanCmdlet([string]$CmdletName, [int]$StepIndex) {
    $cmd = Get-Command -Name $CmdletName -ErrorAction SilentlyContinue
    if (-not $cmd) {
        throw "appliedFixes[$StepIndex] references unknown cmdlet '$CmdletName'."
    }
    if ($cmd.Source -ne 'MSIX' -and $cmd.ModuleName -ne 'MSIX') {
        throw "appliedFixes[$StepIndex] references '$CmdletName' which is not from the MSIX module (source: $($cmd.Source)). Execution blocked."
    }
    return $cmd
}


# ---------------------------------------------------------------------------
# Public cmdlets
# ---------------------------------------------------------------------------

function New-MsixRemediationPlan {
    <#
    .SYNOPSIS
        Creates a new (in-memory) remediation plan object ready to be populated
        and exported.

    .DESCRIPTION
        Constructs the structured plan object that Export-MsixRemediationPlan
        serialises and Invoke-MsixRemediationPlan replays.  You can build the
        plan from the output of Invoke-MsixAutoFixFromAnalysis -DryRun, or
        construct it manually.

    .PARAMETER PackagePath
        Package the plan targets. Used to compute the identity fingerprint
        (Name, Publisher) so Test-MsixRemediationPlan can detect drift.

    .PARAMETER Findings
        Findings from Get-MsixStaticAnalysis / Get-MsixCompatibilityReport that
        motivated the fixes. Stored for audit purposes only — not replayed.

    .PARAMETER AppliedFixes
        Array of hashtables, each with 'Cmdlet' and 'Args' keys. This is the
        same shape produced by Invoke-MsixAutoFixFromAnalysis when -DryRun is
        set (the plan's Stages property). Example:
          @{ Cmdlet = 'Add-MsixPsfV2'; Args = @{ WorkingDirectory = 'VFS\...' } }

    .OUTPUTS
        [pscustomobject] with PSTypeName 'MsixRemediationPlan'.
        .EXAMPLE
        # Turn analysis findings into a reviewable plan file
        New-MsixRemediationPlan -PackagePath app.msix -OutputPath plan.json

    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [object[]]$Findings    = @(),
        [hashtable[]]$AppliedFixes = @()
    )

    [xml]$manifest = Get-MsixManifest -Path $PackagePath
    $id  = $manifest.Package.Identity
    $sha = if (Test-Path -LiteralPath $PackagePath -PathType Leaf) {
        try { (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToLowerInvariant() }
        catch { $null }
    } else { $null }

    $modVer = (Get-Module -Name MSIX -ErrorAction SilentlyContinue).Version
    if (-not $modVer) { $modVer = '0.0.0' }

    $findingSummaries = @($Findings | Where-Object { $_ } | ForEach-Object {
        [pscustomobject][ordered]@{
            category   = [string]$_.Category
            confidence = if ($_.PSObject.Properties['Confidence']) { [double]$_.Confidence } else { $null }
            symptom    = [string]$_.Symptom
        }
    })

    $fixSummaries = @($AppliedFixes | Where-Object { $_ } | ForEach-Object {
        [pscustomobject][ordered]@{
            cmdlet = [string]$_.Cmdlet
            args   = if ($_.Args) { $_.Args } else { @{} }
        }
    })

    $plan = [pscustomobject][ordered]@{
        version            = $script:_MsixPlanVersion
        generatedAt        = (Get-Date -Format 'o')
        generatedBy        = "MSIX.PowerShell $modVer"
        packageFingerprint = [pscustomobject][ordered]@{
            identityName = $id.Name
            publisher    = $id.Publisher
            sha256       = $sha
        }
        findings     = $findingSummaries
        appliedFixes = $fixSummaries
        approval     = [pscustomobject][ordered]@{
            requiredBy = $null
            notes      = $null
        }
    }
    $plan.PSObject.TypeNames.Insert(0, 'MsixRemediationPlan')
    return $plan
}


function Export-MsixRemediationPlan {
    <#
    .SYNOPSIS
        Serialises a remediation plan to a YAML file.

    .DESCRIPTION
        Writes a human-readable, change-control-friendly YAML file that can be
        reviewed, edited (approval.notes / approval.requiredBy), and later
        replayed via Import-MsixRemediationPlan + Invoke-MsixRemediationPlan.

        The YAML emitter is intentionally restricted (no external dependency,
        no dynamic object instantiation). The same safety stance as the
        Accelerator YAML parser.

    .PARAMETER Plan
        A MsixRemediationPlan object from New-MsixRemediationPlan.

    .PARAMETER Path
        Destination file (e.g. .\remediation.yaml). UTF-8 without BOM.

    .EXAMPLE
        $plan = New-MsixRemediationPlan -PackagePath app.msix -AppliedFixes $stages
        Export-MsixRemediationPlan -Plan $plan -Path .\app-remediation.yaml
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [psobject]$Plan,
        [Parameter(Mandatory)] [string]$Path
    )

    $yaml = "# MSIX Remediation Plan - do not edit version or packageFingerprint`n"
    $yaml += "remediation:`n"
    $yaml += _MsixYamlBlock -Obj $Plan -Indent 2

    if ($PSCmdlet.ShouldProcess($Path, 'Write remediation plan')) {
        [IO.File]::WriteAllText($Path, $yaml, [Text.UTF8Encoding]::new($false))
        Write-MsixLog -Level Info -Message "Remediation plan written: $Path"
    }
}


function Import-MsixRemediationPlan {
    <#
    .SYNOPSIS
        Parses a YAML remediation plan file and returns the plan object.

    .DESCRIPTION
        Reads and validates the YAML produced by Export-MsixRemediationPlan.
        Validation checks:
          - version field is present and equals the current schema version.
          - appliedFixes cmdlets are all known AND from the MSIX module.
          - Required top-level keys are present.

        Refuses to load a plan that fails any of these checks so a tampered
        or stale plan is caught before Invoke-MsixRemediationPlan runs.

    .PARAMETER Path
        Path to the .yaml file.

    .OUTPUTS
        [pscustomobject] with PSTypeName 'MsixRemediationPlan'.
        .EXAMPLE
        # Load a saved remediation plan for review or replay
        $plan = Import-MsixRemediationPlan -Path .\plan.json

    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Remediation plan not found: $Path"
    }

    $lines = @(Get-Content -LiteralPath $Path -ErrorAction Stop)
    # Strip comment lines and find the 'remediation:' root key.
    $startIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*remediation\s*:') { $startIdx = $i + 1; break }
    }
    if ($startIdx -lt 0) {
        throw "Invalid remediation plan: missing 'remediation:' root key."
    }

    $pos   = [ref]$startIdx
    $inner = _MsixParseYaml -Lines $lines -Pos $pos -MinIndent 2

    # --- Schema validation ---
    foreach ($req in 'version','generatedAt','generatedBy','packageFingerprint','appliedFixes') {
        if (-not $inner.Contains($req)) {
            throw "Invalid remediation plan: missing required key '$req'."
        }
    }
    if ([int]$inner['version'] -ne $script:_MsixPlanVersion) {
        throw ("Remediation plan version {0} is not supported (expected {1})." -f $inner['version'], $script:_MsixPlanVersion)
    }

    $fixes = @($inner['appliedFixes'])
    for ($i = 0; $i -lt $fixes.Count; $i++) {
        $fix = $fixes[$i]
        $name = if ($fix -is [hashtable]) { $fix['cmdlet'] } else { $fix.cmdlet }
        if (-not $name) { throw "appliedFixes[$i] is missing the 'cmdlet' key." }
        _MsixGuardPlanCmdlet -CmdletName $name -StepIndex $i | Out-Null
    }

    # --- Reconstruct the plan object ---
    $fp  = $inner['packageFingerprint']
    $apv = $inner['approval']

    $findingsList = @($inner['findings'] | Where-Object { $_ } | ForEach-Object {
        $f = $_
        [ordered]@{
            category   = if ($f -is [hashtable]) { $f['category'] } else { $f.category }
            confidence = if ($f -is [hashtable]) { $f['confidence'] } else { $f.confidence }
            symptom    = if ($f -is [hashtable]) { $f['symptom']   } else { $f.symptom   }
        }
    })

    $fixesList = @($fixes | Where-Object { $_ } | ForEach-Object {
        $fx = $_
        $cmdlet = if ($fx -is [hashtable]) { $fx['cmdlet'] } else { $fx.cmdlet }
        $argMap = if ($fx -is [hashtable]) { $fx['args']   } else { $fx.args   }
        [ordered]@{
            cmdlet = $cmdlet
            args   = if ($argMap) { $argMap } else { @{} }
        }
    })

    $plan = [pscustomobject][ordered]@{
        version            = [int]$inner['version']
        generatedAt        = [string]$inner['generatedAt']
        generatedBy        = [string]$inner['generatedBy']
        packageFingerprint = [pscustomobject][ordered]@{
            identityName = if ($fp -is [hashtable]) { $fp['identityName'] } else { $fp.identityName }
            publisher    = if ($fp -is [hashtable]) { $fp['publisher']    } else { $fp.publisher    }
            sha256       = if ($fp -is [hashtable]) { $fp['sha256']       } else { $fp.sha256       }
        }
        findings     = $findingsList
        appliedFixes = $fixesList
        approval     = [pscustomobject][ordered]@{
            requiredBy = if ($apv) { if ($apv -is [hashtable]) { $apv['requiredBy'] } else { $apv.requiredBy } } else { $null }
            notes      = if ($apv) { if ($apv -is [hashtable]) { $apv['notes']      } else { $apv.notes      } } else { $null }
        }
    }
    $plan.PSObject.TypeNames.Insert(0, 'MsixRemediationPlan')
    return $plan
}


function Test-MsixRemediationPlan {
    <#
    .SYNOPSIS
        Validates that a remediation plan is still applicable to a package.

    .DESCRIPTION
        Checks:
          1. Package identity (Name + Publisher) still matches the fingerprint
             recorded in the plan.
          2. Every cmdlet in appliedFixes is still exported by the module.
          3. The SHA-256 of the package matches (with -StrictFingerprint).

        Returns a structured result so callers can decide whether to proceed.

    .PARAMETER Plan
        MsixRemediationPlan object (from Import-MsixRemediationPlan or
        New-MsixRemediationPlan).

    .PARAMETER PackagePath
        Package to validate against.

    .PARAMETER StrictFingerprint
        When set, also requires the package SHA-256 to match the plan's
        recorded value. Off by default so a re-signed package still passes.

    .OUTPUTS
        [pscustomobject] @{ IsValid; Errors[] }.
        .EXAMPLE
        # Validate a plan file without executing it
        Test-MsixRemediationPlan -Path .\plan.json

    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [psobject]$Plan,
        [Parameter(Mandatory)] [string]$PackagePath,
        [switch]$StrictFingerprint
    )

    $errors = [System.Collections.Generic.List[string]]::new()

    if (-not (Test-Path -LiteralPath $PackagePath)) {
        $errors.Add("Package not found: $PackagePath")
    } else {
        [xml]$manifest = Get-MsixManifest -Path $PackagePath
        $id = $manifest.Package.Identity
        $fp = $Plan.packageFingerprint

        if ($fp.identityName -and $id.Name -ne $fp.identityName) {
            $errors.Add("Identity.Name mismatch: plan='$($fp.identityName)' package='$($id.Name)'.")
        }
        if ($fp.publisher -and $id.Publisher -ne $fp.publisher) {
            $errors.Add("Identity.Publisher mismatch: plan='$($fp.publisher)' package='$($id.Publisher)'.")
        }
        if ($StrictFingerprint -and $fp.sha256) {
            $actual = (Get-FileHash -LiteralPath $PackagePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actual -ne $fp.sha256) {
                $errors.Add("SHA-256 mismatch: plan='$($fp.sha256)' package='$actual'. Package may have been rebuilt.")
            }
        }
    }

    $i = 0
    foreach ($fix in @($Plan.appliedFixes)) {
        $name = if ($fix -is [hashtable]) { $fix['cmdlet'] } else { $fix.cmdlet }
        try { _MsixGuardPlanCmdlet -CmdletName $name -StepIndex $i | Out-Null }
        catch { $errors.Add($_.Exception.Message) }
        $i++
    }

    return [pscustomobject]@{
        IsValid = $errors.Count -eq 0
        Errors  = [string[]]$errors
    }
}


function Invoke-MsixRemediationPlan {
    <#
    .SYNOPSIS
        Replays a validated remediation plan against a package.

    .DESCRIPTION
        Applies every step in appliedFixes against -PackagePath, using the
        same single-sign-at-end semantics as Invoke-MsixPlaybook:

          1. Validate the plan against the package (Test-MsixRemediationPlan).
             Throw if validation fails.
          2. For each fix step, verify the cmdlet is from this module.
          3. Force -SkipSigning on every intermediate step.
          4. Sign once at the end (unless -SkipSigning is set).

        -DryRun prints the resolved call sequence without executing anything.

    .PARAMETER Plan
        MsixRemediationPlan to apply.

    .PARAMETER PackagePath
        The .msix file to act on.

    .PARAMETER OutputPath
        Write the result here (default: overwrite PackagePath).

    .PARAMETER DryRun
        Print the plan and exit without writing anything.

    .PARAMETER SkipSigning
        Signing controls forwarded to the final Invoke-MsixSigning call.

    .PARAMETER NoSign
        Signing controls forwarded to the final Invoke-MsixSigning call.

    .PARAMETER Pfx
        Signing controls forwarded to the final Invoke-MsixSigning call.

    .PARAMETER PfxPassword
        Signing controls forwarded to the final Invoke-MsixSigning call.
    .EXAMPLE
        $plan = Import-MsixRemediationPlan .\app-remediation.yaml
        Invoke-MsixRemediationPlan -Plan $plan -PackagePath app.msix `
            -Pfx cert.pfx -PfxPassword $pw
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [psobject]$Plan,
        [Parameter(Mandatory)] [string]$PackagePath,
        [string]$OutputPath,
        [switch]$DryRun,
        [Alias('NoSign')] [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    # --- Validation ---
    $check = Test-MsixRemediationPlan -Plan $Plan -PackagePath $PackagePath
    if (-not $check.IsValid) {
        throw "Remediation plan validation failed:`n" + ($check.Errors -join "`n")
    }

    $fixes = @($Plan.appliedFixes | Where-Object { $_ })
    Write-MsixLog -Level Info -Message "Remediation plan: $($fixes.Count) step(s) from '$($Plan.generatedBy)'"

    if ($DryRun) {
        foreach ($fix in $fixes) {
            $name = if ($fix -is [hashtable]) { $fix['cmdlet'] } else { $fix.cmdlet }
            $argMap = if ($fix -is [hashtable]) { $fix['args'] } else { $fix.args }
            $argsStr = if ($argMap) { ($argMap.GetEnumerator() | ForEach-Object { "-$($_.Key) '$($_.Value)'" }) -join ' ' } else { '' }
            Write-MsixLog -Level Info -Message "  [DryRun] $name $argsStr"
        }
        return
    }

    $current = if ($OutputPath -and $OutputPath -ne $PackagePath) {
        if ($PSCmdlet.ShouldProcess($OutputPath, 'Copy package for remediation')) {
            Copy-Item -LiteralPath $PackagePath -Destination $OutputPath -Force
        }
        $OutputPath
    } else { $PackagePath }

    $i = 0
    foreach ($fix in $fixes) {
        $i++
        $name   = if ($fix -is [hashtable]) { $fix['cmdlet'] } else { $fix.cmdlet }
        $argMap = if ($fix -is [hashtable]) { $fix['args']   } else { $fix.args   }

        $cmd = _MsixGuardPlanCmdlet -CmdletName $name -StepIndex ($i - 1)

        $callArgs = [ordered]@{}
        if ($argMap) { foreach ($k in $argMap.Keys) { $callArgs[$k] = $argMap[$k] } }

        if (-not $callArgs.ContainsKey('PackagePath') -and $cmd.Parameters.ContainsKey('PackagePath')) {
            $callArgs['PackagePath'] = $current
        }
        if ($cmd.Parameters.ContainsKey('SkipSigning') -and -not $callArgs.ContainsKey('SkipSigning')) {
            $callArgs['SkipSigning'] = $true
        }

        Write-MsixLog -Level Info -Message "  Step $i / $($fixes.Count): $name"
        if ($PSCmdlet.ShouldProcess($current, "Remediation plan step ${i}: $name")) {
            & $cmd @callArgs
        }
    }

    # --- Final sign ---
    if (-not $SkipSigning -and $Pfx) {
        if ($PSCmdlet.ShouldProcess($current, 'Sign package')) {
            Invoke-MsixSigning -PackagePath $current -Pfx $Pfx -PfxPassword $PfxPassword
        }
    } elseif (-not $SkipSigning -and -not $Pfx) {
        Write-MsixLog -Level Warning -Message 'No -Pfx supplied - package left unsigned. Pass -SkipSigning to suppress this warning.'
    }
}
