# =============================================================================
# Unified evidence model + confidence scoring
# -----------------------------------------------------------------------------
# Every analyzer in the module (static scanner, heuristic finder, ProcMon
# parser, trace parser, PE-imports scanner, manifest cross-checker, ...)
# emits findings. Before this module, each analyzer used its own ad-hoc
# pscustomobject and the report was just a concatenation. That made three
# things hard:
#
#   1. Knowing whether the same problem was detected by multiple analyzers
#      ("the package writes to install dir" via static + Procmon + trace
#      should be ONE finding with three pieces of evidence, not three
#      separate findings).
#   2. Confidence scoring — every finding was binary, even when one analyzer
#      was 95% sure and another was 30% sure.
#   3. Auditability — operators couldn't tell WHICH signal triggered an
#      autofix, only that "the autofix fired".
#
# This file introduces a canonical evidence-bearing finding shape, math
# for combining evidence into a single confidence score, and helpers for
# merging findings across analyzers.
#
# Backwards-compatible by design: New-MsixFinding returns a pscustomobject
# that has every legacy field (Severity, Category, Symptom, Recommendation,
# Evidence, AppId) PLUS the new fields (Confidence, EvidenceItems[]). All
# existing call sites continue to work unchanged. ConvertTo-MsixFinding wraps
# a legacy pscustomobject with default weights so the orchestrator can
# normalise the whole report without touching 86 emission sites.
#
# Confidence math: probabilistic OR with a saturating ceiling at 1.
#   confidence = 1 - product(1 - w_i) for each evidence item w_i
# Rationale: independent signals reinforce each other but never reach
# certainty unless one of them IS certain. Three weight-0.5 signals
# combine to 1 - 0.5^3 = 0.875 (moderate-high). One weight-0.95 signal
# alone reaches 0.95. Two weight-0.3 signals combine to 0.51 (just under
# the autofix default threshold of 0.85, which is correct — two weak
# signals shouldn't justify mutation).
# =============================================================================

# Per-source default weights. Tuned conservatively — operators can override
# any individual evidence item by passing -Weight on Add-MsixEvidence.
$script:MsixEvidenceDefaultWeights = @{
    'procmon'         = 0.9    # observed at runtime; near-certain
    'trace-fixup'     = 0.9    # observed via PSF TraceFixup; near-certain
    'manifest'        = 0.8    # declared in AppxManifest; high confidence
    'registry-dat'    = 0.8    # observed in package's Registry.dat
    'pe-imports'      = 0.6    # PE imports suggest, don't prove
    'pe-strings'      = 0.5    # strings in the binary
    'filesystem'      = 0.5    # file-existence heuristic
    'static-analysis' = 0.5    # static scan finding
    'manifest-cross'  = 0.7    # cross-check against another manifest element
    'heuristic'       = 0.4    # weak generic signal
    'user-supplied'   = 1.0    # the operator passed it in by hand
}

# Per-severity default weights used by ConvertTo-MsixFinding when a legacy
# finding has no evidence items. Maps to roughly the same scale as the
# per-source table above.
$script:MsixEvidenceSeverityWeights = @{
    'Error'   = 0.95
    'Warning' = 0.70
    'Info'    = 0.40
    'Debug'   = 0.20
}

# Threshold gates. Operators can override per-call on Invoke-MsixAutoFixFromAnalysis.
#   >= MinConfidenceAutoFix : autofix fires
#   >= MinConfidenceReport  : surfaced as Recommendation only
#   <  MinConfidenceReport  : debug-level (suppressed by default)
$script:MsixEvidenceDefaultConfidenceAutoFix = 0.85
$script:MsixEvidenceDefaultConfidenceReport  = 0.50

function Get-MsixFindingConfidence {
    <#
    .SYNOPSIS
        Computes the roll-up confidence of a finding from its EvidenceItems[]
        using probabilistic OR.

    .DESCRIPTION
        confidence = 1 - product(1 - w_i)

        Returns 0.0 for findings with no evidence items, 1.0 if any single
        evidence item has weight 1.0. Clamps each weight to [0,1] before
        combining so a malformed entry can't push the result negative or
        above 1.0.

        Independent of Severity: severity is the analyst's classification
        of impact, not the analyst's confidence that the impact exists.

    .PARAMETER Finding
        A finding object (the shape returned by New-MsixFinding) or any
        object that exposes an EvidenceItems array of items with a
        numeric .Weight property.

    .OUTPUTS
        [double] in [0.0, 1.0]
    #>
    [CmdletBinding()]
    [OutputType([double])]
    param([Parameter(Mandatory, ValueFromPipeline)] $Finding)
    process {
        $items = @($Finding.EvidenceItems)
        if (-not $items -or $items.Count -eq 0) { return 0.0 }
        $compound = 1.0
        foreach ($e in $items) {
            $w = [double]$e.Weight
            if ($w -lt 0) { $w = 0 } elseif ($w -gt 1) { $w = 1 }
            $compound *= (1.0 - $w)
        }
        return [math]::Round(1.0 - $compound, 4)
    }
}

function New-MsixFinding {
    <#
    .SYNOPSIS
        Constructs a finding in the canonical evidence-graph shape.

    .DESCRIPTION
        Returns a pscustomobject with both the legacy fields (Severity,
        Category, Symptom, Recommendation, Evidence, AppId) so existing
        consumers stay green AND the new fields (Confidence,
        EvidenceItems[]) so future consumers can pivot on per-source
        provenance and confidence scores.

        Initial evidence items can be supplied via -EvidenceItems; they
        will be passed straight through to Get-MsixFindingConfidence to
        compute the initial Confidence. Use Add-MsixEvidence to add more
        items after construction.

    .PARAMETER Category
        Stable identifier — the same string SARIF emits as ruleId
        (prefixed with 'MSIX.'). Examples: 'WorkingDirectory',
        'ManifestFix:FileSystemWriteVirtualization', 'ShellExt'.

    .PARAMETER Severity
        Analyst's classification of impact. One of Error / Warning /
        Info / Debug.

    .PARAMETER Symptom
        Single human-readable sentence describing what was observed.

    .PARAMETER Recommendation
        Operator-facing remediation hint (cmdlet name + args, typically).
        Surfaces in SARIF result.properties.recommendation.

    .PARAMETER Evidence
        Legacy evidence string (single, free-form). Retained for the
        pscustomobject projection. Per-source structured evidence
        belongs in -EvidenceItems instead.

    .PARAMETER AppId
        The Application/@Id this finding applies to, when scoped to a
        single Application. $null for package-wide findings.

    .PARAMETER EvidenceItems
        Array of evidence entries (hashtables/pscustomobjects). Each
        entry should have at least Source and Weight; additional
        per-source properties (Path, Result, FilePath, etc.) ride along.

    .OUTPUTS
        [pscustomobject] PSTypeName 'MsixFinding'.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions', '',
        Justification = 'Pure constructor — returns a pscustomobject, no IO, no global state change. PSSA flags any New-* verb without seeing the body.')]
    param(
        [Parameter(Mandatory)] [string]$Category,
        [Parameter(Mandatory)] [ValidateSet('Error','Warning','Info','Debug')] [string]$Severity,
        [Parameter(Mandatory)] [string]$Symptom,
        [string]$Recommendation,
        [string]$Evidence,
        [string]$AppId,
        [object[]]$EvidenceItems = @()
    )

    $finding = [pscustomobject]@{
        PSTypeName     = 'MsixFinding'
        # Legacy fields kept verbatim so every existing consumer (SARIF,
        # autofix orchestrator, Get-MsixCompatibilityReport report) reads
        # the new shape without code changes.
        Severity       = $Severity
        Category       = $Category
        Symptom        = $Symptom
        Recommendation = $Recommendation
        Evidence       = $Evidence
        AppId          = $AppId
        # New fields — additive. Force the cast to [object[]] so PowerShell
        # doesn't unroll a one-element list to a scalar (breaks .Count).
        Confidence     = 0.0
        EvidenceItems  = [object[]] @($EvidenceItems)
    }
    $finding.Confidence = Get-MsixFindingConfidence -Finding $finding
    return $finding
}

function Add-MsixEvidence {
    <#
    .SYNOPSIS
        Appends an evidence item to a finding and recomputes Confidence.

    .DESCRIPTION
        Mutates the finding in place. The supplied -Source must be a known
        source name (see $script:MsixEvidenceDefaultWeights) OR the caller
        must pass an explicit -Weight to override the lookup.

        Extra named parameters are stored as properties of the evidence
        item alongside Source and Weight — e.g. -Path / -Result / -Operation
        for ProcMon evidence, -Import / -Module for PE-imports evidence.

    .PARAMETER Finding
        Finding object from New-MsixFinding (or a legacy finding promoted
        via ConvertTo-MsixFinding).

    .PARAMETER Source
        Provenance label. Should be one of: procmon, trace-fixup,
        manifest, registry-dat, pe-imports, pe-strings, filesystem,
        static-analysis, manifest-cross, heuristic, user-supplied.

    .PARAMETER Weight
        Override the default weight. Use only when you have a good reason
        — e.g. "this static-analysis signal happens to be unambiguous in
        this specific case" or "this Procmon hit is low confidence because
        it's intermittent".

    .PARAMETER Properties
        Hashtable of extra per-source properties to attach to the evidence
        item. Anything goes here; SARIF picks it up verbatim.

    .OUTPUTS
        The same finding object (for fluent chaining: New-MsixFinding ...
        | Add-MsixEvidence ...).
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Finding,
        [Parameter(Mandatory)] [string]$Source,
        # When -Weight isn't passed, we look up the per-source default
        # (or 0.3 for an unknown source). When it IS passed, we honour
        # whatever value the caller gave — INCLUDING negative values,
        # which are clamped to 0 inside Get-MsixFindingConfidence (the
        # "out of range" test relies on that).
        # Detecting "passed vs not passed" via $PSBoundParameters so a
        # legitimate -Weight -2 doesn't accidentally collide with a
        # sentinel.
        [double]$Weight,
        [hashtable]$Properties
    )
    process {
        if (-not $PSBoundParameters.ContainsKey('Weight')) {
            if ($script:MsixEvidenceDefaultWeights.ContainsKey($Source)) {
                $Weight = $script:MsixEvidenceDefaultWeights[$Source]
            } else {
                $Weight = 0.3   # unknown source: weak default, never 0
            }
        }
        $entry = [ordered]@{ Source = $Source; Weight = [double]$Weight }
        if ($Properties) {
            foreach ($k in $Properties.Keys) { $entry[$k] = $Properties[$k] }
        }
        # Assign as a real [object[]]. The forced cast keeps PowerShell
        # from unwrapping a single-element array, which would otherwise
        # collapse "one evidence item" to a scalar and break .Count
        # checks downstream.
        $Finding.EvidenceItems = [object[]] (@($Finding.EvidenceItems) + [pscustomobject]$entry)
        $Finding.Confidence    = Get-MsixFindingConfidence -Finding $Finding
        return $Finding
    }
}

function ConvertTo-MsixFinding {
    <#
    .SYNOPSIS
        Converts a legacy pscustomobject finding into a MsixFinding without
        touching the original analyzer that emitted it.

    .DESCRIPTION
        The orchestrator (Get-MsixCompatibilityReport) calls this on every
        finding before they go into the report, so consumers downstream see
        a uniform shape. Legacy findings with no structured evidence get a
        single synthetic evidence item whose Source = the analyzer-origin
        guess (defaults to 'static-analysis') and whose Weight matches the
        per-severity default table. This way:

          - Error findings come out at confidence 0.95
          - Warning findings at 0.70
          - Info findings at 0.40

        ... matching what the existing autofix orchestrator implicitly
        treated as "fire" vs "recommend" vs "ignore". No behavioural change
        for callers that don't ask for the confidence field.

        If the legacy finding already had an EvidenceItems[] array, this is
        a no-op (the finding is already promoted).

    .PARAMETER Finding
        Legacy pscustomobject finding (Severity/Category/Symptom/...).

    .PARAMETER Source
        Source label to attach to the synthetic evidence item. Defaults
        to 'static-analysis' which is the most common origin.

    .OUTPUTS
        [pscustomobject] PSTypeName 'MsixFinding'.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)] $Finding,
        [string]$Source = 'static-analysis'
    )
    process {
        if (-not $Finding) { return $null }
        # Already promoted — don't re-wrap.
        if ($Finding.PSObject.TypeNames -contains 'MsixFinding' -and `
            $Finding.PSObject.Properties.Match('EvidenceItems').Count -gt 0) {
            return $Finding
        }
        $severity = if ($Finding.Severity) { [string]$Finding.Severity } else { 'Info' }
        $weight   = if ($script:MsixEvidenceSeverityWeights.ContainsKey($severity)) {
            $script:MsixEvidenceSeverityWeights[$severity]
        } else { 0.4 }

        $f = New-MsixFinding `
            -Category       ([string]$Finding.Category) `
            -Severity       $severity `
            -Symptom        ([string]$Finding.Symptom) `
            -Recommendation ([string]$Finding.Recommendation) `
            -Evidence       ([string]$Finding.Evidence) `
            -AppId          ([string]$Finding.AppId)

        $props = @{}
        if ($Finding.Evidence) { $props['EvidenceText'] = [string]$Finding.Evidence }

        Add-MsixEvidence -Finding $f -Source $Source -Weight $weight -Properties $props | Out-Null

        # Tag the synthetic-evidence wrapper so the orchestrator can tell
        # "this came through the legacy adapter; let it through regardless
        # of confidence" apart from "this is a low-weight new-shape
        # finding the operator intentionally produced; respect the gate".
        $f | Add-Member -NotePropertyName 'PromotedFromLegacy' -NotePropertyValue $true -Force
        return $f
    }
}

function Merge-MsixFinding {
    <#
    .SYNOPSIS
        Merges multiple MsixFinding objects covering the same Category +
        AppId into one finding by combining their evidence lists.

    .DESCRIPTION
        Two findings are considered "the same finding" when they have the
        same Category AND the same AppId (null counts as a match). All
        evidence items from the duplicates are concatenated onto the
        primary finding and Confidence is recomputed.

        Severity stays as the maximum of the two (Error > Warning > Info >
        Debug); Symptom and Recommendation come from the higher-severity
        finding (so the "best" wording survives).

        This is the function the orchestrator runs after concatenating
        analyzer outputs. Static + Procmon + heuristic all detecting the
        same install-dir-write issue collapse from three rows into one
        row with three pieces of evidence.

    .PARAMETER Findings
        Array of MsixFinding (or promotable legacy findings — they are
        promoted on the fly).

    .OUTPUTS
        [object[]] de-duplicated MsixFinding array.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([Parameter(Mandatory, ValueFromPipeline)] [object[]]$Findings)

    begin {
        $severityRank = @{ 'Error'=3; 'Warning'=2; 'Info'=1; 'Debug'=0 }
        $byKey        = @{}
    }
    process {
        # Promote any not-yet-promoted entries, then fold each into $byKey
        # keyed by (Category, AppId). Without a real process block here,
        # pipeline input would drop every batch except the last one.
        foreach ($raw in $Findings) {
            if (-not $raw) { continue }
            $f = if ($raw.PSObject.TypeNames -contains 'MsixFinding' -and `
                     $raw.PSObject.Properties.Match('EvidenceItems').Count -gt 0) {
                $raw
            } else {
                ConvertTo-MsixFinding -Finding $raw
            }
            if (-not $f) { continue }

            $appId = if ($null -ne $f.AppId) { $f.AppId } else { '' }
            $key = ('{0}|{1}' -f $f.Category, $appId)
            if (-not $byKey.ContainsKey($key)) {
                $byKey[$key] = $f
                continue
            }
            $primary = $byKey[$key]
            # Concatenate evidence (de-dupe identical Source+Path tuples).
            $combined = @($primary.EvidenceItems) + @($f.EvidenceItems)
            $seen = New-Object System.Collections.Generic.HashSet[string]
            $deduped = @($combined | Where-Object {
                $sig = ('{0}|{1}' -f $_.Source, ($_.PSObject.Properties['Path'] | ForEach-Object Value))
                $seen.Add($sig)
            })
            $primary.EvidenceItems = [object[]]$deduped
            $primary.Confidence    = Get-MsixFindingConfidence -Finding $primary

            # Promote severity to the higher rank.
            $pRank = if ($severityRank.ContainsKey($primary.Severity)) { $severityRank[$primary.Severity] } else { 1 }
            $fRank = if ($severityRank.ContainsKey($f.Severity))       { $severityRank[$f.Severity] }       else { 1 }
            if ($fRank -gt $pRank) {
                $primary.Severity       = $f.Severity
                $primary.Symptom        = $f.Symptom
                $primary.Recommendation = $f.Recommendation
            }
        }
    }
    end {
        return @($byKey.Values)
    }
}

function ConvertTo-MsixLegacyFinding {
    <#
    .SYNOPSIS
        Strips the evidence list and confidence field, returning the
        old-shape pscustomobject. Useful for callers that haven't been
        updated and still expect the original fields only.

    .DESCRIPTION
        New-MsixFinding already includes every legacy field on the
        object, so this is mostly a passthrough; the explicit conversion
        exists so callers can request the narrowed shape without relying
        on PowerShell's quiet property-tolerance.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory, ValueFromPipeline)] $Finding)
    process {
        [pscustomobject]@{
            Severity       = $Finding.Severity
            Category       = $Finding.Category
            Symptom        = $Finding.Symptom
            Recommendation = $Finding.Recommendation
            Evidence       = $Finding.Evidence
            AppId          = $Finding.AppId
        }
    }
}
