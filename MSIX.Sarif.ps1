# =============================================================================
# SARIF 2.1.0 emitter
# -----------------------------------------------------------------------------
# Converts the module's finding objects into a SARIF 2.1.0 document so the
# findings can be ingested by:
#   - GitHub Code Scanning (Security tab)
#   - Azure DevOps Advanced Security
#   - Microsoft Defender for DevOps
#   - any other tool that speaks SARIF
#
# Schema reference:
#   https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
#
# The mapping is deliberately conservative — one SARIF rule per distinct
# Category we have seen in the findings, one SARIF result per finding,
# severity mapped from our Severity field. We use logicalLocations to carry
# AppId / Evidence (where SARIF physical-file locations don't make sense for
# packaged content), and properties{} for the original Recommendation text.
# =============================================================================

# Map our severity vocabulary to SARIF result.level. Anything not listed
# falls back to 'note' (informational) so unknown severities never produce
# a SARIF that fails schema validation.
$script:MsixSarifSeverityMap = @{
    'Error'   = 'error'
    'Warning' = 'warning'
    'Info'    = 'note'
    'Debug'   = 'note'
}

# Curated short helpText strings per Category. Anything not listed gets a
# generic "MSIX module finding: <Category>" — the per-rule helpText shows
# up under the SARIF rule definition in the GitHub Security tab and is what
# operators read first.
$script:MsixSarifRuleHelp = @{
    'WorkingDirectory'                          = 'Application Executable lives in a subfolder with companion files but no working-directory wrap. PSF PsfLauncher with WorkingDirectory resolves it.'
    'ManifestFix:FileSystemWriteVirtualization' = 'Package writes to its install directory. The desktop6:FileSystemWriteVirtualization manifest declaration (Win10 19041+) is the cleanest fix; PSF FileRedirectionFixup works for older targets.'
    'ManifestFix:RegistryWriteVirtualization'   = 'Package writes to HKLM. The desktop6:RegistryWriteVirtualization manifest declaration is the modern fix; PSF RegLegacyFixup Hklm2Hkcu works for older targets.'
    'ManifestFix:StartupTask'                   = 'Run-key autostart entries do not fire under MSIX. Replace with windows.startupTask via uap5:Extension.'
    'ManifestFix:LoaderSearchPathOverride'      = 'DLL load failures inside the container. Declare additional probe paths via uap6:LoaderSearchPathOverride.'
    'ManifestFix:SharedFonts'                   = 'Package ships font files that are not registered via uap4:SharedFonts.'
    'FileRedirectionFixup'                      = 'Container process writes to a path the manifest does not let through. PSF FileRedirectionFixup redirects to per-user storage.'
    'RegLegacyFixups'                           = 'Container process writes to a registry hive the manifest virtualization layer does not let through. PSF RegLegacyFixup handles the per-key cases.'
    'UninstallerArtifact'                       = 'Uninstaller-looking files are baked into the package and do not function inside an MSIX container.'
    'UninstallRegistry'                         = 'Package Registry.dat contains Uninstall\* keys that are not used by MSIX.'
    'UpdaterArtifact'                           = 'Auto-update binaries or scheduled-task XMLs are present. Strip them so the container does not attempt host-side updates.'
    'PluginDirectory'                           = 'Directory looks like a runtime extension point (plugins/themes/add-ins). Selective virtualization carve-out keeps writes alive across sessions.'
    'CapabilityHints'                           = 'PE-imports suggest additional capabilities are required.'
    'VcRuntime'                                 = 'Package references VC++ runtime DLLs that are not bundled.'
    'DesktopShortcuts'                          = 'Package ships .lnk files under VFS desktop folders that would not be installed by MSIX deployment.'
    'AppExecutionAlias'                         = 'Top-level user-facing exe has no AppExecutionAlias.'
    'ShellExt'                                  = 'Legacy COM shellex handler in Registry.dat. Replace with modern desktop4/desktop5 manifest declaration.'
    'ShellVerb'                                 = 'Legacy plain-command shell verb in Registry.dat. Requires conversion to a CLSID-based handler before MSIX deployment.'
    'ComServer'                                 = 'COM server registration in Registry.dat. Declare via com:Extension so the container activates it correctly.'
    'NestedPackage'                             = 'Package contains nested installer .msix/.msi files. MSI cannot run inside the container; nested MSIX requires sideloading.'
    'MultiApp'                                  = 'Package declares multiple Applications sharing one VFS payload.'
    'PSF'                                       = 'Package already wraps applications with PsfLauncher.'
}

function ConvertTo-MsixSarif {
    <#
    .SYNOPSIS
        Converts MSIX finding objects into a SARIF 2.1.0 document.

    .DESCRIPTION
        Public converter used by Get-MsixStaticAnalysis -Sarif (and any
        future investigation cmdlet that wants to surface findings in
        SARIF form). Maps:

          findings -> sarif runs[0].results
          unique Categories -> sarif runs[0].tool.driver.rules
          Severity -> result.level (Error -> error, Warning -> warning, else -> note)
          PackagePath -> sarif runs[0].artifacts[0].location.uri
          AppId / Evidence -> result.locations[0].logicalLocations[]
          Recommendation -> result.properties.recommendation

        The output is a hashtable. ConvertTo-Json -Depth 100 -Compress
        produces a valid .sarif file; the helper does NOT serialise on
        your behalf because callers often want to tweak properties first
        or pipe to Out-File with an explicit encoding.

    .PARAMETER Findings
        Array of pscustomobject findings (must have Category, Severity,
        Symptom, Recommendation, Evidence, AppId fields).

    .PARAMETER PackagePath
        The package the findings apply to. Recorded as the single
        artifact location in the SARIF run.

    .PARAMETER Tool
        Display name of the tool/cmdlet that produced the findings.
        Surfaces as runs[0].tool.driver.name. Defaults to
        'MSIX.PowerShell'.

    .EXAMPLE
        Get-MsixStaticAnalysis -PackagePath app.msix -Sarif |
            ConvertTo-Json -Depth 100 |
            Out-File -FilePath app.sarif -Encoding utf8

    .OUTPUTS
        [hashtable] SARIF 2.1.0 document. Pipe through ConvertTo-Json to
        serialise.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]]$Findings,
        [Parameter(Mandatory)] [string]$PackagePath,
        [string]$Tool = 'MSIX.PowerShell'
    )

    # Tool version comes from the loaded module manifest; falling back to
    # a literal keeps the converter testable when the module isn't loaded.
    $modVersion = (Get-Module -Name MSIX -ErrorAction SilentlyContinue).Version
    if (-not $modVersion) { $modVersion = '0.0.0' }

    # Build the rules list (one per distinct Category seen in this batch).
    $uniqueCats = @($Findings | ForEach-Object { $_.Category } | Where-Object { $_ } | Sort-Object -Unique)
    $rules = foreach ($cat in $uniqueCats) {
        $help = if ($script:MsixSarifRuleHelp.ContainsKey($cat)) {
            $script:MsixSarifRuleHelp[$cat]
        } else {
            "MSIX module finding: $cat"
        }
        @{
            id              = "MSIX.$cat"
            name            = $cat
            shortDescription = @{ text = "MSIX heuristic: $cat" }
            fullDescription  = @{ text = $help }
            help             = @{ text = $help }
            defaultConfiguration = @{ level = 'note' }
            properties = @{
                category = $cat
                tags     = @('MSIX','packaging','heuristic')
            }
        }
    }

    # Convert findings to SARIF results.
    $packageUri = try { ([uri]$PackagePath).AbsoluteUri } catch { $PackagePath }

    $results = foreach ($f in $Findings) {
        if (-not $f.Category) { continue }
        $level = if ($script:MsixSarifSeverityMap.ContainsKey([string]$f.Severity)) {
            $script:MsixSarifSeverityMap[[string]$f.Severity]
        } else {
            'note'
        }

        $logicalLocations = @()
        if ($f.AppId) {
            $logicalLocations += @{
                name                = [string]$f.AppId
                fullyQualifiedName  = "AppId/$($f.AppId)"
                kind                = 'package'
            }
        }
        if ($f.Evidence) {
            $logicalLocations += @{
                name                = [string]$f.Evidence
                fullyQualifiedName  = "Evidence/$($f.Evidence)"
                kind                = 'resource'
            }
        }

        $location = @{
            physicalLocation = @{
                artifactLocation = @{
                    uri   = $packageUri
                    index = 0
                }
            }
        }
        if ($logicalLocations.Count -gt 0) {
            $location['logicalLocations'] = $logicalLocations
        }

        # Pull the evidence graph through if the analyzer emitted one
        # (every finding promoted through Merge-MsixFinding has it).
        # Surface as result.properties.evidence[] + result.properties.confidence
        # so reviewers can pivot to per-source provenance in dashboards.
        $evidenceItems = $null
        $confidence    = $null
        if ($f.PSObject.Properties.Match('EvidenceItems').Count -gt 0 -and $f.EvidenceItems) {
            $evidenceItems = @($f.EvidenceItems)
        }
        if ($f.PSObject.Properties.Match('Confidence').Count -gt 0) {
            $confidence = [double]$f.Confidence
        }

        $props = @{
            severity        = [string]$f.Severity
            category        = [string]$f.Category
            appId           = if ($f.AppId)    { [string]$f.AppId }    else { $null }
            evidence        = if ($f.Evidence) { [string]$f.Evidence } else { $null }
            recommendation  = [string]$f.Recommendation
        }
        if ($null -ne $confidence)    { $props['confidence']    = $confidence }
        if ($null -ne $evidenceItems) { $props['evidenceItems'] = $evidenceItems }

        @{
            ruleId   = "MSIX.$($f.Category)"
            level    = $level
            message  = @{
                text = [string]$f.Symptom
            }
            locations  = @($location)
            properties = $props
        }
    }

    return @{
        '$schema'  = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/schemas/sarif-schema-2.1.0.json'
        version    = '2.1.0'
        runs       = @(
            @{
                tool = @{
                    driver = @{
                        name            = $Tool
                        organization    = 'MSIX PowerShell module'
                        semanticVersion = [string]$modVersion
                        informationUri  = 'https://github.com/sanderdewit/msix'
                        rules           = @($rules)
                    }
                }
                artifacts = @(
                    @{
                        location = @{ uri = $packageUri }
                        roles    = @('analysisTarget')
                    }
                )
                results = @($results)
                columnKind = 'utf16CodeUnits'
            }
        )
    }
}
