# =============================================================================
# Playbook bus
# -----------------------------------------------------------------------------
# A playbook is a curated sequence of fixer cmdlet calls that targets a
# specific package fingerprint (Identity Name regex, signer subject regex,
# Application Executable leaf regex, or any combination). The bus loads
# playbooks from PowerShell files under .\playbooks\, matches them against a
# package, and runs the steps as a single signed pass.
#
# Why this exists:
#   - EXAMPLES.md is documentation — non-executable.
#   - The auto-fix orchestrator is fingerprint-blind (it reacts to findings).
#   - For well-known applications we want a deterministic, named recipe that
#     captures domain knowledge: which fixers, in which order, with which
#     arguments. Playbooks are that recipe.
#
# Anatomy of a playbook (.ps1 file that returns a hashtable):
#
#   @{
#       Name        = 'Notepad++'
#       Description = 'Sparse shell merge + write virtualisation exclusions'
#       Match       = @{
#           IdentityName     = '^Notepad\+\+$|^Notepad$'      # regex
#           ExecutableLeaf   = '^notepad\+\+\.exe$'           # regex (optional)
#           PublisherSubject = 'Notepad\+\+ Team'             # regex (optional)
#       }
#       Steps = @(
#           @{ Cmdlet = 'Import-MsixSparseShellExtension'; Args = @{ SparsePackagePath = 'VFS\ProgramFilesX64\Notepad++\contextMenu\NppShell.msix' } }
#           @{ Cmdlet = 'Set-MsixFileSystemWriteVirtualization'; Args = @{ ExcludedDirectories = @(
#                '$(KnownFolder:LocalAppData)',
#                '$(KnownFolder:RoamingAppData)',
#                'VFS/ProgramFilesX64/Notepad++/plugins'
#                'VFS/ProgramFilesX64/Notepad++/themes'
#                'VFS/ProgramFilesX64/Notepad++/userDefineLangs'
#             ) } }
#           @{ Cmdlet = 'Remove-MsixUpdaterArtifact';  Args = @{} }
#           @{ Cmdlet = 'Remove-MsixUninstallerArtifact'; Args = @{} }
#       )
#   }
#
# Match semantics: ALL conditions in -Match must succeed (AND across keys).
# A missing condition is "any". An empty Match block matches everything.
# =============================================================================

# Default playbook search roots. Callers can append more via -SearchPath.
$script:MsixPlaybookSearchRoots = @(
    (Join-Path -Path $PSScriptRoot -ChildPath 'playbooks')
)

function Get-MsixPlaybook {
    <#
    .SYNOPSIS
        Loads playbook files from disk and returns the parsed objects.

    .DESCRIPTION
        Scans every *.ps1 under -SearchPath (default: the module's
        playbooks\ folder), dot-sources each, and collects the returned
        hashtables. Bad playbooks (missing Name, missing Steps, etc.) are
        skipped with a warning so one bad file doesn't break the bus.

    .PARAMETER SearchPath
        Override the default search roots. Pass one or more directory
        paths; each is scanned recursively for *.ps1 files.

    .OUTPUTS
        [pscustomobject[]] one per loaded playbook (PSTypeName MsixPlaybook).

    .EXAMPLE
        Get-MsixPlaybook | Format-Table Name, Description
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([string[]]$SearchPath)

    $roots = @($SearchPath; $script:MsixPlaybookSearchRoots) | Where-Object { $_ } | Sort-Object -Unique

    $loaded = @()
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($file in Get-ChildItem -LiteralPath $root -Filter '*.ps1' -File -Recurse -ErrorAction SilentlyContinue) {
            try {
                $pb = & $file.FullName
                if (-not $pb)                       { Write-MsixLog -Level Warning -Message "Playbook '$($file.Name)' returned nothing — skipped."; continue }
                if (-not $pb.Name)                  { Write-MsixLog -Level Warning -Message "Playbook '$($file.Name)' has no Name — skipped."; continue }
                if (-not $pb.Steps -or $pb.Steps.Count -eq 0) { Write-MsixLog -Level Warning -Message "Playbook '$($pb.Name)' has no Steps — skipped."; continue }
                $loaded += [pscustomobject]@{
                    PSTypeName  = 'MsixPlaybook'
                    Name        = [string]$pb.Name
                    Description = [string]($pb.Description)
                    Match       = if ($pb.Match) { $pb.Match } else { @{} }
                    Steps       = @($pb.Steps)
                    SourceFile  = $file.FullName
                }
            } catch {
                Write-MsixLog -Level Warning -Message "Failed to load playbook '$($file.Name)': $_"
            }
        }
    }
    return $loaded
}

function Find-MsixPlaybook {
    <#
    .SYNOPSIS
        Returns the playbook(s) whose Match block fits the supplied package
        fingerprint.

    .DESCRIPTION
        Reads the package's manifest (no full unpack — uses Get-MsixManifest)
        to extract Identity Name, the first Application's Executable leaf,
        and Publisher subject. Then evaluates each loaded playbook's Match
        block against those values. Multiple playbooks can match — the
        caller chooses (e.g. by Name) which to run.

        Match keys (all optional; missing key = any):
          IdentityName       regex matched against Package/Identity/@Name
          ExecutableLeaf     regex matched against the first Application
                             Executable attribute's leaf filename
          PublisherSubject   regex matched against Package/Identity/@Publisher

    .PARAMETER PackagePath
        .msix or AppxManifest.xml to fingerprint.

    .PARAMETER SearchPath
        Forwarded to Get-MsixPlaybook.

    .OUTPUTS
        [pscustomobject[]] matched playbooks. Empty array when none match.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [string[]]$SearchPath
    )

    $playbooks = Get-MsixPlaybook -SearchPath $SearchPath
    if (-not $playbooks) { return @() }

    [xml]$manifest = Get-MsixManifest -Path $PackagePath
    $identityName    = $manifest.Package.Identity.GetAttribute('Name')
    $publisherSubj   = $manifest.Package.Identity.GetAttribute('Publisher')
    $firstApp        = @($manifest.Package.Applications.Application) | Select-Object -First 1
    $exeAttr         = if ($firstApp) { $firstApp.GetAttribute('Executable') } else { $null }
    $exeLeaf         = if ($exeAttr) { $exeAttr.Split('\')[-1] } else { $null }

    $matched = @()
    foreach ($pb in $playbooks) {
        $m = $pb.Match
        if ($m.IdentityName     -and $identityName  -notmatch $m.IdentityName)     { continue }
        if ($m.ExecutableLeaf   -and ($null -eq $exeLeaf -or $exeLeaf -notmatch $m.ExecutableLeaf)) { continue }
        if ($m.PublisherSubject -and $publisherSubj -notmatch $m.PublisherSubject) { continue }
        $matched += $pb
    }
    return $matched
}

function Invoke-MsixPlaybook {
    <#
    .SYNOPSIS
        Runs the Steps of a playbook against a package as a single signed
        pass (or unsigned with -SkipSigning / -NoSign).

    .DESCRIPTION
        Each Step is a hashtable with two keys:
          Cmdlet = '<Cmdlet-Name>'
          Args   = @{ Param1 = 'Value1'; ... }

        For every step the playbook bus:
          1. Verifies the cmdlet exists and is from this module (refuses to
             invoke arbitrary commands).
          2. Injects -PackagePath (or -MSIXFolder when the cmdlet has it
             instead) so the playbook author doesn't repeat it for every
             step.
          3. Forces -SkipSigning on every intermediate step so the final
             signing pass is a single deterministic call at the end.
          4. With -DryRun, prints the plan and stops without running.

    .PARAMETER PackagePath
        .msix to act on.

    .PARAMETER Playbook
        A playbook object from Get-MsixPlaybook / Find-MsixPlaybook, OR a
        playbook NAME — when a name is given, the bus matches it against
        Find-MsixPlaybook results, requiring an exact name match.

    .PARAMETER DryRun
        Print the resolved plan and exit without executing.

    .PARAMETER OutputPath / Pfx / PfxPassword / SkipSigning
        Forwarded to the final signing call. Same semantics as
        Invoke-MsixAutoFixFromAnalysis.

    .EXAMPLE
        Find-MsixPlaybook -PackagePath app.msix |
            Invoke-MsixPlaybook -PackagePath app.msix -DryRun
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory, ValueFromPipeline)] $Playbook,
        [switch]$DryRun,
        [string]$OutputPath,
        [Alias('NoSign')] [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    process {
    # Resolve playbook by name if a string was supplied.
    if ($Playbook -is [string]) {
        $candidates = @(Find-MsixPlaybook -PackagePath $PackagePath | Where-Object Name -eq $Playbook)
        if ($candidates.Count -eq 0) { throw "No playbook named '$Playbook' matches '$PackagePath'." }
        if ($candidates.Count -gt 1) { throw "Multiple playbooks named '$Playbook' — pass the object instead." }
        $Playbook = $candidates[0]
    }

    Write-MsixLog -Level Info -Message "Playbook: $($Playbook.Name) ($($Playbook.Steps.Count) step(s))"

    $current = if ($OutputPath -and ($OutputPath -ne $PackagePath)) {
        if (-not $DryRun) { Copy-Item -LiteralPath $PackagePath -Destination $OutputPath -Force }
        $OutputPath
    } else { $PackagePath }

    $i = 0
    foreach ($step in $Playbook.Steps) {
        $i++
        $cmdletName = [string]$step.Cmdlet
        $cmd        = Get-Command -Name $cmdletName -ErrorAction SilentlyContinue
        if (-not $cmd) { throw "Step $i references unknown cmdlet '$cmdletName'." }
        if ($cmd.Source -ne 'MSIX' -and $cmd.ModuleName -ne 'MSIX') {
            # Defence-in-depth — only run cmdlets owned by this module.
            throw "Step $i references '$cmdletName' which is not from the MSIX module (source: $($cmd.Source))."
        }

        $callArgs = @{}
        if ($step.Args) { foreach ($k in $step.Args.Keys) { $callArgs[$k] = $step.Args[$k] } }

        # Inject the right path parameter — Add-MsixCapability/PSF/etc. use
        # -PackagePath; a few _MsixFolder-style internals use -MSIXFolder
        # which we never route here.
        if (-not $callArgs.ContainsKey('PackagePath') -and $cmd.Parameters.ContainsKey('PackagePath')) {
            $callArgs['PackagePath'] = $current
        }
        # Force SkipSigning on every intermediate step so we sign once at end.
        if ($cmd.Parameters.ContainsKey('SkipSigning') -and -not $callArgs.ContainsKey('SkipSigning')) {
            $callArgs['SkipSigning'] = $true
        }

        Write-MsixLog -Level Info -Message "  Step $i / $($Playbook.Steps.Count): $cmdletName"
        foreach ($k in $callArgs.Keys) { Write-MsixLog -Level Debug -Message "    $k = $($callArgs[$k])" }

        if (-not $DryRun -and $PSCmdlet.ShouldProcess($current, "Playbook '$($Playbook.Name)' step ${i}: $cmdletName")) {
            & $cmd @callArgs
        }
    }

    if ($DryRun) {
        Write-MsixLog -Level Info -Message '[DryRun] Plan only — package unchanged.'
        return [pscustomobject]@{
            Playbook    = $Playbook.Name
            PackagePath = $current
            DryRun      = $true
            Steps       = $Playbook.Steps.Count
        }
    }

    if (-not $SkipSigning) {
        Write-MsixLog -Level Info -Message '==> Sign'
        Invoke-MsixSigning -PackagePath $current -Pfx $Pfx -PfxPassword $PfxPassword
    } else {
        Write-MsixLog -Level Info -Message 'NoSign requested; package left unsigned.'
    }

    return [pscustomobject]@{
        Playbook    = $Playbook.Name
        PackagePath = $current
        DryRun      = $false
        Steps       = $Playbook.Steps.Count
    }
    }   # end process block
}
