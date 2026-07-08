# =============================================================================
# MSIX auto-fix orchestrators (split from MSIX.Heuristics.ps1 in issue #38)
# -----------------------------------------------------------------------------
# Invoke-MsixAutoFix chains a heuristic curated set of mutators.
# Invoke-MsixAutoFixFromAnalysis plans the same set from an analyzer
# report (Get-MsixStaticAnalysis / Get-MsixCompatibilityReport).
# Mutators live in MSIX.PackageMutators.ps1; scanners in MSIX.Scanners.ps1.
# =============================================================================

#region AutoFix orchestrator -----------------------------------------------

function Invoke-MsixAutoFix {
    <#
    .SYNOPSIS
        Runs a curated set of heuristic auto-fixes against a package in a
        deterministic order, signing only at the very end.

    .DESCRIPTION
        Stages (applied in a staged, deterministic order):

          PrePsf
            - RemoveUninstallers      strip uninstall*.exe and friends
            - RemoveUpdaters          strip auto-updater binaries + Tasks XMLs
            - BumpVersion             bump the package version
          Recommended
            - AddCapabilities         add common capabilities
            - AddAliases              register AppExecutionAlias for top-level exes
            - InjectPsf               run Add-MsixPsfV2 with the fixups you supply
            - BundleVcRuntimes        copy missing VC runtime DLLs in
          Optional
            - AddSplashImage          show a splash while a startScript runs

        Every stage writes back into the SAME file (or -OutputPath if set) and
        passes -SkipSigning so we sign once at the end. Use -DryRun to see
        which stages would fire without mutating the package.

    .PARAMETER PackagePath
        The .msix to mutate.

    .PARAMETER Capabilities
        Names to add via Add-MsixCapability (rescap or standard, looked up
        against Get-MsixKnownCapability).

    .PARAMETER PsfFixups
        Forwarded to Add-MsixPsfV2.

    .PARAMETER PsfAppOptions
        Forwarded to Add-MsixPsfV2.

    .PARAMETER PsfWorkingDirectory
        Forwarded to Add-MsixPsfV2.

    .PARAMETER PsfAdditionalFiles
        Forwarded to Add-MsixPsfV2.
    .PARAMETER AddAliases
        If set, runs Add-MsixAlias for top-level user-facing executables.
        When -AliasAppIds is supplied, aliases are added only for those apps;
        otherwise Get-MsixAliasCandidate selects candidates automatically and
        skips apps that already have an alias.

    .PARAMETER AliasAppIds
        Optional list of Application IDs to alias. Implies -AddAliases.
        When omitted, Get-MsixAliasCandidate makes the selection.

    .PARAMETER VcRuntimeSourceFolder
        If set, runs Add-MsixVcRuntimeBundle with this source folder.

    .PARAMETER SplashImagePath
        If set, runs Add-MsixSplashScreen after PSF.

    .PARAMETER SplashAppId
        If set, runs Add-MsixSplashScreen after PSF.
    .PARAMETER VersionBumpComponent
        If set, runs Update-MsixPackageVersion before any other stage.

    .PARAMETER RemoveUninstallers
        If $true, strips uninstaller-looking files first.

    .PARAMETER RemoveUpdaters
        If $true, strips auto-updater binaries and scheduled-task XMLs.

    .PARAMETER OutputPath
        If set, all writes go here instead of overwriting -PackagePath.

    .PARAMETER DryRun
        Report which stages would fire, then return — no mutation, no signing.

    .PARAMETER Pfx
        Signing certificate for the final pass.

    .PARAMETER PfxPassword
        Signing certificate for the final pass.
    .EXAMPLE
        Invoke-MsixAutoFix -PackagePath app.msix `
            -RemoveUninstallers `
            -Capabilities runFullTrust,internetClient `
            -PsfFixups @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' ) `
            -VersionBumpComponent Build `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the per-stage scriptblocks built up via _Stage.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,

        # PrePsf stage
        [switch]$RemoveUninstallers,
        [switch]$RemoveUpdaters,
        [switch]$RemoveDesktopShortcuts,
        [ValidateSet('Major','Minor','Build','Revision')]
        [string]$VersionBumpComponent,

        # Recommended stage
        [string[]]$Capabilities,
        [switch]$AddFontExtension,
        [switch]$AddAliases,
        [string[]]$AliasAppIds,
        [hashtable[]]$PsfFixups,
        [hashtable[]]$PsfAppOptions,
        [string]$PsfWorkingDirectory,
        [string[]]$PsfAdditionalFiles,
        [string]$VcRuntimeSourceFolder,

        # Optional stage
        [string]$SplashImagePath,
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$'
        )]
        [string]$SplashAppId,

        # Output / signing
        [string]$OutputPath,
        [switch]$DryRun,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    $stages = [System.Collections.Generic.List[object]]::new()
    function _Stage([string]$Name, [scriptblock]$Action) {
        $stages.Add([pscustomobject]@{ Name = $Name; Action = $Action })
    }

    # All intermediate stages must write through OutputPath if set so the
    # original is preserved; subsequent stages then read from OutputPath.
    $current = $PackagePath
    if ($OutputPath -and -not $DryRun) {
        Copy-Item -LiteralPath $PackagePath -Destination $OutputPath -Force
        $current = $OutputPath
    }

    if ($RemoveUninstallers) {
        _Stage 'PrePsf:RemoveUninstallers' {
            Remove-MsixUninstallerArtifact -PackagePath $current -SkipSigning
        }
    }
    if ($RemoveUpdaters) {
        _Stage 'PrePsf:RemoveUpdaters' {
            Remove-MsixUpdaterArtifact -PackagePath $current -SkipSigning
        }
    }
    if ($RemoveDesktopShortcuts) {
        _Stage 'PrePsf:RemoveDesktopShortcuts' {
            Remove-MsixDesktopShortcut -PackagePath $current -SkipSigning
        }
    }
    if ($VersionBumpComponent) {
        _Stage 'PrePsf:BumpVersion' {
            Update-MsixPackageVersion -PackagePath $current -Component $VersionBumpComponent -SkipSigning
        }
    }
    if ($Capabilities) {
        _Stage 'Recommended:AddCapabilities' {
            Add-MsixCapability -PackagePath $current -Names $Capabilities -SkipSigning
        }
    }
    if ($AddFontExtension) {
        _Stage 'Recommended:AddFontExtension' {
            $fonts = Get-MsixFontCandidate -PackagePath $current
            if ($fonts) {
                Add-MsixFontExtension -PackagePath $current -FontPaths @($fonts | Select-Object -ExpandProperty Path) -SkipSigning
            } else {
                Write-MsixLog -Level Info -Message 'AddFontExtension: no font files found in package.'
            }
        }
    }
    if ($AddAliases -or $AliasAppIds) {
        _Stage 'Recommended:AddAliases' {
            # If explicit AliasAppIds were supplied, honour them; otherwise let
            # Get-MsixAliasCandidate pick the top-level user-facing executables.
            if ($AliasAppIds) {
                Add-MsixAlias -PackagePath $current -AppIds $AliasAppIds -SkipSigning
            } else {
                $candidates = @(Get-MsixAliasCandidate -PackagePath $current |
                    Where-Object { -not $_.AlreadyHasAlias })
                if ($candidates) {
                    Add-MsixAlias -PackagePath $current `
                        -AppIds @($candidates | Select-Object -ExpandProperty AppId) `
                        -SkipSigning
                } else {
                    Write-MsixLog -Level Info -Message 'AddAliases: no eligible alias candidates (all apps already aliased or filtered out).'
                }
            }
        }
    }
    if ($PsfFixups -or $PsfAppOptions) {
        _Stage 'Recommended:InjectPsf' {
            $psfArgs = @{
                PackagePath = $current
                Fixups      = $PsfFixups
                SkipSigning = $true
            }
            if ($PsfAppOptions)         { $psfArgs['AppOptions']        = $PsfAppOptions }
            if ($PsfWorkingDirectory)   { $psfArgs['WorkingDirectory']  = $PsfWorkingDirectory }
            if ($PsfAdditionalFiles)    { $psfArgs['AdditionalFiles']   = $PsfAdditionalFiles }
            Add-MsixPsfV2 @psfArgs
        }
    }
    if ($VcRuntimeSourceFolder) {
        _Stage 'Recommended:BundleVcRuntimes' {
            Add-MsixVcRuntimeBundle -PackagePath $current -SourceFolder $VcRuntimeSourceFolder -SkipSigning
        }
    }
    if ($SplashImagePath -and $SplashAppId) {
        _Stage 'Optional:AddSplashImage' {
            Add-MsixSplashScreen -PackagePath $current -ImagePath $SplashImagePath -AppId $SplashAppId -SkipSigning
        }
    }

    if ($DryRun) {
        Write-MsixLog -Level Info -Message "DryRun: would run $($stages.Count) stages."
        return [pscustomobject]@{
            PackagePath = $PackagePath
            Stages      = $stages.Name
            DryRun      = $true
        }
    }

    if ($PSCmdlet.ShouldProcess($current, "Apply $($stages.Count) auto-fix stages")) {
        foreach ($s in $stages) {
            Write-MsixLog -Level Info -Message "==> $($s.Name)"
            & $s.Action
        }
    }

    # Sign once at the end
    if (-not $stages -or -not $stages.Count) {
        Write-MsixLog -Level Info -Message 'No stages selected; nothing to do.'
        return
    }
    Write-MsixLog -Level Info -Message '==> Sign'
    Invoke-MsixSigning -PackagePath $current -Pfx $Pfx -PfxPassword $PfxPassword

    return [pscustomobject]@{
        PackagePath = $current
        Stages      = $stages.Name
        DryRun      = $false
    }
}


function Invoke-MsixAutoFixFromAnalysis {
    <#
    .SYNOPSIS
        Takes the report produced by Invoke-MsixInvestigation /
        Get-MsixCompatibilityReport and translates each finding into the
        right fixer cmdlet, then runs them sequentially with one signing
        pass at the end. The connect-the-dots layer between analysis and
        remediation.

    .DESCRIPTION
        Maps Findings.Category to a concrete cmdlet:

          UninstallerArtifact                 -> Remove-MsixUninstallerArtifact
          UpdaterArtifact                      -> Remove-MsixUpdaterArtifact (skip with -IgnoreUpdaters)
          AppExecutionAlias                    -> Add-MsixAlias (only AppIds without an existing alias)
          VcRuntime                            -> Add-MsixVcRuntimeBundle (needs -VcRuntimeSourceFolder)
          VcRuntime                            -> Add-MsixPackageDependency (with -VcRuntimeAsPackageDependency)
          ManifestFix:PackagedService          -> Add-MsixService
          ManifestFix:ShellHandlerExtension    -> Add-MsixShellHandlerExtension
          ManifestFix:PackageCertificate       -> Add-MsixPackageCertificate (opt-in via -DeclarePackageCertificates)
          BundledRuntime                       -> strip + Add-MsixRuntimeDependency (opt-in via -DeduplicateBundledRuntime + framework identity)
          ManifestFix:FileSystemWriteVirt..    -> Set-MsixFileSystemWriteVirtualization
          ManifestFix:RegistryWriteVirt..      -> Set-MsixRegistryWriteVirtualization
          ManifestFix:StartupTask              -> Add-MsixStartupTask  (needs -StartupTaskAppId / -StartupTaskName)
          ManifestFix:LoaderSearchPathOverride -> Add-MsixLoaderSearchPathOverride (needs -LoaderPaths)
          FileRedirectionFixup                 -> Add-MsixPsfV2 with the SuggestedFixups already in the report

        Categories that always need extra inputs (VcRuntime, StartupTask,
        LoaderSearchPathOverride) are skipped with a warning unless the
        relevant -* parameter is supplied.

        -DryRun lists the planned fixes without doing anything.

    .PARAMETER Report
        Output of Invoke-MsixInvestigation or Get-MsixCompatibilityReport.

    .PARAMETER PackagePath
        Override (default: $Report.PackagePath).

    .PARAMETER PreferManifestOverPsf
        When both a PSF and a manifest fix are suggested for the same symptom,
        pick the manifest one (modern Windows builds only).
        Default: $true.

    .PARAMETER DeclarePackageCertificates
        Opt in to declaring bundled-but-undeclared .cer/.crt files via the
        windows.certificates extension (Add-MsixPackageCertificate). Off by
        default: installing a certificate into a store is a trust decision.

    .PARAMETER PackageCertificateStore
        Store for -DeclarePackageCertificates: Root, CA, TrustedPeople
        (default) or TrustedPublisher.

    .PARAMETER DeduplicateBundledRuntime
        Opt in to stripping detected bundled runtimes (JRE/.NET/Python) and
        wiring the app to a shared framework package instead. Destructive -
        requires the three RuntimeFramework* identity parameters.

    .PARAMETER RuntimeFrameworkName
        Identity Name of the framework package (New-MsixFrameworkPackage).

    .PARAMETER RuntimeFrameworkMinVersion
        Minimum framework version to depend on.

    .PARAMETER RuntimeFrameworkPublisher
        Publisher DN of the framework package.

    .PARAMETER VcRuntimeSourceFolder
        VS Redist folder; required when a VcRuntime finding is in the report.

    .PARAMETER VcRuntimeAsPackageDependency
        For VcRuntime findings, declare a VCLibs PackageDependency instead of
        bundling DLLs. Requires -VcRuntimeMinVersion.

    .PARAMETER VcRuntimeDependencyName
        Framework dependency name to declare when -VcRuntimeAsPackageDependency
        is used. Defaults to Microsoft.VCLibs.140.00.UWPDesktop.

    .PARAMETER VcRuntimeMinVersion
        Minimum framework version for -VcRuntimeAsPackageDependency.

    .PARAMETER StartupTaskAppId
        Required when a ManifestFix:StartupTask finding is in the report.

    .PARAMETER StartupTaskName
        Required when a ManifestFix:StartupTask finding is in the report.
    .PARAMETER LoaderPaths
        Required when a ManifestFix:LoaderSearchPathOverride finding is in the report.

    .PARAMETER MinConfidence
        Confidence floor (0.0–1.0). Findings whose Confidence is below
        this threshold are kept in the report but NOT auto-fixed. Default
        0.85. Drops to the legacy "every finding auto-fixes" behaviour
        when you pass 0.0. Findings emitted by analyzers that haven't
        been migrated to the evidence model yet (no EvidenceItems) are
        treated as confident — that way nothing regresses while the
        migration is incremental.

    .PARAMETER IgnoreUpdaters
        When set, omit the RemoveUpdaters stage from the plan even if the
        report contains UpdaterArtifact findings. Use to keep package
        auto-update binaries in place (e.g. for testing) without filtering
        the report by hand.

    .PARAMETER IgnorePluginDirectories
        When set, omit the PluginDirectory stage from the plan even if the
        report contains PluginDirectory findings. Useful when the operator
        has already chosen a different plugin strategy (e.g. host-side
        AppData seeding via PSADT scripts).

    .PARAMETER LegacyPluginFix
        Apply plugin-directory write-passthrough via PSF FileRedirection
        instead of the modern desktop6:FileSystemWriteVirtualization +
        ExcludedDirectory route. Default behaviour targets Win10 19041+
        which covers everything from Win10 2004 onward; pass this switch
        when the target fleet still has earlier builds.

    .PARAMETER AddAppIsolation
        Opt into adding AppContainer / Win32 App Isolation after compatible
        fixes. If the report shows PSF, Remove-MsixPsf is planned first.
        If the report shows windows.comServer, pass -RemoveComServerForIsolation
        to allow the lossy COM/context-menu removal required by isolation.

    .PARAMETER DryRun
        Print the plan and return without mutating.

    .PARAMETER OutputPath
        Forwarded to the underlying fixers. Signing only happens once at the end.

    .PARAMETER Pfx
        Forwarded to the underlying fixers. Signing only happens once at the end.

    .PARAMETER PfxPassword
        Forwarded to the underlying fixers. Signing only happens once at the end.

    .PARAMETER SkipSigning
        Forwarded to the underlying fixers. Signing only happens once at the end.
        (alias NoSign)
    .EXAMPLE
        $report = Invoke-MsixInvestigation -PackagePath app.msix
        Invoke-MsixAutoFixFromAnalysis -Report $report `
            -VcRuntimeSourceFolder 'C:\…\VC143.CRT' `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)] $Report,
        [string]$PackagePath,
        [bool]$PreferManifestOverPsf = $true,
        [string]$VcRuntimeSourceFolder,
        [switch]$VcRuntimeAsPackageDependency,
        [string]$VcRuntimeDependencyName = 'Microsoft.VCLibs.140.00.UWPDesktop',
        [string]$VcRuntimeMinVersion,
        [string]$StartupTaskAppId,
        [string]$StartupTaskName,
        [string[]]$LoaderPaths,
        [switch]$IgnoreUpdaters,
        [switch]$IgnorePluginDirectories,
        [switch]$LegacyPluginFix,
        [switch]$IgnoreNestedPackages,
        [switch]$AddAppIsolation,
        [ValidateSet('AppContainer', 'AppSilo')]
        [string]$IsolationMode = 'AppContainer',
        [string[]]$IsolationCapabilities,
        [string]$IsolationAppId,
        [switch]$RemoveComServerForIsolation,
        # windows.certificates (issue #120): declaring a shipped .cer into a
        # store is a TRUST decision, so it is opt-in, and the store must be
        # chosen deliberately (default TrustedPeople - the least powerful of
        # the allowed stores; use Root/CA only for internal-CA chains).
        [switch]$DeclarePackageCertificates,
        [ValidateSet('Root', 'CA', 'TrustedPeople', 'TrustedPublisher')]
        [string]$PackageCertificateStore = 'TrustedPeople',
        # Bundled-runtime deduplication (issue #130): destructive (strips the
        # private runtime folder), so it needs BOTH the opt-in switch and the
        # explicit framework identity - never guessed.
        [switch]$DeduplicateBundledRuntime,
        [string]$RuntimeFrameworkName,
        [ValidatePattern('^\d+\.\d+\.\d+\.\d+$')]
        [string]$RuntimeFrameworkMinVersion,
        [string]$RuntimeFrameworkPublisher,

        # Confidence threshold below which a finding is NOT auto-fixed.
        # Findings between [MinConfidenceReport, MinConfidence) still
        # appear in the printed plan as "recommendation only".
        # Default 0.85 (high-confidence autofix only).
        [ValidateRange(0.0, 1.0)]
        [double]$MinConfidence = 0.85,
        [switch]$DryRun,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    if (-not $PackagePath) { $PackagePath = $Report.PackagePath }
    if (-not $PackagePath) { throw 'PackagePath could not be inferred from the report.' }

    # Normalise the report's findings into the evidence-graph shape.
    # Legacy analyzers that emitted plain pscustomobjects get promoted on
    # the fly (synthetic evidence based on Severity). Same-category +
    # same-AppId findings collapse into one with combined evidence so
    # we don't repeat fixers when multiple analyzers agreed.
    $rawFindings    = @($Report.Findings)
    $mergedFindings = if ($rawFindings.Count -gt 0) {
        Merge-MsixFinding -Findings $rawFindings
    } else { @() }

    # MinConfidence gate. Three classes:
    #   - PromotedFromLegacy : always pass. These come from analyzers that
    #     pre-date the evidence model and were classified by severity only.
    #     Gating them on confidence would silently regress every existing
    #     analyzer's behaviour.
    #   - No EvidenceItems   : always pass. Defensive — shouldn't happen
    #     post-merge but never drop a finding just because it has zero
    #     evidence items.
    #   - New-shape with explicit EvidenceItems : must clear MinConfidence.
    $confidentFindings = @($mergedFindings | Where-Object {
        $items = @($_.EvidenceItems)
        ($_.PSObject.Properties.Match('PromotedFromLegacy').Count -gt 0 -and $_.PromotedFromLegacy) -or `
        ($items.Count -eq 0) -or `
        ([double]$_.Confidence -ge $MinConfidence)
    })

    # Categorise the autofixable findings into a stable plan
    $plan = [System.Collections.Generic.List[object]]::new()

    $byCat = @{}
    foreach ($f in @($confidentFindings)) {
        if ($f -and $f.Category) { $byCat[$f.Category] = $true }
    }

    # Stage 1 — strip uninstaller artefacts (files + registry)
    if ($byCat.ContainsKey('UninstallerArtifact') -or $byCat.ContainsKey('UninstallRegistry')) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RemoveUninstallers'
            Reason = 'Findings include uninstaller-looking files and/or leftover Uninstall registry keys'
            Action = { Remove-MsixUninstallerArtifact -PackagePath $current -SkipSigning }
        })
    }

    # Stage 1b — strip auto-updater binaries and scheduled-task XMLs
    if ($byCat.ContainsKey('UpdaterArtifact') -and -not $IgnoreUpdaters) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RemoveUpdaters'
            Reason = 'Findings include auto-updater binaries or scheduled-task XMLs'
            Action = { Remove-MsixUpdaterArtifact -PackagePath $current -SkipSigning }
        })
    }

    # Stage 1c - strip PSF when the operator explicitly opts into isolation.
    if ($AddAppIsolation -and ($byCat.ContainsKey('IsolationBlockedByPsf') -or $byCat.ContainsKey('PSF'))) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RemovePsfForIsolation'
            Reason = 'App isolation was requested and PSF launchers cannot run in an AppContainer'
            Action = { Remove-MsixPsf -PackagePath $current -SkipSigning }
        })
    }

    # Stage 2 — manifest-only virtualization (preferred over PSF when matching)
    $hasFsManifestFix  = $byCat.ContainsKey('ManifestFix:FileSystemWriteVirtualization')
    $hasRegManifestFix = $byCat.ContainsKey('ManifestFix:RegistryWriteVirtualization')
    $hasStartupFix     = $byCat.ContainsKey('ManifestFix:StartupTask')
    $hasLoaderFix      = $byCat.ContainsKey('ManifestFix:LoaderSearchPathOverride')

    if ($hasFsManifestFix -and $PreferManifestOverPsf) {
        $plan.Add([pscustomobject]@{
            Stage  = 'FileSystemWriteVirtualization'
            Reason = 'Package writes to install dir; manifest fix is simpler than PSF'
            Action = { Set-MsixFileSystemWriteVirtualization -PackagePath $current -SkipSigning }
        })
    }
    if ($hasRegManifestFix -and $PreferManifestOverPsf) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RegistryWriteVirtualization'
            Reason = 'Package writes to HKLM; manifest fix is simpler than RegLegacy Hklm2Hkcu'
            Action = { Set-MsixRegistryWriteVirtualization -PackagePath $current -SkipSigning }
        })
    }

    # Stage 2a - packaged Windows services (desktop6 windows.service).
    # Incompatible with -AddAppIsolation: packaged services run full-trust and
    # need runFullTrust semantics, which the isolation stage removes.
    if ($byCat.ContainsKey('ManifestFix:PackagedService') -and $AddAppIsolation) {
        Write-MsixLog -Level Warning -Message 'Skipping AddPackagedServices: app isolation was requested, and packaged services (full-trust, runFullTrust) cannot coexist with the partial-trust isolation entry point. Fix the services in a separate non-isolated pass, or drop -AddAppIsolation.'
    }
    elseif ($byCat.ContainsKey('ManifestFix:PackagedService')) {
        $serviceEntries = @($Report.Findings |
            Where-Object Category -eq 'ManifestFix:PackagedService' |
            ForEach-Object { @($_.ServiceEntries) } |
            Where-Object { $_ -and $_.CanAutoFix })
        if ($serviceEntries) {
            $capturedServiceEntries = $serviceEntries
            $plan.Add([pscustomobject]@{
                Stage  = 'AddPackagedServices'
                Reason = "Declare $($capturedServiceEntries.Count) Windows service(s) via desktop6:Service"
                Action = {
                    foreach ($svc in $capturedServiceEntries) {
                        $svcArgs = @{
                            PackagePath  = $current
                            Executable   = $svc.VfsExecutable
                            Name         = $svc.Name
                            StartupType  = $svc.StartupType
                            StartAccount = $svc.StartAccount
                            SkipSigning  = $true
                        }
                        if ($svc.Dependencies) { $svcArgs['Dependencies'] = @($svc.Dependencies) }
                        Add-MsixService @svcArgs
                    }
                }
            })
        }
    }

    # Stage 2b' - bundled certificates (windows.certificates, issue #120).
    # Opt-in: installing a certificate into a store is a trust decision.
    if ($byCat.ContainsKey('ManifestFix:PackageCertificate')) {
        if ($DeclarePackageCertificates) {
            $certEntries = @($Report.Findings |
                Where-Object Category -eq 'ManifestFix:PackageCertificate' |
                ForEach-Object { @($_.CertificateEntries) } |
                Where-Object { $_ -and $_.CanAutoFix })
            if ($certEntries) {
                $capturedCertEntries = $certEntries
                $capturedCertStore   = $PackageCertificateStore
                $plan.Add([pscustomobject]@{
                    Stage  = 'DeclarePackageCertificates'
                    Reason = "Declare $($capturedCertEntries.Count) bundled certificate(s) into the $capturedCertStore store via windows.certificates"
                    Action = {
                        foreach ($cert in $capturedCertEntries) {
                            Add-MsixPackageCertificate -PackagePath $current `
                                -CertificatePath $cert.RelativePath `
                                -StoreName $capturedCertStore -SkipSigning
                        }
                    }
                })
            }
        } else {
            Write-MsixLog -Level Info -Message 'Bundled undeclared certificate(s) found. Pass -DeclarePackageCertificates (and optionally -PackageCertificateStore) to declare them via windows.certificates, or run Add-MsixPackageCertificate manually.'
        }
    }

    # Stage 2b'' - bundled-runtime deduplication (issue #130). Destructive:
    # strips the private runtime folder and wires the framework dependency.
    # Requires the opt-in switch AND the explicit framework identity.
    if ($byCat.ContainsKey('BundledRuntime')) {
        if ($DeduplicateBundledRuntime -and $RuntimeFrameworkName -and $RuntimeFrameworkMinVersion -and $RuntimeFrameworkPublisher) {
            $runtimeEntries = @($Report.Findings |
                Where-Object Category -eq 'BundledRuntime' |
                ForEach-Object { @($_.RuntimeEntries) } |
                Where-Object { $_ -and $_.CanAutoFix })
            if ($runtimeEntries) {
                $capturedRuntimes    = $runtimeEntries
                $capturedFwName      = $RuntimeFrameworkName
                $capturedFwVersion   = $RuntimeFrameworkMinVersion
                $capturedFwPublisher = $RuntimeFrameworkPublisher
                $plan.Add([pscustomobject]@{
                    Stage  = 'DeduplicateBundledRuntime'
                    Reason = "Strip $($capturedRuntimes.Count) bundled runtime(s) and depend on framework $capturedFwName >= $capturedFwVersion"
                    Action = {
                        # 1) Strip each detected runtime folder from the payload.
                        $capturedStripRoots = @($capturedRuntimes | ForEach-Object { $_.RuntimeRoot })
                        $null = _MsixMutatePackage -PackagePath $current -Operation 'strip-runtime' `
                            -SkipSigning -NoChangeMessage 'No bundled runtime folders found to strip.' `
                            -Mutator {
                                param($workspace)
                                $removed = 0
                                foreach ($root in $capturedStripRoots) {
                                    $full = Join-Path -Path $workspace -ChildPath $root
                                    if (Test-Path -LiteralPath $full) {
                                        [IO.Directory]::Delete($full, $true)
                                        $removed++
                                        Write-MsixLog -Level Info -Message "Stripped bundled runtime: $root"
                                    }
                                }
                                if ($removed -eq 0) { return $null }
                                @{ RuntimesStripped = $removed }
                            }.GetNewClosure()
                        # 2) Wire the framework dependency (+ env preset per Kind).
                        $kind = @($capturedRuntimes | Select-Object -First 1).Kind
                        $runtimePreset = 'None'
                        if ($kind -in 'Java', 'DotNet') { $runtimePreset = $kind }
                        Add-MsixRuntimeDependency -PackagePath $current `
                            -FrameworkName $capturedFwName `
                            -FrameworkMinVersion $capturedFwVersion `
                            -FrameworkPublisher $capturedFwPublisher `
                            -Runtime $runtimePreset -SkipSigning
                    }
                })
            }
        } else {
            Write-MsixLog -Level Info -Message 'Bundled runtime(s) detected. To deduplicate automatically, pass -DeduplicateBundledRuntime with -RuntimeFrameworkName/-RuntimeFrameworkMinVersion/-RuntimeFrameworkPublisher (build the framework first with New-MsixFrameworkPackage).'
        }
    }
    # Stage 2.5 — plugin/theme/extension directories.
    # Modern path: enable desktop6:FileSystemWriteVirtualization + add each
    # plugin dir to <virtualization:ExcludedDirectories> so writes there
    # pass through to the host filesystem and survive across sessions.
    # Legacy path: PSF FileRedirection mapping the dir to per-user AppData.
    if ($byCat.ContainsKey('PluginDirectory') -and -not $IgnorePluginDirectories -and -not $AddAppIsolation) {
        $pluginFindings = @($Report.Findings | Where-Object Category -eq 'PluginDirectory')
        $pluginDirs = @($pluginFindings | ForEach-Object { $_.Evidence } | Where-Object { $_ } | Sort-Object -Unique)
        if ($pluginDirs) {
            $capturedPluginDirs = $pluginDirs
            if ($LegacyPluginFix) {
                # Wide-compat: PSF FileRedirection per plugin folder.
                $plan.Add([pscustomobject]@{
                    Stage  = 'PluginDirectory'
                    Reason = "PSF FileRedirection passthrough for $($capturedPluginDirs.Count) extension folder(s): $($capturedPluginDirs -join ', ')"
                    Action = {
                        $fixups = @(foreach ($d in $capturedPluginDirs) {
                            # Normalise '\' to '/' for the PSF base path; '.*' covers
                            # everything underneath since plugin payloads vary.
                            New-MsixPsfFileRedirectionConfig -Base ($d -replace '\\','/') -Patterns '.*'
                        })
                        Add-MsixPsfV2 -PackagePath $current -Fixups $fixups -SkipSigning
                    }
                })
            } else {
                # Modern path (Win10 19041+): disable write-virtualization so
                # writes reach the real filesystem.
                #
                # IMPORTANT (issue #81): plugin folders detected here live UNDER
                # the install location (VFS\ProgramFilesX64\App\...). The
                # virtualization:ExcludedDirectory element CANNOT express an
                # install-relative path — its schema only accepts
                # $(KnownFolder:Name)[\subpath] tokens — so passing these paths
                # made MakeAppx fail schema validation. Install-directory
                # passthrough is what PSF FileRedirectionFixup is for, so route
                # the plugin folders through PSF here too; the
                # Set-MsixFileSystemWriteVirtualization call only carries the
                # valid KnownFolder defaults.
                $plan.Add([pscustomobject]@{
                    Stage  = 'PluginDirectory'
                    Reason = "Disable write-virtualization + PSF FileRedirection passthrough for $($capturedPluginDirs.Count) install-dir extension folder(s): $($capturedPluginDirs -join ', ')"
                    Action = {
                        # 1) Disable virtualization with only valid KnownFolder
                        #    exclusions (LocalAppData + RoamingAppData defaults).
                        Set-MsixFileSystemWriteVirtualization -PackagePath $current `
                            -ExcludedDirectories @('$(KnownFolder:LocalAppData)', '$(KnownFolder:RoamingAppData)') `
                            -SkipSigning
                        # 2) Redirect the install-dir plugin folders via PSF so
                        #    their writes survive (ExcludedDirectory can't target
                        #    install-relative paths).
                        $fixups = @(foreach ($d in $capturedPluginDirs) {
                            New-MsixPsfFileRedirectionConfig -Base ($d -replace '\\','/') -Patterns '.*'
                        })
                        Add-MsixPsfV2 -PackagePath $current -Fixups $fixups -SkipSigning
                    }
                })
            }
        }
    }
    elseif ($byCat.ContainsKey('PluginDirectory') -and $AddAppIsolation) {
        Write-MsixLog -Level Info -Message 'Skipping PluginDirectory autofix because app isolation was requested; the current automatic route uses PSF FileRedirection, which is incompatible with AppContainer isolation.'
    }
    if ($hasStartupFix) {
        if ($StartupTaskAppId -and $StartupTaskName) {
            $plan.Add([pscustomobject]@{
                Stage  = 'StartupTask'
                Reason = 'Replace HKLM\Run autostart with windows.startupTask'
                Action = {
                    Add-MsixStartupTask -PackagePath $current `
                        -AppId $StartupTaskAppId -TaskId "$StartupTaskAppId-AutoStart" `
                        -DisplayName $StartupTaskName -Enabled $true -SkipSigning
                }
            })
        } else {
            Write-MsixLog -Level Warning -Message 'Skipping StartupTask: -StartupTaskAppId and -StartupTaskName are required.'
        }
    }
    if ($hasLoaderFix) {
        if ($LoaderPaths) {
            $plan.Add([pscustomobject]@{
                Stage  = 'LoaderSearchPathOverride'
                Reason = 'Replace DLL load failures with manifest declaration'
                Action = { Add-MsixLoaderSearchPathOverride -PackagePath $current -Paths $LoaderPaths -SkipSigning }
            })
        } else {
            Write-MsixLog -Level Warning -Message 'Skipping LoaderSearchPathOverride: -LoaderPaths is required.'
        }
    }

    # Stage 2b — remove desktop shortcuts
    if ($byCat.ContainsKey('DesktopShortcuts')) {
        $plan.Add([pscustomobject]@{
            Stage  = 'RemoveDesktopShortcuts'
            Reason = 'Package ships .lnk files under VFS desktop folders'
            Action = { Remove-MsixDesktopShortcut -PackagePath $current -SkipSigning }
        })
    }

    # Stage 2c — register fonts via uap4:SharedFonts
    if ($byCat.ContainsKey('ManifestFix:SharedFonts')) {
        $plan.Add([pscustomobject]@{
            Stage  = 'AddFontExtension'
            Reason = 'Package ships font files not registered via uap4:SharedFonts'
            Action = {
                $fonts = Get-MsixFontCandidate -PackagePath $current
                if ($fonts) {
                    $fontPaths = @($fonts | Select-Object -ExpandProperty Path)
                    Add-MsixFontExtension -PackagePath $current -FontPaths $fontPaths -SkipSigning
                }
            }
        })
    }

    # Stage 2d — add capability hints
    $capHintFindings = @($Report.Findings | Where-Object Category -eq 'CapabilityHints')
    if ($capHintFindings) {
        $capHintNames = @($capHintFindings.Evidence -split ',\s*' | Where-Object { $_ } | Sort-Object -Unique)
        if ($capHintNames) {
            $plan.Add([pscustomobject]@{
                Stage  = 'AddCapabilityHints'
                Reason = "PE-import hints suggest capabilities: $($capHintNames -join ', ')"
                Action = { Add-MsixCapability -PackagePath $current -Names $capHintNames -SkipSigning }
            })
        }
    }

    # Stage 2e — plain command-based shell verbs (HKCR\*\shell\<verb>\command)
    # These verbs have no CLSID, so desktop9:fileExplorerClassicContextMenuHandler
    # cannot be applied directly. The correct fix is to wrap the command as a COM
    # surrogate server (IContextMenu), register it via Add-MsixLegacyContextMenu, and
    # update the CLSID references in Registry.dat — a manual operation.
    # ExplorerCommandHandler verbs (which DO have a CLSID) are already classified as
    # ShellExt during detection and handled by stage 2g below.
    if ($byCat.ContainsKey('ShellVerb')) {
        $shellVerbFinding = @($Report.Findings | Where-Object Category -eq 'ShellVerb') | Select-Object -First 1
        $verbNames = ($shellVerbFinding.ShellEntries | ForEach-Object { $_.VerbName } | Where-Object { $_ }) -join ', '
        Write-MsixLog -Level Info -Message "ShellVerb: $($shellVerbFinding.ShellEntries.Count) plain command shell verb(s) detected ($verbNames). Cannot be auto-fixed — desktop9:fileExplorerClassicContextMenuHandler requires a COM CLSID. Convert to a COM surrogate server and use Add-MsixLegacyContextMenu."
    }

    # Stage 2f.5 — merge nested (sparse) shell-extension packages
    # Sparse inner .msix packages cannot be activated post-install: the COM
    # surrogate host can't traverse the inner zip. The fix is to lift their
    # manifest declarations + payload into the outer package BEFORE the
    # ShellExt / AddLegacyContextMenu stage so any downstream detection sees
    # the merged declarations.
    if ($byCat.ContainsKey('NestedPackage') -and -not $IgnoreNestedPackages) {
        $nested = @($Report.Findings | Where-Object Category -eq 'NestedPackage')
        foreach ($n in $nested) {
            $captured = $n.Evidence  # package-relative path of the nested .msix
            $plan.Add([pscustomobject]@{
                Stage  = 'ImportSparseShellExtension'
                Reason = "Merge nested package '$captured' into outer manifest"
                Action = {
                    Import-MsixSparseShellExtension -PackagePath $current -NestedPackagePath $captured -SkipSigning
                }
            })
        }
    }

    # Stage 2g — COM shellex context menu via desktop4 + desktop5 (field-verified pattern)
    if ($byCat.ContainsKey('ShellExt') -and -not $AddAppIsolation) {
        $shellExtFinding = @($Report.Findings | Where-Object Category -eq 'ShellExt') | Select-Object -First 1
        $autoFixable     = @($shellExtFinding.ShellEntries | Where-Object { $_.Clsid -and $_.VfsDllPath })
        if ($autoFixable) {
            $capturedShellEntries = $autoFixable   # capture for closure
            $plan.Add([pscustomobject]@{
                Stage  = 'AddLegacyContextMenu'
                Reason = "Register $($capturedShellEntries.Count) shellex COM handler(s) via desktop4/desktop5"
                Action = {
                    foreach ($entry in $capturedShellEntries) {
                        $ft = @(if ($entry.Target -eq '*') { '*' } else { $entry.Target })
                        Add-MsixLegacyContextMenu -PackagePath $current `
                            -ShellExtDll $entry.VfsDllPath `
                            -Clsid $entry.Clsid `
                            -DisplayName $entry.HandlerName `
                            -FileTypes $ft `
                            -SkipSigning
                    }
                }
            })

            # Stage 2g.b — strip the OLD shellex/shell registry entries from
            # Registry.dat now that the modern manifest declaration handles
            # them. Without this, the package's HKCR\<target>\shellex\... and
            # HKCR\<target>\shell\... entries persist and the OS registers the
            # handler TWICE — surfacing as duplicate items in File Explorer's
            # right-click menu (issue #28).
            $plan.Add([pscustomobject]@{
                Stage  = 'StripLegacyShellRegistry'
                Reason = "Remove old Registry.dat shell/shellex entries for $($capturedShellEntries.Count) handler(s) so they don't double-register alongside the new desktop4 declaration"
                Action = {
                    Remove-MsixShellRegistryArtifact -PackagePath $current `
                        -Entries $capturedShellEntries -SkipSigning
                }
            })
        } else {
            Write-MsixLog -Level Info -Message "ShellExt: CLSID/VFS DLL path could not be resolved (the bundled DLL may not be Authenticode-stamped with the CLSID, or the package omits the COM class registration). Call Add-MsixLegacyContextMenu manually with the CLSID and -ShellExtDll path."
        }
    }
    elseif ($byCat.ContainsKey('ShellExt') -and $AddAppIsolation) {
        Write-MsixLog -Level Info -Message 'Skipping ShellExt autofix because app isolation was requested; windows.comServer shell extensions are incompatible with the partial-trust entry point.'
    }

    # Stage 2g.5 - preview/property/thumbnail shell handlers.
    if ($byCat.ContainsKey('ManifestFix:ShellHandlerExtension') -and -not $AddAppIsolation) {
        $handlerEntries = @($Report.Findings |
            Where-Object Category -eq 'ManifestFix:ShellHandlerExtension' |
            ForEach-Object { @($_.ShellHandlerEntries) } |
            Where-Object { $_ -and $_.CanAutoFix })
        if ($handlerEntries) {
            $capturedHandlerEntries = $handlerEntries
            $plan.Add([pscustomobject]@{
                Stage  = 'AddShellHandlerExtensions'
                Reason = "Declare $($capturedHandlerEntries.Count) preview/property/thumbnail handler(s)"
                Action = {
                    foreach ($entry in $capturedHandlerEntries) {
                        Add-MsixShellHandlerExtension -PackagePath $current `
                            -Kind $entry.Kind `
                            -Clsid $entry.Clsid `
                            -Dll $entry.VfsDllPath `
                            -FileTypes @($entry.FileType) `
                            -FtaName $entry.FtaName `
                            -SkipSigning
                    }
                }
            })
        }
    }
    elseif ($byCat.ContainsKey('ManifestFix:ShellHandlerExtension') -and $AddAppIsolation) {
        Write-MsixLog -Level Info -Message 'Skipping shell-handler manifest autofix because app isolation was requested; the generated com:Extension is incompatible with the partial-trust entry point.'
    }

    # Stage 2h — COM InProcessServer declaration (com:Extension, windows.comServer)
    if ($byCat.ContainsKey('ComServer') -and -not $AddAppIsolation) {
        $comFinding = @($Report.Findings | Where-Object Category -eq 'ComServer') | Select-Object -First 1
        # Entries that have a VFS DLL path (package-bundled, auto-fixable)
        # and are not already handled by the ShellExt stage (SurrogateServer)
        $shellExtClsids = @()
        if ($byCat.ContainsKey('ShellExt')) {
            $seF = @($Report.Findings | Where-Object Category -eq 'ShellExt') | Select-Object -First 1
            $shellExtClsids = @($seF.ShellEntries.Clsid | Where-Object { $_ })
        }
        $autoComServers = @($comFinding.ComEntries | Where-Object {
            $_.VfsDllPath -and $_.Clsid -notin $shellExtClsids
        })
        if ($autoComServers) {
            $capturedComServers = $autoComServers
            $plan.Add([pscustomobject]@{
                Stage  = 'AddComServer'
                Reason = "Declare $($capturedComServers.Count) bundled COM InProcessServer(s) in the manifest"
                Action = {
                    $serverSpecs = @($capturedComServers | ForEach-Object {
                        @{ Clsid = $_.Clsid; VfsDllPath = $_.VfsDllPath; ThreadingModel = $_.ThreadingModel }
                    })
                    Add-MsixComServerExtension -PackagePath $current -Servers $serverSpecs -SkipSigning
                }
            })
        } else {
            Write-MsixLog -Level Info -Message "ComServer: no auto-fixable InProc servers (none of the detected CLSIDs resolved to a VFS-bundled DLL)."
        }
    }
    elseif ($byCat.ContainsKey('ComServer') -and $AddAppIsolation) {
        Write-MsixLog -Level Info -Message 'Skipping ComServer autofix because app isolation was requested; windows.comServer is incompatible with the partial-trust entry point.'
    }

    # Stage 2i — AppExecutionAlias suggestions
    # Get-MsixAliasCandidate emits one AppExecutionAlias finding per top-level
    # user-facing exe that lacks an alias. Auto-fix: register the alias for the
    # AppIds carried on those findings.
    if ($byCat.ContainsKey('AppExecutionAlias')) {
        $aliasFindings = @($Report.Findings | Where-Object Category -eq 'AppExecutionAlias')
        $aliasAppIds   = @($aliasFindings | ForEach-Object { $_.AppId } | Where-Object { $_ } | Sort-Object -Unique)
        if ($aliasAppIds) {
            $capturedAliasIds = $aliasAppIds
            $plan.Add([pscustomobject]@{
                Stage  = 'AddAliases'
                Reason = "Register AppExecutionAlias for $($capturedAliasIds.Count) app(s): $($capturedAliasIds -join ', ')"
                Action = { Add-MsixAlias -PackagePath $current -AppIds $capturedAliasIds -SkipSigning }
            })
        }
    }

    # Stage 3 — VC runtime bundle
    if ($byCat.ContainsKey('VcRuntime')) {
        if ($VcRuntimeAsPackageDependency) {
            if ($VcRuntimeMinVersion) {
                $capturedDependencyName = $VcRuntimeDependencyName
                $capturedDependencyMinVersion = $VcRuntimeMinVersion
                $plan.Add([pscustomobject]@{
                    Stage  = 'AddVcRuntimePackageDependency'
                    Reason = "Declare framework dependency $capturedDependencyName >= $capturedDependencyMinVersion"
                    Action = {
                        Add-MsixPackageDependency -PackagePath $current `
                            -Name $capturedDependencyName `
                            -MinVersion $capturedDependencyMinVersion `
                            -SkipSigning
                    }
                })
            } else {
                Write-MsixLog -Level Warning -Message 'Skipping VcRuntime PackageDependency: -VcRuntimeMinVersion is required.'
            }
        }
        elseif ($VcRuntimeSourceFolder) {
            $plan.Add([pscustomobject]@{
                Stage  = 'BundleVcRuntimes'
                Reason = 'Package references VC runtime DLLs that are not bundled'
                Action = { Add-MsixVcRuntimeBundle -PackagePath $current -SourceFolder $VcRuntimeSourceFolder -SkipSigning }
            })
        } else {
            Write-MsixLog -Level Warning -Message 'Skipping VcRuntime bundle: -VcRuntimeSourceFolder is required.'
        }
    }

    # Stage 3b - requested app isolation, after incompatible additions have been skipped.
    if ($AddAppIsolation) {
        if ($byCat.ContainsKey('IsolationBlockedByComServer') -and -not $RemoveComServerForIsolation) {
            Write-MsixLog -Level Warning -Message 'Skipping AppIsolation: report contains windows.comServer and -RemoveComServerForIsolation was not supplied.'
        } else {
            $capturedIsolationMode = $IsolationMode
            $capturedIsolationCapabilities = $IsolationCapabilities
            $capturedIsolationAppId = $IsolationAppId
            $capturedRemoveComServer = [bool]$RemoveComServerForIsolation
            $plan.Add([pscustomobject]@{
                Stage  = 'AddAppIsolation'
                Reason = "Apply Add-MsixAppIsolation ($capturedIsolationMode)"
                Action = {
                    $isoArgs = @{
                        PackagePath     = $current
                        Mode            = $capturedIsolationMode
                        RemoveComServer = $capturedRemoveComServer
                        SkipSigning     = $true
                    }
                    if ($capturedIsolationCapabilities) { $isoArgs['Capabilities'] = $capturedIsolationCapabilities }
                    if ($capturedIsolationAppId)        { $isoArgs['AppId']        = $capturedIsolationAppId }
                    Add-MsixAppIsolation @isoArgs
                }
            })
        }
    }

    # Stage 4 — PSF fixups (only those NOT already covered by a manifest fix)
    if ($Report.SuggestedFixups -and $Report.SuggestedFixups.Count -gt 0 -and -not $AddAppIsolation) {
        $skipPsfFs  = $hasFsManifestFix  -and $PreferManifestOverPsf
        $skipPsfReg = $hasRegManifestFix -and $PreferManifestOverPsf
        $kept = @($Report.SuggestedFixups | Where-Object {
            -not (
                ($skipPsfFs  -and $_.dll -in 'FileRedirectionFixup.dll','MFRFixup.dll') -or
                ($skipPsfReg -and $_.dll -eq 'RegLegacyFixups.dll')
            )
        })
        if ($kept.Count -gt 0) {
            $plan.Add([pscustomobject]@{
                Stage  = 'InjectPsf'
                Reason = "Apply $($kept.Count) PSF fixup(s) from analysis"
                Action = { Add-MsixPsfV2 -PackagePath $current -Fixups $kept -SkipSigning }
            })
        }
    }
    elseif ($Report.SuggestedFixups -and $Report.SuggestedFixups.Count -gt 0 -and $AddAppIsolation) {
        Write-MsixLog -Level Info -Message 'Skipping PSF fixup injection because app isolation was requested; PSF cannot run inside the isolated AppContainer target.'
    }

    if (-not $plan -or -not $plan.Count) {
        Write-MsixLog -Level Info -Message 'Nothing actionable in the report. Either no findings or all need manual parameters.'
        return [pscustomobject]@{
            PackagePath = $PackagePath
            Plan        = @()
            DryRun      = [bool]$DryRun
        }
    }

    # Emit the plan
    Write-MsixLog -Level Info -Message '─── AutoFix plan ───'
    foreach ($p in $plan) {
        Write-MsixLog -Level Info -Message "  $($p.Stage)  ($($p.Reason))"
    }

    if ($DryRun) {
        return [pscustomobject]@{
            PackagePath = $PackagePath
            Plan        = $plan
            DryRun      = $true
        }
    }

    # Stage execution — write to OutputPath if asked, otherwise overwrite in-place
    $current = $PackagePath
    if ($OutputPath -and ($OutputPath -ne $PackagePath)) {
        Copy-Item -LiteralPath $PackagePath -Destination $OutputPath -Force
        $current = $OutputPath
    }

    foreach ($p in $plan) {
        Write-MsixLog -Level Info -Message "==> $($p.Stage)"
        & $p.Action
    }

    if (-not $SkipSigning) {
        Write-MsixLog -Level Info -Message '==> Sign'
        Invoke-MsixSigning -PackagePath $current -Pfx $Pfx -PfxPassword $PfxPassword
    } else {
        Write-MsixLog -Level Info -Message 'NoSign requested; package left unsigned.'
    }

    return [pscustomobject]@{
        PackagePath = $current
        Plan        = $plan
        DryRun      = $false
    }
}
#endregion
