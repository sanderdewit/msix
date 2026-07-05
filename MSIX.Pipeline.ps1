function Invoke-MsixPipeline {
    <#
    .SYNOPSIS
        Runs a full unpack → validate → modify → repack → sign pipeline on an MSIX,
        signing only ONCE at the very end (no per-stage re-signs).

    .DESCRIPTION
        All modifications happen in an isolated GUID workspace. Behaviour:

          - With -OutputPath: original file is preserved; pipeline result is
            written there. Use this for staged/dry-run runs.
          - Without -OutputPath: file is overwritten in-place after success.

        Stages run in order, each touching the SAME workspace, and signing is
        deferred until everything is repacked. This avoids the previous
        per-stage resign that wasted time and risked publisher drift.

    .PARAMETER PackagePath
        Path to the .msix file. Overwritten in place unless -OutputPath is
        also supplied.

    .PARAMETER OutputPath
        Optional output path. Defaults to overwriting -PackagePath.

    .PARAMETER Config
        Hashtable controlling pipeline stages. Supported keys:

          Publisher    [string]      New publisher DN. Omit to skip.

          PSF          [hashtable]   Keys:
            Fixups            [hashtable[]]
            PsfSourcePath     [string]
            WorkingDirectory  [string]
            AppOptions        [hashtable[]]
            AdditionalFiles   [string[]]

          AppIsolation [hashtable]   Keys:
            Mode              [string]     'AppContainer' (GA, default) or 'AppSilo' (preview)
            Capabilities      [string[]]   AppContainer: standard package capabilities;
                                           AppSilo: isolatedWin32-* / device capabilities
                                           (default isolatedWin32-promptForAccess)
            AppId             [string]     Restrict to one Application (default: all)
            RemoveComServer   [bool]       Strip windows.comServer + context-menu
                                           verbs instead of refusing to isolate
            NOTE: applies the same model as Add-MsixAppIsolation — partial-trust
            entry point, TrustLevel=appContainer, runFullTrust removed.

          Signing      [hashtable]   Keys:
            Pfx                 [string]
            PfxPassword         [SecureString]
            TimestampUrl        [string]
            Skip                [bool]          Skip signing entirely (default: false)
            UnsignedOutputPath  [string]        When signing fails, copy the
                                                unsigned scratch package here so
                                                the operator can manually re-sign.
                                                The original target is never
                                                overwritten when signing fails.

    .OUTPUTS
        [System.IO.FileInfo] for the final signed package, or $null in
        WhatIf preview mode.

    .EXAMPLE
        # Publisher rename only — minimal config
        Invoke-MsixPipeline -PackagePath app.msix -Config @{
            Publisher = 'CN=Contoso, O=Contoso, C=NL'
            Signing   = @{ Pfx = 'cert.pfx'; PfxPassword = $pw }
        }

    .EXAMPLE
        # PSF injection only (file redirection)
        $fixup = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'
        Invoke-MsixPipeline -PackagePath app.msix -Config @{
            PSF     = @{ Fixups = @($fixup) }
            Signing = @{ Pfx = 'cert.pfx'; PfxPassword = $pw }
        }

    .EXAMPLE
        # Full pipeline: Publisher rename + PSF + Signing + UnsignedOutputPath
        # (preserves the unsigned package if signing fails)
        $fixup = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'
        Invoke-MsixPipeline -PackagePath app.msix -OutputPath app-fixed.msix `
            -Config @{
                Publisher = 'CN=Contoso, O=Contoso, C=NL'
                PSF       = @{ Fixups = @($fixup) }
                Signing   = @{
                    Pfx                = 'cert.pfx'
                    PfxPassword        = $pw
                    UnsignedOutputPath = 'C:\drop\app-unsigned.msix'
                }
            }

    .EXAMPLE
        # Preview mode: -WhatIf still runs unpack/edit/pack so you can inspect
        # the would-be result; signing and the final Move-Item are skipped.
        Invoke-MsixPipeline -WhatIf -PackagePath app.msix -Config $cfg
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [hashtable]$Config,
        [string]$OutputPath
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath -ErrorAction Stop
    $workspace = New-MsixWorkspace -PackageName $fileinfo.BaseName
    $target    = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }

    # Compute WhatIf semantics once. In WhatIf mode the unpack + edit + pack
    # stages still run (so the user can preview the modified package), but the
    # destructive signing + final Move-Item to $target are skipped. If
    # Config.Signing.UnsignedOutputPath is set, the scratch package is copied
    # there so the user can inspect what would have been produced.
    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Run MSIX pipeline')

    try {
        Write-MsixLog -Level Info -Message "=== MSIX Pipeline: $($fileinfo.Name) -> $target ==="
        if ($isWhatIf) {
            Write-MsixLog -Level Info -Message '[WhatIf] Preview mode: unpack/edit/pack will run; signing and final replacement will be skipped.'
        }

        # ── Unpack into workspace ────────────────────────────────────────
        Write-MsixLog -Level Info -Message 'Stage: Unpack'
        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unpack'

        # ── Validate ─────────────────────────────────────────────────────
        Write-MsixLog -Level Info -Message 'Stage: Validate'
        $null = Test-MsixManifest -Path "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest -Path "$workspace\AppxManifest.xml"
        $manifestDirty = $false

        # ── Publisher update ─────────────────────────────────────────────
        if ($Config.Publisher) {
            $oldPublisher = $manifest.Package.Identity.Publisher
            if ($oldPublisher -cne $Config.Publisher) {
                Set-MsixManifestPublisher -Manifest $manifest -Publisher $Config.Publisher | Out-Null
                $manifestDirty = $true
                Write-MsixLog -Level Info -Message "Publisher: $oldPublisher → $($Config.Publisher)"
            } else {
                Write-MsixLog -Level Info -Message 'Publisher unchanged (already matches)'
            }
        }

        # ── App Isolation ────────────────────────────────────────────────
        # Delegates to the same core as Add-MsixAppIsolation so the pipeline
        # can never again emit the obsolete capability-only shape (issue #97):
        # partial-trust entry point + TrustLevel=appContainer + runFullTrust
        # removed, per Mode = AppContainer (GA default) / AppSilo (preview).
        if ($Config.AppIsolation) {
            $isoMode = 'AppContainer'
            if ($Config.AppIsolation.Mode) { $isoMode = [string]$Config.AppIsolation.Mode }
            if ($Config.AppIsolation.ContainsKey('Capabilities')) {
                $isoCaps = @($Config.AppIsolation.Capabilities)
            } elseif ($isoMode -eq 'AppSilo') {
                $isoCaps = @('isolatedWin32-promptForAccess')   # mirror the cmdlet default
            } else {
                $isoCaps = @()
            }
            $isoAppId = ''
            if ($Config.AppIsolation.AppId) { $isoAppId = [string]$Config.AppIsolation.AppId }
            $isoStripCom = [bool]$Config.AppIsolation.RemoveComServer
            _MsixApplyAppIsolation -Manifest $manifest -Mode $isoMode -Capabilities $isoCaps -AppId $isoAppId -RemoveComServer:$isoStripCom
            $manifestDirty = $true
        }

        if ($manifestDirty) {
            Save-MsixManifest -Manifest $manifest -Path "$workspace\AppxManifest.xml"
        }

        # ── Repack to SCRATCH (never to $target until sign succeeds) ─────
        # Atomic pack-then-sign: original target is preserved if signing fails.
        $scratchExt = [System.IO.Path]::GetExtension($target)
        if (-not $scratchExt) { $scratchExt = '.msix' }
        $scratch = Join-Path -Path $env:TEMP -ChildPath ("msix-pipeline-{0}-{1}{2}" -f `
            $fileinfo.BaseName, ([guid]::NewGuid().ToString('N').Substring(0,8)), $scratchExt)

        $needsPsf      = [bool]$Config.PSF
        $packSucceeded = $false
        $signSucceeded = $false

        try {
            if ($needsPsf) {
                Write-MsixLog -Level Info -Message 'Stage: PSF injection'
                $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $scratch, '/d', $workspace, '/o')
                Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx pack (pre-PSF scratch)'

                $psfArgs = @{
                    PackagePath  = $scratch
                    Fixups       = $Config.PSF.Fixups
                    SkipSigning  = $true        # we sign once at the end
                }
                foreach ($k in 'PsfSourcePath','WorkingDirectory','AppOptions','AdditionalFiles') {
                    if ($Config.PSF.ContainsKey($k)) { $psfArgs[$k] = $Config.PSF[$k] }
                }
                Add-MsixPsfV2 @psfArgs
            } else {
                Write-MsixLog -Level Info -Message 'Stage: Repack'
                $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $scratch, '/d', $workspace, '/o')
                Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx pack'
            }
            $packSucceeded = $true

            if ($isWhatIf) {
                Write-MsixLog -Level Info -Message "[WhatIf] Would replace '$target' with pipeline output. Signing and Move-Item skipped."
                if ($Config.Signing -and $Config.Signing.UnsignedOutputPath) {
                    Copy-Item -LiteralPath $scratch -Destination $Config.Signing.UnsignedOutputPath -Force -ErrorAction Stop
                    Write-MsixLog -Level Info -Message "[WhatIf] Preview package copied to: $($Config.Signing.UnsignedOutputPath)"
                }
                return $null
            }

            # ── Sign (once, at the end, AT THE SCRATCH PATH) ──────────────
            $skipSign = $Config.Signing -and $Config.Signing.Skip
            if ($Config.Signing -and -not $skipSign) {
                Write-MsixLog -Level Info -Message 'Stage: Sign (final)'
                $signArgs = @{ PackagePath = $scratch }
                foreach ($k in 'Pfx','PfxPassword','TimestampUrl','Signer',
                              'TrustedSigningAccount','TrustedSigningProfile',
                              'TrustedSigningEndpoint','TrustedSigningClientDll',
                              'KeyVaultUrl','KeyVaultCertificate','KeyVaultTenantId',
                              'KeyVaultClientId') {
                    if ($Config.Signing.ContainsKey($k)) { $signArgs[$k] = $Config.Signing[$k] }
                }
                Invoke-MsixSigning @signArgs
            } elseif (-not $Config.Signing) {
                Write-MsixLog -Level Info -Message 'No Signing block in config; output is unsigned.'
            } else {
                Write-MsixLog -Level Info -Message 'Signing.Skip=true; output is unsigned.'
            }
            $signSucceeded = $true

            # ── Atomic move: only NOW does the target change ─────────────
            Move-Item -LiteralPath $scratch -Destination $target -Force
            Write-MsixLog -Level Info -Message "=== Pipeline complete: $target ==="
            return Get-Item -LiteralPath $target -ErrorAction Stop

        } catch {
            if ($packSucceeded -and -not $signSucceeded -and `
                $Config.Signing -and $Config.Signing.UnsignedOutputPath) {
                try {
                    Copy-Item -LiteralPath $scratch -Destination $Config.Signing.UnsignedOutputPath -Force -ErrorAction Stop
                    Write-MsixLog -Level Warning -Message "Signing failed. Unsigned package preserved at: $($Config.Signing.UnsignedOutputPath)"
                } catch {
                    Write-MsixLog -Level Error -Message "Signing failed AND unsigned-output copy to '$($Config.Signing.UnsignedOutputPath)' failed: $_"
                }
            } elseif ($packSucceeded -and -not $signSucceeded) {
                Write-MsixLog -Level Warning -Message "Signing failed. Original target '$target' is unchanged. Set Config.Signing.UnsignedOutputPath to preserve the unsigned package next time."
            }
            throw
        } finally {
            if (Test-Path -LiteralPath $scratch) {
                Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue
            }
        }

    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


# =============================================================================
# In-place package mutator scaffolding (issue #37)
# -----------------------------------------------------------------------------
# Every heuristic mutator (Add-MsixCapability + Remove-Msix*Artifact in
# MSIX.Heuristics.ps1) repeats the same unpack -> mutate -> atomic-repack-
# sign-move skeleton. The helper below centralises it so:
#
#   1. The atomic-repack-sign-move semantics (issue #34) are enforced by
#      construction -- no future wrapper can accidentally skip the scratch
#      step and overwrite the user's signed package on signing failure.
#   2. Adding a new mutator drops to ~30 lines of payload logic.
#   3. Bug fixes to the unpack / cleanup / signing-error-handling paths
#      apply in one place instead of four.
# =============================================================================

function _MsixMutatePackage {
    <#
    .SYNOPSIS
        Internal helper: unpack an .msix, hand the workspace to a caller-
        supplied script block, atomic-repack-sign-move the result.

    .DESCRIPTION
        Standard scaffolding used by every in-place package mutator in
        MSIX.Heuristics.ps1.

        Flow:
          1. Resolve $toolsRoot and the package fileinfo.
          2. New-MsixWorkspace -> isolated GUID temp folder.
          3. MakeAppx unpack into the workspace.
          4. Invoke -Mutator { param($workspace) ... }. The mutator returns:
               * `$null` (or `$false`, or an empty hashtable's literal `@{}`)
                 -> "nothing to do". Helper logs -NoChangeMessage, returns `$null`,
                 nothing is repacked or signed.
               * A [hashtable] / [pscustomobject] of summary fields ->
                 "package was mutated, please repack". Helper packs to a
                 scratch path, signs at scratch, Move-Item to target on
                 success. Returns the mutator's summary merged with
                 { Output = $target }.
          5. On signing failure (and only after a successful pack), if
             -UnsignedOutputPath was supplied, the scratch is copied there
             for inspection. The user's -PackagePath is byte-equal to
             before the call.
          6. The workspace is always cleaned up in a finally.

    .PARAMETER PackagePath
        The .msix to mutate.

    .PARAMETER Mutator
        Script block invoked with the workspace path as positional arg 0.
        See DESCRIPTION for the return-value contract.

    .PARAMETER Operation
        Short label used in the scratch filename (e.g. 'cap', 'uninstrm',
        'updrm', 'shellreg'). Helps with debugging when multiple mutators
        are operating in parallel.

    .PARAMETER WorkspaceSuffix
        Optional suffix for New-MsixWorkspace's directory name. Default
        is the package base name plus '-' plus $Operation. Some legacy
        mutators used different suffixes so we expose this for parity.

    .PARAMETER NoChangeMessage
        Log line emitted at Info level when -Mutator reports no work.
        Default: "No changes for $Operation."

    .PARAMETER OutputPath
        Where to write the repacked package. Defaults to overwriting
        -PackagePath.

    .PARAMETER SkipSigning
        Skip the final Invoke-MsixSigning pass. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        If signing fails, copy the unsigned scratch package here for
        inspection. The user's -PackagePath is left byte-equal in this
        failure case (provided the helper got past the pack step).

    .OUTPUTS
        $null when -Mutator reported no changes. Otherwise a
        [pscustomobject] carrying every key the mutator returned plus an
        Output = <final-path> property.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [scriptblock]$Mutator,
        [Parameter(Mandatory)] [string]$Operation,
        [string]$WorkspaceSuffix,
        [string]$NoChangeMessage,
        [string]$OutputPath,
        [Alias('NoSign')] [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    if (-not $NoChangeMessage) { $NoChangeMessage = "No changes for $Operation." }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath
    $wsName    = if ($WorkspaceSuffix) { "$($fileinfo.BaseName)$WorkspaceSuffix" } else { "$($fileinfo.BaseName)-$Operation" }
    $workspace = New-MsixWorkspace -PackageName $wsName

    try {
        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unpack'

        # Invoke the mutator bound to THIS module's session state so module-
        # private helpers (e.g. _MsixOpenOfflineHive) always resolve, even if the
        # scriptblock was created in — or dispatched through — a different scope.
        # NewBoundScriptBlock throws if the block is already bound to a *different*
        # module; in that (unexpected) case fall back to the block as-is.
        $boundMutator = $Mutator
        if ($ExecutionContext.SessionState.Module) {
            try { $boundMutator = $ExecutionContext.SessionState.Module.NewBoundScriptBlock($Mutator) } catch { $boundMutator = $Mutator }
        }
        $summary = & $boundMutator $workspace

        # No-change contract: $null / $false / empty collection -> bail.
        $hasChanges = $false
        if ($null -ne $summary -and $summary -isnot [bool]) {
            if ($summary -is [System.Collections.IDictionary]) {
                $hasChanges = $summary.Count -gt 0 -or $summary.PSObject.Properties['__forcePack']
            } elseif ($summary -is [pscustomobject]) {
                $hasChanges = ($summary.PSObject.Properties | Where-Object MemberType -eq 'NoteProperty' | Measure-Object).Count -gt 0
            } else {
                # Any non-collection truthy value also counts as "changed" so
                # mutators with no per-call summary (e.g. Add-MsixCapability)
                # can return $true.
                $hasChanges = [bool]$summary
            }
        } elseif ($summary -is [bool]) {
            $hasChanges = $summary
        }

        if (-not $hasChanges) {
            Write-MsixLog -Level Info -Message $NoChangeMessage
            return $null
        }

        # ── Atomic repack ──────────────────────────────────────────────────
        $target  = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }
        $scratch = Join-Path -Path $env:TEMP -ChildPath ("msix-{0}-{1}{2}" -f $Operation, ([guid]::NewGuid().ToString('N').Substring(0,8)), ([System.IO.Path]::GetExtension($target)))
        $packOk = $false
        try {
            $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $scratch, '/d', $workspace, '/o')
            Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx pack'
            $packOk = $true
            if (-not $SkipSigning) {
                Invoke-MsixSigning -PackagePath $scratch -Pfx $Pfx -PfxPassword $PfxPassword
            }
            Move-Item -LiteralPath $scratch -Destination $target -Force
        } catch {
            if ($packOk -and $UnsignedOutputPath) {
                Copy-Item -LiteralPath $scratch -Destination $UnsignedOutputPath -Force -ErrorAction SilentlyContinue
                Write-MsixLog -Level Warning -Message "Signing failed. Unsigned package preserved at: $UnsignedOutputPath"
            }
            throw
        } finally {
            if (Test-Path -LiteralPath $scratch) { Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue }
        }

        # Merge mutator's summary + Output into a single pscustomobject.
        $out = [ordered]@{}
        if ($summary -is [System.Collections.IDictionary]) {
            foreach ($k in $summary.Keys) { $out[$k] = $summary[$k] }
        } elseif ($summary -is [pscustomobject]) {
            foreach ($p in $summary.PSObject.Properties | Where-Object MemberType -eq 'NoteProperty') {
                $out[$p.Name] = $p.Value
            }
        }
        $out['Output'] = $target
        return [pscustomobject]$out

    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
