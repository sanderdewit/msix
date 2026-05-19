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
        Path to the .msix file.

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
            Capabilities      [string[]]   Add Win32 isolation capabilities

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

    .EXAMPLE
        Invoke-MsixPipeline -PackagePath app.msix -Config @{
            Publisher = 'CN=Contoso, O=Contoso, C=NL'
            PSF = @{ Fixups = @( New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log' ) }
            Signing = @{ Pfx = 'cert.pfx'; PfxPassword = 'P@ss' }
        }
    .EXAMPLE
        # Dry-run: produce an alternative file
        Invoke-MsixPipeline -PackagePath app.msix -OutputPath app-fixed.msix -Config $cfg
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
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    $target    = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }

    # Compute WhatIf semantics once. In WhatIf mode the unpack + edit + pack
    # stages still run (so the user can preview the modified package), but the
    # destructive signing + final Move-Item to $target are skipped. If
    # Config.Signing.UnsignedOutputPath is set, the scratch package is copied
    # there so the user can inspect what would have been produced.
    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Run MSIX pipeline')

    try {
        Write-MsixLog Info "=== MSIX Pipeline: $($fileinfo.Name) -> $target ==="
        if ($isWhatIf) {
            Write-MsixLog Info '[WhatIf] Preview mode: unpack/edit/pack will run; signing and final replacement will be skipped.'
        }

        # ── Unpack into workspace ────────────────────────────────────────
        Write-MsixLog Info 'Stage: Unpack'
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        # ── Validate ─────────────────────────────────────────────────────
        Write-MsixLog Info 'Stage: Validate'
        $null = Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"
        $manifestDirty = $false

        # ── Publisher update ─────────────────────────────────────────────
        if ($Config.Publisher) {
            $oldPublisher = $manifest.Package.Identity.Publisher
            if ($oldPublisher -cne $Config.Publisher) {
                Set-MsixManifestPublisher -Manifest $manifest -Publisher $Config.Publisher | Out-Null
                $manifestDirty = $true
                Write-MsixLog Info "Publisher: $oldPublisher → $($Config.Publisher)"
            } else {
                Write-MsixLog Info 'Publisher unchanged (already matches)'
            }
        }

        # ── App Isolation ────────────────────────────────────────────────
        if ($Config.AppIsolation -and $Config.AppIsolation.Capabilities) {
            Add-MsixManifestNamespace $manifest 'rescap'
            Set-MsixManifestMaxVersionTested $manifest -MinBuild 26100
            $rescapUri = Get-MsixManifestNamespaceUri 'rescap'
            $capsNode  = $manifest.Package.Capabilities
            if (-not $capsNode) {
                $capsNode = $manifest.CreateElement('Capabilities', $manifest.Package.NamespaceURI)
                $null     = $manifest.Package.AppendChild($capsNode)
            }
            foreach ($cap in @($Config.AppIsolation.Capabilities)) {
                $existing = $capsNode.ChildNodes | Where-Object { $_.LocalName -eq 'Capability' -and $_.Name -eq $cap }
                if (-not $existing) {
                    $node = $manifest.CreateElement('rescap:Capability', $rescapUri)
                    $node.SetAttribute('Name', $cap)
                    $null = $capsNode.AppendChild($node)
                    Write-MsixLog Info "Capability added: $cap"
                    $manifestDirty = $true
                }
            }
        }

        if ($manifestDirty) {
            Save-MsixManifest $manifest "$workspace\AppxManifest.xml"
        }

        # ── Repack to SCRATCH (never to $target until sign succeeds) ─────
        # Atomic pack-then-sign: original target is preserved if signing fails.
        $scratchExt = [System.IO.Path]::GetExtension($target)
        if (-not $scratchExt) { $scratchExt = '.msix' }
        $scratch = Join-Path $env:TEMP ("msix-pipeline-{0}-{1}{2}" -f `
            $fileinfo.BaseName, ([guid]::NewGuid().ToString('N').Substring(0,8)), $scratchExt)

        $needsPsf      = [bool]$Config.PSF
        $packSucceeded = $false
        $signSucceeded = $false

        try {
            if ($needsPsf) {
                Write-MsixLog Info 'Stage: PSF injection'
                $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $scratch, '/d', $workspace, '/o')
                Assert-MsixProcessSuccess $r 'MakeAppx pack (pre-PSF scratch)'

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
                Write-MsixLog Info 'Stage: Repack'
                $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $scratch, '/d', $workspace, '/o')
                Assert-MsixProcessSuccess $r 'MakeAppx pack'
            }
            $packSucceeded = $true

            if ($isWhatIf) {
                Write-MsixLog Info "[WhatIf] Would replace '$target' with pipeline output. Signing and Move-Item skipped."
                if ($Config.Signing -and $Config.Signing.UnsignedOutputPath) {
                    Copy-Item -LiteralPath $scratch -Destination $Config.Signing.UnsignedOutputPath -Force -ErrorAction Stop
                    Write-MsixLog Info "[WhatIf] Preview package copied to: $($Config.Signing.UnsignedOutputPath)"
                }
                return $null
            }

            # ── Sign (once, at the end, AT THE SCRATCH PATH) ──────────────
            $skipSign = $Config.Signing -and $Config.Signing.Skip
            if ($Config.Signing -and -not $skipSign) {
                Write-MsixLog Info 'Stage: Sign (final)'
                $signArgs = @{ PackagePath = $scratch }
                foreach ($k in 'Pfx','PfxPassword','TimestampUrl','Signer',
                              'TrustedSigningAccount','TrustedSigningProfile',
                              'TrustedSigningEndpoint','TrustedSigningClientDll',
                              'KeyVaultUrl','KeyVaultCertificate','KeyVaultTenantId',
                              'KeyVaultClientId','KeyVaultClientSecret') {
                    if ($Config.Signing.ContainsKey($k)) { $signArgs[$k] = $Config.Signing[$k] }
                }
                Invoke-MsixSigning @signArgs
            } elseif (-not $Config.Signing) {
                Write-MsixLog Info 'No Signing block in config; output is unsigned.'
            } else {
                Write-MsixLog Info 'Signing.Skip=true; output is unsigned.'
            }
            $signSucceeded = $true

            # ── Atomic move: only NOW does the target change ─────────────
            Move-Item -LiteralPath $scratch -Destination $target -Force
            Write-MsixLog Info "=== Pipeline complete: $target ==="
            return Get-Item -LiteralPath $target -ErrorAction Stop

        } catch {
            if ($packSucceeded -and -not $signSucceeded -and `
                $Config.Signing -and $Config.Signing.UnsignedOutputPath) {
                try {
                    Copy-Item -LiteralPath $scratch -Destination $Config.Signing.UnsignedOutputPath -Force -ErrorAction Stop
                    Write-MsixLog Warning "Signing failed. Unsigned package preserved at: $($Config.Signing.UnsignedOutputPath)"
                } catch {
                    Write-MsixLog Error "Signing failed AND unsigned-output copy to '$($Config.Signing.UnsignedOutputPath)' failed: $_"
                }
            } elseif ($packSucceeded -and -not $signSucceeded) {
                Write-MsixLog Warning "Signing failed. Original target '$target' is unchanged. Set Config.Signing.UnsignedOutputPath to preserve the unsigned package next time."
            }
            throw
        } finally {
            if (Test-Path -LiteralPath $scratch) {
                Remove-Item -LiteralPath $scratch -Force -ErrorAction SilentlyContinue
            }
        }

    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
