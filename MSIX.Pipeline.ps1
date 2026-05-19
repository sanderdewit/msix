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
            Pfx               [string]
            PfxPassword       [string]
            TimestampUrl      [string]
            Skip              [bool]      Skip signing entirely (default: false)

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
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName
    $target    = if ($OutputPath) { $OutputPath } else { $fileinfo.FullName }

    try {
        Write-MsixLog Info "=== MSIX Pipeline: $($fileinfo.Name) -> $target ==="

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
                $manifest.Package.Identity.Publisher = $Config.Publisher
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

        # ── PSF injection ────────────────────────────────────────────────
        # Repack the workspace into a scratch .msix so Add-MsixPsfV2 (which
        # does its own unpack/repack) sees all manifest edits.
        $needsPsf = [bool]$Config.PSF
        if ($needsPsf) {
            Write-MsixLog Info 'Stage: PSF injection'

            $scratch = Join-Path $env:TEMP "scratch-$($fileinfo.BaseName)-$([guid]::NewGuid().ToString('N').Substring(0,8)).msix"

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
            # Move scratch to final target
            Move-Item $scratch $target -Force

        } else {
            # ── Repack only ──────────────────────────────────────────────
            Write-MsixLog Info 'Stage: Repack'
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $target, '/d', $workspace, '/o')
            Assert-MsixProcessSuccess $r 'MakeAppx pack'
        }

        # ── Sign (once, at the end) ──────────────────────────────────────
        $skipSign = $Config.Signing -and $Config.Signing.Skip
        if ($Config.Signing -and -not $skipSign) {
            Write-MsixLog Info 'Stage: Sign (final)'
            $signArgs = @{ PackagePath = $target }
            foreach ($k in 'Pfx','PfxPassword','TimestampUrl') {
                if ($Config.Signing.ContainsKey($k)) { $signArgs[$k] = $Config.Signing[$k] }
            }
            Invoke-MsixSigning @signArgs
        } elseif (-not $Config.Signing) {
            Write-MsixLog Info 'No Signing block in config; output is unsigned.'
        } else {
            Write-MsixLog Info 'Signing.Skip=true; output is unsigned.'
        }

        Write-MsixLog Info "=== Pipeline complete: $target ==="
        return Get-Item $target

    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
