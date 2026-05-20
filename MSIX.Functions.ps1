# =============================================================================
# Public package-operation functions
# -----------------------------------------------------------------------------
# Originally embedded in MSIX.psm1. Extracted in v0.13 so the root .psm1 only
# contains the dot-source loader + Export-ModuleMember, matching the same
# convention as every other MSIX.*.ps1 sub-module.
# =============================================================================

#region --- Public: Package information -------------------------------------

function Get-MsixInfo {
    <#
    .SYNOPSIS
        Returns identity, publisher, signing, and (optionally) application details
        for an MSIX package without fully unpacking it.

    .DESCRIPTION
        Extracts AppxManifest.xml in memory and combines it with the
        Authenticode signature info. Use this for quick triage / inventory
        scenarios — it does not unzip the entire package.

        For full unpacking and analysis use Get-MsixCompatibilityReport or
        Invoke-MsixInvestigation.

    .PARAMETER PackagePath
        Path to the .msix / .appx file. Accepts pipeline input.

    .PARAMETER Detailed
        Also returns the raw Application XML elements via
        Get-MsixManifestApplications, attached as an `Applications` note property.

    .EXAMPLE
        # Quick summary of one package
        Get-MsixInfo -PackagePath app.msix

    .EXAMPLE
        # Inventory a folder of packages
        Get-ChildItem 'C:\packages\*.msix' | Get-MsixInfo |
            Select-Object Name, Version, Publisher, Signed

    .OUTPUTS
        [pscustomobject] with Name, DisplayName, Publisher, PublisherDisplayName,
        Version, ProcessorArchitecture, Description, Signed (status),
        SignedBy, Thumbprint, TimestampCertificate. With -Detailed,
        also includes an Applications collection.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$PackagePath,
        [switch]$Detailed
    )

    PROCESS {
        $fileinfo  = Get-Item $PackagePath
        [xml]$appinfo = Get-MsixManifest -Path $fileinfo.FullName
        $signinfo     = Get-AuthenticodeSignature -FilePath $fileinfo

        $result = [pscustomobject]@{
            Name                   = $appinfo.Package.Identity.Name
            DisplayName            = $appinfo.Package.Properties.DisplayName
            Publisher              = $appinfo.Package.Identity.Publisher
            PublisherDisplayName   = $appinfo.Package.Properties.PublisherDisplayName
            Version                = $appinfo.Package.Identity.Version
            ProcessorArchitecture  = $appinfo.Package.Identity.ProcessorArchitecture
            Description            = $appinfo.Package.Properties.Description
            Signed                 = $signinfo.Status
            SignedBy               = $signinfo.SignerCertificate.Subject
            Thumbprint             = $signinfo.SignerCertificate.Thumbprint
            TimestampCertificate   = $signinfo.TimeStamperCertificate
        }

        if ($Detailed) {
            $result | Add-Member -NotePropertyName Applications `
                                 -NotePropertyValue @(Get-MsixManifestApplications -Manifest $appinfo)
        }

        return $result
    }
}

#endregion


#region --- Public: Package debugging ---------------------------------------

function Invoke-MsixCommand {
    <#
    .SYNOPSIS
        Launches a command inside the MSIX container of an installed package.

    .DESCRIPTION
        Thin wrapper around Invoke-CommandInDesktopPackage that resolves the
        PackageFamilyName + AppId from a partial package name. Useful for
        interactive debugging — you can run cmd.exe, powershell.exe or any
        diagnostic tool with the package's VFS / virtual registry mappings
        active.

        Throws when the name matches zero or more than one installed package.
        Pass -PackageName as the full PackageFullName to disambiguate.

    .PARAMETER PackageName
        Full or partial package name (wildcards accepted). Matched first with
        Get-AppxPackage -Name; falls back to a substring search.

    .PARAMETER Command
        Command to run inside the container. Defaults to cmd.exe.

    .PARAMETER AppId
        Application Id to use. If omitted, the first app in the manifest is
        used; a warning is emitted when the package declares multiple apps.

    .EXAMPLE
        # Open a cmd shell inside the Notepad++ package
        Invoke-MsixCommand -PackageName 'Notepad++'

    .EXAMPLE
        # Launch PowerShell inside the container — handy for inspecting
        # virtualized registry/file paths
        Invoke-MsixCommand -PackageName 'Notepad++' -Command 'powershell.exe'

    .EXAMPLE
        # Pin to a specific Application when the package declares multiple
        Invoke-MsixCommand -PackageName 'Contoso' -AppId 'App2' -Command 'regedit.exe'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$PackageName,
        [string]$Command = 'cmd.exe',
        [string]$AppId
    )
    PROCESS {
        try {
            $appx = Get-AppxPackage -Name $PackageName -ErrorAction Stop
        } catch {
            $appx = Get-AppxPackage | Where-Object { $_.Name -like "*$PackageName*" }
        }
        if (@($appx).Count -gt 1) { throw "Multiple packages match '$PackageName'. Use the full package name." }
        if (-not $appx)           { throw "No installed package matches '$PackageName'." }

        if (-not $AppId) {
            $manifest = Get-AppPackageManifest -Package $appx.PackageFullName
            $apps     = @($manifest.Package.Applications.Application)
            if ($apps.Count -gt 1) { Write-Warning "Multiple apps in package; using first: $($apps[0].Id)" }
            $AppId = $apps[0].Id
        }

        if ($PSCmdlet.ShouldProcess($appx.PackageFamilyName, "Invoke-CommandInDesktopPackage")) {
            Invoke-CommandInDesktopPackage -PackageFamilyName $appx.PackageFamilyName `
                                           -AppId $AppId `
                                           -Command $Command `
                                           -PreventBreakaway
        }
    }
}
Set-Alias -Name Invoke-MsixCmd  -Value Invoke-MsixCommand
Set-Alias -Name start-MsixCmd   -Value Invoke-MsixCommand

#endregion


#region --- Public: Signing / publisher update ------------------------------

function Update-MsixSigner {
    <#
    .SYNOPSIS
        Re-signs an MSIX package, optionally updating the Publisher identity.

    .DESCRIPTION
        If -Publisher differs from the current Identity/Publisher, the manifest
        is updated, the package filename is rewritten to reflect the new
        publisher hash, and then re-signed. If the publisher already matches,
        only re-signing happens (the file is left in place).

        Idempotent: re-running with the same -Publisher is a no-op for the
        manifest portion (only the signing step runs again).

        For pure key rotation (publisher stays the same), call
        Invoke-MsixSigning directly instead — it skips the unpack/repack cycle.

    .PARAMETER PackagePath
        Path to the .msix / .appx file to re-sign. Accepts pipeline input.

    .PARAMETER Publisher
        New Identity/Publisher distinguished name, e.g. 'CN=Contoso, O=Contoso, C=US'.
        Must match the Subject of the signing certificate. Omit to keep the
        existing value.

    .PARAMETER Pfx
        Path to the signing certificate (.pfx).

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .EXAMPLE
        # Change publisher and sign with a dev cert
        $pw = Read-Host -AsSecureString
        Update-MsixSigner -PackagePath app.msix `
            -Publisher 'CN=Contoso, O=Contoso, C=US' `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Just re-sign (publisher unchanged)
        Update-MsixSigner -PackagePath app.msix -Pfx cert.pfx -PfxPassword $pw

    .OUTPUTS
        None. Writes the (possibly renamed) signed package to disk and logs
        the final path via Write-MsixLog.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$PackagePath,
        [string]$Publisher,
        [string]$Pfx,
        [SecureString]$PfxPassword
    )

    PROCESS {
        $toolsRoot = Get-MsixToolsRoot
        $fileinfo  = Get-Item $PackagePath
        $workspace = New-MsixWorkspace $fileinfo.BaseName

        try {
            Write-MsixLog Info "Unpacking: $($fileinfo.FullName)"
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
            Assert-MsixProcessSuccess $r 'MakeAppx unpack'

            [xml]$appinfo = Get-MsixManifest "$workspace\AppxManifest.xml"

            $outputPath = $fileinfo.FullName

            if ($Publisher -and $appinfo.Package.Identity.Publisher -cne $Publisher) {
                $oldPublisherId = Get-MsixPublisherId $appinfo.Package.Identity.Publisher
                $newPublisherId = Get-MsixPublisherId $Publisher

                $appinfo.Package.Identity.Publisher = $Publisher
                Save-MsixManifest $appinfo "$workspace\AppxManifest.xml"

                $outputPath = $fileinfo.FullName -replace [regex]::Escape($oldPublisherId), $newPublisherId
                Write-MsixLog Info "Output path: $outputPath"
            } else {
                Write-MsixLog Info "Publisher unchanged; repacking with same identity"
            }

            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('pack', '/p', $outputPath, '/d', $workspace, '/o')
            Assert-MsixProcessSuccess $r 'MakeAppx pack'

            Invoke-MsixSigning -PackagePath $outputPath -Pfx $Pfx -PfxPassword $PfxPassword
            Write-MsixLog Info "Done: $outputPath"

        } finally {
            Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion


#region --- Public: PSF (legacy JSON helper, kept for compatibility) --------

function New-MsixPsfJson {
    <#
    .SYNOPSIS
        Generates PSF config.json content from an AppxManifest and fixup parameters.

    .DESCRIPTION
        Legacy helper that emits a flat config.json string for a single fixup
        type. Produces incorrect output for multi-application packages — kept
        only for compatibility with first-generation scripts.

        For new code, build the config with the typed helpers
        (New-MsixPsfFileRedirectionConfig, New-MsixPsfRegLegacyConfig, etc.)
        and pass them to Add-MsixPsfV2 -Fixups.

    .PARAMETER AppxManifest
        Path to the AppxManifest.xml that describes the applications.

    .PARAMETER Fixup
        Which fixup to emit. One of: FileRedirectionFixup, TraceFixup,
        WaitForDebuggerFixup, DynamicLibraryFixup, EnvVarFixup,
        KernelTraceControl, RegLegacyFixups.

    .PARAMETER Patterns
        Pattern strings — interpretation depends on -Fixup.

    .PARAMETER Hive
        HKCU or HKLM. Only meaningful for RegLegacyFixups.

    .PARAMETER Access
        Access level for RegLegacyFixups (FULL2RW, FULL2R, Full2MaxAllowed,
        RW2R, RW2MaxAllowed).

    .PARAMETER Base
        Base path for FileRedirectionFixup.

    .EXAMPLE
        # Legacy: emit a FileRedirection config.json for the first app
        New-MsixPsfJson -AppxManifest .\AppxManifest.xml `
            -Fixup FileRedirectionFixup -Base 'logs' -Patterns '.*\.log'

    .OUTPUTS
        [string] JSON document. Emits a deprecation warning on every call.

    .NOTES
        Prefer the typed helpers (New-MsixPsfFileRedirectionConfig, etc.) combined
        with New-MsixPsfConfig for new scripts. This function is retained for
        backward compatibility with v1 scripts.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSUseShouldProcessForStateChangingFunctions',
        '',
        Justification = 'This compatibility helper only returns JSON and does not change system state.'
    )]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$AppxManifest,
        [Parameter(Mandatory)]
        [ValidateSet('FileRedirectionFixup','TraceFixup','WaitForDebuggerFixup',
                     'DynamicLibraryFixup','EnvVarFixup','KernelTraceControl','RegLegacyFixups')]
        [string]$Fixup,
        [string[]]$Patterns,
        [ValidateSet('HKCU','HKLM')]
        [string]$Hive,
        [ValidateSet('FULL2RW','FULL2R','Full2MaxAllowed','RW2R','RW2MaxAllowed')]
        [string]$Access,
        [string]$Base
    )

    Write-Warning 'New-MsixPsfJson is obsolete and produces incorrect output for multi-app packages. Use New-MsixPsfConfig with typed builders (New-MsixPsfFileRedirectionConfig, etc.) and Add-MsixPsfV2 instead.'
    [xml]$appinfo  = _MsixLoadXmlSecure -Path (Get-Item $AppxManifest).FullName
    $apps          = @($appinfo.Package.Applications.Application)

    $appEntries = foreach ($app in $apps) {
        [pscustomobject]@{
            id         = $app.Id
            executable = $app.Executable.Replace('\', '/')
        }
    }

    $fixupConfig = switch ($Fixup) {
        'FileRedirectionFixup' { New-MsixPsfFileRedirectionConfig -Base $Base -Patterns $Patterns }
        'RegLegacyFixups'      { New-MsixPsfRegLegacyConfig       -Hive $Hive -Access $Access -Patterns $Patterns }
        default {
            @{ dll = "$Fixup.dll" }
        }
    }

    $lastApp = $apps[-1]
    $exeName = $lastApp.Executable.Split('\')[-1] -replace '\.exe$', ''

    return @{
        applications = [array]$appEntries
        processes    = [array]@{
            executable = $exeName
            fixups     = [array]$fixupConfig
        }
    } | ConvertTo-Json -Depth 15
}

#endregion


#region --- Public: App aliases ---------------------------------------------

function Add-MsixAlias {
    <#
    .SYNOPSIS
        Adds AppExecutionAlias extensions to applications in an MSIX package.

    .DESCRIPTION
        Adds a windows.appExecutionAlias extension for each targeted application.
        The alias name matches the application's executable leaf name (or, when
        the executable is a PsfLauncher, the app Id with a `.exe` suffix).
        Idempotent: skips apps that already have an alias declared.

        Suggestions come from Get-MsixAliasCandidate, which also feeds the
        `AppExecutionAlias` finding in Get-MsixHeuristicFinding.

    .PARAMETER PackagePath
        Path to the .msix file to modify.

    .PARAMETER AppIds
        Application IDs to add aliases for. If omitted and -All is not set,
        aliases are added to all applications.

    .PARAMETER All
        Add aliases to all applications in the package.

    .PARAMETER OutputPath
        If set, write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path. Ignored when -SkipSigning is set.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        When signing fails, copy the unsigned scratch package here so the
        caller can inspect or hand-sign it. The original target is left
        intact regardless.

    .EXAMPLE
        # Add aliases to every app and sign in one shot (idempotent)
        Add-MsixAlias -PackagePath app.msix -All `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Test/dev: add aliases for two specific apps, no signing
        Add-MsixAlias -PackagePath app.msix `
            -AppIds 'App','App2' -SkipSigning -OutputPath app-alias.msix
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$PackagePath,
        [string[]]$AppIds,
        [switch]$All,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    PROCESS {
        $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add AppExecutionAlias')

        $targetAll = $All
        $targetAppIds = $AppIds

        _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
            -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
            -UnsignedOutputPath $UnsignedOutputPath `
            -WhatIfPreview:$isWhatIf `
            -Activity 'Add AppExecutionAlias' -Mutate {
            param([xml]$manifest)

            Add-MsixManifestNamespace $manifest 'uap3'
            Add-MsixManifestNamespace $manifest 'desktop'

            $uap3Uri    = Get-MsixManifestNamespaceUri 'uap3'
            $desktopUri = Get-MsixManifestNamespaceUri 'desktop'

            $targets = @($manifest.Package.Applications.Application)
            if (-not $targetAll -and $targetAppIds) {
                $targets = $targets | Where-Object { $targetAppIds -contains $_.Id }
            }

            foreach ($app in $targets) {
                # Reliable duplicate check: walk child nodes of Extensions
                $existingAliasExt = @($app.Extensions.Extension) |
                    Where-Object { $_.Category -eq 'windows.appExecutionAlias' }
                if ($existingAliasExt) {
                    Write-MsixLog Warning "AppExecutionAlias already present for $($app.Id); skipping"
                    continue
                }

                # Determine the alias name from the real executable
                $executable = $app.Executable.Replace('\', '/')
                if ($executable -match 'PsfLauncher') {
                    # Note: workspace is not available inside _MsixMutateManifest callback;
                    # fall back to guessing the alias from the app Id
                    $aliasName = "$($app.Id.ToLower()).exe"
                } else {
                    $aliasName = $executable.Split('/')[-1]
                }

                # Build: <uap3:Extension Category="windows.appExecutionAlias">
                #          <uap3:AppExecutionAlias>
                #            <desktop:ExecutionAlias Alias="myapp.exe" />
                #          </uap3:AppExecutionAlias>
                #        </uap3:Extension>
                $uap3Ext = $manifest.CreateElement('uap3:Extension', $uap3Uri)
                $uap3Ext.SetAttribute('Category', 'windows.appExecutionAlias')

                $aliasEl   = $manifest.CreateElement('uap3:AppExecutionAlias', $uap3Uri)
                $deskAlias = $manifest.CreateElement('desktop:ExecutionAlias', $desktopUri)
                $deskAlias.SetAttribute('Alias', $aliasName)

                $null = $aliasEl.AppendChild($deskAlias)
                $null = $uap3Ext.AppendChild($aliasEl)

                # Get or create Application/Extensions node (use captured ref, not property re-access)
                $extNode = $app.SelectSingleNode('*[local-name()="Extensions"]')
                if (-not $extNode) {
                    $extNode = $manifest.CreateElement('Extensions', $manifest.Package.NamespaceURI)
                    $null    = $app.AppendChild($extNode)
                }
                $null = $extNode.AppendChild($uap3Ext)

                Write-MsixLog Info "AppExecutionAlias added for $($app.Id): $aliasName"
            }
        }
    }
}

#endregion


#region --- Public: Start menu ----------------------------------------------

function Remove-MsixStartMenuEntry {
    <#
    .SYNOPSIS
        Sets AppListEntry=none on selected (or all) applications, hiding them
        from the Start menu.

    .DESCRIPTION
        Useful for helper / background-only apps that should not appear in the
        user's Start menu. Idempotent: re-running on apps already hidden logs
        an info line and leaves the manifest unchanged.

    .PARAMETER PackagePath
        Path to the .msix file.

    .PARAMETER AppIds
        Application IDs to hide. Omit or use -All for every app.

    .PARAMETER All
        Hide all applications.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        When signing fails, copy the unsigned scratch package here so the
        caller can inspect or hand-sign it. The original target is left intact.

    .EXAMPLE
        # Hide every app from Start and re-sign (idempotent)
        Remove-MsixStartMenuEntry -PackagePath app.msix -All `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Hide just the Helper app, skip signing for now
        Remove-MsixStartMenuEntry -PackagePath app.msix `
            -AppIds 'Helper' -SkipSigning
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$PackagePath,
        [string[]]$AppIds,
        [switch]$All,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    PROCESS {
        $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Remove Start menu entry')

        $targetAll = $All
        $targetAppIds = $AppIds

        _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
            -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
            -UnsignedOutputPath $UnsignedOutputPath `
            -WhatIfPreview:$isWhatIf `
            -Activity 'Remove Start menu entry' -Mutate {
            param([xml]$manifest)

            $targets = @($manifest.Package.Applications.Application)
            if (-not $targetAll -and $targetAppIds) {
                $targets = $targets | Where-Object { $targetAppIds -contains $_.Id }
            }

            foreach ($app in $targets) {
                $ve = $app.SelectSingleNode('*[local-name()="VisualElements"]')
                if (-not $ve) { continue }
                if ($ve.GetAttribute('AppListEntry') -eq 'none') {
                    Write-MsixLog Info "$($app.Id) already hidden from Start menu; skipping"
                    continue
                }
                $ve.SetAttribute('AppListEntry', 'none')
                Write-MsixLog Info "Start menu entry removed: $($app.Id)"
            }
        }
    }
}


function Add-MsixStartMenuFolder {
    <#
    .SYNOPSIS
        Sets a VisualGroup (Start menu folder) on all applications in a package.

    .DESCRIPTION
        Sets the VisualGroup attribute on every Application/VisualElements
        node. All apps in the package will be grouped under the supplied
        folder name in the Start menu. Idempotent — re-running with the
        same FolderName produces the same manifest.

    .PARAMETER PackagePath
        Path to the .msix file.

    .PARAMETER FolderName
        Name of the Start menu folder / group.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package. Alias: -NoSign.

    .PARAMETER Pfx
        Signing certificate (.pfx) path.

    .PARAMETER PfxPassword
        SecureString password for the .pfx.

    .PARAMETER UnsignedOutputPath
        When signing fails, copy the unsigned scratch package here so the
        caller can inspect or hand-sign it.

    .EXAMPLE
        # Group all apps under 'Contoso Apps' and sign (idempotent)
        Add-MsixStartMenuFolder -PackagePath app.msix `
            -FolderName 'Contoso Apps' -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Dev: change folder, skip signing
        Add-MsixStartMenuFolder -PackagePath app.msix `
            -FolderName 'Tools' -SkipSigning
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [string]$FolderName,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    PROCESS {
        $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, "Set VisualGroup '$FolderName'")

        _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
            -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
            -UnsignedOutputPath $UnsignedOutputPath `
            -WhatIfPreview:$isWhatIf `
            -Activity "Set VisualGroup '$FolderName'" -Mutate {
            param([xml]$manifest)

            foreach ($app in @($manifest.Package.Applications.Application)) {
                $ve = $app.SelectSingleNode('*[local-name()="VisualElements"]')
                if (-not $ve) { continue }
                $ve.SetAttribute('VisualGroup', $FolderName)
                Write-MsixLog Info "VisualGroup '$FolderName' set on $($app.Id)"
            }
        }
    }
}

#endregion
