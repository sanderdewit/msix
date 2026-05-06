#region --- Load sub-modules ------------------------------------------------
. "$PSScriptRoot\MSIX.Logging.ps1"
. "$PSScriptRoot\MSIX.Core.ps1"
. "$PSScriptRoot\MSIX.Validation.ps1"
. "$PSScriptRoot\MSIX.Manifest.ps1"
. "$PSScriptRoot\MSIX.PSF.ps1"
. "$PSScriptRoot\MSIX.Signing.ps1"
. "$PSScriptRoot\MSIX.ContextMenu.ps1"
. "$PSScriptRoot\MSIX.Pipeline.ps1"
. "$PSScriptRoot\MSIX.Investigation.ps1"
. "$PSScriptRoot\MSIX.AppData.ps1"
. "$PSScriptRoot\MSIX.Accelerator.ps1"
. "$PSScriptRoot\MSIX.PsfBinaries.ps1"
. "$PSScriptRoot\MSIX.Debug.ps1"
. "$PSScriptRoot\MSIX.AppAttach.ps1"
. "$PSScriptRoot\MSIX.AppIsolation.ps1"
. "$PSScriptRoot\MSIX.Limitations.ps1"
. "$PSScriptRoot\MSIX.Trace.ps1"
. "$PSScriptRoot\MSIX.Scripts.ps1"
. "$PSScriptRoot\MSIX.MFR.ps1"
. "$PSScriptRoot\MSIX.VcRuntime.ps1"
. "$PSScriptRoot\MSIX.Detection.ps1"
. "$PSScriptRoot\MSIX.ManifestExtensions.ps1"
. "$PSScriptRoot\MSIX.Heuristics.ps1"
. "$PSScriptRoot\MSIX.Compare.ps1"
#endregion


#region --- Public: Package information -------------------------------------

function Get-MsixInfo {
    <#
    .SYNOPSIS
        Returns identity, publisher, signing, and (optionally) application details
        for an MSIX package without fully unpacking it.

    .PARAMETER PackagePath
        Path to the .msix / .appx file.

    .PARAMETER Detailed
        Also returns the raw Application XML elements.

    .EXAMPLE
        Get-MsixInfo -PackagePath app.msix
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

    .PARAMETER PackageName
        Full or partial package name (wildcards accepted).

    .PARAMETER Command
        Command to run inside the container. Defaults to cmd.exe.

    .PARAMETER AppId
        Application Id to use. If omitted, the first app in the manifest is used.

    .EXAMPLE
        Invoke-MsixCommand -PackageName 'Notepad++' -Command 'powershell.exe'

    .EXAMPLE
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
        If -Publisher is different from the current value, the manifest is updated,
        the package filename is adjusted to reflect the new Publisher ID, and then
        re-signed. If the publisher already matches, only re-signing happens.

    .EXAMPLE
        Update-MsixSigner -PackagePath app.msix -Publisher 'CN=Contoso' -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$PackagePath,
        [string]$Publisher,
        [string]$Pfx,
        [string]$PfxPassword
    )

    PROCESS {
        $toolsRoot = Get-MsixToolsRoot
        $fileinfo  = Get-Item $PackagePath
        $workspace = New-MsixWorkspace $fileinfo.BaseName

        try {
            Write-MsixLog Info "Unpacking: $($fileinfo.FullName)"
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
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

            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$outputPath`" /d `"$workspace`" /o"
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
    [xml]$appinfo  = Get-Content (Get-Item $AppxManifest).FullName -Raw
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
        The alias name matches the application's executable leaf name. Idempotent:
        skips apps that already have an alias declared.

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
        Do not sign the resulting package.

    .EXAMPLE
        Add-MsixAlias -PackagePath app.msix -All -Pfx cert.pfx -PfxPassword 'P@ss'

    .EXAMPLE
        Add-MsixAlias -PackagePath app.msix -AppIds 'App','App2' -NoSign -OutputPath app-alias.msix
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
        [string]$PfxPassword
    )

    PROCESS {
        if (-not $PSCmdlet.ShouldProcess($PackagePath, 'Add AppExecutionAlias')) { return }

        $targetAll = $All
        $targetAppIds = $AppIds

        _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
            -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
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

    .PARAMETER PackagePath
        Path to the .msix file.

    .PARAMETER AppIds
        Application IDs to hide. Omit or use -All for every app.

    .PARAMETER All
        Hide all applications.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package.

    .EXAMPLE
        Remove-MsixStartMenuEntry -PackagePath app.msix -All -Pfx cert.pfx -PfxPassword 'P@ss'

    .EXAMPLE
        Remove-MsixStartMenuEntry -PackagePath app.msix -AppIds 'Helper' -NoSign
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
        [string]$PfxPassword
    )

    PROCESS {
        if (-not $PSCmdlet.ShouldProcess($PackagePath, 'Remove Start menu entry')) { return }

        $targetAll = $All
        $targetAppIds = $AppIds

        _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
            -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
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

    .PARAMETER PackagePath
        Path to the .msix file.

    .PARAMETER FolderName
        Name of the Start menu folder / group.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package.

    .EXAMPLE
        Add-MsixStartMenuFolder -PackagePath app.msix -FolderName 'Contoso Apps' -Pfx cert.pfx -PfxPassword 'P@ss'

    .EXAMPLE
        Add-MsixStartMenuFolder -PackagePath app.msix -FolderName 'Tools' -NoSign
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
        [string]$PfxPassword
    )

    PROCESS {
        if (-not $PSCmdlet.ShouldProcess($PackagePath, "Set VisualGroup '$FolderName'")) { return }

        _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
            -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
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


#region --- Backward-compatible aliases (v1 verb casing) --------------------
Set-Alias -Name update-MsixSigner             -Value Update-MsixSigner
Set-Alias -Name add-MsixPsf                   -Value Add-MsixPsfV2
Set-Alias -Name new-MsixPsfJson               -Value New-MsixPsfJson
Set-Alias -Name add-MsixAlias                 -Value Add-MsixAlias
Set-Alias -Name remove-MsixStartMenuEntry     -Value Remove-MsixStartMenuEntry
Set-Alias -Name add-MsixStartMenuFolder       -Value Add-MsixStartMenuFolder
Set-Alias -Name Get-PublisherIdFromPublisher   -Value Get-MsixPublisherId
#endregion


#region --- Exports ---------------------------------------------------------
Export-ModuleMember -Function @(
    # Logging
    'Write-MsixLog'
    'Set-MsixLogLevel'
    'Set-MsixLogFile'
    # Core / tools
    'Get-MsixToolsRoot'
    'Set-MsixToolsRoot'
    'New-MsixWorkspace'
    'Invoke-MsixProcess'
    'Get-MsixPublisherId'
    # Validation
    'Test-MsixManifest'
    'Test-MsixPsfConfig'
    'Assert-MsixProcessSuccess'
    # Manifest helpers
    'Get-MsixManifest'
    'New-MsixManifestDocument'
    'Select-MsixManifestNode'
    'Select-MsixManifestNodes'
    'Save-MsixManifest'
    'Add-MsixManifestNamespace'
    'Get-MsixManifestApplications'
    'Get-MsixManifestApplication'
    'Get-MsixManifestNamespaceUri'
    'Set-MsixManifestMaxVersionTested'
    # PSF builders
    'New-MsixPsfFileRedirectionConfig'
    'New-MsixPsfRegLegacyConfig'
    'New-MsixPsfEnvVarConfig'
    'New-MsixPsfTraceConfig'
    'New-MsixPsfArguments'
    'New-MsixPsfStartScriptConfig'
    'New-MsixPsfDynamicLibraryConfig'
    'New-MsixPsfWaitForDebuggerConfig'
    'New-MsixPsfConfig'
    'Add-MsixPsfV2'
    # Investigation
    'Invoke-MsixInvestigation'
    'Get-MsixCompatibilityReport'
    'Get-MsixStaticAnalysis'
    'Invoke-MsixProcMonCapture'
    'Get-MsixProcMonFailures'
    'Add-MsixDiagnosticTrace'
    'Resolve-MsixProcMonPath'
    # AppData / out-of-package
    'Get-MsixContainerAppData'
    'Get-MsixOrphanedAppData'
    'Copy-MsixHostAppDataIntoPackage'
    'Invoke-MsixContainerCommand'
    'Get-MsixPackageStorageSummary'
    # Accelerators
    'Import-MsixAccelerator'
    'Invoke-MsixAccelerator'
    'ConvertFrom-MsixYamlAccelerator'
    # PSF binaries / Procmon / SDK
    'Install-MsixPsfBinaries'
    'Update-MsixPsfBinaries'
    'Get-MsixPsfBinariesVersion'
    'Install-MsixProcMon'
    'Update-MsixProcMon'
    'Install-MsixSdkTools'
    'Update-MsixSdkTools'
    'Get-MsixSdkToolsVersion'
    'Initialize-MsixToolchain'
    # Debug session
    'Start-MsixDebugSession'
    'Get-MsixDebugRecommendations'
    'New-MsixSandboxConfig'
    'Start-MsixSandbox'
    'Resolve-MsixDebugViewPath'
    # App Attach
    'New-MsixAppAttachImage'
    'Mount-MsixAppAttachImage'
    'Dismount-MsixAppAttachImage'
    'Test-MsixAppAttachImage'
    'Resolve-MsixMgrPath'
    # App Isolation (Win32)
    'Add-MsixAppIsolation'
    'Remove-MsixAppIsolation'
    'Get-MsixIsolationCapabilities'
    # Limitations / know-your-installer
    'Get-MsixLimitations'
    'Test-MsixAgainstLimitations'
    # Trace Fixup parser
    'ConvertFrom-MsixTraceLine'
    'Get-MsixTraceOutput'
    'Get-MsixTraceFailures'
    'ConvertFrom-MsixTraceToFindings'
    # msixmgr binary management
    'Install-MsixMgr'
    'Update-MsixMgr'
    'Get-MsixMgrVersion'
    # Standard scripts (PSADT-flavoured)
    'Get-MsixStandardScripts'
    'New-MsixStandardScript'
    'Set-MsixScriptSignature'
    'Add-MsixStandardScript'
    # MFR (Modern File Redirection — TMurgent fork)
    'New-MsixMfrTraditionalRule'
    'New-MsixMfrLocalRule'
    'New-MsixPsfMfrConfig'
    'Get-MsixMfrKnownFolders'
    # VC++ runtime detection / bundling
    'Get-MsixVcRuntimeReferences'
    'Add-MsixVcRuntimeBundle'
    # TMEditX-style heuristics
    'Get-MsixKnownCapabilities'
    'Add-MsixCapability'
    'Get-MsixUninstallerCandidates'
    'Get-MsixUninstallRegistryEntries'
    'Remove-MsixUninstallerArtifacts'
    'Get-MsixRunKeyEntries'
    'Get-MsixShellContextMenuEntries'
    'Get-MsixComServerEntries'
    'Get-MsixAliasCandidates'
    'Add-MsixSplashScreen'
    'Update-MsixPackageVersion'
    'Get-MsixHeuristicFindings'
    'Invoke-MsixAutoFix'
    'Invoke-MsixAutoFixFromAnalysis'
    # Auto-detection scanners (v0.11)
    'Get-MsixFontCandidates'
    'Get-MsixDesktopShortcutCandidates'
    'Get-MsixCapabilityHints'
    'Get-MsixNestedPackageCandidates'
    # Package compare
    'Compare-MsixPackage'
    # Manifest-only fixers (alternatives to PSF)
    'Set-MsixFileSystemWriteVirtualization'
    'Set-MsixRegistryWriteVirtualization'
    'Set-MsixInstalledLocationVirtualization'
    'Add-MsixLoaderSearchPathOverride'
    'Add-MsixFirewallRule'
    'Add-MsixProtocolHandler'
    'Add-MsixFileTypeAssociation'
    'Add-MsixStartupTask'
    'Add-MsixFontExtension'
    'Set-MsixBrandMetadata'
    'Add-MsixShellVerbExtension'
    'Add-MsixComServerExtension'
    'Remove-MsixDesktopShortcuts'
    # Signing
    'Invoke-MsixSigning'
    # Context menus
    'Add-MsixLegacyContextMenu'
    'Add-MsixFileExplorerContextMenu'
    # Pipeline
    'Invoke-MsixPipeline'
    # Public (package ops)
    'Get-MsixInfo'
    'Invoke-MsixCommand'
    'Update-MsixSigner'
    'New-MsixPsfJson'
    'Add-MsixAlias'
    'Remove-MsixStartMenuEntry'
    'Add-MsixStartMenuFolder'
) -Alias @(
    'Invoke-MsixCmd'
    'start-MsixCmd'
    'update-MsixSigner'
    'add-MsixPsf'
    'new-MsixPsfJson'
    'add-MsixAlias'
    'remove-MsixStartMenuEntry'
    'add-MsixStartMenuFolder'
    'Get-PublisherIdFromPublisher'
)
#endregion
