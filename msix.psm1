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

    BEGIN {
        Add-Type -Assembly System.IO.Compression.FileSystem
    }

    PROCESS {
        $fileinfo  = Get-Item $PackagePath
        $workspace = New-MsixWorkspace $fileinfo.BaseName

        try {
            # Extract only AppxManifest.xml using ZipFile (no MakeAppx needed)
            $zip = [IO.Compression.ZipFile]::OpenRead($fileinfo.FullName)
            try {
                $entry = $zip.Entries | Where-Object { $_.Name -eq 'AppxManifest.xml' }
                if (-not $entry) { throw 'AppxManifest.xml not found in package' }
                [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, "$workspace\AppxManifest.xml", $true)
            } finally {
                $zip.Dispose()
            }

            [xml]$appinfo = Get-Content "$workspace\AppxManifest.xml" -Raw
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
                                     -NotePropertyValue @($appinfo.Package.Applications.Application)
            }

            return $result

        } finally {
            Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion


#region --- Public: Package debugging ---------------------------------------

function Invoke-MsixCmd {
    <#
    .SYNOPSIS
        Launches a command inside the MSIX container of an installed package.

    .PARAMETER PackageName
        Full or partial package name (wildcards accepted).

    .PARAMETER Command
        Command to run inside the container. Defaults to cmd.exe.

    .EXAMPLE
        Invoke-MsixCmd -PackageName 'Notepad++' -Command 'powershell.exe'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$PackageName,
        [string]$Command = 'cmd.exe'
    )

    PROCESS {
        try {
            $appx = Get-AppxPackage -Name $PackageName -ErrorAction Stop
        } catch {
            $appx = Get-AppxPackage | Where-Object { $_.Name -like "*$PackageName*" }
        }

        if (@($appx).Count -gt 1) {
            throw "Multiple packages match '$PackageName'. Use the full package name."
        }
        if (-not $appx) {
            throw "No installed package matches '$PackageName'."
        }

        $manifest = Get-AppPackageManifest -Package $appx.PackageFullName
        $apps     = @($manifest.Package.Applications.Application)

        if ($apps.Count -gt 1) {
            Write-Warning "Multiple apps in package; using first: $($apps[0].Id)"
        }
        $appId = $apps[0].Id

        if ($PSCmdlet.ShouldProcess($appx.PackageFamilyName, "Invoke-CommandInDesktopPackage")) {
            Invoke-CommandInDesktopPackage -PackageFamilyName $appx.PackageFamilyName `
                                           -AppId $appId `
                                           -Command $Command `
                                           -PreventBreakaway
        }
    }
}

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
                $oldPublisherId = Get-PublisherIdFromPublisher $appinfo.Package.Identity.Publisher
                $newPublisherId = Get-PublisherIdFromPublisher $Publisher

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

    .PARAMETER PackagePath
        Path to the .msix file to modify.

    .PARAMETER AppIds
        Application IDs to add aliases for. Omit or use -All to target every app.

    .PARAMETER All
        Add aliases to all applications in the package.

    .EXAMPLE
        Add-MsixAlias -PackagePath app.msix -All
    .EXAMPLE
        Add-MsixAlias -PackagePath app.msix -AppIds 'App', 'App2' -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$PackagePath,
        [string[]]$AppIds,
        [switch]$All,
        [string]$Pfx,
        [string]$PfxPassword
    )

    PROCESS {
        $toolsRoot = Get-MsixToolsRoot
        $fileinfo  = Get-Item $PackagePath
        $workspace = New-MsixWorkspace $fileinfo.BaseName

        try {
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
            Assert-MsixProcessSuccess $r 'MakeAppx unpack'

            [xml]$appinfo = Get-MsixManifest "$workspace\AppxManifest.xml"
            Add-MsixManifestNamespace $appinfo 'desktop'
            Add-MsixManifestNamespace $appinfo 'uap3'

            $desktopUri = Get-MsixManifestNamespaceUri 'desktop'
            $uap3Uri    = Get-MsixManifestNamespaceUri 'uap3'

            $targets = @($appinfo.Package.Applications.Application)
            if (-not $All -and $AppIds) {
                $targets = $targets | Where-Object { $AppIds -contains $_.Id }
            }

            foreach ($app in $targets) {
                if ($app.Extensions.Extension.AppExecutionAlias.ExecutionAlias) {
                    Write-MsixLog Warning "Alias already exists for $($app.Id); skipping"
                    continue
                }

                # If the app is PSF-wrapped, read the real executable from config.json
                $executable = $app.Executable.Replace('\', '/')
                if ($executable -match 'PsfLauncher') {
                    $relDir    = $executable.Substring(0, $executable.LastIndexOf('/'))
                    $cfgPath   = "$workspace\$($relDir.Replace('/', '\'))\config.json"
                    if (Test-Path $cfgPath) {
                        $cfg        = Get-Content $cfgPath -Raw | ConvertFrom-Json
                        $appEntry   = $cfg.applications | Where-Object { $_.id -eq $app.Id }
                        if ($appEntry) { $executable = $appEntry.executable.Replace('\', '/') }
                    }
                }

                # Ensure Application/Extensions node exists
                if (-not $app.Extensions) {
                    $extNode = $appinfo.CreateElement('Extensions', $appinfo.Package.NamespaceURI)
                    $null    = $app.AppendChild($extNode)
                }

                $uap3Ext = $appinfo.CreateElement('uap3:Extension', $uap3Uri)
                $uap3Ext.SetAttribute('Category',          'windows.appExecutionAlias')
                $uap3Ext.SetAttribute('EntryPoint',        'Windows.FullTrustApplication')
                $uap3Ext.SetAttribute('desktop:Executable', $executable)

                $aliasEl    = $appinfo.CreateElement('uap3:AppExecutionAlias', $uap3Uri)
                $deskAlias  = $appinfo.CreateElement('desktop:ExecutionAlias', $desktopUri)
                $deskAlias.SetAttribute('Alias', $executable.Split('/')[-1])

                $null = $aliasEl.AppendChild($deskAlias)
                $null = $uap3Ext.AppendChild($aliasEl)
                $null = $app.Extensions.AppendChild($uap3Ext)

                Write-MsixLog Info "Alias added for $($app.Id): $($executable.Split('/')[-1])"
            }

            if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save manifest')) {
                Save-MsixManifest $appinfo "$workspace\AppxManifest.xml"
            }

            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
            Assert-MsixProcessSuccess $r 'MakeAppx pack'

            Invoke-MsixSigning -PackagePath $fileinfo.FullName -Pfx $Pfx -PfxPassword $PfxPassword

        } finally {
            Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
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

    .EXAMPLE
        Remove-MsixStartMenuEntry -PackagePath app.msix -All
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$PackagePath,
        [string[]]$AppIds,
        [switch]$All,
        [string]$Pfx,
        [string]$PfxPassword
    )

    PROCESS {
        $toolsRoot = Get-MsixToolsRoot
        $fileinfo  = Get-Item $PackagePath
        $workspace = New-MsixWorkspace $fileinfo.BaseName

        try {
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
            Assert-MsixProcessSuccess $r 'MakeAppx unpack'

            [xml]$appinfo = Get-MsixManifest "$workspace\AppxManifest.xml"

            $targets = @($appinfo.Package.Applications.Application)
            if (-not $All -and $AppIds) {
                $targets = $targets | Where-Object { $AppIds -contains $_.Id }
            }

            $attr       = $appinfo.CreateAttribute('AppListEntry')
            $attr.Value = 'none'

            foreach ($app in $targets) {
                if ($app.VisualElements.AppListEntry -eq 'none') {
                    Write-MsixLog Info "$($app.Id) already hidden from Start menu; skipping"
                    continue
                }
                $app.VisualElements.Attributes.Append($attr.Clone()) | Out-Null
                Write-MsixLog Info "Start menu entry removed: $($app.Id)"
            }

            if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save manifest')) {
                Save-MsixManifest $appinfo "$workspace\AppxManifest.xml"
            }

            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
            Assert-MsixProcessSuccess $r 'MakeAppx pack'

            Invoke-MsixSigning -PackagePath $fileinfo.FullName -Pfx $Pfx -PfxPassword $PfxPassword

        } finally {
            Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
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

    .EXAMPLE
        Add-MsixStartMenuFolder -PackagePath app.msix -FolderName 'Contoso Apps'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [string]$FolderName,
        [string]$Pfx,
        [string]$PfxPassword
    )

    PROCESS {
        $toolsRoot = Get-MsixToolsRoot
        $fileinfo  = Get-Item $PackagePath
        $workspace = New-MsixWorkspace $fileinfo.BaseName

        try {
            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
            Assert-MsixProcessSuccess $r 'MakeAppx unpack'

            [xml]$appinfo = Get-MsixManifest "$workspace\AppxManifest.xml"

            $attr       = $appinfo.CreateAttribute('VisualGroup')
            $attr.Value = $FolderName

            foreach ($app in @($appinfo.Package.Applications.Application)) {
                $app.VisualElements.Attributes.Append($attr.Clone()) | Out-Null
                Write-MsixLog Info "VisualGroup '$FolderName' set on $($app.Id)"
            }

            if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save manifest')) {
                Save-MsixManifest $appinfo "$workspace\AppxManifest.xml"
            }

            $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
            Assert-MsixProcessSuccess $r 'MakeAppx pack'

            Invoke-MsixSigning -PackagePath $fileinfo.FullName -Pfx $Pfx -PfxPassword $PfxPassword

        } finally {
            Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

#endregion


#region --- Backward-compatible aliases (v1 verb casing) --------------------
Set-Alias -Name start-MsixCmd             -Value Invoke-MsixCmd
Set-Alias -Name update-MsixSigner         -Value Update-MsixSigner
Set-Alias -Name add-MsixPsf               -Value Add-MsixPsfV2
Set-Alias -Name new-MsixPsfJson           -Value New-MsixPsfJson
Set-Alias -Name add-MsixAlias             -Value Add-MsixAlias
Set-Alias -Name remove-MsixStartMenuEntry -Value Remove-MsixStartMenuEntry
Set-Alias -Name add-MsixStartMenuFolder   -Value Add-MsixStartMenuFolder
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
    'Get-PublisherIdFromPublisher'
    # Validation
    'Test-MsixManifest'
    'Test-MsixPsfConfig'
    'Assert-MsixProcessSuccess'
    # Manifest helpers
    'Get-MsixManifest'
    'Save-MsixManifest'
    'Add-MsixManifestNamespace'
    'Get-MsixManifestApplications'
    'Set-MsixManifestMaxVersionTested'
    # PSF builders
    'New-MsixPsfFileRedirectionConfig'
    'New-MsixPsfRegLegacyConfig'
    'New-MsixPsfEnvVarConfig'
    'New-MsixPsfTraceConfig'
    'New-MsixPsfArguments'
    'New-MsixPsfStartScriptConfig'
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
    # PSF binaries / Procmon
    'Install-MsixPsfBinaries'
    'Update-MsixPsfBinaries'
    'Get-MsixPsfBinariesVersion'
    'Install-MsixProcMon'
    'Update-MsixProcMon'
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
    'Remove-MsixUninstallerArtifacts'
    'Get-MsixRunKeyEntries'
    'Get-MsixAliasCandidates'
    'Add-MsixSplashScreen'
    'Update-MsixPackageVersion'
    'Get-MsixHeuristicFindings'
    'Invoke-MsixAutoFix'
    # Package compare
    'Compare-MsixPackage'
    # Signing
    'Invoke-MsixSigning'
    # Context menus
    'Add-MsixLegacyContextMenu'
    'Add-MsixFileExplorerContextMenu'
    # Pipeline
    'Invoke-MsixPipeline'
    # Public (package ops)
    'Get-MsixInfo'
    'Invoke-MsixCmd'
    'Update-MsixSigner'
    'New-MsixPsfJson'
    'Add-MsixAlias'
    'Remove-MsixStartMenuEntry'
    'Add-MsixStartMenuFolder'
) -Alias @(
    'start-MsixCmd'
    'update-MsixSigner'
    'add-MsixPsf'
    'new-MsixPsfJson'
    'add-MsixAlias'
    'remove-MsixStartMenuEntry'
    'add-MsixStartMenuFolder'
)
#endregion
