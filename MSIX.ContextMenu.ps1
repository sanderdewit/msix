function Add-MsixLegacyContextMenu {
    <#
    .SYNOPSIS
        Adds a legacy IContextMenu shell extension to an MSIX package.

    .DESCRIPTION
        Supports the COM-based IContextMenu / drag-drop handler pattern used by
        classic Win32 applications, available on Windows 11 21H2 (build 22000+).

        Adds to AppxManifest.xml inside the Application's Extensions node:
          - com:Extension (windows.comServer) for COM server registration
          - desktop9:Extension (windows.fileExplorerClassicContextMenuHandler
            or windows.fileExplorerClassicDragDropContextMenuHandler)

    .PARAMETER PackagePath
        Path to the .msix file to modify.

    .PARAMETER AppId
        Id of the Application element to attach the extensions to.
        Defaults to the first Application in the manifest.

    .PARAMETER ShellExtDll
        Package-relative VFS path to the COM server DLL
        (e.g. VFS\ProgramFilesX64\App\ShellExt.dll).
        MSIX folder-variable prefixes ([{ProgramFilesX64}] etc.) are resolved
        automatically.

    .PARAMETER Clsid
        GUID of the COM class, with or without curly braces (e.g. '{XXXXXXXX-...}').

    .PARAMETER DisplayName
        Friendly display name for the COM surrogate server.

    .PARAMETER FileTypes
        Array of file-type targets. Use '*' for all files, '.ext' for a specific
        extension, 'Directory' for folders, 'Drive' for drives.
        Defaults to @('*').

    .PARAMETER MenuType
        'ContextMenu' (right-click) or 'DragDrop' (drag-and-drop handler).

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package.

    .PARAMETER Pfx / PfxPassword
        Signing certificate. Omit to use automatic store selection.

    .EXAMPLE
        Add-MsixLegacyContextMenu -PackagePath app.msix `
            -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
            -Clsid '{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}' `
            -DisplayName 'My Context Menu' `
            -FileTypes '*', '.log', 'Directory' `
            -Pfx cert.pfx -PfxPassword 'P@ss'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [string]$AppId,
        [Parameter(Mandatory)]
        [string]$ShellExtDll,
        [Parameter(Mandatory)]
        [string]$Clsid,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [string[]]$FileTypes = @('*'),
        [ValidateSet('ContextMenu', 'DragDrop')]
        [string]$MenuType    = 'ContextMenu',
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [string]$PfxPassword
    )

    # Two GUID formats required by the manifest schema:
    #   com:Class Id                    → ST_GUID  → bare,   no braces
    #   desktop9:ExtensionHandler Clsid → ST_CLSID → braced: {XXXXXXXX-...}
    $ClsidBare   = $Clsid.Trim().Trim('{', '}')
    $ClsidBraced = "{$ClsidBare}"

    # Resolve MSIX folder-variable prefixes ([{ProgramFilesX64}]\...) to VFS paths.
    # Callers may pass the raw registry path; normalise it defensively.
    $varMap = @{
        'ProgramFilesX64'  = 'VFS\ProgramFilesX64'
        'ProgramFilesX86'  = 'VFS\ProgramFiles(x86)'
        'ProgramFiles6432' = 'VFS\ProgramFilesX64'
        'System'           = 'VFS\SystemX64'
        'SystemX86'        = 'VFS\System'
        'Windows'          = 'VFS\Windows'
        'CommonAppData'    = 'VFS\ProgramData'
        'AppData'          = 'VFS\AppData\Roaming'
        'LocalAppData'     = 'VFS\AppData\Local'
    }
    foreach ($var in $varMap.Keys) {
        if ($ShellExtDll -match ('^\[\{' + [regex]::Escape($var) + '\}\](.+)$')) {
            $ShellExtDll = $varMap[$var] + '\' + $Matches[1].TrimStart('\')
            break
        }
    }

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -Activity 'Add Legacy Context Menu' -Mutate {
        param([xml]$manifest)

        # Required namespaces
        Add-MsixManifestNamespace $manifest 'com'
        Add-MsixManifestNamespace $manifest 'desktop9'

        # desktop9 requires MaxVersionTested >= 10.0.21301.0
        Set-MsixManifestMaxVersionTested $manifest -MinBuild 21301

        # ── Locate the target Application ─────────────────────────────────
        $apps = @($manifest.Package.Applications.Application)
        $app  = if ($AppId) {
            $apps | Where-Object { $_.GetAttribute('Id') -eq $AppId } | Select-Object -First 1
        } else {
            $apps | Select-Object -First 1
        }
        if (-not $app) { throw "Application '$AppId' not found in the manifest." }

        # ── Application-level Extensions node ────────────────────────────
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        if (-not $appExt) {
            $appExt = $manifest.CreateElement('Extensions', $manifest.Package.NamespaceURI)
            $null   = $app.AppendChild($appExt)
        }

        # ── COM server registration ───────────────────────────────────────
        $comUri    = Get-MsixManifestNamespaceUri 'com'

        $comExt    = $manifest.CreateElement('com:Extension',       $comUri)
        $comExt.SetAttribute('Category', 'windows.comServer')

        $comServer = $manifest.CreateElement('com:ComServer',       $comUri)
        $surrogate = $manifest.CreateElement('com:SurrogateServer', $comUri)
        $surrogate.SetAttribute('DisplayName', $DisplayName)

        $class = $manifest.CreateElement('com:Class', $comUri)
        $class.SetAttribute('Id',             $ClsidBare)   # ST_GUID — no braces
        $class.SetAttribute('Path',           $ShellExtDll)
        $class.SetAttribute('ThreadingModel', 'STA')

        $null = $surrogate.AppendChild($class)
        $null = $comServer.AppendChild($surrogate)
        $null = $comExt.AppendChild($comServer)
        $null = $appExt.AppendChild($comExt)

        # ── Shell extension handler ───────────────────────────────────────
        $d9Uri = Get-MsixManifestNamespaceUri 'desktop9'

        $category, $handlerTag = switch ($MenuType) {
            'ContextMenu' {
                'windows.fileExplorerClassicContextMenuHandler',
                'desktop9:FileExplorerClassicContextMenuHandler'
            }
            'DragDrop' {
                'windows.fileExplorerClassicDragDropContextMenuHandler',
                'desktop9:FileExplorerClassicDragDropContextMenuHandler'
            }
        }

        $d9Ext = $manifest.CreateElement('desktop9:Extension', $d9Uri)
        $d9Ext.SetAttribute('Category', $category)

        $handler = $manifest.CreateElement($handlerTag, $d9Uri)
        foreach ($type in $FileTypes) {
            $extHandler = $manifest.CreateElement('desktop9:ExtensionHandler', $d9Uri)
            $extHandler.SetAttribute('Type',  $type)
            $extHandler.SetAttribute('Clsid', $ClsidBare) 
            $null = $handler.AppendChild($extHandler)
        }
        $null = $d9Ext.AppendChild($handler)
        $null = $appExt.AppendChild($d9Ext)
    }
}


function Add-MsixFileExplorerContextMenu {
    <#
    .SYNOPSIS
        Adds a modern IExplorerCommand-based context menu to an Application in an MSIX package.

    .DESCRIPTION
        Uses desktop4:FileExplorerContextMenus, which is the recommended approach
        for new shell extensions (not legacy IContextMenu COM servers).
        Added at the Application level.

    .PARAMETER PackagePath
        Path to the .msix file to modify.

    .PARAMETER AppId
        The Id attribute of the Application element to extend.

    .PARAMETER VerbId
        Short identifier for the verb (e.g. 'open', 'edit', 'convert').

    .PARAMETER VerbClsid
        GUID of the IExplorerCommand COM class implementing the verb.

    .PARAMETER FileTypes
        File-type targets. Use '*' for all files, '.ext' for specific extensions,
        'Directory' for folders.

    .PARAMETER OutputPath
        Write the modified package here instead of overwriting -PackagePath.

    .PARAMETER SkipSigning
        Do not sign the resulting package.

    .EXAMPLE
        Add-MsixFileExplorerContextMenu -PackagePath app.msix -AppId 'App' `
            -VerbId 'open' -VerbClsid '{XXXXXXXX-...}' `
            -FileTypes '.log', '.txt'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [string]$AppId,
        [Parameter(Mandatory)]
        [string]$VerbId,
        [Parameter(Mandatory)]
        [string]$VerbClsid,
        [Parameter(Mandatory)]
        [string[]]$FileTypes,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [string]$PfxPassword
    )

    # desktop4:Verb Clsid is ST_CLSID — requires braces {XXXXXXXX-...}
    $VerbClsid = '{' + $VerbClsid.Trim().Trim('{', '}') + '}'

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -Activity 'Add File Explorer Context Menu' -Mutate {
        param([xml]$manifest)

        Add-MsixManifestNamespace $manifest 'desktop4'

        $app = @($manifest.Package.Applications.Application) | Where-Object { $_.Id -eq $AppId }
        if (-not $app) { throw "Application '$AppId' not found in the manifest." }

        $d4Uri = Get-MsixManifestNamespaceUri 'desktop4'

        # Ensure Application/Extensions exists
        $extNode = $app.SelectSingleNode('*[local-name()="Extensions"]')
        if (-not $extNode) {
            $extNode = $manifest.CreateElement('Extensions', $manifest.Package.NamespaceURI)
            $null    = $app.AppendChild($extNode)
        }

        $d4Ext = $manifest.CreateElement('desktop4:Extension', $d4Uri)
        $d4Ext.SetAttribute('Category', 'windows.fileExplorerContextMenus')

        $ctxMenus = $manifest.CreateElement('desktop4:FileExplorerContextMenus', $d4Uri)

        foreach ($ft in $FileTypes) {
            $itemType = $manifest.CreateElement('desktop4:ItemType', $d4Uri)
            $itemType.SetAttribute('Type', $ft)

            $verbNode = $manifest.CreateElement('desktop4:Verb', $d4Uri)
            $verbNode.SetAttribute('Id',    $VerbId)
            $verbNode.SetAttribute('Clsid', $VerbClsid)  # ST_CLSID — with braces

            $null = $itemType.AppendChild($verbNode)
            $null = $ctxMenus.AppendChild($itemType)
        }

        $null = $d4Ext.AppendChild($ctxMenus)
        $null = $extNode.AppendChild($d4Ext)
    }
}
