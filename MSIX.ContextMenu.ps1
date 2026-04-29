function Add-MsixLegacyContextMenu {
    <#
    .SYNOPSIS
        Adds a legacy IContextMenu shell extension to an MSIX package.

    .DESCRIPTION
        Supports the COM-based IContextMenu / drag-drop handler pattern used by
        classic Win32 applications, available on Windows 11 21H2 (build 22000+).

        Adds to AppxManifest.xml:
          - com:Extension (windows.comServer) for COM server registration
          - desktop9:Extension (windows.fileExplorerClassicContextMenuHandler
            or windows.fileExplorerClassicDragDropContextMenuHandler)

        Both extensions are added at the Package level (not Application level).

    .PARAMETER PackagePath
        Path to the .msix file to modify.

    .PARAMETER ShellExtDll
        Package-relative path to the COM server DLL (e.g. VFS\ProgramFilesX64\App\ShellExt.dll).

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
        [Parameter(Mandatory)]
        [string]$ShellExtDll,
        [Parameter(Mandatory)]
        [string]$Clsid,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [string[]]$FileTypes = @('*'),
        [ValidateSet('ContextMenu', 'DragDrop')]
        [string]$MenuType    = 'ContextMenu',
        [string]$Pfx,
        [string]$PfxPassword
    )

    # Normalise GUID to {XXXXXXXX-...} form
    $Clsid = $Clsid.Trim()
    if ($Clsid -notmatch '^\{') { $Clsid = "{$Clsid}" }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName

    try {
        Write-MsixLog Info "Unpacking: $($fileinfo.FullName)"
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"

        # Required namespaces
        Add-MsixManifestNamespace $manifest 'com'
        Add-MsixManifestNamespace $manifest 'desktop9'

        # desktop9 requires MaxVersionTested >= 10.0.21301.0
        Set-MsixManifestMaxVersionTested $manifest -MinBuild 21301

        # ── Package-level Extensions node ────────────────────────────────
        $pkgExt = $manifest.Package.Extensions
        if (-not $pkgExt) {
            $pkgExt = $manifest.CreateElement('Extensions', $manifest.Package.NamespaceURI)
            $null   = $manifest.Package.AppendChild($pkgExt)
        }

        # ── COM server registration ───────────────────────────────────────
        $comUri      = Get-MsixManifestNamespaceUri 'com'

        $comExt      = $manifest.CreateElement('com:Extension',       $comUri)
        $comExt.SetAttribute('Category', 'windows.comServer')

        $comServer   = $manifest.CreateElement('com:ComServer',       $comUri)
        $surrogate   = $manifest.CreateElement('com:SurrogateServer', $comUri)
        $surrogate.SetAttribute('DisplayName', $DisplayName)

        $class = $manifest.CreateElement('com:Class', $comUri)
        $class.SetAttribute('Id',             $Clsid)
        $class.SetAttribute('Path',           $ShellExtDll)
        $class.SetAttribute('ThreadingModel', 'STA')

        $null = $surrogate.AppendChild($class)
        $null = $comServer.AppendChild($surrogate)
        $null = $comExt.AppendChild($comServer)
        $null = $pkgExt.AppendChild($comExt)

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
            $extHandler.SetAttribute('Clsid', $Clsid)
            $null = $handler.AppendChild($extHandler)
        }
        $null = $d9Ext.AppendChild($handler)
        $null = $pkgExt.AppendChild($d9Ext)

        if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save manifest')) {
            Save-MsixManifest $manifest "$workspace\AppxManifest.xml"
        }

        Write-MsixLog Info "Repacking: $($fileinfo.FullName)"
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        Invoke-MsixSigning -PackagePath $fileinfo.FullName -Pfx $Pfx -PfxPassword $PfxPassword

    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
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
        [string]$Pfx,
        [string]$PfxPassword
    )

    $VerbClsid = $VerbClsid.Trim()
    if ($VerbClsid -notmatch '^\{') { $VerbClsid = "{$VerbClsid}" }

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item $PackagePath
    $workspace = New-MsixWorkspace $fileinfo.BaseName

    try {
        Write-MsixLog Info "Unpacking: $($fileinfo.FullName)"
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "unpack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx unpack'

        Test-MsixManifest "$workspace\AppxManifest.xml"
        [xml]$manifest = Get-MsixManifest "$workspace\AppxManifest.xml"

        Add-MsixManifestNamespace $manifest 'desktop4'

        $app = @($manifest.Package.Applications.Application) | Where-Object { $_.Id -eq $AppId }
        if (-not $app) { throw "Application '$AppId' not found in the manifest." }

        $d4Uri = Get-MsixManifestNamespaceUri 'desktop4'

        # Ensure Application/Extensions exists
        if (-not $app.Extensions) {
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
            $verbNode.SetAttribute('Clsid', $VerbClsid)

            $null = $itemType.AppendChild($verbNode)
            $null = $ctxMenus.AppendChild($itemType)
        }

        $null = $d4Ext.AppendChild($ctxMenus)
        $null = $app.Extensions.AppendChild($d4Ext)

        if ($PSCmdlet.ShouldProcess("$workspace\AppxManifest.xml", 'Save manifest')) {
            Save-MsixManifest $manifest "$workspace\AppxManifest.xml"
        }

        Write-MsixLog Info "Repacking: $($fileinfo.FullName)"
        $r = Invoke-MsixProcess "$toolsRoot\Tools\MakeAppx.exe" "pack /p `"$($fileinfo.FullName)`" /d `"$workspace`" /o"
        Assert-MsixProcessSuccess $r 'MakeAppx pack'

        Invoke-MsixSigning -PackagePath $fileinfo.FullName -Pfx $Pfx -PfxPassword $PfxPassword

    } finally {
        Remove-Item $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}
