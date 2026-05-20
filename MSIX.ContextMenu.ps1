function Add-MsixLegacyContextMenu {
    <#
    .SYNOPSIS
        Adds a legacy IContextMenu shell extension to an MSIX package.

    .DESCRIPTION
        Supports the COM-based IContextMenu / drag-drop handler pattern used by
        classic Win32 applications.

        Min OS: Windows 11 21H2 (build 22000+). MaxVersionTested is bumped
        automatically.

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

    .PARAMETER Pfx
        Signing certificate file. Omit to use automatic store selection.

    .PARAMETER PfxPassword
        SecureString password for -Pfx.

    .PARAMETER UnsignedOutputPath
        When signing fails, copy the unsigned repacked package here so the
        operator can manually re-sign. The original is never overwritten on
        a failed sign.

    .EXAMPLE
        # LEGACY IContextMenu (desktop9) — pick THIS cmdlet when shipping an
        # existing COM IContextMenu/IDropTarget DLL. Min OS: Win11 21H2.
        $pw = Read-Host -AsSecureString
        Add-MsixLegacyContextMenu -PackagePath app.msix `
            -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
            -Clsid '{D7E6F1A2-3B4C-4D5E-9F00-112233445566}' `
            -DisplayName 'My Context Menu' `
            -FileTypes '*', '.log', 'Directory' `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Drag-and-drop handler variant (also legacy / desktop9)
        Add-MsixLegacyContextMenu -PackagePath app.msix `
            -ShellExtDll '[{ProgramFilesX64}]\App\ShellExt.dll' `
            -Clsid 'D7E6F1A2-3B4C-4D5E-9F00-112233445566' `
            -DisplayName 'Drop Handler' `
            -MenuType DragDrop `
            -FileTypes 'Directory'

    .EXAMPLE
        # Preview only: WhatIf still runs unpack/edit/pack so you can inspect
        # the result; signing and target replacement are skipped.
        Add-MsixLegacyContextMenu -WhatIf -PackagePath app.msix `
            -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
            -Clsid '{D7E6F1A2-3B4C-4D5E-9F00-112233445566}' `
            -DisplayName 'Preview' `
            -UnsignedOutputPath 'C:\drop\app-preview.msix'

    .NOTES
        For NEW shell extensions implementing IExplorerCommand, prefer the
        modern Add-MsixFileExplorerContextMenu which uses desktop4 and
        works on Win10 1803+.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [Parameter(Mandatory)]
        [string]$ShellExtDll,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^(\{)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(\})?$',
            ErrorMessage = 'CLSID must be a GUID like 12345678-1234-1234-1234-123456789abc (curly braces optional).'
        )]
        [string]$Clsid,
        [Parameter(Mandatory)]
        [string]$DisplayName,
        [ValidateScript({
            foreach ($t in $_) {
                if ($t -notmatch '^(\*|\.[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}|Directory|Drive)$') {
                    throw "Invalid file type: '$t'. Allowed: '*', '.ext' (alphanumeric/underscore/dot/hyphen, max 32 chars after dot), 'Directory', 'Drive'."
                }
            }
            $true
        })]
        [string[]]$FileTypes = @('*'),
        [ValidateSet('ContextMenu', 'DragDrop')]
        [string]$MenuType    = 'ContextMenu',
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add Legacy Context Menu')

    # Both com:Class Id and desktop9:ExtensionHandler Clsid use bare GUID format
    # (no curly braces): xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    $ClsidBare = $Clsid.Trim().Trim('{', '}')

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
        -UnsignedOutputPath $UnsignedOutputPath `
        -WhatIfPreview:$isWhatIf `
        -Activity 'Add Legacy Context Menu' -Mutate {
        param([xml]$manifest)

        # Required namespaces
        Add-MsixManifestNamespace $manifest 'com'
        Add-MsixManifestNamespace $manifest 'desktop9'

        # desktop9 requires MaxVersionTested >= 10.0.22000.0 (Windows 11 21H2)
        Set-MsixManifestMaxVersionTested $manifest -MinBuild 22000

        # ── Locate the target Application ─────────────────────────────────
        $apps = @($manifest.Package.Applications.Application)
        $app  = if ($AppId) {
            $apps | Where-Object { $_.GetAttribute('Id') -eq $AppId } | Select-Object -First 1
        } else {
            $apps | Select-Object -First 1
        }
        if (-not $app) { throw "Application '$AppId' not found in the manifest." }

        # ── Idempotency: skip if this CLSID is already declared ──────────
        $existingClass = $manifest.SelectSingleNode("//*[local-name()='Class' and @Id='$ClsidBare']")
        if ($existingClass) {
            Write-MsixLog Info "COM class $ClsidBare already declared in manifest — skipping Add-MsixLegacyContextMenu."
            return
        }

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

        Min OS: Windows 10 build 17134 (1803). MaxVersionTested is bumped
        automatically.

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

    .PARAMETER Pfx
        Signing certificate file. Omit to use automatic store selection.

    .PARAMETER PfxPassword
        SecureString password for -Pfx.

    .PARAMETER UnsignedOutputPath
        When signing fails, copy the unsigned repacked package here so the
        operator can manually re-sign.

    .EXAMPLE
        # MODERN IExplorerCommand (desktop4) — pick THIS cmdlet for new
        # shell extensions. Works on Win10 1803 (build 17134) and above.
        $pw = Read-Host -AsSecureString
        Add-MsixFileExplorerContextMenu -PackagePath app.msix -AppId 'App' `
            -VerbId 'open' -VerbClsid '{A1B2C3D4-E5F6-4789-ABCD-EF0123456789}' `
            -FileTypes '.log', '.txt' `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Multiple verbs in one package: call once per verb
        Add-MsixFileExplorerContextMenu -PackagePath app.msix -AppId 'App' `
            -VerbId 'convert' -VerbClsid 'A1B2C3D4-E5F6-4789-ABCD-EF0123456789' `
            -FileTypes 'Directory' -SkipSigning

    .NOTES
        For LEGACY IContextMenu COM servers (Win32 shell extensions), see
        Add-MsixLegacyContextMenu (desktop9, requires Win11 21H2+).
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute(
        'PSReviewUnusedParameter', '',
        Justification = 'Parameters are captured by the -Mutate scriptblock passed to _MsixMutateManifest.')]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'AppId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$AppId,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^[A-Za-z_][A-Za-z0-9_.-]*$',
            ErrorMessage = 'VerbId must be an XML NCName: start with a letter or underscore, then letters, digits, underscore, dot, or hyphen.'
        )]
        [string]$VerbId,
        [Parameter(Mandatory)]
        [ValidatePattern(
            '^(\{)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(\})?$',
            ErrorMessage = 'CLSID must be a GUID like 12345678-1234-1234-1234-123456789abc (curly braces optional).'
        )]
        [string]$VerbClsid,
        [Parameter(Mandatory)]
        [ValidateScript({
            foreach ($t in $_) {
                if ($t -notmatch '^(\*|\.[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}|Directory|Drive)$') {
                    throw "Invalid file type: '$t'. Allowed: '*', '.ext' (alphanumeric/underscore/dot/hyphen, max 32 chars after dot), 'Directory', 'Drive'."
                }
            }
            $true
        })]
        [string[]]$FileTypes,
        [string]$OutputPath,
        [Alias('NoSign')]
        [switch]$SkipSigning,
        [string]$Pfx,
        [SecureString]$PfxPassword,
        [string]$UnsignedOutputPath
    )

    $isWhatIf = -not $PSCmdlet.ShouldProcess($PackagePath, 'Add File Explorer Context Menu')

    # desktop4:Verb Clsid also uses bare GUID format (no curly braces)
    $verbClsid = $verbClsid.Trim().Trim('{', '}')

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -WhatIfPreview:$isWhatIf `
        -Activity 'Add File Explorer Context Menu' -Mutate {
        param([xml]$manifest)

        Add-MsixManifestNamespace $manifest 'desktop4'
        Set-MsixManifestMaxVersionTested $manifest -MinBuild 17134

        $app = Get-MsixManifestApplication -Manifest $manifest -AppId $AppId

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
            $verbNode.SetAttribute('Clsid', $verbClsid)

            $null = $itemType.AppendChild($verbNode)
            $null = $ctxMenus.AppendChild($itemType)
        }

        $null = $d4Ext.AppendChild($ctxMenus)
        $null = $extNode.AppendChild($d4Ext)
    }
}
