function Add-MsixLegacyContextMenu {
    <#
    .SYNOPSIS
        Adds a legacy IContextMenu shell extension to an MSIX package.

    .DESCRIPTION
        Wraps a COM IContextMenu / IDropTarget shell-extension DLL so it
        surfaces under MSIX containerisation. This is the TMEditX-verified
        pattern that the Windows shell actually wires up at runtime.

        Min OS: Windows 10 1809 (build 17763) for the desktop4
        windows.fileExplorerContextMenus extension. MaxVersionTested is
        bumped automatically.

        Adds to AppxManifest.xml inside the Application's Extensions node:
          - com:Extension (windows.comServer) — wraps the DLL as a
            SurrogateServer so it runs in dllhost.exe under the MSIX
            isolation boundary.
          - desktop4:Extension (windows.fileExplorerContextMenus) — a
            desktop4:FileExplorerContextMenus block containing
            desktop5:ItemType / desktop5:Verb entries that reference the
            CLSID. The verb Id defaults to 'ContextMenuHandlers' for
            -MenuType ContextMenu and 'DragDropHandlers' for -MenuType DragDrop.

        NOTE: An earlier version of this cmdlet emitted desktop9 elements
        (windows.fileExplorerClassicContextMenuHandler). That schema turned
        out NOT to be the right shape for COM-based shell extensions —
        desktop4 + desktop5 handles both legacy IContextMenu and modern
        IExplorerCommand depending on which interface(s) the CLSID's COM
        class implements.

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
        # Wrap a classic COM shell extension (e.g. NppShell.dll) so it
        # surfaces in File Explorer's context menu for all file types.
        $pw = Read-Host -AsSecureString
        Add-MsixLegacyContextMenu -PackagePath app.msix `
            -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
            -Clsid '{D7E6F1A2-3B4C-4D5E-9F00-112233445566}' `
            -DisplayName 'My Context Menu' `
            -FileTypes '*', '.log', 'Directory' `
            -Pfx cert.pfx -PfxPassword $pw

    .EXAMPLE
        # Drag-and-drop handler variant — same schema (desktop4 + desktop5),
        # the Verb Id changes to 'DragDropHandlers'.
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
        Add-MsixFileExplorerContextMenu is the leaner companion when the
        COM class is already declared elsewhere — it emits only the
        desktop4 verb declaration, no COM surrogate registration.
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
                if ($t -notmatch '^(\*|\.[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}|Directory|Directory\\Background|Folder|Drive|DesktopBackground|AllFilesystemObjects)$') {
                    throw "Invalid file type: '$t'. Allowed: '*', '.ext' (alphanumeric/underscore/dot/hyphen, max 32 chars after dot), 'Directory', 'Directory\Background', 'Folder', 'Drive', 'DesktopBackground', 'AllFilesystemObjects'."
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

    # com:Class/@Id and desktop5:Verb/@Clsid both use the bare GUID format
    # (no curly braces): xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    # Normalise CLSID: strip surrounding braces and lower-case. TMEditX-style
    # lowercase matches the format Windows actually persists into HKCR\CLSID\…
    # entries; the AppX schema is case-insensitive but staying lower-case keeps
    # diff output stable when re-running this cmdlet.
    $ClsidBare = $Clsid.Trim().Trim('{', '}').ToLowerInvariant()

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

        # Required namespaces.
        # The TMEditX-verified working pattern for shell-extension context
        # menus in MSIX uses the desktop4 + desktop5 schemas, NOT desktop9:
        #
        #   <com:Extension Category="windows.comServer">                ← Application
        #     <com:ComServer><com:SurrogateServer>
        #       <com:Class Id="..." Path="..." />
        #     </com:SurrogateServer></com:ComServer>
        #   </com:Extension>
        #   <desktop4:Extension Category="windows.fileExplorerContextMenus">  ← Application
        #     <desktop4:FileExplorerContextMenus>
        #       <desktop5:ItemType Type="*">
        #         <desktop5:Verb Id="ContextMenuHandlers" Clsid="..." />
        #       </desktop5:ItemType>
        #     </desktop4:FileExplorerContextMenus>
        #   </desktop4:Extension>
        #
        # desktop9:fileExplorerClassicContextMenuHandler turns out NOT to be
        # the right schema for COM-based shell extensions — the desktop4/5
        # pair handles both legacy (IContextMenu) and modern (IExplorerCommand)
        # via the same path because the CLSID's COM class implements whichever
        # interface(s) it supports.
        Add-MsixManifestNamespace -Manifest $manifest -Prefix 'com'
        Add-MsixManifestNamespace -Manifest $manifest -Prefix 'desktop4'
        Add-MsixManifestNamespace -Manifest $manifest -Prefix 'desktop5'

        # desktop4:windows.fileExplorerContextMenus requires Win10 1809 (17763).
        Set-MsixManifestMaxVersionTested -Manifest $manifest -MinBuild 17763

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
            Write-MsixLog -Level Info -Message "COM class $ClsidBare already declared in manifest — skipping Add-MsixLegacyContextMenu."
            return
        }

        # ── Application-level Extensions node ────────────────────────────
        # Everything in this cmdlet lives at Applications/Application/Extensions —
        # the COM declaration AND the desktop4 verb. This is the placement
        # TMEditX uses and that Explorer actually wires up at runtime.
        $appExt = $app.SelectSingleNode('*[local-name()="Extensions"]')
        if (-not $appExt) {
            $appExt = $manifest.CreateElement('Extensions', $manifest.Package.NamespaceURI)
            $null   = $app.AppendChild($appExt)
        }

        # ── COM SurrogateServer (bare 'com' namespace, Application level) ──
        $comUri    = Get-MsixManifestNamespaceUri -Prefix 'com'
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

        # ── desktop4 + desktop5 verb declaration ─────────────────────────
        # desktop4:Extension wraps desktop4:FileExplorerContextMenus, which
        # in turn wraps desktop5:ItemType / desktop5:Verb (desktop5 is the
        # ItemType/Verb namespace — desktop4 is the outer container).
        # For -MenuType DragDrop we use the same schema; the COM class
        # decides whether it implements drag/drop or context menu interfaces.
        $d4Uri = Get-MsixManifestNamespaceUri -Prefix 'desktop4'
        $d5Uri = Get-MsixManifestNamespaceUri -Prefix 'desktop5'

        $d4Ext = $manifest.CreateElement('desktop4:Extension', $d4Uri)
        $d4Ext.SetAttribute('Category', 'windows.fileExplorerContextMenus')

        $menus = $manifest.CreateElement('desktop4:FileExplorerContextMenus', $d4Uri)

        # The Verb Id is the registry key name historically used for shellex
        # COM handlers. We default to 'ContextMenuHandlers' (matching TMEditX)
        # for ContextMenu, and 'DragDropHandlers' for DragDrop.
        $verbId = switch ($MenuType) {
            'ContextMenu' { 'ContextMenuHandlers' }
            'DragDrop'    { 'DragDropHandlers'    }
        }

        foreach ($type in $FileTypes) {
            $itemType = $manifest.CreateElement('desktop5:ItemType', $d5Uri)
            $itemType.SetAttribute('Type', $type)

            $verbNode = $manifest.CreateElement('desktop5:Verb', $d5Uri)
            $verbNode.SetAttribute('Id',    $verbId)
            $verbNode.SetAttribute('Clsid', $ClsidBare)

            $null = $itemType.AppendChild($verbNode)
            $null = $menus.AppendChild($itemType)
        }
        $null = $d4Ext.AppendChild($menus)
        $null = $appExt.AppendChild($d4Ext)
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
        For shipping an existing IContextMenu COM shell-extension DLL,
        prefer Add-MsixLegacyContextMenu — it emits the matching
        com:Extension/SurrogateServer block alongside the desktop4 verb
        so the CLSID is fully registered in one call.
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
                if ($t -notmatch '^(\*|\.[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}|Directory|Directory\\Background|Folder|Drive|DesktopBackground|AllFilesystemObjects)$') {
                    throw "Invalid file type: '$t'. Allowed: '*', '.ext' (alphanumeric/underscore/dot/hyphen, max 32 chars after dot), 'Directory', 'Directory\Background', 'Folder', 'Drive', 'DesktopBackground', 'AllFilesystemObjects'."
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

    # CLSID is case-insensitive in the schema but we normalise to lower-case
    # (matching TMEditX style and the persisted HKCR\CLSID\... format).
    $verbClsid = $verbClsid.Trim().Trim('{', '}').ToLowerInvariant()

    _MsixMutateManifest -PackagePath $PackagePath -OutputPath $OutputPath `
        -SkipSigning:$SkipSigning -Pfx $Pfx -PfxPassword $PfxPassword `
        -UnsignedOutputPath $UnsignedOutputPath `
        -WhatIfPreview:$isWhatIf `
        -Activity 'Add File Explorer Context Menu' -Mutate {
        param([xml]$manifest)

        # desktop4 wraps the Extension/FileExplorerContextMenus container;
        # desktop5 provides the ItemType/Verb children (TMEditX-verified
        # working pattern). desktop4 alone (using desktop4:ItemType/Verb)
        # also exists but desktop5 is the newer, preferred form.
        Add-MsixManifestNamespace -Manifest $manifest -Prefix 'desktop4'
        Add-MsixManifestNamespace -Manifest $manifest -Prefix 'desktop5'
        Set-MsixManifestMaxVersionTested -Manifest $manifest -MinBuild 17763

        # Locate the Application (windows.fileExplorerContextMenus lives at
        # Applications/Application/Extensions per the TMEditX-verified
        # working manifest — the schema permits Package level too but the
        # Application-level form is what Explorer actually wires up).
        $app    = Get-MsixManifestApplication -Manifest $manifest -AppId $AppId
        $extNode = $app.SelectSingleNode('*[local-name()="Extensions"]')
        if (-not $extNode) {
            $extNode = $manifest.CreateElement('Extensions', $manifest.Package.NamespaceURI)
            $null    = $app.AppendChild($extNode)
        }

        $d4Uri = Get-MsixManifestNamespaceUri -Prefix 'desktop4'
        $d5Uri = Get-MsixManifestNamespaceUri -Prefix 'desktop5'

        $d4Ext = $manifest.CreateElement('desktop4:Extension', $d4Uri)
        $d4Ext.SetAttribute('Category', 'windows.fileExplorerContextMenus')

        $ctxMenus = $manifest.CreateElement('desktop4:FileExplorerContextMenus', $d4Uri)

        foreach ($ft in $FileTypes) {
            $itemType = $manifest.CreateElement('desktop5:ItemType', $d5Uri)
            $itemType.SetAttribute('Type', $ft)

            $verbNode = $manifest.CreateElement('desktop5:Verb', $d5Uri)
            $verbNode.SetAttribute('Id',    $VerbId)
            $verbNode.SetAttribute('Clsid', $verbClsid)

            $null = $itemType.AppendChild($verbNode)
            $null = $ctxMenus.AppendChild($itemType)
        }

        $null = $d4Ext.AppendChild($ctxMenus)
        $null = $extNode.AppendChild($d4Ext)
    }
}
