BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Build-MsixTestFixture.ps1')
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# =============================================================================
# Add-MsixCapability
# =============================================================================

Describe 'Add-MsixCapability end-to-end (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:CapDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-cap-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:CapDir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'MakeAppx not available on this host.'
        }
    }
    AfterAll {
        if ($script:CapDir -and (Test-Path -LiteralPath $script:CapDir)) {
            Remove-Item -LiteralPath $script:CapDir -Recurse -Force
        }
    }

    It 'adds a standard capability to a real package without throwing' {
        $pkg = Join-Path -Path $script:CapDir -ChildPath 'base.msix'
        $out = Join-Path -Path $script:CapDir -ChildPath 'with-std-cap.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        { Add-MsixCapability -PackagePath $fx.PackagePath -Names 'internetClient' -OutputPath $out -SkipSigning } |
            Should -Not -Throw

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'emits a plain Capability element (standard namespace) for internetClient' {
        $out = Join-Path -Path $script:CapDir -ChildPath 'with-std-cap.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out
        # standard capabilities live in the foundation namespace — no uap/rescap prefix
        $foundationUri = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10'
        $cap = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.NamespaceURI -eq $foundationUri -and $_.GetAttribute('Name') -eq 'internetClient' }
        $cap | Should -Not -BeNullOrEmpty -Because 'internetClient must appear as a plain Capability in the foundation namespace'
    }

    It 'adds a rescap capability with the correct namespace' {
        $out  = Join-Path -Path $script:CapDir -ChildPath 'with-std-cap.msix'
        $out2 = Join-Path -Path $script:CapDir -ChildPath 'with-rescap.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'earlier test must have produced the base package'

        # broadFileSystemAccess is a rescap cap not present in the test fixture.
        Add-MsixCapability -PackagePath $out -Names 'broadFileSystemAccess' -OutputPath $out2 -SkipSigning

        [xml]$m    = Get-MsixManifest -Path $out2
        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
        $cap = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.NamespaceURI -eq $rescapUri -and $_.GetAttribute('Name') -eq 'broadFileSystemAccess' }
        $cap | Should -Not -BeNullOrEmpty -Because 'broadFileSystemAccess must appear as rescap:Capability'
    }

    It 'is idempotent: re-adding a present capability does not throw and does not duplicate it' {
        $out = Join-Path -Path $script:CapDir -ChildPath 'with-std-cap.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'earlier test must have produced the base package'

        # internetClient is already in with-std-cap.msix; _MsixMutatePackage skips
        # the repack entirely (correct no-op behaviour) — no output file is written.
        { Add-MsixCapability -PackagePath $out -Names 'internetClient' -SkipSigning } |
            Should -Not -Throw -Because 're-adding a present capability must not throw'

        # Count in the unchanged source file must still be exactly 1.
        [xml]$m        = Get-MsixManifest -Path $out
        $foundationUri = 'http://schemas.microsoft.com/appx/manifest/foundation/windows10'
        $caps = @($m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.NamespaceURI -eq $foundationUri -and $_.GetAttribute('Name') -eq 'internetClient' })
        $caps.Count | Should -Be 1 -Because 'capability must appear exactly once'
    }
}

# =============================================================================
# Add-MsixLegacyContextMenu
# =============================================================================

Describe 'Add-MsixLegacyContextMenu end-to-end (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:CtxDir    = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-ctx-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:CtxDir -Force | Out-Null
        $script:TestClsid = '12345678-abcd-ef01-2345-6789abcdef01'
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'MakeAppx not available on this host.'
        }
    }
    AfterAll {
        if ($script:CtxDir -and (Test-Path -LiteralPath $script:CtxDir)) {
            Remove-Item -LiteralPath $script:CtxDir -Recurse -Force
        }
    }

    It 'adds a context menu to a real package without throwing' {
        $pkg = Join-Path -Path $script:CtxDir -ChildPath 'base.msix'
        $out = Join-Path -Path $script:CtxDir -ChildPath 'with-ctx.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        { Add-MsixLegacyContextMenu -PackagePath $fx.PackagePath `
                -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
                -Clsid $script:TestClsid -DisplayName 'Test Shell Ext' `
                -FileTypes '*', 'Directory' `
                -OutputPath $out -SkipSigning } | Should -Not -Throw

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'emits com:Class, desktop5:ItemType and desktop5:Verb for each requested FileType' {
        $out  = Join-Path -Path $script:CtxDir -ChildPath 'with-ctx.msix'
        $bare = $script:TestClsid.ToLowerInvariant()
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out

        $comClass = $m.SelectSingleNode("//*[local-name()='Class' and @Id='$bare']")
        $comClass | Should -Not -BeNullOrEmpty -Because 'com:Class must be present for the registered CLSID'

        $menus = $m.SelectSingleNode("//*[local-name()='FileExplorerContextMenus']")
        $menus | Should -Not -BeNullOrEmpty -Because 'desktop4:FileExplorerContextMenus block must be present'

        foreach ($type in @('*', 'Directory')) {
            $verb = $menus.SelectSingleNode(
                "*[local-name()='ItemType' and @Type='$type']/*[local-name()='Verb' and @Id='ContextMenuHandlers' and @Clsid='$bare']")
            $verb | Should -Not -BeNullOrEmpty -Because "desktop5:Verb must exist for FileType '$type'"
        }
    }

    It 'maps the Folder registry class to Directory in the manifest' {
        $pkg2   = Join-Path -Path $script:CtxDir -ChildPath 'base2.msix'
        $out2   = Join-Path -Path $script:CtxDir -ChildPath 'with-folder.msix'
        $fx2    = New-MsixTestFixture -OutputPath $pkg2
        $clsid2 = 'aaaabbbb-cccc-dddd-eeee-ffffffffffff'
        $bare2  = $clsid2.ToLowerInvariant()

        Add-MsixLegacyContextMenu -PackagePath $fx2.PackagePath `
            -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
            -Clsid $clsid2 -DisplayName 'Folder Map Test' `
            -FileTypes 'Folder' `
            -OutputPath $out2 -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out2
        $menus  = $m.SelectSingleNode("//*[local-name()='FileExplorerContextMenus']")

        $dirVerb = $menus.SelectSingleNode(
            "*[local-name()='ItemType' and @Type='Directory']/*[local-name()='Verb' and @Clsid='$bare2']")
        $dirVerb | Should -Not -BeNullOrEmpty -Because 'Folder must be mapped to Directory in the manifest'

        $folderItem = $menus.SelectSingleNode("*[local-name()='ItemType' and @Type='Folder']")
        $folderItem | Should -BeNullOrEmpty -Because 'Folder is not a valid desktop5:ItemType/@Type value'

        if (Test-Path -LiteralPath $fx2.StagingFolder) { Remove-Item -LiteralPath $fx2.StagingFolder -Recurse -Force }
    }

    It 'DragDrop variant emits Verb/@Id = DragDropHandlers' {
        $pkg3   = Join-Path -Path $script:CtxDir -ChildPath 'base3.msix'
        $out3   = Join-Path -Path $script:CtxDir -ChildPath 'with-dragdrop.msix'
        $fx3    = New-MsixTestFixture -OutputPath $pkg3
        $clsid3 = '11112222-3333-4444-5555-666677778888'
        $bare3  = $clsid3.ToLowerInvariant()

        Add-MsixLegacyContextMenu -PackagePath $fx3.PackagePath `
            -ShellExtDll 'VFS\ProgramFilesX64\App\DropHandler.dll' `
            -Clsid $clsid3 -DisplayName 'Drop Handler' `
            -FileTypes 'Directory' -MenuType DragDrop `
            -OutputPath $out3 -SkipSigning

        [xml]$m = Get-MsixManifest -Path $out3
        $menus  = $m.SelectSingleNode("//*[local-name()='FileExplorerContextMenus']")
        $verb   = $menus.SelectSingleNode(
            "*[local-name()='ItemType' and @Type='Directory']/*[local-name()='Verb' and @Id='DragDropHandlers' and @Clsid='$bare3']")
        $verb | Should -Not -BeNullOrEmpty -Because 'DragDrop menu type must emit Verb/@Id=DragDropHandlers'

        if (Test-Path -LiteralPath $fx3.StagingFolder) { Remove-Item -LiteralPath $fx3.StagingFolder -Recurse -Force }
    }

    It 'is idempotent: second call for same CLSID does not duplicate the com:Class entry' {
        $out  = Join-Path -Path $script:CtxDir -ChildPath 'with-ctx.msix'
        $out2 = Join-Path -Path $script:CtxDir -ChildPath 'ctx-idempotent.msix'
        $bare = $script:TestClsid.ToLowerInvariant()
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'earlier test must have produced the base package'

        Add-MsixLegacyContextMenu -PackagePath $out `
            -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
            -Clsid $script:TestClsid -DisplayName 'Test Shell Ext' `
            -FileTypes '*', 'Directory' `
            -OutputPath $out2 -SkipSigning

        [xml]$m  = Get-MsixManifest -Path $out2
        $classes = @($m.SelectNodes("//*[local-name()='Class' and @Id='$bare']"))
        $classes.Count | Should -Be 1 -Because 'com:Class must appear exactly once even when added twice'
    }
}

# =============================================================================
# Remove-MsixUninstallerArtifact
# =============================================================================

Describe 'Remove-MsixUninstallerArtifact end-to-end (real package + hive)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:UninstDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-uninst-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:UninstDir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'MakeAppx not available on this host.'
        }
    }
    AfterAll {
        if ($script:UninstDir -and (Test-Path -LiteralPath $script:UninstDir)) {
            Remove-Item -LiteralPath $script:UninstDir -Recurse -Force
        }
    }

    It 'strips an uninstaller .exe and its Uninstall registry key from a real package without throwing' {
        # Build a Registry.dat with a fake Uninstall\MyApp entry using the
        # offreg helpers (same pattern as MSIX.MutatorScope.Tests.ps1).
        $datPath = Join-Path -Path $script:UninstDir -ChildPath 'Registry.dat'
        & (Get-Module MSIX) {
            param($DatPath)
            $h = _MsixCreateOfflineHive
            try {
                $cur = $h
                foreach ($seg in @('REGISTRY','MACHINE','SOFTWARE','Microsoft','Windows','CurrentVersion','Uninstall','MyApp')) {
                    $cur = _MsixOfflineCreateKey -Parent $cur -SubKey $seg
                }
                _MsixOfflineSetValueString -Key $cur -Name 'DisplayName' -Value 'MyApp'
                if (Test-Path -LiteralPath $DatPath) { Remove-Item -LiteralPath $DatPath -Force }
                if (-not (_MsixOfflineSaveHive -Hive $h -Path $DatPath)) { throw 'ORSaveHive failed.' }
            } finally { _MsixCloseOfflineHive -Hive $h }
        } $datPath

        $pkg = Join-Path -Path $script:UninstDir -ChildPath 'base.msix'
        $out = Join-Path -Path $script:UninstDir -ChildPath 'clean.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg -Files @(
            @{ Path = 'VFS\ProgramFilesX64\App\uninstall.exe'; Bytes = [byte[]]@(0x4D, 0x5A) }
            @{ Path = 'Registry.dat'; Bytes = [IO.File]::ReadAllBytes($datPath) }
        )

        { Remove-MsixUninstallerArtifact -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning } |
            Should -Not -Throw

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'the cleaned package no longer contains uninstall.exe' {
        $out = Join-Path -Path $script:UninstDir -ChildPath 'clean.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the cleaned package'

        $expandDir  = Join-Path -Path $script:UninstDir -ChildPath 'expanded'
        Expand-Archive -LiteralPath $out -DestinationPath $expandDir -Force

        $uninstExe = Join-Path -Path $expandDir -ChildPath 'VFS\ProgramFilesX64\App\uninstall.exe'
        Test-Path -LiteralPath $uninstExe | Should -BeFalse -Because 'uninstall.exe must have been removed from the package'
    }

    It 'the cleaned package Registry.dat no longer contains the Uninstall\MyApp key' {
        $out       = Join-Path -Path $script:UninstDir -ChildPath 'clean.msix'
        $expandDir = Join-Path -Path $script:UninstDir -ChildPath 'expanded'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the cleaned package'

        # Reuse the expanded directory from the previous test if it exists.
        if (-not (Test-Path -LiteralPath $expandDir)) {
            Expand-Archive -LiteralPath $out -DestinationPath $expandDir -Force
        }

        $datPath = Join-Path -Path $expandDir -ChildPath 'Registry.dat'
        Test-Path -LiteralPath $datPath | Should -BeTrue -Because 'Registry.dat must still be present in the cleaned package'

        $keyGone = & (Get-Module MSIX) {
            param($DatPath)
            $h = _MsixOpenOfflineHive -Path $DatPath
            try {
                $k = _MsixOfflineOpenKey -Parent $h `
                    -SubKey 'REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\MyApp'
                if ($k -ne [IntPtr]::Zero) {
                    _MsixOfflineCloseKey -Key $k
                    return $false
                }
                return $true
            } finally { _MsixCloseOfflineHive -Hive $h }
        } $datPath

        $keyGone | Should -BeTrue -Because 'Uninstall\MyApp must have been removed from Registry.dat'
    }
}

# =============================================================================
# Set-MsixFileSystemWriteVirtualization
# =============================================================================

Describe 'Set-MsixFileSystemWriteVirtualization end-to-end (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:FsVirtDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-fsvirt-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:FsVirtDir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'MakeAppx not available on this host.'
        }
    }
    AfterAll {
        if ($script:FsVirtDir -and (Test-Path -LiteralPath $script:FsVirtDir)) {
            Remove-Item -LiteralPath $script:FsVirtDir -Recurse -Force
        }
    }

    It 'sets the desktop6 flag to disabled in a real package without throwing' {
        $pkg = Join-Path -Path $script:FsVirtDir -ChildPath 'base.msix'
        $out = Join-Path -Path $script:FsVirtDir -ChildPath 'fsvirt-disabled.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        { Set-MsixFileSystemWriteVirtualization -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning } |
            Should -Not -Throw

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'emits desktop6:FileSystemWriteVirtualization = disabled in Properties' {
        $out   = Join-Path -Path $script:FsVirtDir -ChildPath 'fsvirt-disabled.msix'
        $d6Uri = Get-MsixManifestNamespaceUri -Prefix 'desktop6'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out
        $flag   = $m.Package.Properties.SelectSingleNode(
            "*[local-name()='FileSystemWriteVirtualization' and namespace-uri()='$d6Uri']")
        $flag           | Should -Not -BeNullOrEmpty -Because 'desktop6:FileSystemWriteVirtualization must be present in Properties'
        $flag.InnerText | Should -Be 'disabled'
    }

    It 'automatically adds the unvirtualizedResources rescap capability' {
        $out       = Join-Path -Path $script:FsVirtDir -ChildPath 'fsvirt-disabled.msix'
        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out
        $cap    = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.NamespaceURI -eq $rescapUri -and $_.GetAttribute('Name') -eq 'unvirtualizedResources' }
        $cap | Should -Not -BeNullOrEmpty -Because 'unvirtualizedResources must be added automatically'
    }

    It 'is idempotent: running twice does not duplicate the flag or the capability' {
        $out  = Join-Path -Path $script:FsVirtDir -ChildPath 'fsvirt-disabled.msix'
        $out2 = Join-Path -Path $script:FsVirtDir -ChildPath 'fsvirt-idempotent.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'earlier test must have produced the base package'

        Set-MsixFileSystemWriteVirtualization -PackagePath $out -OutputPath $out2 -SkipSigning

        [xml]$m    = Get-MsixManifest -Path $out2
        $d6Uri     = Get-MsixManifestNamespaceUri -Prefix 'desktop6'
        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'

        $flags = @($m.Package.Properties.SelectNodes(
            "*[local-name()='FileSystemWriteVirtualization' and namespace-uri()='$d6Uri']"))
        $flags.Count | Should -Be 1 -Because 'desktop6 flag must appear exactly once even when added twice'

        $caps = @($m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.NamespaceURI -eq $rescapUri -and $_.GetAttribute('Name') -eq 'unvirtualizedResources' })
        $caps.Count | Should -Be 1 -Because 'unvirtualizedResources must appear exactly once even when added twice'
    }
}

# =============================================================================
# Set-MsixRegistryWriteVirtualization
# =============================================================================

Describe 'Set-MsixRegistryWriteVirtualization end-to-end (real package)' -Tag 'Integration' {

    BeforeAll {
        $script:ToolingAvailable = Test-MsixFixtureToolingAvailable
        if (-not $script:ToolingAvailable) {
            Write-Warning 'Integration tests SKIPPED: MakeAppx not resolvable on this host.'
        }
        $script:RegVirtDir = Join-Path -Path ([IO.Path]::GetTempPath()) -ChildPath "msix-regvirt-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:RegVirtDir -Force | Out-Null
    }
    BeforeEach {
        if (-not $script:ToolingAvailable) {
            Set-ItResult -Skipped -Because 'MakeAppx not available on this host.'
        }
    }
    AfterAll {
        if ($script:RegVirtDir -and (Test-Path -LiteralPath $script:RegVirtDir)) {
            Remove-Item -LiteralPath $script:RegVirtDir -Recurse -Force
        }
    }

    It 'sets the desktop6 flag to disabled in a real package without throwing' {
        $pkg = Join-Path -Path $script:RegVirtDir -ChildPath 'base.msix'
        $out = Join-Path -Path $script:RegVirtDir -ChildPath 'regvirt-disabled.msix'
        $fx  = New-MsixTestFixture -OutputPath $pkg

        { Set-MsixRegistryWriteVirtualization -PackagePath $fx.PackagePath -OutputPath $out -SkipSigning } |
            Should -Not -Throw

        if (Test-Path -LiteralPath $fx.StagingFolder) { Remove-Item -LiteralPath $fx.StagingFolder -Recurse -Force }
    }

    It 'emits desktop6:RegistryWriteVirtualization = disabled in Properties' {
        $out   = Join-Path -Path $script:RegVirtDir -ChildPath 'regvirt-disabled.msix'
        $d6Uri = Get-MsixManifestNamespaceUri -Prefix 'desktop6'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out
        $flag   = $m.Package.Properties.SelectSingleNode(
            "*[local-name()='RegistryWriteVirtualization' and namespace-uri()='$d6Uri']")
        $flag           | Should -Not -BeNullOrEmpty -Because 'desktop6:RegistryWriteVirtualization must be present in Properties'
        $flag.InnerText | Should -Be 'disabled'
    }

    It 'automatically adds the unvirtualizedResources rescap capability' {
        $out       = Join-Path -Path $script:RegVirtDir -ChildPath 'regvirt-disabled.msix'
        $rescapUri = Get-MsixManifestNamespaceUri -Prefix 'rescap'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'previous test must have produced the output package'

        [xml]$m = Get-MsixManifest -Path $out
        $cap    = $m.Package.Capabilities.ChildNodes |
            Where-Object { $_.LocalName -eq 'Capability' -and $_.NamespaceURI -eq $rescapUri -and $_.GetAttribute('Name') -eq 'unvirtualizedResources' }
        $cap | Should -Not -BeNullOrEmpty -Because 'unvirtualizedResources must be added automatically'
    }

    It 'respects -ExcludedKeys and emits the virtualization:ExcludedKey entries' {
        $out  = Join-Path -Path $script:RegVirtDir -ChildPath 'regvirt-disabled.msix'
        $out2 = Join-Path -Path $script:RegVirtDir -ChildPath 'regvirt-excl.msix'
        Test-Path -LiteralPath $out | Should -BeTrue -Because 'earlier test must have produced the base package'

        $keys = @('HKEY_CURRENT_USER\SOFTWARE\Contoso', 'HKEY_CURRENT_USER\SOFTWARE\Contoso\v2')
        Set-MsixRegistryWriteVirtualization -PackagePath $out -ExcludedKeys $keys -OutputPath $out2 -SkipSigning

        [xml]$m   = Get-MsixManifest -Path $out2
        $virtUri  = Get-MsixManifestNamespaceUri -Prefix 'virtualization'
        $virtNode = $m.Package.Properties.SelectSingleNode(
            "*[local-name()='RegistryWriteVirtualization' and namespace-uri()='$virtUri']")
        $virtNode | Should -Not -BeNullOrEmpty -Because 'virtualization:RegistryWriteVirtualization must be present when ExcludedKeys are supplied'

        $keyNodes = @($virtNode.SelectNodes(".//*[local-name()='ExcludedKey']"))
        $keyNodes.Count | Should -Be 2 -Because 'both excluded keys must appear in the manifest'
        ($keyNodes | ForEach-Object { $_.GetAttribute('Key') }) | Should -Contain 'HKEY_CURRENT_USER\SOFTWARE\Contoso'
    }
}
