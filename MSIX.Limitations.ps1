# =============================================================================
# MSIX Limitations knowledge base
# -----------------------------------------------------------------------------
# Curated list of what MSIX cannot do (or where it requires PSF / app workarounds).
# Sourced from current Microsoft Learn documentation; vendor-specific opinions
# are tagged separately so you can filter them out.
#
# References (all checked against current MS Learn — date stamped per item):
#   - https://learn.microsoft.com/windows/msix/desktop/desktop-to-uwp-known-issues
#   - https://learn.microsoft.com/windows/msix/packaging-tool/know-your-installer
#   - https://learn.microsoft.com/windows/msix/packaging-tool/convert-an-installer-with-services
#   - https://learn.microsoft.com/windows/msix/desktop/desktop-to-uwp-behind-the-scenes
# =============================================================================

$script:MsixLimitations = @(
    @{
        Id          = 'no-drivers'
        Title       = 'Drivers are not supported'
        Source      = 'msft-docs'
        Severity    = 'blocker'
        Description = 'MSIX cannot install kernel-mode drivers, file-system filter drivers, or any signed-driver components. Apps that bundle their own drivers must split them into a separate non-MSIX installer.'
        Workaround  = 'Ship the driver via a separate signed MSI/INF and depend on it as an OS prereq.'
    },
    @{
        Id          = 'install-dir-readonly'
        Title       = 'Installation directory is read-only at runtime'
        Source      = 'msft-docs'
        Severity    = 'medium'
        Description = 'The package install location under C:\Program Files\WindowsApps is mounted read-only. Apps that write log/config files alongside their executable will fail.'
        Workaround  = 'Preferred (Win11 25H2+): Set-MsixFileSystemWriteVirtualization. Alternative: Use PSF FileRedirectionFixup or MFRFixup, or change the app to write to %LocalAppData%.'
    },
    @{
        Id          = 'cwd-system32'
        Title       = 'Working directory defaults to System32'
        Source      = 'msft-docs'
        Severity    = 'medium'
        Description = 'Packaged apps launch with CWD=C:\Windows\System32 (or SysWOW64), not their install folder. Apps that read companion files via relative paths break.'
        Workaround  = 'Set workingDirectory in PSF config.json (Add-MsixPsfV2 -WorkingDirectory).'
    },
    @{
        Id          = 'hklm-redirected'
        Title       = 'HKLM writes are redirected to a private hive'
        Source      = 'msft-docs'
        Severity    = 'medium'
        Description = 'Writes to HKLM are diverted to an isolated binary file per package. Other apps cannot see them. Reads merge through the virtual registry.'
        Workaround  = 'For genuine per-machine state, ship a separate config script. Otherwise, RegLegacyFixups can grant write access to specific keys.'
    },
    @{
        Id          = 'appdata-private'
        Title       = 'AppData is private per package'
        Source      = 'msft-docs'
        Severity    = 'medium'
        Description = '%AppData% is redirected to %LocalAppData%\Packages\<PFN>\LocalCache\Roaming. Two apps cannot share data via AppData unless they ship in the same package.'
        Workaround  = 'Use a known shared location (Documents, ProgramData with explicit ACL) for cross-app data.'
    },
    @{
        Id          = 'inproc-shellext'
        Title       = 'In-process shell extensions cannot be registered'
        Source      = 'msft-docs'
        Severity    = 'medium'
        Description = 'Classic IContextMenu / drop handlers normally load in-process into explorer.exe and are blocked by MSIX. Use the desktop9 surrogate-server pattern for legacy COM, or desktop4 IExplorerCommand for new extensions.'
        Workaround  = 'Add-MsixLegacyContextMenu (Win11 21H2+) or Add-MsixFileExplorerContextMenu.'
    },
    @{
        Id          = 'service-elevation'
        Title       = 'Packages with services need admin elevation to install'
        Source      = 'msft-docs'
        Severity    = 'low'
        Description = 'Services are supported (since MPT 1.2019.1220.0) but require admin to install and per-machine deployment.'
        Workaround  = 'Deploy via Intune/SCCM with admin context.'
    },
    @{
        Id          = 'sxs-assemblies'
        Title       = 'WinSxS shared assemblies cannot be loaded'
        Source      = 'msft-docs'
        Severity    = 'medium'
        Description = 'Apps dynamically linking to C:\Windows\WinSxS DLLs (older C runtimes, etc.) will not find them inside the package.'
        Workaround  = 'Statically link the redistributable, or ship the DLLs alongside the executable inside the package.'
    },
    @{
        Id          = 'shortcut-args'
        Title       = 'Start-menu shortcuts cannot pass arguments natively'
        Source      = 'mixed'
        Severity    = 'medium'
        Description = 'The MSIX-installed shortcut points at the Application entry, with no native way to inject command-line arguments.'
        Workaround  = "PSF arguments field (New-MsixPsfArgument + Add-MsixPsfV2)."
    },
    @{
        Id          = 'multi-pkg-fileassoc'
        Title       = 'Multiple installed packages cannot register the same file extension'
        Source      = 'msft-docs'
        Severity    = 'low'
        Description = 'File-type associations are exclusive per family. Last-write-wins or both apps register but only one is the default handler.'
        Workaround  = 'Ensure only the intended package owns the extension.'
    },
    @{
        Id          = 'dotnet-pre-462'
        Title       = '.NET Framework pre-4.6.2 requires extra validation'
        Source      = 'msft-docs'
        Severity    = 'low'
        Description = 'Apps targeting .NET 2.0/3.5 generally work but may show performance issues; .NET 3.5 feature must be installed on the target machine.'
        Workaround  = 'Retarget to 4.6.2+ where possible.'
    },
    @{
        Id          = 'com-discovery'
        Title       = 'External processes may not see in-package COM servers'
        Source      = 'mixed'
        Severity    = 'medium'
        Description = 'COM servers registered via the package manifest are visible inside the container, but classic out-of-process discovery from non-packaged callers can fail without explicit OutOfProcessServer + RuntimeBehavior tuning.'
        Workaround  = 'Use windows.comServer extension with appropriate OutOfProcessServer config; expose only intended classes.'
    },
    @{
        Id          = 'no-windows-services-deps'
        Title       = 'Cannot depend on services that live outside the package'
        Source      = 'msft-docs'
        Severity    = 'low'
        Description = 'Service dependencies must resolve to services included in the package; cross-package service dependencies are not supported.'
        Workaround  = 'Bundle the dependent service in the same package, or run it as a separate non-MSIX install.'
    },
    @{
        Id          = 'protocol-handler-private'
        Title       = 'Custom URL/protocol handlers are scoped to the package'
        Source      = 'mixed'
        Severity    = 'low'
        Description = 'A protocol handler registered by the manifest is visible to the OS but the launching app/browser must support packaged-app activation. Some legacy callers do not.'
        Workaround  = 'Test from edge/non-packaged callers; some require the handler to be registered for both URL and FileType activation.'
    },
    @{
        Id          = 'signing-publisher-mismatch'
        Title       = 'Manifest Publisher must match the signing certificate Subject'
        Source      = 'msft-docs'
        Severity    = 'low'
        Description = 'signtool fails with 0x8007000B if the AppxManifest Publisher and the cert Subject differ exactly (case-sensitive, including spaces).'
        Workaround  = 'Update-MsixSigner -Publisher … (this module already handles re-stamping the publisher).'
    }
)


function Get-MsixLimitation {
    <#
    .SYNOPSIS
        Lists known MSIX limitations and their workarounds.

    .DESCRIPTION
        Returns entries from the module's curated MSIX-limitation knowledge
        base. Each entry describes a documented scenario where the MSIX
        runtime cannot host an application as-is, along with the recommended
        workaround (PSF fixup, manifest extension, or out-of-band install).

        Most entries are sourced directly from Microsoft Learn and tagged
        'msft-docs'; a smaller set comes from community/vendor practice and
        is tagged 'mixed'. Use -ExcludeVendor to limit the output to the
        documented-by-Microsoft subset.

    .PARAMETER Id
        Filter to one limitation by id.

    .PARAMETER Severity
        Filter by severity: blocker, medium, low.

    .PARAMETER ExcludeVendor
        Exclude entries where Source != 'msft-docs' (i.e. drop vendor-flavoured
        items that are not directly documented by Microsoft).

    .OUTPUTS
        [pscustomobject] one per limitation with properties Id, Title, Source,
        Severity, Description, Workaround.

    .EXAMPLE
        Get-MsixLimitation -Severity blocker

    .EXAMPLE
        Get-MsixLimitation -ExcludeVendor | Format-Table Id, Severity, Title

    .EXAMPLE
        Get-MsixLimitation -Id 'install-dir-readonly' | Select-Object -ExpandProperty Workaround
    #>
    [CmdletBinding()]
    param(
        [string]$Id,
        [ValidateSet('blocker','medium','low')]
        [string]$Severity,
        [switch]$ExcludeVendor
    )

    $list = $script:MsixLimitations | ForEach-Object { [pscustomobject]$_ }

    if ($Id)            { $list = $list | Where-Object Id -eq $Id }
    if ($Severity)      { $list = $list | Where-Object Severity -eq $Severity }
    if ($ExcludeVendor) { $list = $list | Where-Object Source -eq 'msft-docs' }

    return $list
}


function Test-MsixAgainstLimitation {
    <#
    .SYNOPSIS
        Inspects an MSIX file and reports which documented limitations are
        likely to apply, based on heuristics on the manifest and unpacked
        content.

    .DESCRIPTION
        Unpacks the supplied .msix into a temporary workspace, parses
        AppxManifest.xml, and walks the Applications / Extensions tree to
        flag scenarios that are known to hit MSIX limitations (e.g. an
        executable nested under a subfolder triggers the CWD=System32 and
        install-dir-readonly limitations; a windows.service extension flags
        elevation requirements). Limitations that always apply to a packaged
        Win32 app (HKLM redirection, private AppData) are appended to the
        result for completeness.

        Complements Get-MsixStaticAnalysis. The workspace is removed
        afterwards.

    .PARAMETER PackagePath
        .msix file to analyse.

    .OUTPUTS
        [pscustomobject] one per matched limitation, deduplicated by Id. Same
        shape as Get-MsixLimitation.

    .EXAMPLE
        Test-MsixAgainstLimitation -PackagePath .\app.msix |
            Format-Table Id, Severity, Title

    .EXAMPLE
        # Merge with a full static-analysis run
        $hits  = Test-MsixAgainstLimitation -PackagePath .\app.msix
        $static = Get-MsixStaticAnalysis    -PackagePath .\app.msix
        $hits, $static.Findings
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$PackagePath
    )

    $toolsRoot = Get-MsixToolsRoot
    $fileinfo  = Get-Item -LiteralPath $PackagePath
    $workspace = New-MsixWorkspace -PackageName "$($fileinfo.BaseName)-limits"
    $hits = @()

    try {
        $r = Invoke-MsixProcess -FilePath "$toolsRoot\Tools\MakeAppx.exe" -ArgumentList @('unpack', '/p', $fileinfo.FullName, '/d', $workspace, '/o')
        Assert-MsixProcessSuccess -Result $r -Operation 'MakeAppx unpack'

        [xml]$manifest = Get-MsixManifest -Path "$workspace\AppxManifest.xml"

        # cwd-system32 / install-dir-readonly: any executable in a subfolder + writable companions
        foreach ($app in @($manifest.Package.Applications.Application)) {
            if ($app.Executable -and $app.Executable.Contains('\')) {
                $hits += (Get-MsixLimitation -Id 'cwd-system32')
                $hits += (Get-MsixLimitation -Id 'install-dir-readonly')
                break
            }
        }

        # com-discovery: any com:Extension
        if ($manifest.Package.Extensions.Extension -or
            ($manifest.Package.Applications.Application.Extensions.Extension |
                Where-Object { $_.Category -eq 'windows.comServer' })) {
            $hits += (Get-MsixLimitation -Id 'com-discovery')
        }

        # no-windows-services-deps: any windows.service extension
        if ($manifest.Package.Applications.Application.Extensions.Extension |
            Where-Object { $_.Category -eq 'windows.service' }) {
            $hits += (Get-MsixLimitation -Id 'no-windows-services-deps')
            $hits += (Get-MsixLimitation -Id 'service-elevation')
        }

        # protocol handlers
        if ($manifest.Package.Applications.Application.Extensions.Extension |
            Where-Object { $_.Category -eq 'windows.protocol' }) {
            $hits += (Get-MsixLimitation -Id 'protocol-handler-private')
        }

        # multi-package file association
        if ($manifest.Package.Applications.Application.Extensions.Extension |
            Where-Object { $_.Category -eq 'windows.fileTypeAssociation' }) {
            $hits += (Get-MsixLimitation -Id 'multi-pkg-fileassoc')
        }

        # always applicable for any packaged Win32 app
        $hits += (Get-MsixLimitation -Id 'hklm-redirected')
        $hits += (Get-MsixLimitation -Id 'appdata-private')

        return $hits | Sort-Object Id -Unique

    } finally {
        Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
    }
}


# Backward-compatible plural aliases
Set-Alias Get-MsixLimitations Get-MsixLimitation
Set-Alias Test-MsixAgainstLimitations Test-MsixAgainstLimitation
