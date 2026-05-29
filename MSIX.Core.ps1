# Resolved once per module load; overridable via $env:MSIX_TOOLS_PATH
$script:ToolsRoot = $null

function _MsixSetVerifiedToolsRoot {
    <#
    .SYNOPSIS
        Authenticode-verifies the SDK tools under a resolved root, then caches
        and returns it.

    .DESCRIPTION
        SECURITY (#54): Get-MsixToolsRoot discovers signtool.exe / MakeAppx.exe
        by env override, parent-walk, or SDK glob and the module then EXECUTES
        them — signtool signs the output package, so a planted binary is a
        high-value target. Every resolved root is therefore verified (fail-closed)
        against the trusted-publisher allowlist before it is trusted, regardless
        of how it was found.

        Verification can be disabled by setting the MSIX_SKIP_TOOL_VERIFICATION
        environment variable — intended ONLY for offline / air-gapped build
        agents where CRL/OCSP chain checks cannot complete for a legitimately
        Microsoft-signed binary. A loud warning is logged when it is bypassed.

        Note: msixmgr is NOT resolved through this path (it lives under its own
        folder via MSIX.AppAttach.ps1) and keeps its documented unsigned/preview
        exception (microsoft/msix-packaging#710).

    .PARAMETER Root
        The candidate tools root. signtool.exe / MakeAppx.exe are looked for
        both directly under it and under a Tools\ subfolder (the two layouts
        Get-MsixToolsRoot produces).
    #>
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param([Parameter(Mandatory)][string]$Root)

    if ($env:MSIX_SKIP_TOOL_VERIFICATION) {
        Write-MsixLog -Level Warning -Message "Tool Authenticode verification BYPASSED (MSIX_SKIP_TOOL_VERIFICATION is set). SDK tools under '$Root' are trusted without a signature check. Unset this variable to restore fail-closed verification."
    } elseif (Get-Command -Name _MsixVerifyAuthenticode -ErrorAction SilentlyContinue) {
        foreach ($tool in @('signtool.exe', 'MakeAppx.exe')) {
            $candidate = @(
                (Join-Path -Path $Root -ChildPath "Tools\$tool"),
                (Join-Path -Path $Root -ChildPath $tool)
            ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            if ($candidate) {
                # Throws (fail-closed) if the binary is unsigned, untrusted, or
                # its chain cannot be validated.
                $null = _MsixVerifyAuthenticode -Path $candidate -ToolName $tool
            }
        }
    }

    $script:ToolsRoot = $Root
    return $Root
}

function Get-MsixToolsRoot {
    <#
    .SYNOPSIS
        Returns a folder that contains Tools\MakeAppx.exe.

    .DESCRIPTION
        Search order (first hit wins, result cached for the session):

          1. $env:MSIX_TOOLS_PATH          explicit override
          2. <module folder>\Tools\        installed by Install-MsixSdkTool
          3. Sibling / parent-walk         e.g. ..\0.56\Tools\
          4. Windows 10/11 SDK             %ProgramFiles(x86)%\Windows Kits\10\bin
          5. Auto-install (if -AutoInstall) one-call download from NuGet

    .PARAMETER AutoInstall
        If set and nothing was found, run Install-MsixSdkTool to fetch
        Microsoft.Windows.SDK.BuildTools and use that.

    .PARAMETER Refresh
        Drop the cached result and re-resolve from scratch.

    .OUTPUTS
        [string] Absolute path that contains a Tools\MakeAppx.exe.

    .EXAMPLE
        # First call resolves and caches; later calls are O(1)
        $root = Get-MsixToolsRoot
        & "$root\Tools\MakeAppx.exe" /?

    .EXAMPLE
        # Force a one-shot install if nothing is found
        Get-MsixToolsRoot -AutoInstall

    .EXAMPLE
        # Pin a specific layout via env var (overrides every other source)
        $env:MSIX_TOOLS_PATH = 'C:\tools\msix-sdk'
        Get-MsixToolsRoot -Refresh
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [switch]$AutoInstall,
        [switch]$Refresh
    )
    if ($Refresh) { $script:ToolsRoot = $null }
    if ($script:ToolsRoot) { return $script:ToolsRoot }

    # 1) Explicit env override
    if ($env:MSIX_TOOLS_PATH -and (Test-Path "$env:MSIX_TOOLS_PATH\Tools\MakeAppx.exe")) {
        return _MsixSetVerifiedToolsRoot -Root $env:MSIX_TOOLS_PATH
    }

    # 2) Tools folder next to this module file (Install-MsixSdkTool default)
    if (Test-Path "$PSScriptRoot\Tools\MakeAppx.exe") {
        return _MsixSetVerifiedToolsRoot -Root $PSScriptRoot
    }

    # 3) Walk up to four parent levels looking for any sibling that hosts
    #    Tools\MakeAppx.exe (e.g. C:\temp\msix\0.56\ next to C:\temp\msix\MSIX\,
    #    or any other vendored toolchain elsewhere on the same path).
    $cursor = $PSScriptRoot
    for ($i = 0; $i -lt 4; $i++) {
        $cursor = Split-Path -Path $cursor -Parent
        if (-not $cursor) { break }
        # Same-level siblings under this ancestor
        $sibling = Get-ChildItem -LiteralPath $cursor -Directory -ErrorAction SilentlyContinue |
                   Where-Object { Test-Path -LiteralPath "$($_.FullName)\Tools\MakeAppx.exe" } |
                   Sort-Object Name -Descending |
                   Select-Object -First 1
        if ($sibling) {
            return _MsixSetVerifiedToolsRoot -Root $sibling.FullName
        }
        # Or the ancestor itself
        if (Test-Path "$cursor\Tools\MakeAppx.exe") {
            return _MsixSetVerifiedToolsRoot -Root $cursor
        }
    }

    # 4) Windows SDK default paths — pick the highest-versioned bin dir
    foreach ($arch in @('x64','x86')) {
        $kitBin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
        if (Test-Path -LiteralPath $kitBin) {
            # Versioned subfolders + a flat <arch> root (older SDKs)
            $candidate = Get-ChildItem -LiteralPath $kitBin -Directory -ErrorAction SilentlyContinue |
                         Where-Object { Test-Path "$($_.FullName)\$arch\makeappx.exe" } |
                         Sort-Object Name -Descending |
                         Select-Object -First 1
            if ($candidate) {
                return _MsixSetVerifiedToolsRoot -Root "$($candidate.FullName)\$arch"
            }
            if (Test-Path "$kitBin\$arch\makeappx.exe") {
                return _MsixSetVerifiedToolsRoot -Root "$kitBin\$arch"
            }
        }
    }

    # 5) One-shot auto-install
    if ($AutoInstall) {
        if (-not (Get-Command Install-MsixSdkTool -ErrorAction SilentlyContinue)) {
            throw 'Install-MsixSdkTool is not available; cannot auto-install. Make sure the module loaded fully.'
        }
        Write-MsixLog -Level Info -Message 'No SDK tools found; auto-installing via Install-MsixSdkTool.'
        Install-MsixSdkTool | Out-Null
        if (Test-Path "$PSScriptRoot\Tools\MakeAppx.exe") {
            return _MsixSetVerifiedToolsRoot -Root $PSScriptRoot
        }
    }

    throw @"
MakeAppx.exe not found. Pick ONE of these:

  # Easiest -- auto-download MakeAppx + signtool from the official Microsoft
  # NuGet package (Microsoft.Windows.SDK.BuildTools), once per machine:
  Install-MsixSdkTool

  # Or do everything (PSF + Procmon + msixmgr + SDK tools) in a single call:
  Initialize-MsixToolchain

  # Or point at an existing layout (must contain Tools\MakeAppx.exe):
  `$env:MSIX_TOOLS_PATH = 'C:\path\to\toolsroot'
  Set-MsixToolsRoot     -Path 'C:\path\to\toolsroot'
"@
}

function Set-MsixToolsRoot {
    <#
    .SYNOPSIS
        Pins the tools root used by every cmdlet in this session.

    .DESCRIPTION
        Validates that <Path>\Tools\MakeAppx.exe exists, then sets the
        session-level cache that Get-MsixToolsRoot returns. Use this when
        you have a vendored SDK layout and don't want to set
        $env:MSIX_TOOLS_PATH globally.

        Equivalent to setting $env:MSIX_TOOLS_PATH and then calling
        Get-MsixToolsRoot -Refresh, but scoped to the current session only.

    .PARAMETER Path
        Folder that directly contains a Tools subfolder with MakeAppx.exe.

    .EXAMPLE
        Set-MsixToolsRoot -Path 'C:\tools\msix-sdk'
        # Get-MsixToolsRoot now returns 'C:\tools\msix-sdk'.
    #>
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path "$Path\Tools\MakeAppx.exe")) {
        throw "MakeAppx.exe not found under '$Path\Tools\'. Verify the path."
    }
    # Authenticode-verify (fail-closed) before pinning — same gate as the
    # auto-discovery paths (#54).
    $null = _MsixSetVerifiedToolsRoot -Root $Path
    Write-MsixLog -Level Info -Message "Tools root set to: $Path"
}

function New-MsixWorkspace {
    <#
    .SYNOPSIS
        Creates a fresh, GUID-stamped temp folder for an unpack/repack cycle.

    .DESCRIPTION
        Primarily used internally by Invoke-MsixPipeline, Add-MsixPsfV2, and
        the context-menu cmdlets to keep multiple concurrent runs isolated.
        Exposed for callers who script custom unpack/edit/repack flows
        outside the high-level pipeline.

        The caller is responsible for removing the workspace when done
        (Remove-Item -Recurse -Force).

    .PARAMETER PackageName
        Short label baked into the folder name. Use the package base name to
        make the workspace easy to identify while it exists.

    .OUTPUTS
        [string] Absolute path of the new directory.

    .EXAMPLE
        $ws = New-MsixWorkspace -PackageName 'Contoso.App'
        try {
            # unpack, edit, repack into $ws
        } finally {
            Remove-Item -LiteralPath $ws -Recurse -Force
        }
    #>
    [OutputType([string])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [string]$PackageName
    )
    $id   = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $path = Join-Path -Path $env:TEMP -ChildPath "msix-$PackageName-$id"
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    Write-MsixLog -Level Debug -Message "Workspace created: $path"
    return $path
}

function Invoke-MsixProcess {
    <#
    .SYNOPSIS
        Runs an external executable and captures its exit code, stdout, and stderr.

    .DESCRIPTION
        Arguments are passed as an array (one element per argument) so each argument
        is correctly quoted by the .NET process API. This prevents argument injection
        from filenames or values that contain spaces, quotes, or shell metacharacters.

    .PARAMETER FilePath
        Absolute path to the executable.

    .PARAMETER ArgumentList
        Array of arguments. Each element is one argument; do not pre-concatenate.
        Example: @('unpack', '/p', $path, '/d', $workspace, '/o')

    .PARAMETER Arguments
        DEPRECATED. Legacy single-string argument form. Internally split with a
        naive parser for backward compatibility -- new callers MUST use -ArgumentList.
        Logs a warning to encourage migration.

    .OUTPUTS
        [pscustomobject] with ExitCode (int), StdOut (string), StdErr (string).

    .EXAMPLE
        # Preferred: array form (each argument quoted correctly)
        Invoke-MsixProcess -FilePath "$root\Tools\MakeAppx.exe" -ArgumentList @(
            'unpack', '/p', $packagePath, '/d', $workspace, '/o'
        )

    .EXAMPLE
        # DEPRECATED legacy single-string form — emits a warning. New callers
        # MUST use -ArgumentList; this is retained only for older scripts.
        Invoke-MsixProcess -FilePath "$root\Tools\MakeAppx.exe" `
            -Arguments "unpack /p `"$packagePath`" /d `"$workspace`" /o"
    #>
    [CmdletBinding(DefaultParameterSetName = 'ArgumentList')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$FilePath,

        [Parameter(Mandatory, ParameterSetName = 'ArgumentList', Position = 1)]
        [AllowEmptyCollection()]
        [string[]]$ArgumentList,

        [Parameter(Mandatory, ParameterSetName = 'LegacyString', Position = 1)]
        [string]$Arguments
    )

    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) {
        throw "Executable not found: $FilePath"
    }

    # Backward-compat: split the legacy single string into an array using a
    # quote-aware tokenizer. Issues a deprecation warning so callers migrate.
    if ($PSCmdlet.ParameterSetName -eq 'LegacyString') {
        Write-MsixLog -Level Warning -Message "Invoke-MsixProcess: -Arguments (single string) is deprecated. Pass -ArgumentList @(...) instead. Caller: $((Get-PSCallStack)[1].Command)"
        $ArgumentList = @()
        if ($Arguments) {
            # Honour double-quoted segments containing spaces; otherwise split on whitespace.
            $regex = [regex]'(?<=^|\s)"([^"]*)"(?=\s|$)|\S+'
            foreach ($m in $regex.Matches($Arguments)) {
                $ArgumentList += if ($m.Groups[1].Success) { $m.Groups[1].Value } else { $m.Value }
            }
        }
    }

    Write-MsixLog -Level Debug -Message "Exec: $FilePath $([string]::Join(' ', ($ArgumentList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } })))"

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName               = $FilePath
    $psi.RedirectStandardError  = $true
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute        = $false
    $psi.WorkingDirectory       = (Get-Location).Path

    # PowerShell 5.1 / .NET Framework 4.x does not expose ProcessStartInfo.ArgumentList.
    # Fall back to safely quoting into the single Arguments string. The quoting rules
    # match CommandLineToArgvW: wrap in double quotes; escape embedded " as \" ; double
    # trailing backslashes before closing quote.
    if ($null -ne $psi.PSObject.Properties['ArgumentList']) {
        foreach ($a in $ArgumentList) { [void]$psi.ArgumentList.Add([string]$a) }
    } else {
        $psi.Arguments = [string]::Join(' ', ($ArgumentList | ForEach-Object {
            $s = [string]$_
            if ($s -eq '') { return '""' }
            if ($s -notmatch '[\s"]') { return $s }
            # Escape embedded backslashes-before-quotes per CommandLineToArgvW rules.
            $escaped = $s -replace '(\\*)"', '$1$1\"'
            $escaped = $escaped -replace '(\\+)$', '$1$1'
            return '"' + $escaped + '"'
        }))
    }

    $p = [System.Diagnostics.Process]::new()
    $p.StartInfo = $psi
    try {
        $null = $p.Start()
        # Read both streams concurrently to prevent buffer deadlocks
        $stdoutTask = $p.StandardOutput.ReadToEndAsync()
        $stderrTask = $p.StandardError.ReadToEndAsync()
        $p.WaitForExit()
        return [pscustomobject]@{
            ExitCode = $p.ExitCode
            StdOut   = $stdoutTask.Result
            StdErr   = $stderrTask.Result
        }
    } finally {
        $p.Dispose()
    }
}

function Get-MsixPublisherId {
    <#
    .SYNOPSIS
        Computes the Crockford-Base32-encoded SHA-256 publisher hash used by
        MSIX for VFS paths and package family names.

    .DESCRIPTION
        Implements the algorithm Windows uses to derive PublisherId from a
        certificate Subject (e.g. 'CN=Contoso, O=Contoso, C=NL'):
          1. Encode Publisher as UTF-16LE.
          2. SHA-256 the bytes; keep the first 8 bytes.
          3. Re-encode those 8 bytes as 13 Crockford-Base32 characters.

        Useful for predicting the install path under
        %ProgramFiles%\WindowsApps\<Name>_<Version>_<Arch>__<PublisherId>
        without having to install the package first.

        Available under the legacy alias Get-PublisherIdFromPublisher.

    .PARAMETER Publisher
        Full publisher Distinguished Name exactly as it appears in
        AppxManifest.xml's Identity/Publisher attribute. Matching is
        case-sensitive — even a space difference yields a different ID.

    .OUTPUTS
        [string] 13-character lowercase publisher ID.

    .EXAMPLE
        Get-MsixPublisherId -Publisher 'CN=Contoso, O=Contoso, C=NL'
        # -> e.g. 8wekyb3d8bbwe-style id
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Publisher
    )

    $encUtf16  = [System.Text.Encoding]::Unicode
    $encSha256 = [System.Security.Cryptography.HashAlgorithm]::Create('SHA256')

    $bytes = @()
    ($encSha256.ComputeHash($encUtf16.GetBytes($Publisher)))[0..7] |
        ForEach-Object { $bytes += '{0:x2}' -f $_ }

    $bin = (-join $bytes.ForEach{
        [convert]::ToString([convert]::ToByte($_, 16), 2).PadLeft(8, '0')
    }).PadRight(65, '0')

    $table  = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'
    $coded  = ''
    for ($i = 0; $i -lt $bin.Length; $i += 5) {
        $coded += $table[[convert]::ToInt32($bin.Substring($i, 5), 2)]
    }
    return $coded.ToLower()
}

Set-Alias -Name Get-PublisherIdFromPublisher -Value Get-MsixPublisherId
