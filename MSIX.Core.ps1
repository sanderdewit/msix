# Resolved once per module load; overridable via $env:MSIX_TOOLS_PATH
$script:ToolsRoot = $null

# Session-scoped verification opt-out. Deliberately in-memory only: see
# _MsixIsToolVerificationBypassed.
$script:MsixToolVerificationDisabled = $false

function Set-MsixToolVerification {
    <#
    .SYNOPSIS
        Enables or disables Authenticode verification of the toolchain for the
        CURRENT SESSION only. No administrator rights required.

    .DESCRIPTION
        The escape hatch for offline / air-gapped build agents where CRL/OCSP
        chain checks cannot complete for a legitimately Microsoft-signed binary.

        SECURITY (#147): this is deliberately a session-scoped, in-memory switch
        rather than an environment variable. An environment variable can be
        persisted by a non-admin into HKCU\Environment, after which EVERY later
        PowerShell session in that user's context silently trusts an arbitrary
        tools root - and combined with MSIX_TOOLS_PATH that is control over what
        the organisation signs. A setting that lives only in the current
        runspace cannot be planted for a future session to pick up: the operator
        has to opt out explicitly, in the script that is doing the work.

        The state does not persist. Re-import the module, or open a new session,
        and verification is on again.

    .PARAMETER Enabled
        $false disables verification for this session; $true restores it.

    .EXAMPLE
        # Air-gapped agent: no CRL/OCSP reachability
        Set-MsixToolVerification -Enabled $false
        Invoke-MsixSigning -PackagePath app.msix

    .OUTPUTS
        None.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][bool]$Enabled
    )
    $action = if ($Enabled) { 'Enable toolchain Authenticode verification' } else { 'DISABLE toolchain Authenticode verification' }
    if (-not $PSCmdlet.ShouldProcess('MSIX toolchain verification (this session)', $action)) { return }

    $script:MsixToolVerificationDisabled = -not $Enabled
    # Drop any cached root so the next resolution re-evaluates under the new setting.
    $script:ToolsRoot = $null

    if ($Enabled) {
        Write-MsixLog -Level Info -Message 'Toolchain Authenticode verification ENABLED for this session.'
    } else {
        Write-Warning 'MSIX: toolchain Authenticode verification DISABLED for this session. SDK tools will be trusted without a signature check. This lasts until the session ends or the module is re-imported.'
        Write-MsixLog -Level Warning -Message 'Toolchain Authenticode verification DISABLED for this session via Set-MsixToolVerification.'
    }
}

function _MsixIsToolVerificationBypassed {
    <#
    .SYNOPSIS
        Returns $true when toolchain Authenticode verification has been opted out
        of, either for this session or machine-wide.

    .DESCRIPTION
        SECURITY (#147). The bypass used to be an ordinary environment variable,
        so a non-admin attacker could persist it in HKCU\Environment and every
        later PowerShell session in that user's context would trust an arbitrary
        tools root - combined with MSIX_TOOLS_PATH, that is full control of what
        the organisation signs, with only a suppressible log line as a signal.

        Two supported opt-outs remain, neither of which can be planted for a
        FUTURE session to silently pick up:

          1. Set-MsixToolVerification -Enabled $false
             Session-scoped, in-memory, NO admin rights required. This is the
             normal escape hatch for an air-gapped agent.

          2. MSIX_SKIP_TOOL_VERIFICATION at MACHINE scope
             For fleet configuration; writing it needs administrator rights.

        A process- or user-scoped environment variable is deliberately IGNORED,
        and says so loudly rather than silently appearing to work.
    #>
    [OutputType([bool])]
    param()

    if ($script:MsixToolVerificationDisabled) { return $true }

    $machine = $null
    try {
        $machine = [Environment]::GetEnvironmentVariable('MSIX_SKIP_TOOL_VERIFICATION', 'Machine')
    } catch {
        # Registry read denied (locked-down host): treat as not bypassed.
        Write-MsixLog -Level Debug -Message "Could not read the machine-scoped MSIX_SKIP_TOOL_VERIFICATION: $($_.Exception.Message)"
    }
    if ($machine) { return $true }

    # Set somewhere, but not at machine scope: ignore it, and point at the
    # supported, admin-free alternative.
    if ($env:MSIX_SKIP_TOOL_VERIFICATION) {
        Write-Warning "MSIX: MSIX_SKIP_TOOL_VERIFICATION is set for this process/user but is IGNORED, because an environment variable can be planted to affect future sessions. Use 'Set-MsixToolVerification -Enabled `$false' for this session (no admin needed), or set the variable at Machine scope for the whole host. Verification remains ENABLED."
    }
    return $false
}

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

    if (_MsixIsToolVerificationBypassed) {
        # Real Warning stream as well as the module log: Write-MsixLog routes to
        # Write-Information, which is invisible to -WarningVariable and is dropped
        # entirely under Set-MsixLogLevel -Level Error. Disabling the control that
        # protects the signing toolchain must not be silenceable (issue #147).
        Write-Warning "MSIX: tool Authenticode verification BYPASSED (machine-scoped MSIX_SKIP_TOOL_VERIFICATION is set) for '$Root'."
        Write-MsixLog -Level Warning -Message "Tool Authenticode verification BYPASSED (machine-scoped MSIX_SKIP_TOOL_VERIFICATION is set). SDK tools under '$Root' are trusted without a signature check. Clear the machine-scoped variable to restore fail-closed verification."
    } elseif (Get-Command -Name _MsixVerifyAuthenticode -ErrorAction SilentlyContinue) {
        # Verify the tools we EXECUTE plus signtool's private side-by-side load
        # surface (issue #147).
        #
        # Checking only signtool/MakeAppx/makepri was not enough: SDK signtool.exe
        # is SxS-manifest-bound to load wintrust.dll / mssign32.dll / AppxSip.dll
        # from its OWN directory, so an attacker able to write that directory could
        # keep the three genuine Microsoft-signed executables (passing the check)
        # and plant a trojaned dependency DLL beside them, running their code
        # inside the process that holds the organisation's code-signing key.
        #
        # Verifying EVERY file in the root is NOT viable and was tried first:
        # Microsoft itself ships unsigned binaries in these directories - 9 in the
        # real Windows SDK bin\x64 (gamesaveutil.exe, SirepClient.dll,
        # WinAppDeployCmd.exe, ...) and 5 in the NuGet BuildTools layout
        # (PackageEditor.exe, Microsoft.Packaging.SDKUtils.dll, ...). That rejects
        # every legitimate SDK install, so the check must be targeted.
        #
        # This list is deliberately the executables we invoke plus the documented
        # signing load surface; it is not a claim that every other file in the
        # folder is irrelevant, only that nothing else is loaded by the tools this
        # module runs.
        $verifyNames = @(
            'signtool.exe', 'MakeAppx.exe', 'makepri.exe',   # executed directly
            'wintrust.dll', 'mssign32.dll', 'AppxSip.dll',   # signtool SxS bindings
            'msisip.dll', 'opcservices.dll'                  # SIP/OPC helpers
        )
        $toolsFound = 0
        foreach ($name in $verifyNames) {
            $candidate = @(
                (Join-Path -Path $Root -ChildPath "Tools\$name"),
                (Join-Path -Path $Root -ChildPath $name)
            ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
            if (-not $candidate) { continue }
            if ($name -like '*.exe') { $toolsFound++ }
            # Throws (fail-closed) if unsigned, untrusted, or the chain cannot be
            # validated.
            $null = _MsixVerifyAuthenticode -Path $candidate -ToolName $name
        }
        if ($toolsFound -eq 0) {
            throw "Tool verification failed: none of signtool.exe / MakeAppx.exe / makepri.exe were found under '$Root'. Refusing to trust an empty or unexpected tools root."
        }
    } else {
        # Fail CLOSED. Previously this branch silently cached and trusted the root
        # with no warning at all, defeating the whole control if the verifier was
        # not in scope for any reason (issue #147).
        throw 'Tool verification unavailable: _MsixVerifyAuthenticode is not loaded. Re-import the MSIX module; set MSIX_SKIP_TOOL_VERIFICATION only for a deliberate air-gapped bypass.'
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
        & (_MsixToolPath -Name 'MakeAppx.exe' -Root $root) /?

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

    # 3) Look for a vendored toolchain NEXT TO the module only (one level up),
    #    e.g. C:\temp\msix\0.56\ beside C:\temp\msix\MSIX\.
    #
    #    SECURITY (issue #147): this used to walk up to FOUR parent levels and
    #    accept any subdirectory containing Tools\MakeAppx.exe, ordered by
    #    Sort-Object Name -Descending - lexically highest wins, not most
    #    trustworthy. For a -Scope CurrentUser install the 4th hop reaches
    #    ~\Documents, which is fully user-writable: creating
    #    ~\Documents\zzz\Tools\ beat every legitimate candidate on every later
    #    session. Combined with the SxS-DLL gap above that handed an unprivileged
    #    attacker code execution inside signing. One level keeps the intended
    #    side-by-side layout working without reaching a user profile root.
    $parent = Split-Path -Path $PSScriptRoot -Parent
    if ($parent) {
        $sibling = Get-ChildItem -LiteralPath $parent -Directory -ErrorAction SilentlyContinue |
                   Where-Object { Test-Path -LiteralPath "$($_.FullName)\Tools\MakeAppx.exe" } |
                   Sort-Object Name -Descending |
                   Select-Object -First 1
        if ($sibling) {
            return _MsixSetVerifiedToolsRoot -Root $sibling.FullName
        }
        if (Test-Path "$parent\Tools\MakeAppx.exe") {
            return _MsixSetVerifiedToolsRoot -Root $parent
        }
    }

    # 4) Windows SDK default paths — pick the highest-versioned bin dir.
    #
    #    This is a FALLBACK, not the intended workflow. It resolves to a FLAT
    #    root (makeappx.exe directly, no Tools\ subfolder), which every call site
    #    used to mishandle - so a machine with the SDK installed but no module
    #    toolchain failed with "Executable not found: ...\x64\Tools\MakeAppx.exe".
    #    _MsixToolPath now resolves both layouts (#151), but the toolchain version
    #    then depends on whatever SDK that machine happens to have. Warn, so an
    #    operator who wants reproducible builds knows to pin one.
    foreach ($arch in @('x64','x86')) {
        $kitBin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
        if (Test-Path -LiteralPath $kitBin) {
            # Versioned subfolders + a flat <arch> root (older SDKs)
            $candidate = Get-ChildItem -LiteralPath $kitBin -Directory -ErrorAction SilentlyContinue |
                         Where-Object { Test-Path "$($_.FullName)\$arch\makeappx.exe" } |
                         Sort-Object Name -Descending |
                         Select-Object -First 1
            $sdkRoot = $null
            if ($candidate) {
                $sdkRoot = "$($candidate.FullName)\$arch"
            } elseif (Test-Path "$kitBin\$arch\makeappx.exe") {
                $sdkRoot = "$kitBin\$arch"
            }
            if ($sdkRoot) {
                Write-MsixLog -Level Warning -Message "Using the Windows SDK already installed on this machine ($sdkRoot). The toolchain version is therefore whatever this host has, which is not reproducible across build agents. Run Initialize-MsixToolchain (or Install-MsixSdkTool) to pin a downloaded toolchain under the module."
                return _MsixSetVerifiedToolsRoot -Root $sdkRoot
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
    # Accept BOTH layouts, matching _MsixToolPath: <Path>\Tools\MakeAppx.exe
    # (vendored / Install-MsixSdkTool) and <Path>\makeappx.exe (a system Windows
    # SDK bin\<ver>\<arch> root). Requiring only the first rejected a perfectly
    # usable SDK root (#151).
    $probe = @(
        (Join-Path -Path $Path -ChildPath 'Tools\MakeAppx.exe'),
        (Join-Path -Path $Path -ChildPath 'MakeAppx.exe')
    ) | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $probe) {
        throw "MakeAppx.exe not found under '$Path' (checked '$Path\Tools\' and the root). Verify the path."
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
    # -WhatIf:$false is REQUIRED. The workspace is private scratch, not a
    # user-visible side effect, but New-Item honours the $WhatIfPreference
    # inherited through the module scope chain. Without this, running any
    # mutator with -WhatIf skips the create, the Get-Item below fails, and this
    # function returns an EMPTY STRING - which broke -WhatIf across all ~46
    # _MsixMutateManifest call sites plus _MsixMutatePackage (issue #145).
    New-Item -ItemType Directory -Path $path -Force -WhatIf:$false | Out-Null
    # Return the LONG-form path. $env:TEMP can carry an 8.3 short segment
    # (SANDER~1 vs SanderdeWit) while Get-ChildItem returns long-form
    # FullNames; any relative-path Substring against a short-form workspace
    # then chops the wrong number of characters (this shipped as the
    # '08\VFS\...' nested-package corruption in Import-MsixSparseShellExtension).
    $path = (Get-Item -LiteralPath $path).FullName
    Write-MsixLog -Level Debug -Message "Workspace created: $path"
    return $path
}

function _MsixTestTrustedExecutable {
    <#
    .SYNOPSIS
        Returns $true when a resolved helper executable is Authenticode-trusted,
        $false (with a Warning) otherwise. Does not throw.

    .DESCRIPTION
        SECURITY (#147). Resolve-MsixProcMonPath and friends pick an executable
        out of env-var overrides, PATH, and fixed fallbacks such as
        'C:\PSF\ProcessMonitor\Procmon.exe' - and their results are executed,
        usually ELEVATED (ProcMon needs its kernel driver). None of that was
        verified, so a standard user who created C:\PSF - the root of C: grants
        Authenticated Users CreateDirectories, and C:\PSF does not exist by
        default - got their binary run as SYSTEM.

        This returns a boolean rather than throwing so a resolver can simply skip
        an untrusted candidate and keep looking, which keeps a poisoned override
        from denying service as well.

        Honours the same machine-scoped bypass as the SDK toolchain check.
    #>
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$ToolName = 'tool'
    )
    if (_MsixIsToolVerificationBypassed) { return $true }
    if (-not (Get-Command -Name _MsixVerifyAuthenticode -ErrorAction SilentlyContinue)) {
        Write-MsixLog -Level Warning -Message "Cannot verify $ToolName at '$Path': the Authenticode verifier is not loaded. Skipping this candidate."
        return $false
    }
    try {
        $null = _MsixVerifyAuthenticode -Path $Path -ToolName $ToolName
        return $true
    } catch {
        Write-MsixLog -Level Warning -Message "Ignoring untrusted $ToolName at '$Path': $($_.Exception.Message.Split([char]10)[0]). It will NOT be executed."
        return $false
    }
}

function _MsixToolPath {
    <#
    .SYNOPSIS
        Resolves an SDK tool (MakeAppx / signtool / makepri) inside a tools root,
        supporting BOTH layouts Get-MsixToolsRoot can return.

    .DESCRIPTION
        Get-MsixToolsRoot resolves a root from five sources. Two layouts result:

          <root>\Tools\MakeAppx.exe   vendored / Install-MsixSdkTool
          <root>\makeappx.exe         a system Windows SDK bin\<ver>\<arch>

        Every call site used to hardcode the first form, so search path 4 (the
        installed Windows SDK) returned a root the module could then never use -
        "Executable not found: ...\bin\10.0.26100.0\x64\Tools\MakeAppx.exe". The
        test-suite tooling gate happened to require the Tools\ form too, so on a
        system-SDK host every integration test skipped and the defect stayed
        invisible until the gate was corrected (#151).

        When neither layout has the file, the Tools\ form is returned so callers
        still produce the familiar "Executable not found" message.
    #>
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string]$Name,
        [string]$Root
    )
    if (-not $Root) { $Root = Get-MsixToolsRoot }
    $nested = Join-Path -Path $Root -ChildPath (Join-Path -Path 'Tools' -ChildPath $Name)
    if (Test-Path -LiteralPath $nested -PathType Leaf) { return $nested }
    $flat = Join-Path -Path $Root -ChildPath $Name
    if (Test-Path -LiteralPath $flat -PathType Leaf) { return $flat }
    return $nested
}

function _MsixWriteUtf8 {
    <#
    .SYNOPSIS
        Writes a text file as UTF-8 with a DETERMINISTIC byte-order mark,
        identical under Windows PowerShell 5.1 and PowerShell 7.

    .DESCRIPTION
        `-Encoding utf8` does not mean the same thing on both editions:
        5.1 writes UTF-8 **with** a BOM, 7 writes it **without** (issue #146).
        That divergence is silent and only shows up downstream:

          - The Trusted Signing metadata JSON is parsed by
            Azure.CodeSigning.Dlib.dll via `signtool /dmdf`. System.Text.Json
            rejects a leading BOM outright ("'0xEF' is an invalid start of a
            value"), so packages signed from 5.1 failed on the module's DEFAULT
            signing backend while 7 worked.
          - PSF `config.json` is parsed by the PSF runtime at every app launch.
            `Test-MsixPsfConfig` reads it with `Get-Content -Raw`, which strips
            the BOM on 5.1, so the module's own validator could not see the
            defect and it shipped inside customer packages.

        Rule of thumb for -WithBom:
          - OFF for anything a non-PowerShell parser consumes (JSON, XML, HTML).
          - ON  for generated .ps1 files, where Windows PowerShell 5.1 otherwise
            reads a BOM-less UTF-8 file as CP-1252 and mis-parses non-ASCII
            (the hazard documented in CLAUDE.md).

    .PARAMETER WithBom
        Emit the UTF-8 BOM (EF BB BF). Default is no BOM.

    .PARAMETER NoNewline
        Do not append a trailing newline. Set-Content/Out-File add one by
        default; this keeps that behaviour unless suppressed.
    #>
    [OutputType([void])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][AllowNull()][string]$Text,
        [switch]$WithBom,
        [switch]$NoNewline
    )
    $body = if ($null -eq $Text) { '' } else { $Text }
    if (-not $NoNewline -and -not $body.EndsWith("`n")) { $body += [Environment]::NewLine }
    [IO.File]::WriteAllText($Path, $body, [Text.UTF8Encoding]::new([bool]$WithBom))
}

function _MsixPreserveUnsigned {
    <#
    .SYNOPSIS
        Copies a scratch package to -UnsignedOutputPath after a signing failure,
        and reports honestly whether that actually succeeded.

    .DESCRIPTION
        Every repack site used to preserve the artifact like this:

            Copy-Item -LiteralPath $scratch -Destination $dest -Force -ErrorAction SilentlyContinue
            Write-MsixLog -Level Warning -Message "... Unsigned package preserved at: $dest"

        with the enclosing finally deleting $scratch immediately after. If the
        copy failed - destination directory missing, volume full, file locked -
        the error was fully suppressed, the log still claimed the package had
        been preserved, and the only copy was then destroyed. The operator
        followed the log to an empty path and the build was unrecoverable: the
        exact inverse of what the parameter promises (issue #145).

        This helper creates the destination directory when needed, copies with
        -ErrorAction Stop, and logs at Error - not Warning - when preservation
        genuinely failed.
    #>
    [OutputType([void])]
    param(
        [Parameter(Mandatory)][string]$Scratch,
        [Parameter(Mandatory)][string]$Destination
    )
    try {
        $dir = Split-Path -Parent -Path $Destination
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -ErrorAction Stop | Out-Null
        }
        Copy-Item -LiteralPath $Scratch -Destination $Destination -Force -ErrorAction Stop
        Write-MsixLog -Level Warning -Message "Signing failed. Unsigned package preserved at: $Destination"
    } catch {
        Write-MsixLog -Level Error -Message "Signing failed AND the unsigned package could NOT be preserved at '$Destination': $($_.Exception.Message). The scratch build is being discarded; re-run after fixing the destination."
    }
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
        Invoke-MsixProcess -FilePath (_MsixToolPath -Name 'MakeAppx.exe' -Root $root) -ArgumentList @(
            'unpack', '/p', $packagePath, '/d', $workspace, '/o'
        )

    .EXAMPLE
        # DEPRECATED legacy single-string form — emits a warning. New callers
        # MUST use -ArgumentList; this is retained only for older scripts.
        Invoke-MsixProcess -FilePath (_MsixToolPath -Name 'MakeAppx.exe' -Root $root) `
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

    # SECURITY (issue #148): redact the value FOLLOWING a secret-bearing switch
    # before logging. The SignTool-PFX backend passes '/p', <plaintext password>
    # in this vector; Write-MsixLog also appends to the file configured by
    # Set-MsixLogFile, so the documented troubleshooting flow
    # (Set-MsixLogLevel Debug + Set-MsixLogFile) wrote the code-signing password
    # to disk in clear text, where CI artifact upload and log shippers collect it.
    $secretSwitches = @('/p', '-p', '--password', '/password', '-Password')
    $redacted = New-Object System.Collections.Generic.List[string]
    $hideNext = $false
    foreach ($a in $ArgumentList) {
        $s = [string]$a
        if ($hideNext) {
            $redacted.Add('***REDACTED***')
            $hideNext = $false
            continue
        }
        if ($secretSwitches -contains $s) { $hideNext = $true }
        $redacted.Add($(if ($s -match '\s') { '"' + $s + '"' } else { $s }))
    }
    Write-MsixLog -Level Debug -Message "Exec: $FilePath $([string]::Join(' ', $redacted))"

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
