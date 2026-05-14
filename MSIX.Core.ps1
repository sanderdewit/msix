# Resolved once per module load; overridable via $env:MSIX_TOOLS_PATH
$script:ToolsRoot = $null

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
        $script:ToolsRoot = $env:MSIX_TOOLS_PATH
        return $script:ToolsRoot
    }

    # 2) Tools folder next to this module file (Install-MsixSdkTool default)
    if (Test-Path "$PSScriptRoot\Tools\MakeAppx.exe") {
        $script:ToolsRoot = $PSScriptRoot
        return $script:ToolsRoot
    }

    # 3) Walk up to four parent levels looking for any sibling that hosts
    #    Tools\MakeAppx.exe (e.g. C:\temp\msix\0.56\ next to C:\temp\msix\MSIX\,
    #    or any other vendored toolchain elsewhere on the same path).
    $cursor = $PSScriptRoot
    for ($i = 0; $i -lt 4; $i++) {
        $cursor = Split-Path $cursor -Parent
        if (-not $cursor) { break }
        # Same-level siblings under this ancestor
        $sibling = Get-ChildItem $cursor -Directory -ErrorAction SilentlyContinue |
                   Where-Object { Test-Path "$($_.FullName)\Tools\MakeAppx.exe" } |
                   Sort-Object Name -Descending |
                   Select-Object -First 1
        if ($sibling) {
            $script:ToolsRoot = $sibling.FullName
            return $script:ToolsRoot
        }
        # Or the ancestor itself
        if (Test-Path "$cursor\Tools\MakeAppx.exe") {
            $script:ToolsRoot = $cursor
            return $script:ToolsRoot
        }
    }

    # 4) Windows SDK default paths — pick the highest-versioned bin dir
    foreach ($arch in @('x64','x86')) {
        $kitBin = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
        if (Test-Path $kitBin) {
            # Versioned subfolders + a flat <arch> root (older SDKs)
            $candidate = Get-ChildItem $kitBin -Directory -ErrorAction SilentlyContinue |
                         Where-Object { Test-Path "$($_.FullName)\$arch\makeappx.exe" } |
                         Sort-Object Name -Descending |
                         Select-Object -First 1
            if ($candidate) {
                $script:ToolsRoot = "$($candidate.FullName)\$arch"
                return $script:ToolsRoot
            }
            if (Test-Path "$kitBin\$arch\makeappx.exe") {
                $script:ToolsRoot = "$kitBin\$arch"
                return $script:ToolsRoot
            }
        }
    }

    # 5) One-shot auto-install
    if ($AutoInstall) {
        if (-not (Get-Command Install-MsixSdkTool -ErrorAction SilentlyContinue)) {
            throw 'Install-MsixSdkTool is not available; cannot auto-install. Make sure the module loaded fully.'
        }
        Write-MsixLog Info 'No SDK tools found; auto-installing via Install-MsixSdkTool.'
        Install-MsixSdkTool | Out-Null
        if (Test-Path "$PSScriptRoot\Tools\MakeAppx.exe") {
            $script:ToolsRoot = $PSScriptRoot
            return $script:ToolsRoot
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
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if (-not (Test-Path "$Path\Tools\MakeAppx.exe")) {
        throw "MakeAppx.exe not found under '$Path\Tools\'. Verify the path."
    }
    $script:ToolsRoot = $Path
    Write-MsixLog Info "Tools root set to: $Path"
}

function New-MsixWorkspace {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param(
        [Parameter(Mandatory)]
        [string]$PackageName
    )
    $id   = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $path = Join-Path $env:TEMP "msix-$PackageName-$id"
    New-Item -ItemType Directory -Path $path -Force | Out-Null
    Write-MsixLog Debug "Workspace created: $path"
    return $path
}

function Invoke-MsixProcess {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath,
        [Parameter(Mandatory)]
        [string]$Arguments
    )

    if (-not (Test-Path $FilePath)) {
        throw "Executable not found: $FilePath"
    }

    Write-MsixLog Debug "Exec: $FilePath $Arguments"

    $psi                       = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName              = $FilePath
    $psi.Arguments             = $Arguments
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardOutput= $true
    $psi.UseShellExecute       = $false
    $psi.WorkingDirectory      = (Get-Location).Path

    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
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
}

function Get-MsixPublisherId {
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
