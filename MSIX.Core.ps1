# Resolved once per module load; overridable via $env:MSIX_TOOLS_PATH
$script:ToolsRoot = $null

function Get-MsixToolsRoot {
    if ($script:ToolsRoot) { return $script:ToolsRoot }

    # 1) Explicit env override
    if ($env:MSIX_TOOLS_PATH -and (Test-Path "$env:MSIX_TOOLS_PATH\Tools\MakeAppx.exe")) {
        $script:ToolsRoot = $env:MSIX_TOOLS_PATH
        return $script:ToolsRoot
    }

    # 2) Tools folder next to this module file
    if (Test-Path "$PSScriptRoot\Tools\MakeAppx.exe") {
        $script:ToolsRoot = $PSScriptRoot
        return $script:ToolsRoot
    }

    # 3) Versioned sibling directory (e.g. ..\0.56\)
    $parent  = Split-Path $PSScriptRoot -Parent
    $sibling = Get-ChildItem $parent -Directory -ErrorAction SilentlyContinue |
               Where-Object { Test-Path "$($_.FullName)\Tools\MakeAppx.exe" } |
               Sort-Object Name -Descending |
               Select-Object -First 1
    if ($sibling) {
        $script:ToolsRoot = $sibling.FullName
        return $script:ToolsRoot
    }

    # 4) Windows SDK default paths
    $sdkRoots = @(
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\x64",
        "${env:ProgramFiles(x86)}\Windows Kits\10\bin\x86"
    )
    foreach ($r in $sdkRoots) {
        if (Test-Path "$r\makeappx.exe") {
            $script:ToolsRoot = $r
            return $script:ToolsRoot
        }
    }

    throw 'MakeAppx.exe not found. Set $env:MSIX_TOOLS_PATH to the folder that contains a Tools\ subfolder, or install the Windows SDK.'
}

function Set-MsixToolsRoot {
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

function Get-PublisherIdFromPublisher {
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
