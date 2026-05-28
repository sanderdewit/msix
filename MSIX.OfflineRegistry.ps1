# =============================================================================
# MSIX Offline Registry — offreg.dll wrapper
# -----------------------------------------------------------------------------
# Parses Registry.dat hive files (from inside an MSIX package) without
# requiring elevation. reg.exe load / RegLoadKey demand SeBackupPrivilege +
# SeRestorePrivilege (admins only); offreg.dll's OR* APIs parse the hive
# directly from disk and never mount it into the live registry, so any user
# can call them.
#
# offreg.dll ships in C:\Windows\System32 on Windows 10/11 by default.
#
# On Windows 10/11 (10.0.26100 confirmed) the named exports are:
#   ORCloseHive, ORCloseKey, ORCreateHive, ORCreateHiveEx, ORCreateKey,
#   ORDeleteKey, ORDeleteValue, OREnumKey, OREnumValue, ORFlushHive,
#   OROpenHiveByHandle, OROpenKey, ORQueryInfoKey(Ex|ValueEx),
#   ORRenameKey, ORSaveHive(Ex|ToHandle), ORSetKeySecurity, ORSetValue,
#   ORSetVirtualFlags
#
# There is intentionally no ORLoadHive / OROpenHive (those existed in older
# SDKs); callers must open the file themselves via CreateFile and pass the
# HANDLE to OROpenHiveByHandle. This module wraps that for you.
#
# Reference: https://learn.microsoft.com/windows/win32/devnotes/offline-registry-library
# =============================================================================

if (-not ([System.Management.Automation.PSTypeName]'MsixOffReg').Type) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

public static class MsixOffReg {
    // Win32 constants
    public const uint GENERIC_READ      = 0x80000000;
    public const uint GENERIC_WRITE     = 0x40000000;
    public const uint FILE_SHARE_READ   = 0x00000001;
    public const uint OPEN_EXISTING     = 3;

    // OR error codes (subset)
    public const int ERROR_SUCCESS        = 0;
    public const int ERROR_FILE_NOT_FOUND = 2;
    public const int ERROR_MORE_DATA      = 234;
    public const int ERROR_NO_MORE_ITEMS  = 259;

    // REG_* value types
    public const uint REG_NONE      = 0;
    public const uint REG_SZ        = 1;
    public const uint REG_EXPAND_SZ = 2;
    public const uint REG_BINARY    = 3;
    public const uint REG_DWORD     = 4;
    public const uint REG_MULTI_SZ  = 7;
    public const uint REG_QWORD     = 11;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName,
        uint   dwDesiredAccess,
        uint   dwShareMode,
        IntPtr lpSecurityAttributes,
        uint   dwCreationDisposition,
        uint   dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("offreg.dll", ExactSpelling = true, SetLastError = true)]
    public static extern int OROpenHiveByHandle(
        SafeFileHandle FileHandle,
        out IntPtr     phkResult);

    [DllImport("offreg.dll", ExactSpelling = true)]
    public static extern int ORCloseHive(IntPtr Handle);

    [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int OROpenKey(
        IntPtr     Handle,
        string     lpSubKey,
        out IntPtr phkResult);

    [DllImport("offreg.dll", ExactSpelling = true)]
    public static extern int ORCloseKey(IntPtr Handle);

    [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int OREnumKey(
        IntPtr        Handle,
        uint          dwIndex,
        StringBuilder lpName,
        ref uint      lpcName,
        IntPtr        lpClass,
        IntPtr        lpcClass,
        IntPtr        lpftLastWriteTime);

    [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int ORGetValue(
        IntPtr     Handle,
        string     lpSubKey,
        string     lpValue,
        out uint   pdwType,
        byte[]     pvData,
        ref uint   pcbData);

    [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int OREnumValue(
        IntPtr        Handle,
        uint          dwIndex,
        StringBuilder lpValueName,
        ref uint      lpcValueName,
        out uint      lpType,
        byte[]        lpData,
        ref uint      lpcbData);

    [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int ORDeleteKey(IntPtr Handle, string lpSubKey);

    [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int ORSaveHive(
        IntPtr Handle,
        string lpHivePath,
        uint   dwOsMajorVersion,
        uint   dwOsMinorVersion);

    // --- Hive / key creation (used by tests and Remove-MsixUninstallerArtifact)
    [DllImport("offreg.dll", ExactSpelling = true)]
    public static extern int ORCreateHive(out IntPtr phkResult);

    [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int ORCreateKey(
        IntPtr     Handle,
        string     lpSubKey,
        string     lpClass,
        uint       dwOptions,
        IntPtr     pSecurityDescriptor,
        out IntPtr phkResult,
        out uint   pdwDisposition);

    [DllImport("offreg.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    public static extern int ORSetValue(
        IntPtr   Handle,
        string   lpValueName,
        uint     dwType,
        byte[]   lpData,
        uint     cbData);
}
"@
}

function _MsixOpenOfflineHive {
    <#
    .SYNOPSIS
        Loads a registry hive file (Registry.dat from an MSIX, etc.) via
        offreg.dll and returns the hive root key handle.

    .DESCRIPTION
        Opens the file with CreateFile (GENERIC_READ, share-read, OPEN_EXISTING)
        and passes the HANDLE to OROpenHiveByHandle. Returns the hive root key
        as an [IntPtr]. Throws on failure.

        IMPORTANT: the caller MUST call _MsixCloseOfflineHive on the returned
        handle to release the in-memory hive — the easiest way is to use the
        _MsixWithOfflineHive scriptblock wrapper.

    .PARAMETER Path
        Absolute path to the hive file.

    .OUTPUTS
        [IntPtr] hive root key handle.
    #>
    [CmdletBinding()]
    [OutputType([IntPtr])]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Offline hive not found: $Path"
    }
    $fh = [MsixOffReg]::CreateFileW(
        $Path,
        [MsixOffReg]::GENERIC_READ,
        [MsixOffReg]::FILE_SHARE_READ,
        [IntPtr]::Zero,
        [MsixOffReg]::OPEN_EXISTING,
        0,
        [IntPtr]::Zero)
    if ($fh.IsInvalid) {
        $code = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "CreateFile failed for '$Path' (Win32 error $code)"
    }
    try {
        $hive = [IntPtr]::Zero
        $rc = [MsixOffReg]::OROpenHiveByHandle($fh, [ref]$hive)
        if ($rc -ne 0) {
            throw "OROpenHiveByHandle failed (error $rc) for '$Path'"
        }
        return $hive
    } finally {
        $fh.Close()
    }
}

function _MsixCloseOfflineHive {
    [CmdletBinding()]
    param([IntPtr]$Hive)
    if ($Hive -ne [IntPtr]::Zero) {
        $null = [MsixOffReg]::ORCloseHive($Hive)
    }
}

function _MsixOfflineOpenKey {
    <#
    .SYNOPSIS
        Opens a subkey under the given hive/key handle.
        Returns the new key handle, or [IntPtr]::Zero if the key does not exist.
        Caller is responsible for closing the returned handle via
        _MsixOfflineCloseKey.
    #>
    [CmdletBinding()]
    [OutputType([IntPtr])]
    param(
        [Parameter(Mandatory)][IntPtr]$Parent,
        [Parameter(Mandatory)][string]$SubKey
    )
    if ($Parent -eq [IntPtr]::Zero) { return [IntPtr]::Zero }
    $key = [IntPtr]::Zero
    $rc = [MsixOffReg]::OROpenKey($Parent, $SubKey, [ref]$key)
    if ($rc -ne 0) { return [IntPtr]::Zero }
    return $key
}

function _MsixOfflineCloseKey {
    [CmdletBinding()]
    param([IntPtr]$Key)
    if ($Key -ne [IntPtr]::Zero) {
        $null = [MsixOffReg]::ORCloseKey($Key)
    }
}

function _MsixOfflineEnumSubKeys {
    <#
    .SYNOPSIS
        Returns the names (string[]) of all subkeys under the given key handle.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)][IntPtr]$Key)

    if ($Key -eq [IntPtr]::Zero) { return [string[]]@() }
    $names = [System.Collections.Generic.List[string]]::new()
    $i = [uint32]0
    while ($true) {
        $sb = [System.Text.StringBuilder]::new(512)
        $cName = [uint32]512
        $rc = [MsixOffReg]::OREnumKey($Key, $i, $sb, [ref]$cName, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
        if ($rc -ne 0) { break }
        $names.Add($sb.ToString())
        $i++
    }
    return [string[]]$names.ToArray()
}

function _MsixOfflineGetValue {
    <#
    .SYNOPSIS
        Reads a named value from the given subkey (relative to the hive root or
        an open key handle). Pass an empty -Name to read the default value.
        Decodes REG_SZ / REG_EXPAND_SZ to [string], REG_DWORD to [int],
        REG_QWORD to [long], REG_MULTI_SZ to [string[]]; everything else
        returns raw [byte[]]. Returns $null if the value does not exist.

    .PARAMETER Parent
        Either the hive root handle (for -SubKey-relative lookups) or an open
        key handle (use -SubKey '' to read values directly on that key).

    .PARAMETER SubKey
        Subkey path relative to -Parent. Use '' to read on -Parent directly.

    .PARAMETER Name
        Value name. Use '' (default) to read the default (unnamed) value.
    #>
    [CmdletBinding()]
    [OutputType([string], [int], [long], [byte[]], [string[]])]
    param(
        [Parameter(Mandatory)][IntPtr]$Parent,
        [Parameter(Mandatory)][AllowEmptyString()][string]$SubKey,
        [AllowEmptyString()][string]$Name = ''
    )
    if ($Parent -eq [IntPtr]::Zero) { return $null }
    $type = [uint32]0
    $size = [uint32]0
    # ORGetValue signature requires a non-null subkey string; '' is acceptable.
    $rc = [MsixOffReg]::ORGetValue($Parent, $SubKey, $Name, [ref]$type, $null, [ref]$size)
    if ($rc -ne 0 -and $rc -ne 234) { return $null }
    if ($size -eq 0) {
        # Zero-length value: still emit appropriate empty result by type.
        switch ($type) {
            1 { return '' }
            2 { return '' }
            7 { return [string[]]@() }
            default { return $null }
        }
    }
    $buf = [byte[]]::new($size)
    $rc = [MsixOffReg]::ORGetValue($Parent, $SubKey, $Name, [ref]$type, $buf, [ref]$size)
    if ($rc -ne 0) { return $null }

    switch ($type) {
        1 {  # REG_SZ
            return [System.Text.Encoding]::Unicode.GetString($buf, 0, [int]$size).TrimEnd("`0")
        }
        2 {  # REG_EXPAND_SZ — return raw, callers can ExpandEnvironmentStrings if needed
            return [System.Text.Encoding]::Unicode.GetString($buf, 0, [int]$size).TrimEnd("`0")
        }
        4 {  # REG_DWORD
            if ($size -lt 4) { return $null }
            return [BitConverter]::ToInt32($buf, 0)
        }
        7 {  # REG_MULTI_SZ
            $s = [System.Text.Encoding]::Unicode.GetString($buf, 0, [int]$size)
            return [string[]]@($s -split "`0" | Where-Object { $_ })
        }
        11 { # REG_QWORD
            if ($size -lt 8) { return $null }
            return [BitConverter]::ToInt64($buf, 0)
        }
        default { return $buf }
    }
}

function _MsixOfflineDeleteKey {
    <#
    .SYNOPSIS
        Deletes a subkey under the given parent handle. Wraps ORDeleteKey,
        which per MSDN is NOT recursive: it returns an error if the subkey
        still has children. For uninstall-style entries that ship with
        component subkeys (e.g. Uninstall\Notepad++\Components), call
        _MsixOfflineDeleteKeyRecursive instead.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][IntPtr]$Parent,
        [Parameter(Mandatory)][string]$SubKey
    )
    if ($Parent -eq [IntPtr]::Zero) { return $false }
    $rc = [MsixOffReg]::ORDeleteKey($Parent, $SubKey)
    return ($rc -eq 0)
}

function _MsixOfflineDeleteKeyRecursive {
    <#
    .SYNOPSIS
        Deletes a subkey and ALL of its descendants under the given parent
        handle, working bottom-up because ORDeleteKey itself is NOT recursive.

    .DESCRIPTION
        Per MSDN "The subkey to be deleted must not have any subkeys" — so
        we open the target, enumerate children, recurse into each child,
        close the target, then issue ORDeleteKey on the now-empty subtree.

        Returns $true when the SubKey ends up deleted (or was already gone).
        Returns $false on any failure mid-walk so the caller knows the hive
        is now in a partial state and should not be persisted.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][IntPtr]$Parent,
        [Parameter(Mandatory)][string]$SubKey
    )
    if ($Parent -eq [IntPtr]::Zero) { return $false }

    # Open the target so we can walk it. If it doesn't exist treat as success
    # (idempotent — the caller asked us to delete something that's not there).
    $target = _MsixOfflineOpenKey -Parent $Parent -SubKey $SubKey
    if ($target -eq [IntPtr]::Zero) { return $true }

    try {
        $children = _MsixOfflineEnumSubKeys -Key $target
    } finally {
        _MsixOfflineCloseKey -Key $target
    }

    # Recurse into children first (depth-first), then delete the now-empty
    # parent. SubKey paths are joined with '\' which is the AppX/Reg convention.
    foreach ($child in $children) {
        if (-not (_MsixOfflineDeleteKeyRecursive -Parent $Parent -SubKey "$SubKey\$child")) {
            return $false
        }
    }
    return (_MsixOfflineDeleteKey -Parent $Parent -SubKey $SubKey)
}

function _MsixCreateOfflineHive {
    <#
    .SYNOPSIS
        Creates a new in-memory empty hive via ORCreateHive. Returns the hive
        root handle. Caller must release with _MsixCloseOfflineHive.
    #>
    [CmdletBinding()]
    [OutputType([IntPtr])]
    param()
    $hive = [IntPtr]::Zero
    $rc = [MsixOffReg]::ORCreateHive([ref]$hive)
    if ($rc -ne 0) { throw "ORCreateHive failed (error $rc)" }
    return $hive
}

function _MsixOfflineCreateKey {
    <#
    .SYNOPSIS
        Creates a subkey under the given parent. Returns the new key handle.
    #>
    [CmdletBinding()]
    [OutputType([IntPtr])]
    param(
        [Parameter(Mandatory)][IntPtr]$Parent,
        [Parameter(Mandatory)][string]$SubKey
    )
    $key = [IntPtr]::Zero
    $disp = [uint32]0
    $rc = [MsixOffReg]::ORCreateKey($Parent, $SubKey, $null, 0, [IntPtr]::Zero, [ref]$key, [ref]$disp)
    if ($rc -ne 0) { throw "ORCreateKey failed (error $rc) for '$SubKey'" }
    return $key
}

function _MsixOfflineSetValueString {
    <#
    .SYNOPSIS
        Sets a REG_SZ string value on the given key. Use -Type to set
        REG_EXPAND_SZ instead.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$Key,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Value,
        [ValidateSet('REG_SZ','REG_EXPAND_SZ')][string]$Type = 'REG_SZ'
    )
    # Encode as null-terminated UTF-16LE
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Value + "`0")
    $typeNum = if ($Type -eq 'REG_EXPAND_SZ') { [MsixOffReg]::REG_EXPAND_SZ } else { [MsixOffReg]::REG_SZ }
    $rc = [MsixOffReg]::ORSetValue($Key, $Name, $typeNum, $bytes, [uint32]$bytes.Length)
    if ($rc -ne 0) { throw "ORSetValue failed (error $rc) for '$Name'" }
}

function _MsixOfflineSetValueDword {
    <#
    .SYNOPSIS
        Sets a REG_DWORD value on the given key.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][IntPtr]$Key,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Name,
        [Parameter(Mandatory)][int]$Value
    )
    $bytes = [BitConverter]::GetBytes($Value)
    $rc = [MsixOffReg]::ORSetValue($Key, $Name, [MsixOffReg]::REG_DWORD, $bytes, [uint32]$bytes.Length)
    if ($rc -ne 0) { throw "ORSetValue (DWORD) failed (error $rc) for '$Name'" }
}

function _MsixOfflineSaveHive {
    <#
    .SYNOPSIS
        Persists an in-memory hive to disk via ORSaveHive. ORSaveHive will NOT
        overwrite an existing file — pass a new path and rename afterwards.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)][IntPtr]$Hive,
        [Parameter(Mandatory)][string]$Path,
        [uint32]$OsMajor = 6,
        [uint32]$OsMinor = 1
    )
    if ($Hive -eq [IntPtr]::Zero) { return $false }
    if (Test-Path -LiteralPath $Path) {
        throw "ORSaveHive will not overwrite an existing file: $Path"
    }
    $rc = [MsixOffReg]::ORSaveHive($Hive, $Path, $OsMajor, $OsMinor)
    return ($rc -eq 0)
}
