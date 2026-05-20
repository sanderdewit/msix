BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force

    # Build a synthetic hive entirely via the OR* APIs — guarantees the on-disk
    # format is one OROpenHiveByHandle understands (reg.exe save produces a
    # variant that fails with ERROR_BADDB on some Windows builds).
    $script:TestHive = Join-Path $env:TEMP "msix-offreg-test-$([guid]::NewGuid().ToString('N').Substring(0,8)).dat"

    & (Get-Module MSIX) {
        param($hivePath)
        $hive = _MsixCreateOfflineHive
        try {
            _MsixOfflineSetValueString -Key $hive -Name 'StringVal' -Value 'hello world'
            _MsixOfflineSetValueDword  -Key $hive -Name 'DwordVal'  -Value 42
            _MsixOfflineSetValueString -Key $hive -Name 'ExpandVal' -Value '%TEMP%\foo' -Type REG_EXPAND_SZ

            $child = _MsixOfflineCreateKey -Parent $hive -SubKey 'Child'
            try {
                _MsixOfflineSetValueString -Key $child -Name 'NestedVal' -Value 'nested'
            } finally {
                _MsixOfflineCloseKey -Key $child
            }

            if (Test-Path $hivePath) { Remove-Item -LiteralPath $hivePath -Force }
            if (-not (_MsixOfflineSaveHive -Hive $hive -Path $hivePath)) {
                throw 'ORSaveHive returned a non-success result.'
            }
        } finally {
            _MsixCloseOfflineHive -Hive $hive
        }
    } $script:TestHive

    if (-not (Test-Path $script:TestHive)) {
        throw "Test setup failed: synthetic hive not produced at '$script:TestHive'."
    }
}

AfterAll {
    if (Test-Path $script:TestHive) {
        Remove-Item -LiteralPath $script:TestHive -Force -ErrorAction SilentlyContinue
    }
    Remove-Module MSIX -ErrorAction SilentlyContinue
}

Describe 'Offline registry (offreg.dll) helpers' -Tag 'OfflineRegistry' {

    It 'offreg.dll is present in System32' {
        Test-Path 'C:\Windows\System32\offreg.dll' | Should -BeTrue
    }

    It 'Loads a hive without elevation and exposes a non-zero handle' {
        & (Get-Module MSIX) {
            param($p)
            $h = _MsixOpenOfflineHive -Path $p
            $h | Should -Not -Be ([IntPtr]::Zero)
            _MsixCloseOfflineHive -Hive $h
        } $script:TestHive
    }

    It 'Reads a REG_SZ value' {
        $result = & (Get-Module MSIX) {
            param($p)
            $h = _MsixOpenOfflineHive -Path $p
            try { _MsixOfflineGetValue -Parent $h -SubKey '' -Name 'StringVal' }
            finally { _MsixCloseOfflineHive -Hive $h }
        } $script:TestHive
        $result | Should -Be 'hello world'
    }

    It 'Reads a REG_DWORD value as [int]' {
        $result = & (Get-Module MSIX) {
            param($p)
            $h = _MsixOpenOfflineHive -Path $p
            try { _MsixOfflineGetValue -Parent $h -SubKey '' -Name 'DwordVal' }
            finally { _MsixCloseOfflineHive -Hive $h }
        } $script:TestHive
        $result | Should -Be 42
        $result | Should -BeOfType ([int])
    }

    It 'Reads a REG_EXPAND_SZ value (raw, not expanded)' {
        $result = & (Get-Module MSIX) {
            param($p)
            $h = _MsixOpenOfflineHive -Path $p
            try { _MsixOfflineGetValue -Parent $h -SubKey '' -Name 'ExpandVal' }
            finally { _MsixCloseOfflineHive -Hive $h }
        } $script:TestHive
        $result | Should -Be '%TEMP%\foo'
    }

    It 'Returns $null for a missing value' {
        $result = & (Get-Module MSIX) {
            param($p)
            $h = _MsixOpenOfflineHive -Path $p
            try { _MsixOfflineGetValue -Parent $h -SubKey '' -Name 'NoSuchValue' }
            finally { _MsixCloseOfflineHive -Hive $h }
        } $script:TestHive
        $result | Should -BeNullOrEmpty
    }

    It 'Enumerates subkeys' {
        $result = & (Get-Module MSIX) {
            param($p)
            $h = _MsixOpenOfflineHive -Path $p
            try { _MsixOfflineEnumSubKeys -Key $h }
            finally { _MsixCloseOfflineHive -Hive $h }
        } $script:TestHive
        $result | Should -Contain 'Child'
    }

    It 'Reads a value under a nested subkey' {
        $result = & (Get-Module MSIX) {
            param($p)
            $h = _MsixOpenOfflineHive -Path $p
            try { _MsixOfflineGetValue -Parent $h -SubKey 'Child' -Name 'NestedVal' }
            finally { _MsixCloseOfflineHive -Hive $h }
        } $script:TestHive
        $result | Should -Be 'nested'
    }

    It 'OROpenKey returns IntPtr::Zero for a non-existent subkey' {
        $result = & (Get-Module MSIX) {
            param($p)
            $h = _MsixOpenOfflineHive -Path $p
            try { _MsixOfflineOpenKey -Parent $h -SubKey 'NoSuchKey' }
            finally { _MsixCloseOfflineHive -Hive $h }
        } $script:TestHive
        $result | Should -Be ([IntPtr]::Zero)
    }

    It 'Throws when the hive file does not exist' {
        & (Get-Module MSIX) {
            { _MsixOpenOfflineHive -Path 'C:\does\not\exist\fake.dat' } |
                Should -Throw -ExceptionType ([System.Management.Automation.RuntimeException])
        }
    }
}
