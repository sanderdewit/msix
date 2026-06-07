BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    # Build a synthetic hive entirely via the OR* APIs — guarantees the on-disk
    # format is one OROpenHiveByHandle understands (reg.exe save produces a
    # variant that fails with ERROR_BADDB on some Windows builds).
    $script:TestHive = Join-Path -Path $env:TEMP -ChildPath "msix-offreg-test-$([guid]::NewGuid().ToString('N').Substring(0,8)).dat"

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

            if (Test-Path -LiteralPath $hivePath) { Remove-Item -LiteralPath $hivePath -Force }
            if (-not (_MsixOfflineSaveHive -Hive $hive -Path $hivePath)) {
                throw 'ORSaveHive returned a non-success result.'
            }
        } finally {
            _MsixCloseOfflineHive -Hive $hive
        }
    } $script:TestHive

    if (-not (Test-Path -LiteralPath $script:TestHive)) {
        throw "Test setup failed: synthetic hive not produced at '$script:TestHive'."
    }
}

AfterAll {
    if (Test-Path -LiteralPath $script:TestHive) {
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

    It 'Enumerates value names on a key (#56)' {
        $result = & (Get-Module MSIX) {
            param($p)
            $h = _MsixOpenOfflineHive -Path $p
            try { _MsixOfflineEnumValueNames -Key $h }
            finally { _MsixCloseOfflineHive -Hive $h }
        } $script:TestHive
        $result | Should -Contain 'StringVal'
        $result | Should -Contain 'DwordVal'
        $result | Should -Contain 'ExpandVal'
    }

    It '_MsixWithOfflineHive runs the block and releases the hive (#59)' {
        $result = & (Get-Module MSIX) {
            param($p)
            _MsixWithOfflineHive -Path $p -ScriptBlock {
                param($hive)
                _MsixOfflineGetValue -Parent $hive -SubKey '' -Name 'StringVal'
            }
        } $script:TestHive
        $result | Should -Be 'hello world'
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


Describe 'Recursive offline-hive deletion (_MsixOfflineDeleteKeyRecursive)' -Tag 'OfflineRegistry' {

    It '_MsixOfflineDeleteKeyRecursive is defined inside the module' {
        # The helper is module-internal so Get-Command -Module won't surface
        # it from the outside; invoke via the module's session state.
        & (Get-Module MSIX) {
            Get-Command -Name '_MsixOfflineDeleteKeyRecursive' -ErrorAction SilentlyContinue
        } | Should -Not -BeNullOrEmpty
    }

    It 'Deletes a subtree with children — the case where bare ORDeleteKey fails' {
        $hivePath = Join-Path -Path $env:TEMP -ChildPath "msix-recdel-$([guid]::NewGuid().ToString('N').Substring(0,8)).dat"
        try {
            & (Get-Module MSIX) {
                # ($hivePath isn't needed inside — the test asserts in-memory
                # state via _MsixOfflineOpenKey rather than persisting & re-loading.)
                $h = _MsixCreateOfflineHive
                try {
                    # Build Uninstall\App\Components\Foo and ...\Bar.
                    $a = _MsixOfflineCreateKey -Parent $h -SubKey 'Uninstall'
                    try {
                        $b = _MsixOfflineCreateKey -Parent $a -SubKey 'App'
                        try {
                            _MsixOfflineSetValueString -Key $b -Name 'DisplayName' -Value 'TheApp'
                            $c = _MsixOfflineCreateKey -Parent $b -SubKey 'Components'
                            try {
                                $d = _MsixOfflineCreateKey -Parent $c -SubKey 'Foo'
                                _MsixOfflineCloseKey -Key $d
                                $e = _MsixOfflineCreateKey -Parent $c -SubKey 'Bar'
                                _MsixOfflineCloseKey -Key $e
                            } finally { _MsixOfflineCloseKey -Key $c }
                        } finally { _MsixOfflineCloseKey -Key $b }
                    } finally { _MsixOfflineCloseKey -Key $a }

                    # Non-recursive should FAIL (key has children).
                    $bareOk = _MsixOfflineDeleteKey -Parent $h -SubKey 'Uninstall\App'
                    if ($bareOk) { throw "Setup invalid: bare ORDeleteKey unexpectedly succeeded on a key with children." }

                    # Recursive should SUCCEED and the key should be gone.
                    $recOk = _MsixOfflineDeleteKeyRecursive -Parent $h -SubKey 'Uninstall\App'
                    if (-not $recOk) { throw "_MsixOfflineDeleteKeyRecursive returned false." }
                    $stillThere = _MsixOfflineOpenKey -Parent $h -SubKey 'Uninstall\App'
                    if ($stillThere -ne [IntPtr]::Zero) {
                        _MsixOfflineCloseKey -Key $stillThere
                        throw 'Uninstall\App still exists after recursive delete.'
                    }
                } finally {
                    _MsixCloseOfflineHive -Hive $h
                }
            }
        } finally {
            if (Test-Path -LiteralPath $hivePath) { Remove-Item -LiteralPath $hivePath -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'Returns $true (no-op) when deleting a subkey that does not exist' {
        $hivePath = Join-Path -Path $env:TEMP -ChildPath "msix-noexist-$([guid]::NewGuid().ToString('N').Substring(0,8)).dat"
        try {
            $result = & (Get-Module MSIX) {
                $h = _MsixCreateOfflineHive
                try {
                    return (_MsixOfflineDeleteKeyRecursive -Parent $h -SubKey 'Does\Not\Exist')
                } finally {
                    _MsixCloseOfflineHive -Hive $h
                }
            }
            $result | Should -BeTrue
        } finally {
            if (Test-Path -LiteralPath $hivePath) { Remove-Item -LiteralPath $hivePath -Force -ErrorAction SilentlyContinue }
        }
    }

    It 'Remove-MsixUninstallerArtifact source calls the recursive helper' {
        # Issue #38: function moved from MSIX.Heuristics.ps1 to MSIX.PackageMutators.ps1.
        $src = Get-Content -LiteralPath (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.PackageMutators.ps1')) -Raw
        $idx = $src.IndexOf('function Remove-MsixUninstallerArtifact')
        $nextIdx = $src.IndexOf("`nfunction ", $idx + 1)
        if ($nextIdx -lt 0) { $nextIdx = $src.Length }
        $body = $src.Substring($idx, $nextIdx - $idx)
        $body | Should -Match '_MsixOfflineDeleteKeyRecursive'
    }
}
