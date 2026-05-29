BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Regression coverage for #59 — an offline registry hive (Registry.dat from an
# untrusted package) must be validated as a plausible 'regf' hive before it is
# handed to native offreg.dll for parsing.

Describe '_MsixAssertValidHiveFile (#59)' -Tag 'Security' {

    It 'rejects a file without the regf signature' {
        $p = Join-Path -Path $TestDrive -ChildPath 'bad.dat'
        [System.IO.File]::WriteAllBytes($p, [byte[]](1..16))
        { InModuleScope MSIX -Parameters @{ P = $p } { param($P) _MsixAssertValidHiveFile -Path $P } } |
            Should -Throw -ExpectedMessage '*regf*'
    }

    It 'rejects a truncated (sub-4-byte) file' {
        $p = Join-Path -Path $TestDrive -ChildPath 'tiny.dat'
        [System.IO.File]::WriteAllBytes($p, [byte[]](1, 2))
        { InModuleScope MSIX -Parameters @{ P = $p } { param($P) _MsixAssertValidHiveFile -Path $P } } |
            Should -Throw -ExpectedMessage '*too small*'
    }

    It 'accepts a file beginning with the regf signature' {
        $p = Join-Path -Path $TestDrive -ChildPath 'good.dat'
        $bytes = [byte[]]::new(64)
        $bytes[0] = 0x72; $bytes[1] = 0x65; $bytes[2] = 0x67; $bytes[3] = 0x66   # 'regf'
        [System.IO.File]::WriteAllBytes($p, $bytes)
        { InModuleScope MSIX -Parameters @{ P = $p } { param($P) _MsixAssertValidHiveFile -Path $P } } |
            Should -Not -Throw
    }
}
