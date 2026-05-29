BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Regression coverage for #60 — scanner findings must not let package-derived
# values inject into the single-quoted command snippets they emit, and the VFS
# path mapper must not resolve traversal paths outside the workspace.

Describe '_MsixEscapeSingleQuote (#60)' -Tag 'Security' {

    It 'doubles embedded single quotes' {
        InModuleScope MSIX { _MsixEscapeSingleQuote "a'b" } | Should -Be "a''b"
    }

    It 'neutralises a break-out payload' {
        InModuleScope MSIX { _MsixEscapeSingleQuote "x'); Start-Process calc #" } |
            Should -Be "x''); Start-Process calc #"
    }

    It 'leaves quote-free values unchanged' {
        InModuleScope MSIX { _MsixEscapeSingleQuote 'VFS\ProgramFilesX64\app.dll' } |
            Should -Be 'VFS\ProgramFilesX64\app.dll'
    }
}

Describe '_MsixRegPathToVfsRelative rejects traversal (#60)' -Tag 'Security' {

    It 'returns $null for a path that escapes the workspace' {
        $r = InModuleScope MSIX -Parameters @{ Ws = $TestDrive } {
            param($Ws)
            _MsixRegPathToVfsRelative -RegPath '[{ProgramFilesX64}]\..\..\..\Windows\System32\evil.dll' -WorkspacePath $Ws
        }
        $r | Should -BeNullOrEmpty
    }

    It 'maps a normal folder-variable path to its VFS-relative form' {
        $r = InModuleScope MSIX -Parameters @{ Ws = $TestDrive } {
            param($Ws)
            _MsixRegPathToVfsRelative -RegPath '[{ProgramFilesX64}]\App\foo.dll' -WorkspacePath $Ws
        }
        $r | Should -Be 'VFS\ProgramFilesX64\App\foo.dll'
    }
}
