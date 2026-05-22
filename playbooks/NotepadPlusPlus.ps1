# Reference playbook — Notepad++ with NppShell sparse shell extension.
# Drives a deterministic one-shot fix sequence for Notepad++ MSIX packages
# that ship NppShell as an inner sparse package.
#
# Returned hashtable is consumed by the playbook bus
# (Get-MsixPlaybook / Find-MsixPlaybook / Invoke-MsixPlaybook).

@{
    Name        = 'Notepad++'
    Description = 'Merge NppShell sparse package, declare modern context menu, carve-out plugin/themes/userDefineLangs, strip uninstaller artefacts.'

    Match = @{
        IdentityName     = '^Notepad(\+\+)?$'
        ExecutableLeaf   = '^notepad\+\+\.exe$'
        PublisherSubject = 'Notepad\+\+ Team'
    }

    Steps = @(
        @{ Cmdlet = 'Import-MsixSparseShellExtension'
           Args   = @{
               SparsePackagePath = 'VFS\ProgramFilesX64\Notepad++\contextMenu\NppShell.msix'
           }
        }

        @{ Cmdlet = 'Set-MsixFileSystemWriteVirtualization'
           Args   = @{
               # Carve-outs so plugin/theme/language extensibility survives
               # under MSIX containerisation (writes pass through to the real
               # filesystem instead of vanishing into a per-user shadow).
               ExcludedDirectories = @(
                   '$(KnownFolder:LocalAppData)'
                   '$(KnownFolder:RoamingAppData)'
                   'VFS/ProgramFilesX64/Notepad++/plugins'
                   'VFS/ProgramFilesX64/Notepad++/themes'
                   'VFS/ProgramFilesX64/Notepad++/userDefineLangs'
                   'VFS/ProgramFilesX64/Notepad++/localization'
               )
           }
        }

        @{ Cmdlet = 'Remove-MsixUpdaterArtifact';    Args = @{} }
        @{ Cmdlet = 'Remove-MsixUninstallerArtifact'; Args = @{} }
    )
}
