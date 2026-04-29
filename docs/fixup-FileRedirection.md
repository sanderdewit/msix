# FileRedirectionFixup

Redirects file I/O that would otherwise fail because the target lives inside
the read-only package install location (`C:\Program Files\WindowsApps\…`).

**Reference:** [PSF — Filesystem Write Permission](https://learn.microsoft.com/windows/msix/psf/psf-filesystem-writepermission)

## When to use

- App tries to write log/config/cache files next to its `.exe`.
- App expects `%InstallDir%\data\…` to be writable.
- ProcMon shows `ACCESS DENIED` with `Desired Access: Generic Write` under
  `C:\Program Files\WindowsApps\…`.

## Three modes

| Mode                  | What it does                                                                 |
|-----------------------|-------------------------------------------------------------------------------|
| `packageRelative`     | Redirects writes to a path INSIDE the package back to per-user storage.       |
| `packageDriveRelative`| Redirects writes to a drive-rooted path (`C:\App\logs`).                      |
| `knownFolderRelative` | Redirects writes inside a known folder (Documents, AppData, …).               |

## Examples

### Per-package: redirect log files

```powershell
$frf = New-MsixPsfFileRedirectionConfig `
    -Base 'VFS/ProgramFilesX64/Contoso/' `
    -Patterns '.*\.log', '.*\.tmp', '.*\.cache'

Add-MsixPsfV2 -PackagePath app.msix -Fixups @($frf) `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

Generated `config.json` snippet:

```json
{
  "dll": "FileRedirectionFixup.dll",
  "config": {
    "redirectedPaths": {
      "packageRelative": [
        { "base": "VFS/ProgramFilesX64/Contoso/", "patterns": [".*\\.log", ".*\\.tmp", ".*\\.cache"] }
      ]
    }
  }
}
```

### Multiple bases

Supply multiple fixup hashtables (or extend the helper output):

```powershell
$logs = New-MsixPsfFileRedirectionConfig -Base 'logs/'   -Patterns '.*\.log'
$ini  = New-MsixPsfFileRedirectionConfig -Base 'config/' -Patterns '.*\.ini'
Add-MsixPsfV2 -PackagePath app.msix -Fixups @($logs, $ini) -Pfx ... -PfxPassword ...
```

### Known-folder redirect

```powershell
$kf = New-MsixPsfFileRedirectionConfig -PathType knownFolderRelative `
    -Base 'Documents' -Patterns '.*\.csv'
```

## Notes

- Redirected files actually land in
  `%LocalAppData%\Packages\<PFN>\LocalCache\Roaming\…` — readable from outside
  the container, useful when admins want to retrieve user data.
- TMurgent's fork ships **MFRFixup.dll** as a drop-in replacement with broader
  pattern support; once you have v0.7+ PSF binaries you can switch the
  `dll` field to `MFRFixup.dll` and use the same config shape.
