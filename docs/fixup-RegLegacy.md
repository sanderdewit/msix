# RegLegacyFixups

Modifies how packaged code interacts with the registry, primarily to relax
access masks on keys the OS would otherwise mark write-only-via-redirect.

**Reference:** [PSF integration with MPT](https://learn.microsoft.com/windows/msix/psf/psf-integration-with-mpt)

## When to use

- App opens an HKLM key with `KEY_ALL_ACCESS` and crashes/exits immediately.
- App enumerates keys under `HKEY_LOCAL_MACHINE\SOFTWARE\Vendor\…` and fails
  because the redirect doesn't surface those keys.
- App requires `RegOpenKey` to succeed even when the redirected hive is empty.

## Supported types

`type: ModifyKeyAccess` (currently the only type wrapped by this module)

| Access option       | Effect                                                  |
|---------------------|----------------------------------------------------------|
| `Full2RW`           | `KEY_ALL_ACCESS` → `KEY_READ \| KEY_WRITE`               |
| `Full2R`            | `KEY_ALL_ACCESS` → `KEY_READ`                            |
| `Full2MaxAllowed`   | `KEY_ALL_ACCESS` → `MAXIMUM_ALLOWED`                     |
| `RW2R`              | RW masks → READ                                          |
| `RW2MaxAllowed`     | RW masks → `MAXIMUM_ALLOWED`                             |

## Example

```powershell
$reg = New-MsixPsfRegLegacyConfig `
    -Hive HKLM `
    -Access Full2MaxAllowed `
    -Patterns 'SOFTWARE\Contoso\*', 'SOFTWARE\WOW6432Node\Contoso\*'

Add-MsixPsfV2 -PackagePath app.msix -Fixups @($reg) `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

Generated:

```json
{
  "dll": "RegLegacyFixups.dll",
  "config": {
    "type": "ModifyKeyAccess",
    "remediation": [
      {
        "hive": "HKLM",
        "access": "Full2MaxAllowed",
        "patterns": ["SOFTWARE\\Contoso\\*", "SOFTWARE\\WOW6432Node\\Contoso\\*"]
      }
    ]
  }
}
```

## Notes / TODO

- TMurgent's fork supports additional types (`FakeDelete`, `DeletionMarker`,
  `Redirect`) — not yet wrapped; you can hand-construct the hashtable if needed.
- HKLM writes are still redirected to the per-package private hive even with
  this fixup. For genuine per-machine state, ship a separate config script.
