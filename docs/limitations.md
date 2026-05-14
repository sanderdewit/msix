# What MSIX cannot do

Comprehensive, current limitations sourced from Microsoft documentation. The
module exposes this same data programmatically via `Get-MsixLimitations`
(filterable by id, severity, or whether the source is purely Microsoft).

| Severity | Limitation                                                    | Workaround                                  |
|----------|---------------------------------------------------------------|---------------------------------------------|
| blocker  | Drivers are not supported                                     | Ship driver as separate signed installer    |
| medium   | Install dir is read-only at runtime                           | FileRedirectionFixup (PSF)                  |
| medium   | CWD defaults to `System32`                                    | `-WorkingDirectory` in PSF config           |
| medium   | HKLM writes go to a private hive                              | RegLegacyFixups, or external config script  |
| medium   | AppData is private per package                                | Use Documents/ProgramData for shared state  |
| medium   | In-process shell extensions blocked                           | desktop9 (Win11) or desktop4 IExplorerCommand|
| medium   | WinSxS shared assemblies cannot load                          | Statically link or ship the DLLs            |
| medium   | Shortcuts can't carry CLI arguments                           | PSF `applications[].arguments`              |
| medium   | External processes may not see in-package COM servers         | Tune `windows.comServer` extension          |
| low      | Packages with services need admin to install                  | Deploy via Intune/SCCM with admin context   |
| low      | Multiple packages can't own the same file extension           | Plan the FTA owner explicitly               |
| low      | .NET Framework < 4.6.2 needs extra validation                 | Retarget to 4.6.2+                          |
| low      | Cross-package service dependencies are not allowed            | Bundle services together                    |
| low      | Custom URL/protocol handlers scoped to package                | Test from non-packaged callers              |
| low      | Manifest Publisher must match cert Subject exactly            | `Update-MsixSigner -Publisher …`            |

## Sources

| Source         | Reliability                                                  |
|----------------|--------------------------------------------------------------|
| `msft-docs`    | Documented behaviour on Microsoft Learn.                     |
| `mixed`        | MS-documented but rephrased / contextualised by community.   |
| `vendor`       | Vendor-specific opinion (filter out with `-ExcludeVendor`).  |

```powershell
# Vendor opinions excluded
Get-MsixLimitations -ExcludeVendor | Format-Table Id, Severity, Title

# Just blockers
Get-MsixLimitations -Severity blocker

# What applies to a specific package
Test-MsixAgainstLimitations -PackagePath app.msix
```

## Things that work, despite the noise

If you've read a vendor article claiming MSIX is incompatible with X, check
whether X is in the table above before assuming. The following commonly-cited
"limitations" are actually solvable in MSIX today:

- **Custom CLI arguments in shortcuts** — PSF arguments field.
- **Working-directory issues** — PSF working directory.
- **Writes to the install folder** — FileRedirectionFixup.
- **Legacy IContextMenu shell extensions** — desktop9 namespace (Win11 21H2+).
- **First-launch icon copying / shortcut creation** — PSF startScript.

The combination of PSF + the manifest extensions (`uap`, `desktop`, `desktop4`,
`desktop9`, `com`, `rescap`) covers the majority of real-world apps. MSIX
limitations are real but smaller than vendor marketing implies.
