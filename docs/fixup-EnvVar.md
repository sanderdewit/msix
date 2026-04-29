# EnvVarFixup

Sets process environment variables for the packaged app at launch time, without
needing a wrapper script.

## When to use

- App reads `%MY_APP_HOME%` or `%MY_APP_MODE%` and you want a stable value.
- You're packaging a CLI tool that expects PATH-style additions but the legacy
  installer used to write them into `HKLM\Environment` (which is now sandboxed).
- You need different behaviour per packaged build (test/staging/prod).

## Example

```powershell
$env = New-MsixPsfEnvVarConfig -Variables @{
    APP_MODE     = 'packaged'
    APP_HOME     = 'C:\\Program Files\\WindowsApps\\Contoso.App\\app'
    LANG_DEFAULT = 'en-US'
}

Add-MsixPsfV2 -PackagePath app.msix -Fixups @($env) `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

Generated:

```json
{
  "dll": "EnvVarFixup.dll",
  "config": {
    "envVars": {
      "APP_MODE": "packaged",
      "APP_HOME": "C:\\Program Files\\WindowsApps\\Contoso.App\\app",
      "LANG_DEFAULT": "en-US"
    }
  }
}
```

## Notes

- Variables set this way are visible only to processes inside the package
  container. Other processes on the host see whatever the OS provides.
- If you want PATH manipulation, prepend rather than overwrite — the host's
  PATH is still merged in for child processes.
