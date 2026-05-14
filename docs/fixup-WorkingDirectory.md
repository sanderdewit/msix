# Working Directory + Arguments + Start Scripts

These three "fixups" aren't separate DLLs — they're per-application options
in the PSF `config.json` that `PsfLauncher` honours when starting the target.

**References:**
- [Working Directory](https://learn.microsoft.com/windows/msix/psf/psf-current-working-directory)
- [Launching apps with parameters](https://learn.microsoft.com/windows/msix/psf/psf-launch-apps-with-parameters)
- [Run scripts to create a shortcut](https://learn.microsoft.com/windows/msix/psf/create-shortcut-with-script-package-support-framework)

## Working directory

Without PSF, packaged apps launch with `CWD = C:\Windows\System32`. Apps that
load companion files via relative paths break.

```powershell
Add-MsixPsfV2 -PackagePath app.msix `
    -Fixups @() `
    -WorkingDirectory 'VFS/ProgramFilesX64/Contoso/' `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

The `-WorkingDirectory` is applied to every Application in the package. For
per-app working directories, use `New-MsixPsfArguments` instead (next section).

## Arguments + per-app workingDirectory

```powershell
$opts = @(
    New-MsixPsfArguments -AppId 'App'      -Arguments '/silent' -WorkingDirectory 'VFS/ProgramFilesX64/App/'
    New-MsixPsfArguments -AppId 'AppAdmin' -Arguments '/admin'  -WorkingDirectory 'VFS/ProgramFilesX64/App/'
)
Add-MsixPsfV2 -PackagePath app.msix -Fixups @() -AppOptions $opts `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

Generated `applications[]`:

```json
{ "id": "App",      "executable": "VFS/.../App.exe", "arguments": "/silent", "workingDirectory": "VFS/ProgramFilesX64/App/" }
{ "id": "AppAdmin", "executable": "VFS/.../App.exe", "arguments": "/admin",  "workingDirectory": "VFS/ProgramFilesX64/App/" }
```

## Start / End scripts

`PsfLauncher` can run a PowerShell script before (or after) the target. Use it
for:

- Creating Start menu / desktop shortcuts on first launch.
- Copying icons to `%LocalAppData%` so they survive package updates.
- Pre-populating per-user state.

Required PSF artefact: `StartingScriptWrapper.ps1` — copied automatically when
your `-AppOptions` contains a startScript/endScript.

```powershell
$start = New-MsixPsfStartScriptConfig -AppId 'App' `
    -ScriptPath 'createshortcut.ps1' `
    -RunOnce -WaitForScriptToFinish

Add-MsixPsfV2 -PackagePath app.msix `
    -Fixups          @() `
    -AppOptions      @($start) `
    -AdditionalFiles 'C:\src\createshortcut.ps1', 'C:\src\Contoso.lnk', 'C:\src\contoso.ico' `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

Switches:

| Switch                  | Effect                                                          |
|-------------------------|------------------------------------------------------------------|
| `-RunOnce`              | Marker file in `%LocalAppData%` ensures script runs only once.   |
| `-WaitForScriptToFinish`| App launch blocks until the script exits.                        |
| `-RunInVirtualEnvironment` | Run inside the package container (vs. on the host).          |
| `-StopOnScriptError`    | Abort app launch on non-zero exit.                              |
| `-ShowWindow`           | Show the PowerShell host window.                                 |
| `-Timeout`              | Seconds before giving up.                                        |
| `-EndScript`            | Returned as `endScript` instead of `startScript`.               |

## Notes

- `applications[].arguments` is the only way to bake CLI args into a Start menu
  shortcut for an MSIX app — the shortcut itself can't carry them.
- Sign your bundled scripts (`Set-AuthenticodeSignature`) before adding them
  via `-AdditionalFiles` if your environment enforces script signing.
