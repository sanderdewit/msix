# Know your installer

Pre-flight checklist before converting a Win32 installer into an MSIX. Adapted
from [the MS Learn doc](https://learn.microsoft.com/windows/msix/packaging-tool/know-your-installer).

## Hard blockers

| Trait                              | Reason                                                |
|------------------------------------|-------------------------------------------------------|
| Installs a kernel driver           | MSIX cannot host drivers.                             |
| Requires kernel callbacks/hooks    | Same.                                                 |
| Installs Windows-side-by-side DLLs | WinSxS isn't visible inside the container.            |

## Needs PSF or manifest tweaks

| Trait                                        | Tool                                                |
|----------------------------------------------|-----------------------------------------------------|
| Uses CWD-relative file lookups               | PSF working directory                              |
| Writes log/config files next to the .exe     | FileRedirectionFixup                               |
| Writes to HKLM\SOFTWARE\…                    | RegLegacyFixups                                    |
| Needs a CLI argument from a Start-menu shortcut | PSF applications.arguments                      |
| Drops legacy IContextMenu shell ext          | desktop9 + com namespace (Win11 21H2+)             |

## Requires extra MPT / package settings

| Trait                                    | Notes                                                  |
|------------------------------------------|--------------------------------------------------------|
| Installer reboots                        | Supported since MPT 1.2019.701.0; configure restart codes. |
| Installer needs unattended switches      | Capture them now: `/silent /norestart /qn /verysilent`. |
| Includes a Windows service               | Supported since MPT 1.2019.1220.0; admin required to install. |
| Targets .NET Framework < 4.6.2           | Test on the lowest supported Windows build.            |
| Has a per-machine vs per-user mode       | MSIX is always per-user; package the per-user mode.    |

## Common silent-install switches

```text
.exe based on InstallShield   /S /v"/qn" /silent /norestart
.exe based on Inno Setup      /VERYSILENT /SUPPRESSMSGBOXES /SP- /NORESTART
.exe based on NSIS            /S
.exe based on Wix Burn        /quiet /norestart
.msi                          /qn /norestart
.msi (admin install)          /a TARGETDIR="..." /qn
.appx / .msix                 N/A — Add-AppPackage
```

If the installer doesn't accept any of the above, run it through MPT's
installer detection wizard — MPT will record the right command line in the
generated `accelerator.xml`.

## Pre-conversion checklist

- [ ] You have admin rights on a clean VM / Windows Sandbox.
- [ ] You captured the silent-install command line on a clean baseline.
- [ ] The installer doesn't bundle a driver or kernel component.
- [ ] You know the publisher CN to use (must match the signing cert Subject).
- [ ] You have a valid code-signing certificate (or are using Trusted Signing
      / Azure Key Vault — see todo).
- [ ] You verified MaxVersionTested matches your minimum target (default
      10.0.17763.0; 21H2 for legacy ContextMenu; 24H2 for App Isolation).

## After conversion

- Run `Invoke-MsixInvestigation -PackagePath app.msix` to surface anything
  the static analyser catches.
- Run `Test-MsixAgainstLimitations -PackagePath app.msix` to print the
  documented limitations that apply given the manifest content.
- Inside Windows Sandbox, run `Start-MsixDebugSession -PackagePath app.msix
  -Install -LaunchProcMon -LaunchDebugView` for a full diagnostic stage.
