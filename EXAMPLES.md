# MSIX Module — Copy-Paste Examples

End-to-end recipes for the common tasks. Every snippet is self-contained:
load the module, set inputs, run. Comments explain the *why* alongside the
*what*.

```powershell
Import-Module C:\temp\msix\MSIX\MSIX.psd1
```

---

## Table of contents

1. [Inspect a package without unpacking](#1-inspect-a-package-without-unpacking)
2. [Update the Publisher and re-sign](#2-update-the-publisher-and-re-sign)
3. [Inject a PSF FileRedirection fixup](#3-inject-a-psf-fileredirection-fixup)
4. [Add a legacy IContextMenu shell extension (desktop9)](#4-add-a-legacy-icontextmenu-shell-extension-desktop9)
5. [Add a modern IExplorerCommand context menu (desktop4)](#5-add-a-modern-iexplorercommand-context-menu-desktop4)
6. [Add an AppExecutionAlias](#6-add-an-appexecutionalias)
7. [Enable / configure FileSystem write virtualization](#7-enable--configure-filesystem-write-virtualization)
8. [Fix Notepad++ plugins that want to write to Program Files](#8-fix-notepad-plugins-that-want-to-write-to-program-files)
9. [Add a Windows Firewall rule that lives with the package](#9-add-a-windows-firewall-rule-that-lives-with-the-package)
10. [Bundle a Visual C++ runtime](#10-bundle-a-visual-c-runtime)
11. [Static analysis + auto-fix in one pass](#11-static-analysis--auto-fix-in-one-pass)
12. [Sign with Azure Trusted Signing (production)](#12-sign-with-azure-trusted-signing-production)
13. [Sign with Azure Key Vault via AzureSignTool](#13-sign-with-azure-key-vault-via-azuresigntool)
14. [Self-signed dev cert and Windows Sandbox debug session](#14-self-signed-dev-cert-and-windows-sandbox-debug-session)
15. [Compare two packages](#15-compare-two-packages)
16. [App Attach VHDX for multi-session hosts](#16-app-attach-vhdx-for-multi-session-hosts)
17. [Full pipeline: publisher + PSF + signing in one call](#17-full-pipeline-publisher--psf--signing-in-one-call)

---

## 1. Inspect a package without unpacking

`Get-MsixManifest` extracts AppxManifest.xml directly from the archive — no
MakeAppx required.

```powershell
$m = Get-MsixManifest -Path 'C:\drop\App.msix'

$m.Package.Identity.Name      # 'Contoso.App'
$m.Package.Identity.Publisher # 'CN=Contoso, O=Contoso, C=NL'
$m.Package.Identity.Version   # '1.2.3.4'

# Iterate all Application elements
$doc = New-MsixManifestDocument -Document $m
Get-MsixManifestApplication -Manifest $doc -All |
    ForEach-Object { "$($_.GetAttribute('Id')) -> $($_.GetAttribute('Executable'))" }
```

---

## 2. Update the Publisher and re-sign

Use when the original signing identity is gone and you need to re-publisher
the package to match a new cert.

```powershell
$pw = Read-Host -AsSecureString 'New cert PFX password'
Update-MsixSigner `
    -PackagePath 'C:\drop\App.msix' `
    -Publisher   'CN=New Owner, O=NewCo, C=NL' `
    -Pfx 'C:\certs\newco.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-reowned.msix'
```

The cmdlet asserts the cert Subject matches the new Publisher before signing
(prevents "publisher mismatch" install failures).

---

## 3. Inject a PSF FileRedirection fixup

Use when the app writes to `C:\Program Files\<App>\` (or another VFS path)
and MSIX virtualization alone isn't enough. PSF intercepts the Win32 file
APIs and redirects.

```powershell
$logRedirect = New-MsixPsfFileRedirectionConfig `
    -Base 'logs' -Patterns '.*\.log$'

$pw = Read-Host -AsSecureString
Add-MsixPsfV2 `
    -PackagePath 'C:\drop\App.msix' `
    -Fixups @($logRedirect) `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-psf.msix'
```

`New-MsixPsfFileRedirectionConfig` produces the right JSON shape for the
TMurgent PSF fork. For multiple fixups, build them separately and pass an
array to `-Fixups`.

---

## 4. Add a legacy IContextMenu shell extension (desktop9)

Classic shell extension DLLs (the kind that fail to load if Explorer can't
find the DLL via registry). MSIX hosts them in a surrogate process.

```powershell
$pw = Read-Host -AsSecureString
Add-MsixLegacyContextMenu `
    -PackagePath 'C:\drop\App.msix' `
    -ShellExtDll 'VFS\ProgramFilesX64\App\ShellExt.dll' `
    -Clsid       '12345678-1234-1234-1234-1234567890ab' `
    -DisplayName 'My Tools' `
    -FileTypes   '*','.log','Directory' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-ctxmenu.msix'
```

Notes:

- Requires Windows 11 21H2 (build 22000). `MaxVersionTested` is auto-bumped.
- CLSID can be passed with or without curly braces — the cmdlet normalises.
- `-FileTypes '*'` registers the handler for all files; `.log` is type-specific;
  `Directory` matches folders; `Drive` matches drive roots.
- `runFullTrust` is auto-injected (required for COM surrogate).

---

## 5. Add a modern IExplorerCommand context menu (desktop4)

The modern, recommended pattern for new shell extensions.

```powershell
$pw = Read-Host -AsSecureString
Add-MsixFileExplorerContextMenu `
    -PackagePath 'C:\drop\App.msix' `
    -AppId       'App' `
    -VerbId      'open-with-app' `
    -VerbClsid   '11111111-2222-3333-4444-555555555555' `
    -FileTypes   '.log','.txt' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-modern-ctx.msix'
```

Requires Windows 10 1803 (build 17134). Auto-bumped.

---

## 6. Add an AppExecutionAlias

Lets users invoke the packaged app by short name from cmd or pwsh
(`mytool.exe` → packaged app).

```powershell
$pw = Read-Host -AsSecureString
Add-MsixAlias `
    -PackagePath 'C:\drop\App.msix' `
    -AppId       'App' `
    -ExecutableName 'mytool.exe' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-alias.msix'
```

After install, `where mytool.exe` resolves to
`%LOCALAPPDATA%\Microsoft\WindowsApps\mytool.exe`.

---

## 7. Enable / configure FileSystem write virtualization

The canonical Win32-conversion fix: writes to `C:\Program Files\<App>\`
get redirected to the per-user package cache.

```powershell
$pw = Read-Host -AsSecureString

# Default behaviour: ENABLE virtualization, exclude AppData paths.
Set-MsixFileSystemWriteVirtualization `
    -PackagePath 'C:\drop\App.msix' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-virt.msix'
```

To disable (writes go to the real filesystem; usually wrong for converted
Win32 apps unless you've also added the right ACLs):

```powershell
Set-MsixFileSystemWriteVirtualization -Disable `
    -PackagePath 'C:\drop\App.msix' `
    -OutputPath  'C:\drop\App-no-virt.msix'
```

To customise excluded directories (default: `LocalAppData`, `RoamingAppData`):

```powershell
Set-MsixFileSystemWriteVirtualization `
    -PackagePath 'C:\drop\App.msix' `
    -ExcludedDirectories '$(KnownFolder:LocalAppData)','$(KnownFolder:RoamingAppData)','VFS/ProgramFilesX64/App/Cache' `
    -OutputPath 'C:\drop\App-virt-custom.msix'
```

---

## 8. Fix Notepad++ plugins that want to write to Program Files

The Notepad++ plugin manager extracts to `C:\Program Files\Notepad++\plugins\`.
Out of the box this fails inside MSIX because the plugin manager probes
write-access *before* extracting, and the probe returns "no" even though
MSIX would virtualize the write.

**Solution**: combine VFS virtualization (so the write *can* happen) with a
PSF FileRedirection rule (so the *probe* also sees a writable path).

```powershell
$pw = Read-Host -AsSecureString

# 1. Ensure FS virtualization is enabled (the default — but make it explicit)
Set-MsixFileSystemWriteVirtualization `
    -PackagePath 'C:\drop\Notepadpp.msix' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\Notepadpp-step1.msix'

# 2. Add PSF FileRedirection for the plugins path specifically
$pluginsRedirect = New-MsixPsfFileRedirectionConfig `
    -Base 'VFS\ProgramFilesX64\Notepad++\plugins' `
    -Patterns '.*'

Add-MsixPsfV2 `
    -PackagePath 'C:\drop\Notepadpp-step1.msix' `
    -Fixups @($pluginsRedirect) `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\Notepadpp-final.msix'

Remove-Item 'C:\drop\Notepadpp-step1.msix'
```

Same pattern works for any plugin manager that does an access probe before
extracting (7-Zip themes, Audacity plugins, etc.).

---

## 9. Add a Windows Firewall rule that lives with the package

The rule is created on install and removed on uninstall — no `netsh` in your
deployment scripts.

```powershell
$pw = Read-Host -AsSecureString
Add-MsixFirewallRule `
    -PackagePath 'C:\drop\App.msix' `
    -AppId       'App' `
    -Executable  'VFS\ProgramFilesX64\App\App.exe' `
    -Direction   'in' `
    -Protocol    'TCP' `
    -LocalPort   '8443' `
    -Description 'App HTTPS listener' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath  'C:\drop\App-fw.msix'
```

The rule lands under `<Package><Extensions>` (correct per the schema; fixed
in issue #12). `runFullTrust` is auto-injected.

---

## 10. Bundle a Visual C++ runtime

When an app needs `vcruntime140.dll` etc., bundle them directly so the host
doesn't need the redistributable installed.

```powershell
# Detect which VC runtimes the EXEs reference
$refs = Get-MsixVcRuntimeReference -PackagePath 'C:\drop\App.msix'
$refs

# Bundle the matching DLLs from a VS Redist source folder
$pw = Read-Host -AsSecureString
Add-MsixVcRuntimeBundle `
    -PackagePath 'C:\drop\App.msix' `
    -VcRedistRoot 'C:\Program Files (x86)\Microsoft Visual Studio\2022\Enterprise\VC\Redist\MSVC\<version>\x64\Microsoft.VC143.CRT' `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath 'C:\drop\App-vcrt.msix'
```

---

## 11. Static analysis + auto-fix in one pass

`Invoke-MsixInvestigation` runs the static manifest scanner, the heuristic
finder, and (optionally) procmon capture and DebugView trace parsing.
`Invoke-MsixAutoFixFromAnalysis` then applies the right fixers — signing
ONCE at the end.

```powershell
$report = Invoke-MsixInvestigation -PackagePath 'C:\drop\App.msix'

# Look at what was found
$report.Findings | Format-Table Severity, Category, Symptom
$report.SuggestedFixups | Format-Table

# Apply the recommended fixes (DryRun first)
Invoke-MsixAutoFixFromAnalysis -Report $report -DryRun

# Real run
$pw = Read-Host -AsSecureString
Invoke-MsixAutoFixFromAnalysis -Report $report `
    -Pfx 'C:\certs\cert.pfx' -PfxPassword $pw `
    -OutputPath 'C:\drop\App-autofixed.msix'
```

`-PreferManifestOverPsf` (default `$true`) skips PSF injection when a
manifest-only fix covers the same symptom.

---

## 12. Sign with Azure Trusted Signing (production)

The recommended production signing backend. No local PFX, no password on
the command line, no key material on disk.

```powershell
# Prereq: az login; Azure.CodeSigning.Dlib.dll on disk
Invoke-MsixSigning `
    -PackagePath 'C:\drop\App.msix' `
    -Signer TrustedSigning `
    -TrustedSigningAccount  'MyProdAccount' `
    -TrustedSigningProfile  'MyProdProfile' `
    -TrustedSigningEndpoint 'https://eus.codesigning.azure.net'
```

The cmdlet writes a temp metadata JSON for signtool /dlib, then deletes it
in a finally block. Auth flows via the Azure CLI session.

---

## 13. Sign with Azure Key Vault via AzureSignTool

For HSM-backed certs in an Azure Key Vault.

```powershell
$svcSecret = Read-Host -AsSecureString 'Service principal client secret'
Invoke-MsixSigning `
    -PackagePath 'C:\drop\App.msix' `
    -Signer AzureSignTool `
    -KeyVaultUrl 'https://prod-vault.vault.azure.net' `
    -KeyVaultCertificate 'msix-prod-cert' `
    -KeyVaultTenantId '00000000-0000-0000-0000-000000000000' `
    -KeyVaultClientId '11111111-2222-3333-4444-555555555555' `
    -KeyVaultClientSecret $svcSecret
```

The client secret is held as a SecureString and decrypted only at the
signtool CLI boundary (BSTR + ZeroFreeBSTR).

---

## 14. Self-signed dev cert and Windows Sandbox debug session

For dev / sandbox workflows where you need a quick signed package without
involving real signing infrastructure.

```powershell
$cert = New-MsixSelfSignedCertificate `
    -Subject 'CN=Lab Test, O=Lab, C=NL' `
    -OutputPath 'C:\lab\cert\'

# Update the package Publisher to match the cert
Update-MsixSigner `
    -PackagePath 'C:\drop\App.msix' `
    -Publisher   'CN=Lab Test, O=Lab, C=NL' `
    -Pfx $cert.PfxPath -PfxPassword $cert.Password `
    -OutputPath  'C:\drop\App-lab.msix'

# Launch a Windows Sandbox session with the package preloaded + DebugView running
Invoke-MsixSelfSignAndDebug -PackagePath 'C:\drop\App-lab.msix'
```

---

## 15. Compare two packages

Diff manifest + file list + signing state between two `.msix` files. Useful
in CI gates ("does this build change anything in the manifest?").

```powershell
$diff = Compare-MsixPackage `
    -ReferencePath 'C:\drop\App-v1.msix' `
    -DifferencePath 'C:\drop\App-v2.msix'

$diff.HasChanges
$diff.ManifestChanges | Format-Table
$diff.FileChanges     | Format-Table Status, Path, ReferenceSize, DifferenceSize
$diff.SigningChanges  | Format-Table
```

File-level diffs are SHA-256 based.

---

## 16. App Attach VHDX for multi-session hosts

Generate an Azure Virtual Desktop App Attach image.

```powershell
# Requires admin + Hyper-V
New-MsixAppAttachImage `
    -PackagePath 'C:\drop\App.msix' `
    -OutputPath  'C:\appattach\App.vhdx' `
    -Format VHDX
```

CIM format is also supported (`-Format CIM`). Mount/dismount with
`Mount-MsixAppAttachImage` / `Dismount-MsixAppAttachImage`.

---

## 17. Full pipeline: publisher + PSF + signing in one call

The full unpack → modify → repack → sign-once pipeline.

```powershell
$pw = Read-Host -AsSecureString

$fixup = New-MsixPsfFileRedirectionConfig -Base 'logs' -Patterns '.*\.log'

Invoke-MsixPipeline -PackagePath 'C:\drop\App.msix' `
    -OutputPath 'C:\drop\App-final.msix' `
    -Config @{
        Publisher = 'CN=Contoso, O=Contoso, C=NL'
        PSF       = @{ Fixups = @($fixup) }
        Signing   = @{
            Pfx                = 'C:\certs\cert.pfx'
            PfxPassword        = $pw
            UnsignedOutputPath = 'C:\drop\App-unsigned-fallback.msix'
        }
    }
```

- Unpacks once.
- Applies every edit to the same workspace.
- Signs exactly once at the end.
- Atomic: if signing fails, the original `App.msix` is untouched and the
  unsigned scratch is preserved at `UnsignedOutputPath`.
- `-WhatIf` runs the unpack-edit-pack stages so you can preview the result
  (via `-UnsignedOutputPath` and `-SaveManifestTo`) but skips the destructive
  sign + replace.

---

## Common gotchas

- **CLSID format**: the MSIX manifest schema wants bare GUIDs
  (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) — no curly braces. The module
  normalises whatever you pass.
- **`MaxVersionTested`**: every manifest mutator auto-bumps this to the
  feature's minimum OS. Don't set it manually unless you know what you're
  doing.
- **`runFullTrust`**: required for COM servers, firewall rules, and most
  desktop integrations. The module auto-injects it where required (issues
  #12 and the M9 fix in PR 2).
- **Signing secrets**: prefer `-Signer TrustedSigning` over `-Signer SignTool
  -Pfx`. SignTool with a PFX exposes the password on the process command
  line (a Write-Warning fires when this happens so it shows up in CI logs).
- **WhatIf**: `-WhatIf` runs the unpack-edit-pack stages so you can preview
  the result, but skips signing and the final Move-Item to the target. Use
  `-SaveManifestTo` to capture the would-be manifest, and
  `-UnsignedOutputPath` to capture the would-be package.
