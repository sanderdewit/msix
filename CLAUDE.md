# Project rules for AI agents

This file is auto-loaded by Claude Code in this repo. Read it first, then
read `CONTRIBUTING.md` for the full coding standard.

## Hard rules (these break the build if violated)

### 1. UTF-8 BOM on every `.ps1`, `.psm1`, `.psd1` file

Always create and edit PowerShell files with a UTF-8 **BOM** (`EF BB BF`
prefix). Never write a bare UTF-8 file.

- PSScriptAnalyzer's `PSUseBOMForUnicodeEncodedFile` runs in CI and
  fails the build if a file containing non-ASCII bytes lacks a BOM.
- The module targets Windows PowerShell 5.1, which reads BOM-less files
  as CP-1252. A bare em-dash inside a string literal (UTF-8 `E2 80 94`,
  where `0x94` = CP-1252 `"` right double curly quote) silently
  terminates the string and triggers cascading parse errors hundreds
  of lines later. This wasted ~30 minutes of debugging in v0.70.5; do
  not repeat.

**When you create a new `.ps1`:** use the `Write` tool, then
immediately re-save with BOM:

```powershell
$p = 'path\to\new.ps1'
$t = [IO.File]::ReadAllText($p, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($p, $t, [Text.UTF8Encoding]::new($true))
# Verify: must print "239 187 191"
(Get-Content $p -Encoding Byte -TotalCount 3) -join ' '
```

(The `$true` to `UTF8Encoding` is `encoderShouldEmitUTF8Identifier`.)

The `Edit` tool preserves the existing BOM, so once a file is BOM'd you
don't need to re-stamp it on every edit.

### 2. No PowerShell 7-only syntax in module code

The module targets PS5.1. Test files may use PS7 syntax (Pester runs
under `pwsh`), but anything dot-sourced from `MSIX.psm1` must parse
under Windows PowerShell 5.1.

Banned in module code:

- `??` (null-coalescing) — use a temp variable:
  `$v = if ($null -ne $x) { $x } else { $default }`
- `?.` / `?[]` (null-conditional) — guard with `if`.
- Ternary `?:` — use `if ... else ...`.

Also note: `(if ...)` as an inline expression argument is a parser
error in **both** 5.1 and 7. PowerShell parses bare `if` inside `(...)`
as a command call. Always extract to a temp variable first, or use
`$(if ...)` (subexpression syntax) — but the temp-variable form is
clearer.

### 3. Verify before claiming done

Before saying "PSSA is clean" or "tests pass," actually run them:

```powershell
# PSSA, scoped to MSIX module:
Set-Location C:\temp\msix\MSIX
Invoke-ScriptAnalyzer -Path . -Recurse -Severity Error,Warning

# Pester (use pwsh, not Windows PowerShell, for the canonical baseline):
pwsh -NonInteractive -Command "Invoke-Pester -Path MSIX.Tests -Output Minimal"
```

The release pipeline is unforgiving — every push triggers PSSA + Pester,
and a tagged release triggers PSGallery publish. A red build blocks the
release.

## Soft conventions (see CONTRIBUTING.md for details)

- Use `Write-MsixLog Info|Warning|Error|Debug`, not `Write-Host`.
- All XML from user packages goes through `_MsixLoadXmlSecure` (XXE
  prevention).
- All downloaded toolchain binaries must be Authenticode-verified
  before use (`_MsixVerifyAuthenticode`).
- Every mutator supports `-WhatIf` via `[CmdletBinding(SupportsShouldProcess)]`.
- PFX passwords are `[SecureString]` end-to-end. `ConvertTo-SecureString
  -AsPlainText -Force` is banned outside `ConvertTo-TestSecureString`.
- Default signer is `TrustedSigning` (Azure-managed certs), not SignTool
  with `-Pfx`.
