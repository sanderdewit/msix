# Contributing to the MSIX PowerShell Module

Thanks for contributing. This module is used in mission-critical IT environments
(DoD/NATO/Pentagon-scale deployments) — the code style choices below are about
making the module safe to extend without introducing security or reliability
regressions.

## File encoding (UTF-8 BOM — non-negotiable)

**Every `.ps1`, `.psm1`, and `.psd1` file in this repo MUST be saved as
UTF-8 with a Byte Order Mark (`EF BB BF`).** This applies to source,
tests, and anything Pester imports — no exceptions.

This is enforced two ways:

1. PSScriptAnalyzer's `PSUseBOMForUnicodeEncodedFile` rule runs in CI on
   every push and fails the build on a BOM-less file with non-ASCII bytes.
2. The module's `PowerShellVersion = '5.1'` floor means Windows PowerShell
   5.1 (not pwsh 7) is a supported runtime, and Windows PowerShell 5.1
   reads BOM-less files as Windows-1252 (CP-1252), not UTF-8.

### Why this matters — the silent-corruption failure mode

A BOM-less UTF-8 file containing a non-ASCII character like `—` (em-dash,
U+2014) is stored on disk as the three bytes `E2 80 94`. Under CP-1252,
those bytes are read as the three characters `â`, `€`, `"` — and the last
one is **U+201D RIGHT DOUBLE QUOTATION MARK**, which Windows PowerShell
treats as a valid string terminator. The result: a single em-dash inside
a double-quoted string silently closes the string, and the parser
explodes hundreds of lines later with confusing errors like
`The string is missing the terminator: '` or `Missing closing '}'`.

The same trap exists for the curly single-quote (UTF-8 ending in `0x92`,
e.g. arrow `→` = `E2 86 92`) inside single-quoted strings, and for any
2- or 3-byte UTF-8 sequence whose final byte happens to be `0x91`-`0x94`.

The fix is always the same: **add a UTF-8 BOM**. The BOM tells Windows
PowerShell to use UTF-8, the bytes are interpreted as the character the
author actually typed, and string delimiters work as written.

### How to save with BOM

- **VS Code**: status-bar bottom-right → "UTF-8 with BOM" (not "UTF-8").
- **`Set-Content -Encoding utf8BOM`** (pwsh 7+).
- **`Out-File -Encoding utf8` in Windows PowerShell 5.1** (the default is
  BOM'd in 5.1 but BOM-less in 7+ — opposite of intuition).
- **Programmatic**: `[IO.File]::WriteAllText($path, $text, [Text.UTF8Encoding]::new($true))`
  (the `$true` is `encoderShouldEmitUTF8Identifier`, i.e. the BOM).
- **Verify**: `(Get-Content $path -Encoding Byte -TotalCount 3) -join ' '`
  must print `239 187 191`.

### Avoid PS7-only syntax in module code

The module targets Windows PowerShell 5.1. Do not introduce:

- `??` (null-coalescing) — use
  `if ($null -ne $x) { $x } else { $default }` assigned to a temp
  variable. Note that `(if ...)` inline as an expression argument is a
  parser error in both 5.1 and 7 — extract to a variable first.
- `?.` / `?[]` (null-conditional) — guard with `if`.
- Ternary `?:` — use `if ... else ...`.

Test files may use PS7-only syntax because Pester runs them under
`pwsh`, but module code that ships to PSGallery must not.

## Error handling

- **Use `throw` to terminate.** Never `Write-Error` without `-ErrorAction Stop` —
  it makes callers' `try/catch` break silently when the user's
  `$ErrorActionPreference` is `Continue` (the default).
- **All file-system calls on user-supplied paths use `-ErrorAction Stop`.**
  `Get-Item`, `Test-Path`, `Get-Content`, `Get-ChildItem`, etc. should not be
  allowed to fail silently.
- **`Invoke-MsixProcess` results must be checked with `Assert-MsixProcessSuccess`.**
  Never trust `$LASTEXITCODE` from an external tool without explicit assertion.

## Logging

- Use `Write-MsixLog Info|Warning|Error|Debug` — it routes to the Information
  stream (capturable by CI / transcripts) and respects `Set-MsixLogLevel`.
- Use the real `Write-Warning` only for security-relevant notices that callers
  must be able to capture via `-WarningVariable` (e.g. the SignTool cmdline
  exposure warning).
- Never log a secret. PFX passwords, key-vault client secrets, signing
  thumbprints (sometimes considered sensitive in regulated environments) —
  none of these should reach the log stream.

## XML

- **Never** load XML from a user-supplied package with `[xml]$x = Get-Content ...`
  or `LoadXml(...)`. Use `_MsixLoadXmlSecure` (private helper in
  `MSIX.Manifest.ps1`) — it disables DTD processing and external entity
  resolution, the two XXE vectors.

## External processes

- Always pass `Invoke-MsixProcess -ArgumentList @(...)` (array form). Never
  use the deprecated `-Arguments` (single string) — it's a command-injection
  surface from package-supplied filenames.
- The `Process` object must be disposed (handled inside `Invoke-MsixProcess`).
  If you start a process directly, wrap in `try { } finally { $p.Dispose() }`.

## Tool downloads

- All `Install-Msix*` functions must call `_MsixVerifyAuthenticode` on the
  downloaded binaries before installing them into the toolchain.
- Trusted publishers are listed in `$script:MsixTrustedPublishers` in
  `MSIX.PsfBinaries.ps1`. Adding a new publisher requires PR review and a link
  to the publisher's official cert thumbprint (see issue #19 for governance).

## Signing

- Default to `-Signer TrustedSigning` (Azure-managed certs) in any documented
  example. `-Signer SignTool` with `-Pfx` works but emits a warning because the
  PFX password lands on the process command line.
- See PR #16 for the architecture rationale.

## Manifest mutators

- Use `Invoke-MsixManifestTransform` for pure in-memory transforms (testable
  without packaging). Use `_MsixMutateManifest` for the full unpack-edit-pack-sign
  cycle.
- Every mutator should auto-inject required capabilities (e.g. `runFullTrust`
  for COM servers and firewall rules) and bump `MaxVersionTested` to the
  minimum OS version documented on the schema element page.

## Tests

- Import the module via `MSIX.psd1` (not `MSIX.psm1`) so manifest export
  filtering is exercised.
- Save test files with UTF-8 BOM — see the **File encoding** section at
  the top of this doc.
- Tag tests appropriately: `Manifest`, `Security`, `Integration`, etc.
- Mutators must have at least one idempotency test (run twice, assert no
  duplicate elements added).
