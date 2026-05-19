# Contributing to the MSIX PowerShell Module

Thanks for contributing. This module is used in mission-critical IT environments
(DoD/NATO/Pentagon-scale deployments) — the code style choices below are about
making the module safe to extend without introducing security or reliability
regressions.

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
- Save test files with **UTF-8 BOM** — PSScriptAnalyzer's
  PSUseBOMForUnicodeEncodedFile rule is enforced in CI.
- Tag tests appropriately: `Manifest`, `Security`, `Integration`, etc.
- Mutators must have at least one idempotency test (run twice, assert no
  duplicate elements added).
