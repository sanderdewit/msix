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

## Cmdlet calls -- always use named parameters

Every cmdlet invocation in module source MUST pass its arguments by
explicit parameter name. Positional arguments are forbidden in source,
even when they happen to be correct today.

```powershell
# WRONG -- positional
Resolve-Path $Path
Start-Process $exe
Out-File $configPath -Encoding utf8

# RIGHT -- named
Resolve-Path -LiteralPath $Path
Start-Process -FilePath $exe
Out-File -LiteralPath $configPath -Encoding utf8
```

### Why

- **Positional binding is fragile.** A future cmdlet update can shuffle
  parameter sets, and a positional argument that bound to `-Path`
  yesterday can quietly bind to `-Filter` or `-Include` tomorrow.
  Named arguments don't move under your feet.
- **`-LiteralPath` is impossible to add later in some forms.** When
  the first positional argument binds to `-Path`, it's already wildcard-
  expanded by the time the cmdlet runs. The bug class that #45 and #46
  hunted (`Get-Item $pkg` returning `$null` for `C:\drop\app[v1.2].msix`)
  is a positional-binding bug -- not a wildcard bug per se.
- **Reviewability.** A reader scanning a 200-line function shouldn't
  have to remember which cmdlet's third positional is which. Named
  parameters document the call at the call site.

### Convention

- Every cmdlet -- built-in or user-defined -- gets named parameters in
  source. There is no "harmless positional" exception (we found we
  couldn't agree on what's harmless during review).
- Splat hashtables (`@params`) are encouraged for cmdlets with 4+ args.
- Aliases for cmdlets are forbidden (`gci`, `?`, `%`); the full
  cmdlet name + named parameters is the rule.
- The path-specific section below codifies the most enforceable
  subset of this rule with a CI guard.

## Filesystem paths -- use `-LiteralPath`

Every call to a PowerShell provider cmdlet (`Get-Item`, `Get-ChildItem`,
`Test-Path`, `Copy-Item`, `Move-Item`, `Remove-Item`, `Get-Content`,
`Set-Content`, `Out-File`, ...) MUST pass user-supplied or generated
paths via `-LiteralPath`, never positionally.

### Why

PowerShell's provider cmdlets default to *wildcard expansion* on
positional path arguments. Vendor build systems and CI artifact stores
can legitimately produce filenames containing `[`, `]`, `?`, or `*`,
and the positional form silently re-interprets those characters as
wildcards -- giving you either nothing back, or worse, the wrong file.

```powershell
# WRONG -- positional. If $pkg is "C:\drop\app[v1.2].msix" this
# returns $null instead of the file, because [v1.2] is parsed as
# a character class.
$info = Get-Item $pkg

# RIGHT -- -LiteralPath. Brackets are treated as characters.
$info = Get-Item -LiteralPath $pkg
```

### Convention

- `Copy-Item` / `Move-Item` take BOTH `-LiteralPath <src>` and
  `-Destination <dst>` explicitly. Never positional.
- For internal workspace paths (GUID-based folders the module created
  itself), prefer `-LiteralPath` anyway for consistency. The runtime
  cost is zero; the rule is easier to enforce when there are no
  exceptions to remember.
- A source-level regression guard in
  `MSIX.Tests/MSIX.LiteralPath.Tests.ps1` fails the build on any
  positional `Verb-Noun $variable` form for the watched cmdlets.

## Trusted-publisher governance (signers.json)

The Authenticode allowlist used by every toolchain installer
(`_MsixVerifyAuthenticodeFolder` -> `_MsixVerifyAuthenticode`) lives in
`signers.json` at the module root. The file is loaded at module import
time by `_MsixLoadTrustedPublishers` in `MSIX.PsfBinaries.ps1`. Issue
[#19](https://github.com/sanderdewit/msix/issues/19) moved this out of
code so security teams can add publishers without re-shipping the
module.

### Adding a new publisher

Open a PR that adds one object to the `publishers` array in
`signers.json`. The object must have:

- **`subjectPrefix`** *(required)*: the X.509 Subject prefix to match
  with `-like "$prefix*"` against the leaf cert's `Subject` property.
  Must start with `CN=` and end with `,` (the trailing comma stops a
  prefix from accidentally matching a longer common name — e.g.
  `CN=Microsoft Corp,` will not match `CN=Microsoft Corp Test`). The
  PSScriptAnalyzer-style regression test in
  `MSIX.Tests/MSIX.TrustedPublishers.Tests.ps1` enforces this format.
- **`description`** *(required)*: human-readable rationale — which
  binaries / which redistribution channel.
- **`addedBy`** *(strongly recommended)*: PR number or release where the
  entry was first introduced. Helps reviewers cross-check the audit
  trail.
- **`addedAt`** *(strongly recommended)*: ISO-8601 date the entry was
  added.

### Evidence required for review

The PR description must include:

1. A direct link to the publisher's officially-distributed signed
   binary (URL must be HTTPS, must come from the publisher's own
   domain — not a redistribution mirror).
2. The expected leaf-cert thumbprint observed from running
   `Get-AuthenticodeSignature <file>` against a freshly-downloaded
   sample. Cross-check against the publisher's published thumbprint
   if they publish one.
3. The *exact* `Subject` string from that same signature. Confirm the
   proposed `subjectPrefix` matches the start of that string up to
   the first separating `,`.

### Review

PRs that modify `signers.json` must be reviewed by at least one
maintainer with a security focus. The trust boundary the module
enforces is only as strong as the membership of this list — adding an
entry effectively says "every binary signed by this publisher is
allowed to land in the toolchain on every host that runs the module."

### Future hardening

The file is intentionally unsigned today. A future change will
Authenticode-sign `signers.json` itself and require
`Get-AuthenticodeSignature -Status -eq 'Valid'` before the loader
accepts the file. That work is tracked in #19's follow-ups.

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
