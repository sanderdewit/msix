# TraceFixup

Adds a verbose tracer DLL that logs filesystem and registry calls (with their
results) to the OS debug stream — viewable in real time with
[DebugView](https://learn.microsoft.com/sysinternals/downloads/debugview).

**Reference:** [Use the Trace Fixup](https://learn.microsoft.com/windows/msix/psf/package-support-framework#use-the-trace-fixup)

## When to use

- ProcMon's signal-to-noise ratio is too low.
- You can't easily get ProcMon onto the target machine.
- You want a quick "what is the app actually trying to do" log without
  setting up filters.

## Easy mode

```powershell
Add-MsixDiagnosticTrace -PackagePath app.msix -Pfx cert.pfx -PfxPassword 'P@ss'
# Then: install the package, run it, watch DebugView (Ctrl+E to "Capture Win32").
```

## Manual / fine-grained

```powershell
$tr = New-MsixPsfTraceConfig `
    -FilesystemLevel allFailures `
    -RegistryLevel   unexpectedFailures
Add-MsixPsfV2 -PackagePath app.msix -Fixups @($tr) `
    -Pfx cert.pfx -PfxPassword 'P@ss'
```

Levels:

| Level                  | Meaning                                                       |
|------------------------|----------------------------------------------------------------|
| `allFailures`          | Every call that returned a non-success status                  |
| `unexpectedFailures`   | Failures that PSF/Microsoft has marked as "interesting"        |
| `ignore`               | Don't trace this category                                      |

## Notes

- The trace fixup writes via `OutputDebugString`. DebugView shows it under
  "Capture Global Win32" mode (admin required).
- Don't ship a TraceFixup-instrumented build to production — it's verbose
  enough to slow the app and leaks function-level paths to anyone running
  DebugView on the box.
