# Run all Pester tests in this folder. Usage:
#   .\MSIX.Tests\Invoke-MsixTests.ps1
#   .\MSIX.Tests\Invoke-MsixTests.ps1 -Tag Builders
#
# Requires Pester v5+:
#   Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser
#
# Write-Host usage policy:
#   This is an interactive test runner. The pass/fail summary banner must be
#   visible by default and benefits from colour, which Write-Information
#   cannot deliver. Write-Output would pollute the success pipeline so the
#   caller can't reliably capture the Pester result object. Pester's own
#   runner uses Write-Host for the same reason. Suppression below is the
#   documented PSScriptAnalyzer pattern for legitimate operator output.

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSAvoidUsingWriteHost', '',
    Justification = 'Interactive test runner banner: must be visible by default and uses colour for at-a-glance readability. See policy comment above.')]
[CmdletBinding()]
param(
    [string[]]$Tag,
    [string]$OutputPath = (Join-Path $PSScriptRoot 'TestResults.xml'),

    # Issue #47: hardened developer workstations / build agents may revoke
    # the WMI/CIM privileges Pester's NUnit metadata exporter needs (calls
    # Get-CimInstance Win32_*). The tests themselves don't care, but the
    # end-step throws and the wrapper exits with the infra-failure code.
    # Pass -DisableTestResult to skip NUnit XML emission and run the suite
    # to completion on those hosts. CI still defaults to emitting the
    # artifact so release-time logs remain machine-readable.
    [Alias('NoTestResult')]
    [switch]$DisableTestResult
)

$ErrorActionPreference = 'Stop'

Import-Module Pester -MinimumVersion 5.5 -ErrorAction Stop

$config = New-PesterConfiguration
$config.Run.Path        = $PSScriptRoot
$config.Run.PassThru    = $true
$config.Output.Verbosity = 'Detailed'
if ($DisableTestResult) {
    $config.TestResult.Enabled = $false
    Write-Host "TestResult XML emission DISABLED (-DisableTestResult). Tests still run, but no NUnit artifact will be written." -ForegroundColor Yellow
} else {
    $config.TestResult.Enabled    = $true
    $config.TestResult.OutputPath = $OutputPath
    $config.TestResult.OutputFormat = 'NUnitXml'
}

if ($Tag) { $config.Filter.Tag = $Tag }

# Issue #43: Invoke-Pester can throw AFTER executing the tests -- e.g. the
# NUnit Write-NUnitEnvironmentInformation step calls Get-CimInstance, which
# needs WMI privileges that some hardened agents revoke. When that happens
# the previous wrapper exited 0 and printed blank pass/fail/skipped counts
# because $result was never assigned. CI then reported "successful" even
# though the test artifact was missing and we had zero confidence in the
# release. Wrap in try/catch; treat any throw OR a missing result object
# as a hard failure with a non-zero exit code distinct from "tests failed".
$WrapperExitTestsFailed = 1
$WrapperExitInfraFailure = 2

try {
    $result = Invoke-Pester -Configuration $config
} catch {
    Write-Host ''
    Write-Host ('Pester wrapper: Invoke-Pester threw -- ' + $_.Exception.Message) -ForegroundColor Red
    if ($_.ScriptStackTrace) {
        Write-Host $_.ScriptStackTrace -ForegroundColor DarkRed
    }
    Write-Host ('Output (NUnit): ' + $OutputPath) -ForegroundColor DarkRed
    Write-Host 'Treating as INFRASTRUCTURE FAILURE; pass/fail counts are NOT trustworthy.' -ForegroundColor Red
    exit $WrapperExitInfraFailure
}

if (-not $result -or
    -not $result.PSObject.Properties['PassedCount'] -or
    -not $result.PSObject.Properties['FailedCount']) {
    Write-Host ''
    Write-Host 'Pester wrapper: Invoke-Pester returned no usable result object.' -ForegroundColor Red
    Write-Host 'Treating as INFRASTRUCTURE FAILURE.' -ForegroundColor Red
    exit $WrapperExitInfraFailure
}

Write-Host ''
Write-Host "Passed: $($result.PassedCount)" -ForegroundColor Green
Write-Host "Failed: $($result.FailedCount)" -ForegroundColor Red
Write-Host "Skipped: $($result.SkippedCount)" -ForegroundColor Yellow
Write-Host "Output: $OutputPath"

if ($result.FailedCount -gt 0) { exit $WrapperExitTestsFailed }
exit 0
