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
    [string]$OutputPath = (Join-Path $PSScriptRoot 'TestResults.xml')
)

$ErrorActionPreference = 'Stop'

Import-Module Pester -MinimumVersion 5.5 -ErrorAction Stop

$config = New-PesterConfiguration
$config.Run.Path        = $PSScriptRoot
$config.Run.PassThru    = $true
$config.Output.Verbosity = 'Detailed'
$config.TestResult.Enabled    = $true
$config.TestResult.OutputPath = $OutputPath
$config.TestResult.OutputFormat = 'NUnitXml'

if ($Tag) { $config.Filter.Tag = $Tag }

$result = Invoke-Pester -Configuration $config

Write-Host ''
Write-Host "Passed: $($result.PassedCount)" -ForegroundColor Green
Write-Host "Failed: $($result.FailedCount)" -ForegroundColor Red
Write-Host "Skipped: $($result.SkippedCount)" -ForegroundColor Yellow
Write-Host "Output: $OutputPath"

exit $result.FailedCount
