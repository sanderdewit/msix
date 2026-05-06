# Run all Pester tests in this folder. Usage:
#   .\MSIX.Tests\Invoke-MsixTests.ps1
#   .\MSIX.Tests\Invoke-MsixTests.ps1 -Tag Builders
#
# Requires Pester v5+:
#   Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser
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
