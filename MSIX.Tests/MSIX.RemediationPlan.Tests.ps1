BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    # Build a minimal .msix fixture so New-MsixRemediationPlan can fingerprint it.
    $script:FixtureDir = Join-Path $env:TEMP "msix-remedplan-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $script:FixtureDir -Force | Out-Null

    $manifestXml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="TestPlan" Version="1.0.0.0"
            Publisher="CN=Test" ProcessorArchitecture="x64" />
  <Properties><DisplayName>TestPlan</DisplayName><PublisherDisplayName>Test</PublisherDisplayName><Logo>Assets\logo.png</Logo></Properties>
  <Dependencies><TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22000.0"/></Dependencies>
  <Applications>
    <Application Id="App" Executable="App\app.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="TestPlan" Description="Test" BackgroundColor="transparent"
                          Square150x150Logo="Assets\logo.png" Square44x44Logo="Assets\logo.png"/>
    </Application>
  </Applications>
</Package>
'@
    $manifestXml | Out-File -FilePath (Join-Path $script:FixtureDir 'AppxManifest.xml') -Encoding utf8

    $script:PlanYamlPath = Join-Path $env:TEMP "msix-remedplan-test-$([guid]::NewGuid().ToString('N').Substring(0,8)).yaml"
}

AfterAll {
    Remove-Item -LiteralPath $script:FixtureDir -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $script:PlanYamlPath -Force -ErrorAction SilentlyContinue
    Remove-Module MSIX -ErrorAction SilentlyContinue
}

Describe 'Remediation plan round-trip' -Tag 'RemediationPlan' {

    Context 'Exports' {
        It 'All four cmdlets are exported' {
            foreach ($cmd in 'New-MsixRemediationPlan','Export-MsixRemediationPlan',
                             'Import-MsixRemediationPlan','Test-MsixRemediationPlan',
                             'Invoke-MsixRemediationPlan') {
                Get-Command -Name $cmd -Module MSIX | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'New-MsixRemediationPlan' {
        It 'Returns a MsixRemediationPlan object' {
            $plan = New-MsixRemediationPlan -PackagePath $script:FixtureDir
            $plan.PSObject.TypeNames | Should -Contain 'MsixRemediationPlan'
        }

        It 'Captures the identity fingerprint' {
            $plan = New-MsixRemediationPlan -PackagePath $script:FixtureDir
            $plan.packageFingerprint.identityName | Should -Be 'TestPlan'
            $plan.packageFingerprint.publisher    | Should -Be 'CN=Test'
        }

        It 'Records generatedBy with module version' {
            $plan = New-MsixRemediationPlan -PackagePath $script:FixtureDir
            $plan.generatedBy | Should -Match 'MSIX\.PowerShell'
        }

        It 'Stores applied fixes with cmdlet and args keys' {
            $fixes = @(
                @{ Cmdlet = 'Set-MsixFileSystemWriteVirtualization'; Args = @{} }
            )
            $plan = New-MsixRemediationPlan -PackagePath $script:FixtureDir -AppliedFixes $fixes
            $plan.appliedFixes.Count | Should -Be 1
            $plan.appliedFixes[0].cmdlet | Should -Be 'Set-MsixFileSystemWriteVirtualization'
        }
    }

    Context 'Export-MsixRemediationPlan' {
        It 'Writes a YAML file that starts with the remediation: root key' {
            $plan = New-MsixRemediationPlan -PackagePath $script:FixtureDir
            Export-MsixRemediationPlan -Plan $plan -Path $script:PlanYamlPath
            Test-Path -LiteralPath $script:PlanYamlPath | Should -BeTrue
            $content = Get-Content -LiteralPath $script:PlanYamlPath -Raw
            $content | Should -Match 'remediation:'
        }

        It 'Includes the identity name in the YAML output' {
            $plan = New-MsixRemediationPlan -PackagePath $script:FixtureDir
            Export-MsixRemediationPlan -Plan $plan -Path $script:PlanYamlPath
            $content = Get-Content -LiteralPath $script:PlanYamlPath -Raw
            $content | Should -Match 'TestPlan'
        }
    }

    Context 'Import-MsixRemediationPlan (round-trip)' {
        BeforeAll {
            $fixes = @(
                @{ Cmdlet = 'Set-MsixFileSystemWriteVirtualization'; Args = @{} }
                @{ Cmdlet = 'Set-MsixRegistryWriteVirtualization';   Args = @{} }
            )
            $script:OrigPlan = New-MsixRemediationPlan -PackagePath $script:FixtureDir -AppliedFixes $fixes
            Export-MsixRemediationPlan -Plan $script:OrigPlan -Path $script:PlanYamlPath
            $script:Reimported = Import-MsixRemediationPlan -Path $script:PlanYamlPath
        }

        It 'Round-trip produces a MsixRemediationPlan object' {
            $script:Reimported.PSObject.TypeNames | Should -Contain 'MsixRemediationPlan'
        }

        It 'Round-trip preserves identityName' {
            $script:Reimported.packageFingerprint.identityName |
                Should -Be $script:OrigPlan.packageFingerprint.identityName
        }

        It 'Round-trip preserves publisher' {
            $script:Reimported.packageFingerprint.publisher |
                Should -Be $script:OrigPlan.packageFingerprint.publisher
        }

        It 'Round-trip preserves the number of applied fixes' {
            @($script:Reimported.appliedFixes).Count |
                Should -Be @($script:OrigPlan.appliedFixes).Count
        }

        It 'Round-trip preserves fix cmdlet names' {
            $orig   = @($script:OrigPlan.appliedFixes   | ForEach-Object { if ($_ -is [hashtable]) { $_['cmdlet'] } else { $_.cmdlet } }) | Sort-Object
            $reimp  = @($script:Reimported.appliedFixes | ForEach-Object { if ($_ -is [hashtable]) { $_['cmdlet'] } else { $_.cmdlet } }) | Sort-Object
            $orig | Should -Be $reimp
        }
    }

    Context 'Import-MsixRemediationPlan validation' {
        It 'Throws when the file is missing the remediation: root key' {
            $bad = Join-Path $env:TEMP 'bad-plan.yaml'
            'version: 1' | Out-File -FilePath $bad -Encoding utf8
            try {
                { Import-MsixRemediationPlan -Path $bad } | Should -Throw
            } finally {
                Remove-Item -LiteralPath $bad -ErrorAction SilentlyContinue
            }
        }

        It 'Throws when a fix cmdlet is not from the MSIX module' {
            $rogue = Join-Path $env:TEMP 'rogue-plan.yaml'
            @"
remediation:
  version: 1
  generatedAt: 2026-05-23T00:00:00Z
  generatedBy: MSIX.PowerShell 0.70.4
  packageFingerprint:
    identityName: TestPlan
    publisher: CN=Test
    sha256: null
  findings: []
  appliedFixes:
    - cmdlet: Remove-Item
      args: {}
  approval:
    requiredBy: null
    notes: null
"@ | Out-File -FilePath $rogue -Encoding utf8
            try {
                { Import-MsixRemediationPlan -Path $rogue } | Should -Throw
            } finally {
                Remove-Item -LiteralPath $rogue -ErrorAction SilentlyContinue
            }
        }
    }

    Context 'Test-MsixRemediationPlan' {
        It 'Returns IsValid=$true when identity matches' {
            $plan = New-MsixRemediationPlan -PackagePath $script:FixtureDir
            $result = Test-MsixRemediationPlan -Plan $plan -PackagePath $script:FixtureDir
            $result.IsValid | Should -BeTrue
            $result.Errors  | Should -BeNullOrEmpty
        }

        It 'Returns IsValid=$false when identityName does not match' {
            $plan = New-MsixRemediationPlan -PackagePath $script:FixtureDir
            # Tamper with the fingerprint
            $plan.packageFingerprint.identityName = 'OtherApp'
            $result = Test-MsixRemediationPlan -Plan $plan -PackagePath $script:FixtureDir
            $result.IsValid | Should -BeFalse
            $result.Errors  | Should -Not -BeNullOrEmpty
        }
    }
}
