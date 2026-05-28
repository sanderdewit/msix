BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Playbook bus' -Tag 'Playbooks' {

    Context 'Exports + discovery' {
        It 'Get-MsixPlaybook, Find-MsixPlaybook, Invoke-MsixPlaybook are exported' {
            (Get-Command Get-MsixPlaybook    -Module MSIX) | Should -Not -BeNullOrEmpty
            (Get-Command Find-MsixPlaybook   -Module MSIX) | Should -Not -BeNullOrEmpty
            (Get-Command Invoke-MsixPlaybook -Module MSIX) | Should -Not -BeNullOrEmpty
        }

        It 'Discovers the bundled Notepad++ playbook' {
            $pb = Get-MsixPlaybook | Where-Object Name -eq 'Notepad++'
            $pb | Should -Not -BeNullOrEmpty
            $pb.Steps.Count | Should -BeGreaterThan 0
            $pb.Match.IdentityName | Should -Match 'Notepad'
        }

        It 'Loaded playbook objects carry the MsixPlaybook PSTypeName' {
            (Get-MsixPlaybook | Select-Object -First 1).PSObject.TypeNames | Should -Contain 'MsixPlaybook'
        }
    }

    Context 'Matching' {
        BeforeAll {
            $script:TmpHive = Join-Path $env:TEMP "msix-playbook-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
            New-Item -ItemType Directory -Path $script:TmpHive -Force | Out-Null
            # Synthesise a minimal manifest that the playbook should match.
            $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         xmlns:uap="http://schemas.microsoft.com/appx/manifest/uap/windows10">
  <Identity Name="Notepad" Publisher="CN=&quot;Notepad++ Team&quot;" Version="8.9.4.0" ProcessorArchitecture="x64" />
  <Properties>
    <DisplayName>Notepad++</DisplayName>
    <PublisherDisplayName>Notepad++ Team</PublisherDisplayName>
    <Logo>l.png</Logo>
  </Properties>
  <Resources><Resource Language="en-us" /></Resources>
  <Dependencies>
    <TargetDeviceFamily Name="Windows.Desktop" MinVersion="10.0.17763.0" MaxVersionTested="10.0.22000.1" />
  </Dependencies>
  <Applications>
    <Application Id="NOTEPAD" Executable="VFS\ProgramFilesX64\Notepad++\notepad++.exe" EntryPoint="Windows.FullTrustApplication">
      <uap:VisualElements DisplayName="Notepad++" Description="np" BackgroundColor="transparent" Square150x150Logo="l.png" Square44x44Logo="l.png" />
    </Application>
  </Applications>
</Package>
'@
            $script:ManifestPath = Join-Path $script:TmpHive 'AppxManifest.xml'
            [System.IO.File]::WriteAllText($script:ManifestPath, $xml, [System.Text.UTF8Encoding]::new($false))
        }
        AfterAll {
            if (Test-Path $script:TmpHive) {
                Remove-Item -LiteralPath $script:TmpHive -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'Find-MsixPlaybook matches the Notepad++ playbook on a Notepad manifest' {
            $matched = Find-MsixPlaybook -PackagePath $script:ManifestPath
            $matched.Name | Should -Contain 'Notepad++'
        }
    }

    Context 'Invoke-MsixPlaybook' {
        It 'Refuses to invoke a cmdlet that is not in the MSIX module' {
            $rogue = [pscustomobject]@{
                PSTypeName = 'MsixPlaybook'
                Name       = 'Rogue'
                Steps      = @(@{ Cmdlet = 'Stop-Computer'; Args = @{} })
                Match      = @{}
            }
            { Invoke-MsixPlaybook -PackagePath 'C:\nope.msix' -Playbook $rogue -DryRun } |
                Should -Throw '*not from the MSIX module*'
        }

        It 'Refuses to invoke an unknown cmdlet' {
            $bad = [pscustomobject]@{
                PSTypeName = 'MsixPlaybook'
                Name       = 'Bad'
                Steps      = @(@{ Cmdlet = 'Does-Not-Exist-9F8B7'; Args = @{} })
                Match      = @{}
            }
            { Invoke-MsixPlaybook -PackagePath 'C:\nope.msix' -Playbook $bad -DryRun } |
                Should -Throw '*unknown cmdlet*'
        }

        It 'DryRun emits a plan summary without executing steps' {
            $pb = Get-MsixPlaybook | Where-Object Name -eq 'Notepad++' | Select-Object -First 1
            $result = Invoke-MsixPlaybook -PackagePath 'C:\nope.msix' -Playbook $pb -DryRun -SkipSigning
            $result.DryRun   | Should -BeTrue
            $result.Playbook | Should -Be 'Notepad++'
            $result.Steps    | Should -BeGreaterThan 0
        }
    }
}
