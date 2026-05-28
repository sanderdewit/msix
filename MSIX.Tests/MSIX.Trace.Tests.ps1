BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Trace Fixup parser' -Tag 'Trace' {

    Context 'ConvertFrom-MsixTraceLine' {

        It 'Parses a filesystem failure line' {
            $line = '[00:00:01.234 8472:A1B] CreateFileW: \\?\C:\Program Files\WindowsApps\app\app.log -> ACCESS_DENIED'
            $r = ConvertFrom-MsixTraceLine -Line $line
            $r.Function | Should -Be 'CreateFileW'
            $r.Result   | Should -Be 'ACCESS_DENIED'
            $r.Path     | Should -Match 'app\.log'
            $r.Category | Should -Be 'filesystem'
            $r.ProcessId | Should -Be 8472
        }

        It 'Parses a registry SUCCESS line' {
            $line = '[00:00:02.000 8472:A1B] RegOpenKeyExW: HKLM\SOFTWARE\Vendor -> SUCCESS'
            $r = ConvertFrom-MsixTraceLine -Line $line
            $r.Function | Should -Be 'RegOpenKeyExW'
            $r.Result   | Should -Be 'SUCCESS'
            $r.Category | Should -Be 'registry'
        }

        It 'Returns nothing on a non-matching line' {
            ConvertFrom-MsixTraceLine -Line 'some random debug output' | Should -BeNullOrEmpty
        }

        It 'Returns nothing on an empty line' {
            ConvertFrom-MsixTraceLine -Line '' | Should -BeNullOrEmpty
        }
    }

    Context 'Get-MsixTraceFailure' {
        BeforeAll {
            $script:LogPath = Join-Path -Path $env:TEMP -ChildPath "trace-$([guid]::NewGuid().ToString('N').Substring(0,8)).log"
            @(
                '[00:00:01.001 1234:A1] CreateFileW: C:\Windows\SysWOW64\settings.cfg -> NAME_NOT_FOUND'
                '[00:00:01.002 1234:A1] CreateFileW: C:\Program Files\WindowsApps\app\out.log -> ACCESS_DENIED'
                '[00:00:01.003 1234:A1] RegOpenKeyExW: HKLM\SOFTWARE\Foo -> SUCCESS'
                '[00:00:01.004 1234:A1] RegSetValueExW: HKLM\SOFTWARE\Foo\Bar -> ACCESS_DENIED'
                'random unrelated debug output'
            ) | Set-Content -LiteralPath $script:LogPath
        }
        AfterAll { Remove-Item -LiteralPath $script:LogPath -Force -ErrorAction SilentlyContinue }

        It 'Returns only failing rows' {
            $f = Get-MsixTraceFailure -Path $script:LogPath
            $f.Count | Should -Be 3
            $f.Result | Should -Not -Contain 'SUCCESS'
        }

        It 'Drops unparseable lines' {
            $r = Get-MsixTraceOutput -Path $script:LogPath
            $r.Function | Should -Not -Contain $null
        }
    }

    Context 'ConvertFrom-MsixTraceToFinding' {
        It 'Maps WindowsApps writes to FileRedirectionFixup' {
            $f = [pscustomobject]@{
                Function = 'CreateFileW'
                Path     = 'C:\Program Files\WindowsApps\app\out.log'
                Result   = 'ACCESS_DENIED'
                Category = 'filesystem'
                ProcessId= 1; ThreadId='A'
            }
            $finding = ConvertFrom-MsixTraceToFinding -Failures @($f)
            $finding.Category | Should -Be 'FileRedirectionFixup'
            $finding.Severity | Should -Be 'Error'
        }
        It 'Maps SysWOW64 reads to WorkingDirectory' {
            $f = [pscustomobject]@{
                Function = 'CreateFileW'
                Path     = 'C:\Windows\SysWOW64\settings.cfg'
                Result   = 'NAME_NOT_FOUND'
                Category = 'filesystem'
                ProcessId= 1; ThreadId='A'
            }
            $finding = ConvertFrom-MsixTraceToFinding -Failures @($f)
            $finding.Category | Should -Be 'WorkingDirectory'
        }
        It 'Maps HKLM access denied to RegLegacyFixups' {
            $f = [pscustomobject]@{
                Function = 'RegSetValueExW'
                Path     = 'HKLM\SOFTWARE\Foo'
                Result   = 'ACCESS_DENIED'
                Category = 'registry'
                ProcessId= 1; ThreadId='A'
            }
            $finding = ConvertFrom-MsixTraceToFinding -Failures @($f)
            $finding.Category | Should -Be 'RegLegacyFixups'
        }
        It 'Deduplicates by category + leaf' {
            $f1 = [pscustomobject]@{ Function='CreateFileW'; Path='C:\Program Files\WindowsApps\a.log'; Result='ACCESS_DENIED'; ProcessId=1; ThreadId='A' }
            $f2 = [pscustomobject]@{ Function='CreateFileW'; Path='C:\Program Files\WindowsApps\a.log'; Result='ACCESS_DENIED'; ProcessId=2; ThreadId='B' }
            (ConvertFrom-MsixTraceToFinding -Failures @($f1, $f2)).Count | Should -Be 1
        }
    }
}
