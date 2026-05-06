BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psm1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'SDK tools resolution (v0.9.1)' -Tag 'Toolchain' {

    It 'Install-MsixSdkTools is exported' {
        Get-Command Install-MsixSdkTools -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Update-MsixSdkTools is exported' {
        Get-Command Update-MsixSdkTools -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Get-MsixSdkToolsVersion is exported' {
        Get-Command Get-MsixSdkToolsVersion -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It 'Initialize-MsixToolchain accepts -Skip Sdk' {
        $cmd = Get-Command Initialize-MsixToolchain
        $skipSet = $cmd.Parameters['Skip'].Attributes |
                   Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
                   Select-Object -ExpandProperty ValidValues
        $skipSet | Should -Contain 'Sdk'
    }

    Context 'Friendly error when nothing is configured' {
        BeforeAll {
            # Stash and clear any existing override + cached root so we trigger the throw branch.
            $script:_saved = $env:MSIX_TOOLS_PATH
            $env:MSIX_TOOLS_PATH = 'C:\does\not\exist'
            # Force re-resolution
            try { Get-MsixToolsRoot -Refresh -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
        AfterAll {
            $env:MSIX_TOOLS_PATH = $script:_saved
            try { Get-MsixToolsRoot -Refresh -ErrorAction SilentlyContinue | Out-Null } catch {}
        }

        It 'Mentions Install-MsixSdkTools in the error when MakeAppx is missing' {
            # Don't let any cached result mask the throw
            $caught = $null
            try { Get-MsixToolsRoot -Refresh } catch { $caught = $_.Exception.Message }
            # Either the user happens to have a real toolchain (test inconclusive) OR we got the friendly error
            if ($caught) {
                $caught | Should -Match 'Install-MsixSdkTools'
                $caught | Should -Match 'Initialize-MsixToolchain'
            } else {
                Set-ItResult -Skipped -Because 'A real toolchain is already configured on this host.'
            }
        }
    }
}
