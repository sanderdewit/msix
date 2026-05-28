BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    $script:Tmp = Join-Path $env:TEMP "msix-scripts-$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item $script:Tmp -ItemType Directory -Force | Out-Null
}
AfterAll {
    Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Module MSIX -ErrorAction SilentlyContinue
}

Describe 'Standard scripts' -Tag 'Scripts' {

    It 'Get-MsixStandardScript lists all five templates' {
        $list = Get-MsixStandardScript
        $list.Name | Should -Contain 'CreateShortcut'
        $list.Name | Should -Contain 'CopyIconToAppData'
        $list.Name | Should -Contain 'CleanupOldUserData'
        $list.Name | Should -Contain 'RegisterFileAssociation'
        $list.Name | Should -Contain 'CustomerSettingsBootstrap'
    }

    It 'Each catalogue entry points to a real template file' {
        foreach ($e in Get-MsixStandardScript) {
            Test-Path -LiteralPath $e.Template | Should -BeTrue
        }
    }

    It 'New-MsixStandardScript renders CreateShortcut substituting parameters' {
        $out = Join-Path $script:Tmp 'cs.ps1'
        New-MsixStandardScript -Name CreateShortcut -OutputPath $out -Parameters @{
            DisplayName = 'Contoso'
            Target      = 'contoso.exe'
        } | Out-Null
        $text = Get-Content -LiteralPath $out -Raw
        $text | Should -Match "displayName\s*=\s*'Contoso'"
        $text | Should -Match "target\s*=\s*'contoso\.exe'"
        $text | Should -Not -Match '<#PARAM:'
    }

    It 'Throws when a required parameter is missing' {
        $out = Join-Path $script:Tmp 'missing.ps1'
        { New-MsixStandardScript -Name CreateShortcut -OutputPath $out -Parameters @{ DisplayName = 'X' } } |
            Should -Throw '*Target*'
    }

    It 'Validates Name against the catalogue' {
        $out = Join-Path $script:Tmp 'n.ps1'
        { New-MsixStandardScript -Name 'Bogus' -OutputPath $out -Parameters @{} } | Should -Throw
    }

    It 'Applies defaults for optional parameters' {
        $out = Join-Path $script:Tmp 'defaults.ps1'
        New-MsixStandardScript -Name CreateShortcut -OutputPath $out -Parameters @{
            DisplayName = 'A'
            Target      = 'a.exe'
        } | Out-Null
        # 'Location' default is 'Desktop'
        (Get-Content -LiteralPath $out -Raw) | Should -Match "location\s*=\s*'Desktop'"
    }
}
