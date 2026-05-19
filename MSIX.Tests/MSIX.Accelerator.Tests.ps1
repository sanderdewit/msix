BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Accelerator YAML parser is safe-by-design' -Tag 'Security' {

    It 'Parses simple key:value' {
        $yaml = @'
package: contoso.app
publisher: CN=Contoso
'@
        $tmp = Join-Path $env:TEMP "msix-accel-$([guid]::NewGuid().ToString('N').Substring(0,8)).yaml"
        Set-Content -LiteralPath $tmp -Value $yaml -NoNewline -Encoding utf8
        try {
            $r = ConvertFrom-MsixYamlAccelerator -Path $tmp
            $r.package   | Should -Be 'contoso.app'
            $r.publisher | Should -Be 'CN=Contoso'
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Parses inline list values' {
        $yaml = "patterns: [.log, .tmp, .bak]"
        $tmp = Join-Path $env:TEMP "msix-accel-$([guid]::NewGuid().ToString('N').Substring(0,8)).yaml"
        Set-Content -LiteralPath $tmp -Value $yaml -NoNewline -Encoding utf8
        try {
            $r = ConvertFrom-MsixYamlAccelerator -Path $tmp
            $r.patterns | Should -HaveCount 3
            $r.patterns | Should -Contain '.log'
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Does NOT attempt to load powershell-yaml at runtime' {
        # Grep the module source: ConvertFrom-Yaml should not appear.
        $modulePath = Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.Accelerator.ps1')
        (Get-Content $modulePath -Raw) | Should -Not -Match 'ConvertFrom-Yaml'
        (Get-Content $modulePath -Raw) | Should -Not -Match 'powershell-yaml'
    }

    It 'Treats YAML type tags as literal text (no object instantiation)' {
        $hostile = "package: !!python/object/apply:os.system [`"whoami`"]"
        $tmp = Join-Path $env:TEMP "msix-accel-$([guid]::NewGuid().ToString('N').Substring(0,8)).yaml"
        Set-Content -LiteralPath $tmp -Value $hostile -NoNewline -Encoding utf8
        try {
            { $r = ConvertFrom-MsixYamlAccelerator -Path $tmp; $r } | Should -Not -Throw
            # The parser should yield a literal string with the tag, not execute anything.
            $r = ConvertFrom-MsixYamlAccelerator -Path $tmp
            ($r.package -as [string]) | Should -Match 'python|whoami|!!|os\.system'
        } finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}
