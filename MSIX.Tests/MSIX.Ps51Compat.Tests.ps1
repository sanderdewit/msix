BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot

    # Match only REAL code. A plain Select-String also hits explanatory comments
    # (including the ones documenting these very fixes) and the '.EXAMPLE' blocks
    # inside comment-based help, which are guidance for the user, not module
    # behaviour. Tokenising and dropping Comment tokens removes both classes.
    function script:Find-MsixCodeMatch {
        param([Parameter(Mandatory)][string[]]$Pattern)
        Get-ChildItem -Path $script:ModuleRoot -Filter 'MSIX.*.ps1' |
            Where-Object { $_.Name -notmatch '\.Tests\.ps1$' } |
            ForEach-Object {
                $file   = $_
                $tokens = $null; $errors = $null
                $null = [System.Management.Automation.Language.Parser]::ParseFile(
                            $file.FullName, [ref]$tokens, [ref]$errors)
                # NewLine must be excluded too: the newline token terminating a
                # comment line starts on that same line, so filtering only
                # 'Comment' still marks every comment line as code.
                $codeLines = @($tokens |
                    Where-Object { $_.Kind -notin @('Comment', 'NewLine', 'EndOfInput') } |
                    ForEach-Object { $_.Extent.StartLineNumber }) |
                    Sort-Object -Unique
                Select-String -LiteralPath $file.FullName -Pattern $Pattern |
                    Where-Object { $codeLines -contains $_.LineNumber } |
                    ForEach-Object { "{0}:{1}: {2}" -f $file.Name, $_.LineNumber, $_.Line.Trim() }
            }
    }
}

# =============================================================================
# Windows PowerShell 5.1 compatibility guard (issue #142)
# -----------------------------------------------------------------------------
# The module targets PowerShellVersion 5.1, but the Pester lane runs under
# pwsh 7 where PS7-only constructs work — so a 5.1-only break can pass every
# test. This is a fast STATIC guard for the specific regression from #142: the
# `ErrorMessage` named argument on validation attributes ([ValidatePattern],
# [ValidateSet], [ValidateScript], …) was added in PS 6.0 and throws
# "Property 'ErrorMessage' cannot be found" at parameter binding under 5.1.
# The compat-ps51 CI job is the broad runtime guard; this pins the exact class
# with a clear message at the pwsh unit-test altitude.
# =============================================================================

Describe 'PowerShell 5.1 source compatibility' -Tag 'Compat' {

    It 'no module .ps1 uses the PS7-only ErrorMessage validation-attribute argument' {
        $offenders = Find-MsixCodeMatch -Pattern 'ErrorMessage\s*='
        # A non-empty list means someone re-introduced ErrorMessage = on an
        # attribute. Drop the argument (the Validate* regex/set still enforces
        # the rule) to keep the declared 5.1 floor honest.
        $offenders | Should -BeNullOrEmpty
    }

    It 'no module .ps1 calls PS6+ cmdlets that do not exist on Windows PowerShell 5.1' {
        # Join-String (PS6+) shipped at MSIX.Scanners.ps1:1470 inside a try whose
        # catch converted the CommandNotFoundException into a generic scanner
        # error - silently replacing the real ComServer finding on 5.1 (#146).
        # PSScriptAnalyzer's PSUseCompatibleCmdlets does not flag this class.
        $ps6Only = 'Join-String', 'ConvertFrom-Json\s+.*-AsHashtable', 'Test-Json', 'Get-Error', 'Split-Path\s+.*-LeafBase'
        $offenders = Find-MsixCodeMatch -Pattern $ps6Only
        $offenders | Should -BeNullOrEmpty
    }

    It 'no module .ps1 uses Get-PfxCertificate -Password (added in PS 6)' {
        $offenders = Find-MsixCodeMatch -Pattern 'Get-PfxCertificate[^\r\n]*-Password'
        $offenders | Should -BeNullOrEmpty
    }

    It 'writes no file with the edition-dependent "-Encoding utf8"' {
        # '-Encoding utf8' = BOM on 5.1, no BOM on 7. That divergence broke the
        # Trusted Signing metadata JSON (System.Text.Json rejects a BOM) and put
        # a BOM into PSF config.json parsed by the PSF runtime (#146).
        # _MsixWriteUtf8 makes the choice explicit and identical on both.
        $offenders = Find-MsixCodeMatch -Pattern '(Set-Content|Out-File)[^\r\n]*-Encoding\s+utf8'
        $offenders | Should -BeNullOrEmpty
    }
}

Describe '_MsixWriteUtf8 deterministic encoding (issue #146)' -Tag 'Compat' {

    It 'writes no BOM by default and a BOM only when asked' {
        $res = InModuleScope MSIX {
            $d = Join-Path ([IO.Path]::GetTempPath()) ("enc-" + [guid]::NewGuid().ToString('N').Substring(0,8))
            New-Item -ItemType Directory -Path $d -Force | Out-Null
            $plain = Join-Path $d 'a.json'
            $bommed = Join-Path $d 'b.ps1'
            _MsixWriteUtf8 -Path $plain  -Text '{"a":1}' -NoNewline
            _MsixWriteUtf8 -Path $bommed -Text '# x' -WithBom
            $out = [pscustomobject]@{
                Plain = ([IO.File]::ReadAllBytes($plain))[0..2] -join ' '
                Bom   = ([IO.File]::ReadAllBytes($bommed))[0..2] -join ' '
            }
            Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue
            $out
        }
        # '{"a' - no BOM.
        $res.Plain | Should -Be '123 34 97'
        # EF BB BF.
        $res.Bom   | Should -Be '239 187 191'
    }
}
