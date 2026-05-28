BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Regression coverage for the P1 security findings raised in the code-security
# review (issues #49 template injection, #50 XXE, #51 Zip-Slip, #52 TLS floor).

Describe 'Template substitution is injection-safe (#49)' -Tag 'Security' {

    It 'doubles single quotes so a value cannot break out of its literal' {
        $tmpl = Join-Path -Path $TestDrive -ChildPath 'inj.ps1.tmpl'
        Set-Content -LiteralPath $tmpl -Value "`$x = '<#PARAM:V#>'" -Encoding utf8
        $rendered = InModuleScope MSIX -Parameters @{ Tmpl = $tmpl } {
            param($Tmpl)
            _MsixRenderTemplate -TemplatePath $Tmpl -Parameters @{ V = "a'; bad" }
        }
        $rendered | Should -Be "`$x = 'a''; bad'"
    }

    It 'produces a script with no injected statement for a hostile DisplayName' {
        $out = Join-Path -Path $TestDrive -ChildPath 'cs.ps1'
        New-MsixStandardScript -Name CreateShortcut -Parameters @{
            DisplayName = "x'; throw 'INJECTED'; '"
            Target      = 'app.exe'
        } -OutputPath $out | Out-Null

        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($out, [ref]$null, [ref]$errors)
        @($errors).Count | Should -Be 0

        # The payload must survive only as inert string data, never as a throw.
        $throws = $ast.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.ThrowStatementAst] }, $true)
        @($throws).Count | Should -Be 0

        # And the payload must survive verbatim as an inert string constant.
        $strings = $ast.FindAll(
            { param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
        @($strings.Value) | Should -Contain "x'; throw 'INJECTED'; "
    }
}

Describe 'Invoke-MsixManifestTransform rejects XXE on string input (#50)' -Tag 'Security' {

    It 'does not resolve external entities when handed untrusted manifest text' {
        $xxe = @'
<?xml version="1.0"?>
<!DOCTYPE Package [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<Package><Identity Name="&xxe;" Publisher="CN=X" Version="1.0.0.0" /></Package>
'@
        { Invoke-MsixManifestTransform -Manifest $xxe -Transform { } } | Should -Throw
    }

    It 'still transforms a well-formed manifest string' {
        $clean = '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"><Identity Name="X" Publisher="CN=X" Version="1.0.0.0" /></Package>'
        $doc = Invoke-MsixManifestTransform -Manifest $clean -Transform { }
        $doc.Package.Identity.Name | Should -Be 'X'
    }
}

Describe '_MsixExpandZip blocks Zip-Slip traversal (#51)' -Tag 'Security' {

    It 'throws and writes nothing outside the destination for a "..\\" entry' {
        Add-Type -AssemblyName System.IO.Compression
        Add-Type -AssemblyName System.IO.Compression.FileSystem

        $zipPath = Join-Path -Path $TestDrive -ChildPath 'evil.zip'
        $fs = [System.IO.File]::Open($zipPath, [System.IO.FileMode]::Create)
        $archive = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        $entry = $archive.CreateEntry('..\..\evil_zipslip.txt')
        $w = [System.IO.StreamWriter]::new($entry.Open())
        $w.Write('pwned'); $w.Dispose()
        $archive.Dispose(); $fs.Dispose()

        $dest = Join-Path -Path $TestDrive -ChildPath 'extract\sub'
        New-Item -Path $dest -ItemType Directory -Force | Out-Null

        { InModuleScope MSIX -Parameters @{ Zip = $zipPath; Dest = $dest } {
              param($Zip, $Dest)
              _MsixExpandZip -ArchivePath $Zip -DestinationPath $Dest
          } } | Should -Throw -ExpectedMessage '*Zip-Slip*'

        # The traversal target (TestDrive\extract\evil_zipslip.txt) must not exist.
        $escaped = Join-Path -Path $TestDrive -ChildPath 'extract\evil_zipslip.txt'
        Test-Path -LiteralPath $escaped | Should -BeFalse
    }
}

Describe 'TLS floor is raised at import (#52)' -Tag 'Security' {

    It 'includes TLS 1.2 in ServicePointManager.SecurityProtocol' {
        ([Net.ServicePointManager]::SecurityProtocol -band [Net.SecurityProtocolType]::Tls12) |
            Should -Not -Be 0
    }
}
