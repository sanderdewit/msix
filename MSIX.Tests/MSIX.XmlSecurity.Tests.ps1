BeforeAll {
    Import-Module (Resolve-Path (Join-Path $PSScriptRoot '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'XML loaders reject malicious input' -Tag 'Security' {

    It 'Rejects external entity reference (XXE)' {
        $xxe = @'
<?xml version="1.0"?>
<!DOCTYPE Package [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<Package><Identity Name="&xxe;" Publisher="CN=X" Version="1.0.0.0" /></Package>
'@
        # XmlReader with DtdProcessing=Prohibit must throw before parsing entities.
        { New-MsixManifestDocument -XmlText $xxe } | Should -Throw
    }

    It 'Rejects billion-laughs entity expansion' {
        $bomb = @'
<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<Package><Identity Name="&lol3;" Publisher="CN=X" Version="1.0.0.0" /></Package>
'@
        { New-MsixManifestDocument -XmlText $bomb } | Should -Throw
    }

    It 'Accepts a well-formed manifest without DTD' {
        $clean = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Applications><Application Id="A" Executable="x.exe" /></Applications>
</Package>
'@
        $doc = New-MsixManifestDocument -XmlText $clean
        $doc.Package.Identity.Name | Should -Be 'X'
    }
}
