BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Manifest namespace registry (v0.10)' -Tag 'Manifest' {

    It 'Knows uap5 / uap6 / uap10 / desktop2 / desktop6' {
        foreach ($p in 'uap5','uap6','uap10','desktop2','desktop6') {
            (Get-MsixManifestNamespaceUri $p) | Should -Not -BeNullOrEmpty
        }
    }

    It 'Returns the documented uap10 URI' {
        Get-MsixManifestNamespaceUri 'uap10' |
            Should -Be 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
    }

    It 'Returns the documented desktop6 URI' {
        Get-MsixManifestNamespaceUri 'desktop6' |
            Should -Be 'http://schemas.microsoft.com/appx/manifest/desktop/windows10/6'
    }

    It 'Add-MsixManifestNamespace works for all the new prefixes' {
        $xml = [xml]@'
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         IgnorableNamespaces="">
  <Identity Name="A" Publisher="CN=X" Version="1.0.0.0" />
  <Applications><Application Id="A" Executable="x.exe" /></Applications>
</Package>
'@
        foreach ($p in 'uap5','uap6','uap10','desktop2','desktop6') {
            Add-MsixManifestNamespace -Manifest $xml -Prefix $p
        }
        foreach ($p in 'uap5','uap6','uap10','desktop2','desktop6') {
            $xml.Package.IgnorableNamespaces | Should -Match "\b$p\b"
        }
    }
}

Describe 'Manifest-only fixer cmdlets are exported (v0.10)' -Tag 'Manifest' {
    It 'Set-MsixFileSystemWriteVirtualization is exported' {
        Get-Command Set-MsixFileSystemWriteVirtualization -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Set-MsixRegistryWriteVirtualization is exported' {
        Get-Command Set-MsixRegistryWriteVirtualization -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Set-MsixInstalledLocationVirtualization is exported' {
        Get-Command Set-MsixInstalledLocationVirtualization -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'Add-MsixLoaderSearchPathOverride is exported and validates 1..5 paths' {
        $cmd = Get-Command Add-MsixLoaderSearchPathOverride -Module MSIX -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
        $param = $cmd.Parameters['Paths']
        $vc = $param.Attributes |
              Where-Object { $_ -is [System.Management.Automation.ValidateCountAttribute] } |
              Select-Object -First 1
        $vc.MinLength | Should -Be 1
        $vc.MaxLength | Should -Be 5
    }
    It 'Add-MsixFirewallRule is exported with proper Direction enum' {
        $cmd = Get-Command Add-MsixFirewallRule -Module MSIX -ErrorAction SilentlyContinue
        $cmd | Should -Not -BeNullOrEmpty
        $vs = $cmd.Parameters['Direction'].Attributes |
              Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
              Select-Object -First 1
        $vs.ValidValues | Should -Contain 'in'
        $vs.ValidValues | Should -Contain 'out'
    }
    It 'Add-MsixStartupTask, Add-MsixProtocolHandler, Add-MsixFileTypeAssociation are exported' {
        foreach ($n in 'Add-MsixStartupTask','Add-MsixProtocolHandler','Add-MsixFileTypeAssociation') {
            Get-Command -Name $n -Module MSIX -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Set-MsixInstalledLocationVirtualization parameter validation' -Tag 'Manifest' {
    It 'Rejects invalid ModifiedItems values' {
        $cmd = Get-Command Set-MsixInstalledLocationVirtualization
        $vs  = $cmd.Parameters['ModifiedItems'].Attributes |
               Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } |
               Select-Object -First 1
        $vs.ValidValues | Should -Be @('keep','reset')
    }
}
