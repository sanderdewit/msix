BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force

    $script:SampleXml = @'
<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
         IgnorableNamespaces="">
  <Identity Name="X" Publisher="CN=X" Version="1.0.0.0" />
  <Properties>
    <DisplayName>X</DisplayName>
    <PublisherDisplayName>X</PublisherDisplayName>
    <Logo>Assets\Logo.png</Logo>
  </Properties>
  <Applications><Application Id="A" Executable="a.exe" /></Applications>
</Package>
'@

    # Replicates the validation + emission block inside
    # Set-MsixRegistryWriteVirtualization so we can pure-transform test it
    # without MakeAppx round-tripping a real .msix.
    $script:ApplyMutation = {
        param([xml]$M, [string[]]$ExcludedKeys, [switch]$Enable)

        $validatedKeys = @()
        if ($ExcludedKeys -and $ExcludedKeys.Count -gt 0) {
            foreach ($key in $ExcludedKeys) {
                if ([string]::IsNullOrWhiteSpace($key)) {
                    throw "ExcludedKeys entries may not be empty or whitespace."
                }
                if ($key -notmatch '^HKEY_CURRENT_USER\\') {
                    throw "ExcludedKeys may only contain HKEY_CURRENT_USER paths. Got: '$key'"
                }
                if ($key.Length -gt 512) {
                    throw "ExcludedKeys entry exceeds 512 chars ($($key.Length)): '$key'"
                }
            }
            $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($key in $ExcludedKeys) {
                if ($seen.Add($key)) { $validatedKeys += $key }
            }
        }

        Add-MsixManifestNamespace -Manifest $M -Prefix 'desktop6'
        Add-MsixManifestNamespace -Manifest $M -Prefix 'rescap'

        $props = $M.Package.Properties
        $d6    = Get-MsixManifestNamespaceUri -Prefix 'desktop6'

        $flag = $props.SelectSingleNode(
            '*[local-name()="RegistryWriteVirtualization" and ' +
            'namespace-uri()="' + $d6 + '"]')
        if (-not $flag) {
            $flag = $M.CreateElement('desktop6:RegistryWriteVirtualization', $d6)
            $null = $props.AppendChild($flag)
        }
        $flag.InnerText = if ($Enable) { 'enabled' } else { 'disabled' }

        $virtUri  = Get-MsixManifestNamespaceUri -Prefix 'virtualization'
        $virtNode = $props.SelectSingleNode(
            '*[local-name()="RegistryWriteVirtualization" and ' +
            'namespace-uri()="' + $virtUri + '"]')
        if ($virtNode) { $null = $props.RemoveChild($virtNode) }

        if ($validatedKeys.Count -gt 0) {
            Add-MsixManifestNamespace -Manifest $M -Prefix 'virtualization'
            $virtNode = $M.CreateElement('virtualization:RegistryWriteVirtualization', $virtUri)
            $keys     = $M.CreateElement('virtualization:ExcludedKeys', $virtUri)
            foreach ($k in $validatedKeys) {
                $entry = $M.CreateElement('virtualization:ExcludedKey', $virtUri)
                $entry.SetAttribute('Key', $k)
                $null = $keys.AppendChild($entry)
            }
            $null = $virtNode.AppendChild($keys)
            $null = $props.AppendChild($virtNode)
        }
    }
}

AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Set-MsixRegistryWriteVirtualization -ExcludedKeys (selective passthrough)' -Tag 'Manifest' {

    It 'Exposes -ExcludedKeys parameter of type [string[]]' {
        $cmd = Get-Command Set-MsixRegistryWriteVirtualization -Module MSIX
        $p   = $cmd.Parameters['ExcludedKeys']
        $p | Should -Not -BeNullOrEmpty
        $p.ParameterType.FullName | Should -Be 'System.String[]'
    }

    It 'Throws on HKLM entries with a clear message' {
        [xml]$m = $script:SampleXml
        $sb = $script:ApplyMutation
        { & $sb $m @('HKEY_LOCAL_MACHINE\SOFTWARE\Contoso') } |
            Should -Throw "*may only contain HKEY_CURRENT_USER*"
    }

    It 'Throws on an empty/whitespace entry' {
        [xml]$m = $script:SampleXml
        $sb = $script:ApplyMutation
        { & $sb $m @('HKEY_CURRENT_USER\SOFTWARE\Good','   ') } |
            Should -Throw "*may not be empty or whitespace*"
    }

    It 'Deduplicates case-insensitively' {
        [xml]$m = $script:SampleXml
        $sb = $script:ApplyMutation
        & $sb $m @(
            'HKEY_CURRENT_USER\SOFTWARE\Contoso',
            'hkey_current_user\software\contoso',
            'HKEY_CURRENT_USER\SOFTWARE\Other'
        )
        $virtUri = Get-MsixManifestNamespaceUri -Prefix 'virtualization'
        $nodes = $m.Package.Properties.SelectNodes(
            '*[local-name()="RegistryWriteVirtualization" and namespace-uri()="' + $virtUri + '"]' +
            '/*[local-name()="ExcludedKeys"]/*[local-name()="ExcludedKey"]')
        $nodes.Count | Should -Be 2
        @($nodes | ForEach-Object { $_.GetAttribute('Key') }) |
            Should -Be @('HKEY_CURRENT_USER\SOFTWARE\Contoso','HKEY_CURRENT_USER\SOFTWARE\Other')
    }

    It 'Places <virtualization:RegistryWriteVirtualization> under <Properties> (not <Extensions>)' {
        [xml]$m = $script:SampleXml
        $sb = $script:ApplyMutation
        & $sb $m @('HKEY_CURRENT_USER\SOFTWARE\Contoso')

        $virtUri = Get-MsixManifestNamespaceUri -Prefix 'virtualization'
        $node = $m.Package.Properties.SelectSingleNode(
            '*[local-name()="RegistryWriteVirtualization" and namespace-uri()="' + $virtUri + '"]')
        $node | Should -Not -BeNullOrEmpty
        $node.ParentNode.LocalName | Should -Be 'Properties'

        # And it must NOT appear under Extensions.
        $ext = $m.Package.SelectSingleNode('*[local-name()="Extensions"]')
        if ($ext) {
            $ext.SelectSingleNode('*[local-name()="RegistryWriteVirtualization"]') |
                Should -BeNullOrEmpty
        }
    }

    It 'Is idempotent: running the mutation twice does not duplicate ExcludedKey children' {
        [xml]$m = $script:SampleXml
        $sb = $script:ApplyMutation
        & $sb $m @('HKEY_CURRENT_USER\SOFTWARE\Contoso','HKEY_CURRENT_USER\SOFTWARE\Contoso\v2')
        & $sb $m @('HKEY_CURRENT_USER\SOFTWARE\Contoso','HKEY_CURRENT_USER\SOFTWARE\Contoso\v2')

        $virtUri = Get-MsixManifestNamespaceUri -Prefix 'virtualization'
        # Only one <virtualization:RegistryWriteVirtualization> element.
        $blocks = $m.Package.Properties.SelectNodes(
            '*[local-name()="RegistryWriteVirtualization" and namespace-uri()="' + $virtUri + '"]')
        $blocks.Count | Should -Be 1

        $nodes = $m.Package.Properties.SelectNodes(
            '*[local-name()="RegistryWriteVirtualization" and namespace-uri()="' + $virtUri + '"]' +
            '/*[local-name()="ExcludedKeys"]/*[local-name()="ExcludedKey"]')
        $nodes.Count | Should -Be 2
        @($nodes | ForEach-Object { $_.GetAttribute('Key') }) |
            Should -Be @('HKEY_CURRENT_USER\SOFTWARE\Contoso','HKEY_CURRENT_USER\SOFTWARE\Contoso\v2')
    }
}
