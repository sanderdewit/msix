BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

# Regression coverage for #18 — the accelerator YAML parser must handle nested
# maps + block lists (RemediationApproach trees) while remaining a safe,
# value-only parser that never instantiates types from hostile input.

Describe 'Accelerator YAML nested parsing (#18)' -Tag 'Accelerator', 'Security' {

    It 'parses scalars and inline lists (backward compatible)' {
        $doc = @'
Name: Contoso
Tags: [a, b, c]
'@
        $r = InModuleScope MSIX -Parameters @{ Y = $doc } { param($Y) ConvertFrom-MsixAcceleratorYaml -Yaml $Y }
        $r['Name'] | Should -Be 'Contoso'
        ($r['Tags'] -join ',') | Should -Be 'a,b,c'
    }

    It 'parses a nested map' {
        $doc = @'
Match:
  Publisher: "CN=Notepad"
  Executables: [notepad++.exe, gup.exe]
'@
        $r = InModuleScope MSIX -Parameters @{ Y = $doc } { param($Y) ConvertFrom-MsixAcceleratorYaml -Yaml $Y }
        $r['Match']['Publisher'] | Should -Be 'CN=Notepad'
        ($r['Match']['Executables'] -join ',') | Should -Be 'notepad++.exe,gup.exe'
    }

    It 'parses a block list of maps with deep nesting (RemediationApproach tree)' {
        $doc = @'
RemediationApproach:
  - Fix: RemoveUpdater
    FixDetails:
      Pattern: gup.exe
  - Fix: AddPsf
    FixDetails:
      PSFConfig:
        applications: [app1, app2]
'@
        $r = InModuleScope MSIX -Parameters @{ Y = $doc } { param($Y) ConvertFrom-MsixAcceleratorYaml -Yaml $Y }
        $steps = @($r['RemediationApproach'])
        $steps.Count | Should -Be 2
        $steps[0]['Fix'] | Should -Be 'RemoveUpdater'
        $steps[0]['FixDetails']['Pattern'] | Should -Be 'gup.exe'
        $steps[1]['Fix'] | Should -Be 'AddPsf'
        ($steps[1]['FixDetails']['PSFConfig']['applications'] -join ',') | Should -Be 'app1,app2'
    }

    It 'treats a YAML type tag as an inert literal string (no type instantiation)' {
        $doc = "Evil: !!python/object/apply:os.system ['rm -rf /']"
        $r = InModuleScope MSIX -Parameters @{ Y = $doc } { param($Y) ConvertFrom-MsixAcceleratorYaml -Yaml $Y }
        $r['Evil'] | Should -BeOfType ([string])
        $r['Evil'] | Should -BeLike '*python/object*'
    }

    It 'treats anchors/aliases as literal text (no resolution/expansion)' {
        $doc = @'
A: &anchor value
B: *anchor
'@
        $r = InModuleScope MSIX -Parameters @{ Y = $doc } { param($Y) ConvertFrom-MsixAcceleratorYaml -Yaml $Y }
        $r['A'] | Should -BeLike '*anchor*'
        $r['B'] | Should -Be '*anchor'
    }

    It 'ignores multi-document markers (single-doc only, no crash)' {
        $doc = @'
---
Name: one
---
Name: two
'@
        { InModuleScope MSIX -Parameters @{ Y = $doc } { param($Y) ConvertFrom-MsixAcceleratorYaml -Yaml $Y } } |
            Should -Not -Throw
    }

    It 'rejects tab indentation with a clear error' {
        $doc = "Match:`n`tPublisher: x"
        { InModuleScope MSIX -Parameters @{ Y = $doc } { param($Y) ConvertFrom-MsixAcceleratorYaml -Yaml $Y } } |
            Should -Throw -ExpectedMessage '*tab*'
    }
}
