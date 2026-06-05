BeforeAll {
    Import-Module -Name (Resolve-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath '..\MSIX.psd1')) -Force
}
AfterAll { Remove-Module MSIX -ErrorAction SilentlyContinue }

Describe 'Win32 App Isolation' -Tag 'AppIsolation' {

    It 'Get-MsixIsolationCapability returns a list with promptForAccess' {
        (Get-MsixIsolationCapability).Name | Should -Contain 'isolatedWin32-promptForAccess'
    }

    It 'All rescap capabilities follow isolatedWin32- naming' {
        Get-MsixIsolationCapability |
            Where-Object ElementType -eq 'rescap:Capability' |
            ForEach-Object {
                $_.Name | Should -Match '^isolatedWin32-'
            }
    }

    It 'Device capabilities have ElementType DeviceCapability' {
        $deviceCaps = @(Get-MsixIsolationCapability | Where-Object ElementType -eq 'DeviceCapability')
        $deviceCaps.Count | Should -BeGreaterThan 0
        $deviceCaps.Name | Should -Contain 'microphone'
        $deviceCaps.Name | Should -Contain 'webcam'
    }
}
