# =============================================================================
# Runtime deployment test loop (deploy -> launch -> probe -> verdict)
# -----------------------------------------------------------------------------
# Test-MsixDeployment installs a signed package into a clean Hyper-V VM via
# PowerShell Direct (no VM networking needed), launches it through the shell,
# probes for liveness/crashes, and returns a verdict object shaped like the
# other Test-Msix* results (bottom-line boolean + reasons + artifacts).
#
# The VM interaction is funnelled through _MsixInvokeInVM / _MsixCopyToVM so
# the orchestration is unit-testable via mocks; the real Hyper-V path only runs
# on a host with the module and a prepared golden VM.
#
# On failure the collected ProcMon/event artifacts feed straight back into
# Get-MsixProcMonFailure -> Get-MsixIsolationAdvice -> Invoke-MsixAutoFixFromAnalysis,
# closing the loop test -> analyze -> autofix -> retest.
# =============================================================================

function _MsixInvokeInVM {
    # Thin seam over PowerShell Direct so Test-MsixDeployment is mockable.
    # Returns whatever the scriptblock returns.
    param(
        [Parameter(Mandatory)] [string]$VMName,
        [Parameter(Mandatory)] [pscredential]$Credential,
        [Parameter(Mandatory)] [scriptblock]$ScriptBlock,
        [object[]]$ArgumentList
    )
    Invoke-Command -VMName $VMName -Credential $Credential -ScriptBlock $ScriptBlock -ArgumentList $ArgumentList -ErrorAction Stop
}

function _MsixCopyToVM {
    # Copies a host file into the VM over the PowerShell Direct session.
    param(
        [Parameter(Mandatory)] [string]$VMName,
        [Parameter(Mandatory)] [pscredential]$Credential,
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Destination
    )
    $session = New-PSSession -VMName $VMName -Credential $Credential -ErrorAction Stop
    try {
        Copy-Item -ToSession $session -Path $Path -Destination $Destination -Force -ErrorAction Stop
    } finally {
        Remove-PSSession -Session $session -ErrorAction SilentlyContinue
    }
}

function _MsixRestoreVMCheckpoint {
    param([Parameter(Mandatory)][string]$VMName, [Parameter(Mandatory)][string]$Checkpoint)
    Restore-VMCheckpoint -VMName $VMName -Name $Checkpoint -Confirm:$false -ErrorAction Stop
    Start-VM -Name $VMName -ErrorAction SilentlyContinue
}


function Test-MsixDeployment {
    <#
    .SYNOPSIS
        Installs, launches and probes a signed .msix inside a clean Hyper-V VM
        and returns a pass/fail verdict with reasons and diagnostic artifacts.

    .DESCRIPTION
        The automated runtime tier that complements static analysis:

          1. (optional) revert the VM to a clean checkpoint
          2. copy + trust the signing cert, then Add-AppxPackage the .msix
          3. launch via shell:AppsFolder\<PFN>!<AppId>
          4. probe: process alive after -SettleSeconds, no WER crash entry,
             no AppXDeployment-Server error events, (optional) a top-level
             window appeared
          5. return a verdict; on failure, pull the relevant event-log entries
             as artifacts so they can feed Invoke-MsixAutoFixFromAnalysis.

        VM interaction uses PowerShell Direct (Credential over the hypervisor
        bus — no VM network required). The VM must be a prepared golden image
        with Developer Mode / sideloading enabled and the module's runtime
        expectations met; see TEST-PLAN Scenario 14.

    .PARAMETER PackagePath
        The signed .msix to deploy (must be signed by a cert the VM will trust,
        or pass -CertPath to install one first).

    .PARAMETER VMName
        Name of the Hyper-V VM to deploy into.

    .PARAMETER Credential
        Local admin credential for the VM (PowerShell Direct auth).

    .PARAMETER CertPath
        Optional .cer to install into the VM's LocalMachine\TrustedPeople +
        Root before deployment (self-signed dev flows).

    .PARAMETER Checkpoint
        Optional VM checkpoint name to restore to before the run (clean slate).

    .PARAMETER AppId
        Application Id to launch. Default: the first Application in the manifest.

    .PARAMETER SettleSeconds
        Seconds to wait after launch before probing liveness. Default 10.

    .PARAMETER RequireWindow
        Also assert that the app created a top-level visible window (uses the
        VM's UI automation). Off by default (many valid apps are trayless).

    .PARAMETER KeepInstalled
        Do not remove the package / revert after the run (for manual inspection).

    .EXAMPLE
        $cred = Get-Credential
        Test-MsixDeployment -PackagePath .\app.msix -VMName 'Win11-24H2' `
            -Credential $cred -CertPath .\app.cer -Checkpoint 'clean'

    .OUTPUTS
        [pscustomobject] MSIX.DeploymentTestResult with Passed, PackageFullName,
        Reasons, Installed, Launched, ProcessAlive, WindowAppeared,
        CrashDetected, EventLogArtifacts.

    .LINK
        TEST-PLAN.md Scenario 14
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'phase',
        Justification = 'Phase marker consumed by the mockable _MsixInvokeInVM seam to discriminate calls, not by the remote scriptblocks themselves.')]
    param(
        [Parameter(Mandatory)] [string]$PackagePath,
        [Parameter(Mandatory)] [string]$VMName,
        [Parameter(Mandatory)] [pscredential]$Credential,
        [string]$CertPath,
        # Modification packages (#131) installed AFTER the main package so the
        # layered content/settings are part of the probed run.
        [string[]]$ModificationPackagePaths,
        [string]$Checkpoint,
        [ValidatePattern('^[A-Za-z_][A-Za-z0-9_.-]*$')]
        [string]$AppId,
        [ValidateRange(0, 600)]
        [int]$SettleSeconds = 10,
        [switch]$RequireWindow,
        [switch]$KeepInstalled
    )

    # Read identity on the host (avoids a round-trip and lets us build the AUMID).
    [xml]$manifest = Get-MsixManifest -Path $PackagePath
    $identityName = $manifest.Package.Identity.Name
    $apps = @($manifest.Package.Applications.Application)
    if ($AppId) {
        $app = $apps | Where-Object { $_.GetAttribute('Id') -eq $AppId } | Select-Object -First 1
        if (-not $app) { throw "Application '$AppId' not found in the manifest." }
    } else {
        $app = $apps | Select-Object -First 1
        if (-not $app) { throw 'No <Application> element found in the manifest.' }
    }
    $launchAppId = $app.GetAttribute('Id')

    $reasons = [System.Collections.Generic.List[string]]::new()
    $result = [ordered]@{
        PSTypeName        = 'MSIX.DeploymentTestResult'
        PackagePath       = $PackagePath
        VMName            = $VMName
        PackageFullName   = $null
        Installed         = $false
        ModificationsInstalled = 0
        Launched          = $false
        ProcessAlive      = $false
        WindowAppeared    = $null
        CrashDetected     = $false
        EventLogArtifacts = @()
        Reasons           = @()
        Passed            = $false
    }

    if ($Checkpoint) {
        Write-MsixLog -Level Info -Message "Restoring VM '$VMName' to checkpoint '$Checkpoint'."
        _MsixRestoreVMCheckpoint -VMName $VMName -Checkpoint $Checkpoint
    }

    # Stage the package (and cert, and modification packages) into the VM.
    $vmPkg = "C:\Windows\Temp\$([IO.Path]::GetFileName($PackagePath))"
    _MsixCopyToVM -VMName $VMName -Credential $Credential -Path $PackagePath -Destination $vmPkg
    $vmCert = $null
    if ($CertPath) {
        $vmCert = "C:\Windows\Temp\$([IO.Path]::GetFileName($CertPath))"
        _MsixCopyToVM -VMName $VMName -Credential $Credential -Path $CertPath -Destination $vmCert
    }
    $vmMods = @()
    foreach ($mod in @($ModificationPackagePaths | Where-Object { $_ })) {
        $vmMod = "C:\Windows\Temp\$([IO.Path]::GetFileName($mod))"
        _MsixCopyToVM -VMName $VMName -Credential $Credential -Path $mod -Destination $vmMod
        $vmMods += $vmMod
    }

    # Install (trust cert first if supplied), then any modification packages,
    # and capture the PackageFullName. The first ArgumentList element is a
    # phase marker so the mockable seam can discriminate the calls.
    $install = _MsixInvokeInVM -VMName $VMName -Credential $Credential -ArgumentList @('install', $vmPkg, $vmCert, $identityName, $vmMods) -ScriptBlock {
        param($phase, $pkgPath, $certPath, $idName, $modPaths)
        $r = [ordered]@{ Installed = $false; PackageFullName = $null; ModificationsInstalled = 0; Error = $null }
        try {
            if ($certPath) {
                Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null
                Import-Certificate -FilePath $certPath -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
            }
            Add-AppxPackage -Path $pkgPath -ErrorAction Stop
            $pkg = Get-AppxPackage -Name $idName | Select-Object -First 1
            $r.PackageFullName = $pkg.PackageFullName
            $r.Installed = [bool]$pkg
            foreach ($modPath in @($modPaths | Where-Object { $_ })) {
                Add-AppxPackage -Path $modPath -ErrorAction Stop
                $r.ModificationsInstalled++
            }
        } catch {
            $r.Error = $_.Exception.Message
        }
        [pscustomobject]$r
    }

    $result.Installed = [bool]$install.Installed
    $result.ModificationsInstalled = [int]$install.ModificationsInstalled
    $result.PackageFullName = $install.PackageFullName
    if (-not $install.Installed) {
        $null = $reasons.Add("Add-AppxPackage failed: $($install.Error)")
        $result.Reasons = @($reasons)
        return [pscustomobject]$result
    }

    # Launch via the AppsFolder AUMID and probe liveness inside the VM.
    $probe = _MsixInvokeInVM -VMName $VMName -Credential $Credential -ArgumentList @('probe', $install.PackageFullName, $launchAppId, $SettleSeconds, [bool]$RequireWindow) -ScriptBlock {
        param($phase, $pfn, $appId, $settle, $requireWindow)
        $r = [ordered]@{ Launched = $false; ProcessAlive = $false; WindowAppeared = $null; CrashDetected = $false; Events = @(); Error = $null }
        try {
            $family = ($pfn -split '_')[0] + '_' + ($pfn -split '_')[-1]
            $aumid = "$family!$appId"
            $before = @(Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id)
            Start-Process "shell:AppsFolder\$aumid" -ErrorAction Stop
            $r.Launched = $true
            Start-Sleep -Seconds $settle

            $after = @(Get-Process -ErrorAction SilentlyContinue)
            $new = @($after | Where-Object { $_.Id -notin $before -and $_.Path -and $_.Path -like '*\WindowsApps\*' })
            $r.ProcessAlive = ($new.Count -gt 0)

            if ($requireWindow) {
                $r.WindowAppeared = [bool](@($new | Where-Object { $_.MainWindowHandle -ne 0 }).Count -gt 0)
            }

            # WER + AppXDeployment errors in the last few minutes.
            $since = (Get-Date).AddMinutes(-5)
            $wer = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Windows Error Reporting'; StartTime = $since } -ErrorAction SilentlyContinue)
            $appx = @(Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-AppXDeploymentServer/Operational'; Level = 2; StartTime = $since } -ErrorAction SilentlyContinue)
            $r.CrashDetected = ($wer.Count -gt 0)
            $r.Events = @(($wer + $appx) | Select-Object -First 20 | ForEach-Object { "$($_.TimeCreated) [$($_.ProviderName)] $($_.Message -replace '\s+',' ')".Substring(0, [Math]::Min(400, "$($_.TimeCreated) [$($_.ProviderName)] $($_.Message -replace '\s+',' ')".Length)) })
        } catch {
            $r.Error = $_.Exception.Message
        }
        [pscustomobject]$r
    }

    $result.Launched          = [bool]$probe.Launched
    $result.ProcessAlive      = [bool]$probe.ProcessAlive
    $result.WindowAppeared    = $probe.WindowAppeared
    $result.CrashDetected     = [bool]$probe.CrashDetected
    $result.EventLogArtifacts = @($probe.Events)

    if (-not $probe.Launched)      { $null = $reasons.Add("Launch failed: $($probe.Error)") }
    if (-not $probe.ProcessAlive)  { $null = $reasons.Add("No packaged process alive after ${SettleSeconds}s.") }
    if ($probe.CrashDetected)      { $null = $reasons.Add('Windows Error Reporting recorded a crash during the run.') }
    if ($RequireWindow -and $probe.WindowAppeared -eq $false) { $null = $reasons.Add('No top-level window appeared (-RequireWindow).') }

    $windowOk = (-not $RequireWindow) -or ($probe.WindowAppeared -eq $true)
    $result.Passed = ($result.Installed -and $probe.Launched -and $probe.ProcessAlive -and -not $probe.CrashDetected -and $windowOk)
    $result.Reasons = @($reasons)

    if (-not $KeepInstalled) {
        _MsixInvokeInVM -VMName $VMName -Credential $Credential -ArgumentList @('cleanup', $identityName) -ScriptBlock {
            param($phase, $idName)
            Get-AppxPackage -Name $idName | Remove-AppxPackage -ErrorAction SilentlyContinue
        } | Out-Null
        if ($Checkpoint) {
            _MsixRestoreVMCheckpoint -VMName $VMName -Checkpoint $Checkpoint
        }
    }

    $verdict = if ($result.Passed) { 'Info' } else { 'Warning' }
    Write-MsixLog -Level $verdict -Message "Test-MsixDeployment: $($result.PackageFullName) Passed=$($result.Passed) ($($reasons -join '; '))"
    [pscustomobject]$result
}
