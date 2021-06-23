#new 23-06-2021
##############################################################################################################
# HELPER Functions
##############################################################################################################

function get-MsixAppXManifest {
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $sourcefile,
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
            )]
        [string[]]  $extractfolder
    )
    BEGIN {
    Add-Type -Assembly System.IO.Compression.FileSystem
    $item = Get-Item -Path $sourcefile
    }
    PROCESS {
    $zip = [IO.Compression.ZipFile]::OpenRead($($item.FullName))
    $zip.Entries | Where-Object {$_.Name -eq 'AppxManifest.xml'} | ForEach-Object {[System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$extractfolder\AppxManifest.xml", $true)}
    $zip.Dispose()
    }
    END {
    Clear-Variable sourcefile, extractfolder, item, zip
    }
}

function start-MsixProcess {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $Process,
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
            )]
        [string[]]  $arguments
    )
    BEGIN {
    $item = Get-Item -Path $Process
    }
    PROCESS {
    $ProcessInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName = $($item.FullName)
    $ProcessInfo.WorkingDirectory = Get-Location
    $ProcessInfo.RedirectStandardError = $true
    #$ProcessInfo.RedirectStandardOutput = $true #uncomment due to 4096 buffer issue
    $ProcessInfo.UseShellExecute = $false
    $ProcessInfo.Arguments = $arguments
    $MsixProcess = New-Object System.Diagnostics.Process
    $MsixProcess.StartInfo = $ProcessInfo
    $null = $MsixProcess.Start()
    $MsixProcess.WaitForExit()
    #$stdout = $MsixProcess.StandardOutput.ReadToEnd()
    $stderr = $MsixProcess.StandardError.ReadToEnd()
    $exitcode = $MsixProcess.ExitCode
    }
    END {
    return [pscustomobject]@{
    'stdout' = $stdout
    'stderr' = $stderr
    'exitcode' = $exitcode
    }
    Clear-Variable ProcessInfo, MsixProcess, stdout, stderr, process, arguments, item
    }
}

function start-MsixSigntool {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackagePath,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
            )]
        [string[]]  $pfx,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
            )]
        [string[]]  $pfxpassword
    )
    BEGIN {
    $msix_module_ver = (Get-Module msix -ListAvailable |select -ExpandProperty version|Sort-Object)[-1]
    $msixmodule = Get-Module msix -ListAvailable|Where-Object {$_.version -eq $msix_module_ver}
    $msixtool = $msixmodule.ModuleBase

    $fileinfo = Get-Item $PackagePath
    if ($pfx){
    if (!($pfxpassword)){throw 'missing pfx password'}
    $cert = Get-Item -Path $pfx
    $arguments = "sign /v /tr http://timestamp.digicert.com /fd sha256 /f $($cert.FullName) /p $pfxpassword $($fileinfo.FullName)"
    }
    else {
    $arguments = "sign /v /tr http://timestamp.digicert.com /fd sha256 /a $($fileinfo.FullName)"
    }

    }
    PROCESS {
    $signing = start-MsixProcess -Process "$msixtool\tools\signtool.exe" -arguments $arguments
    if ($($signing.exitcode) -ne '0'){write-error -Message "signing went wrong: $($signing.stderr)" -RecommendedAction "please check eventlog Microsoft\Windows\AppxPackagingom"}
    }
    END {
    Clear-Variable fileinfo, PackagePath
    }

}

function new-MsixPsfJson {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position
            )]
        [string[]] $AppxManiFest,
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
            )]
            [validateset('FileRedirectionFixup','TraceFixup','WaitForDebuggerFixup','DynamicLibraryFixup','EnvVarFixup','KernelTraceControl','RegLegacyFixups')]
        [string] $fixup,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2
            )]
        [string[]] $patterns,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 3
            )]
        [validateset('HKCU','HKLM')]
        [string] $hive,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 4
            )]
        [validateset('FULL2RW','FULL2R','Full2MaxAllowed','RW2R','RW2MaxAllowed')]
        [string] $access,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 4
            )]
        [string] $base
    )
    BEGIN {
    $manifest = get-item $AppxManiFest
    [xml]$appinfo = Get-Content -Path $($manifest.Fullname)

        if ($fixup -eq 'RegLegacyFixups'){
         if (!($access)){$access = Read-Host -Prompt 'please specify access level (FULL2RW,FULL2R,Full2MaxAllowed,RW2R,RW2MaxAllowed)'}
         if (!($hive)){$hive = Read-Host -Prompt 'please specify the hive (HKCU, HKLM)'}
         if (!($patterns)){$patterns = Read-Host -Prompt 'please specify the patterns (software\app\*)'}
        }
        if ($fixup -eq 'FileRedirectionFixup'){
         if (!($base)){$base = Read-Host -Prompt 'please specify base directory (e.g. app)'}
         if (!($patterns)){$patterns = Read-Host -Prompt 'please specify the patterns (e.g. *.log)'}
        }
    }
    PROCESS {
    $applications = $appinfo.Package.Applications.Application
    
    $appjson = foreach ($app in $applications){
    [pscustomobject]@{
    'id' = $app.id
    'executable' = $app.executable.replace('\','/')
    }
    }
    
    if ($fixup -eq 'FileRedirectionFixup'){
    $json = @{
        'applications' = [array]$appjson
        'processes' = [array]@{
            'executable' = $app.executable.replace('\','/').split('/')[-1].replace('.exe','')
                'fixups'= [array]@{
                    'dll' = "$fixup.dll"
                    'config' = @{
                        'redirectedPaths' = @{
                            'packageRelative' = [array]@{
                                'base'= $base
                                'patterns' = [array]$patterns
                            }
                        }
                    }
                }
        }
    }
    }

    if ($fixup -eq 'RegLegacyFixups'){
    $json = @{
        'applications' = [array]$appjson
        'processes' = [array]@{
            'executable' = $app.executable.replace('\','/').split('/')[-1].replace('.exe','')
                'fixups'= [array]@{
                    'dll' = "$fixup.dll"
                    'config' = @{
                        'type' = 'ModifyKeyAccess'
                        'remediation' = @{
                            'hive' = $hive
                                'access' = $access
                                'patterns' = [array]$patterns
                        }
                    }
                }
            }
    }
    }
    
    return $json|ConvertTo-Json -Depth 10
    
    }
    END {
    Clear-Variable appjson, applications, app, appinfo, manifest
    }
}
###################################################################################################
#REGULAR Functions
###################################################################################################
Function Get-MsixInfo {
<#
.SYNOPSIS
    Get msix info for a specific package


.NOTES
    Name: Get-MsixInfo
    Author: Sander de Wit
    Version: 1.0
    DateCreated: 04-05-2021


.EXAMPLE
    Get-MsixInfo -PackagePath c:\temp\app.msix

.EXAMPLE
    Get-MsixInfo -PackagePath c:\temp\app.msix -detailed

#>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackagePath,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $false,
            Position = 1
            )]
        [switch] $detailed

    )

    BEGIN {
    $fileinfo = Get-Item -Path $PackagePath
    $tempdir = "$env:temp\msix\$($fileinfo.BaseName)"
    if (!(Test-Path -Path $tempdir)){
    $null = New-Item -ItemType Directory -force -path $tempdir}
    else
    {
    Write-Verbose "temp directory already unpacked, cleaning up"
    Remove-Item -Path $tempdir\* -Force -Recurse}
    try {
    write-verbose 'calling makeappx to unpack package'
    #$null = .\Tools\MakeAppx.exe unpack /p $($fileinfo.FullName) /d $tempdir /o
    get-MsixAppXManifest -sourcefile $fileinfo.FullName -extractfolder $tempdir
    }catch {
    Write-Error "unable to extract the msix package"
    }
    }

    PROCESS {
    Write-Verbose "reading $($tempdir)\AppxManifest.xml"
    [xml]$appinfo = Get-Content -Path "$tempdir\AppxManifest.xml"
    Write-Verbose 'getting signature information'
    $signinfo = Get-AuthenticodeSignature -FilePath $fileinfo

    $info = @()
    $info += [pscustomobject]@{
    'name' = $($appinfo.Package.Identity.Name)
    'DisplayName' = $($appinfo.Package.Properties.DisplayName)
    'Publisher' = $($appinfo.Package.Identity.Publisher)
    'PublisherDisplayName' = $($appinfo.Package.Properties.PublisherDisplayName)
    'Version' = $($appinfo.Package.Identity.Version)
    'ProcessorArchitecture' = $($appinfo.Package.Identity.ProcessorArchitecture)
    'Description' = $($appinfo.Package.Properties.Description)
    'Signed' = $($signinfo.Status)
    'SignedBy' = $($signinfo.SignerCertificate.Subject)
    'ThumbPrint' = $($signinfo.SignerCertificate.Thumbprint)
    'TimeStampCertificate' = $($signinfo.TimeStamperCertificate)
    }
    if ($detailed)
        {
         $info += $($appinfo.Package.Applications.Application)
        }

    return $info
    }

    END {
    Write-Verbose "cleaning up"
    Remove-Item -Path $tempdir -Force -Recurse
    }
}

Function start-MsixCmd {
<#
.SYNOPSIS
    start command in specific package


.NOTES
    Name: start-MsixCmd
    Author: Sander de Wit
    Version: 1.0
    DateCreated: 04-05-2021


.EXAMPLE
    start-MsixCmd -PackageName npp -command notepad.exe

.EXAMPLE
    start-MsixCmd -PackageName npp

#>

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackageName,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string]  $command = 'cmd.exe'
    )

    BEGIN {
    try {
    $appx = Get-AppxPackage -Name $PackageName
    }
    catch {
    $appx = Get-AppxPackage|Where-Object {$_.name -like "*$($PackageName)*"}
    }
    if ($appx.count -gt '1'){ throw ('multiple applications match the criteria')}
    $AppXManifest = Get-AppPackageManifest -Package $($appx.PackageFullName)
    $PackageFamilyName = $($AppX.PackageFamilyName)
    $apps = $($AppXManifest.Package.Applications.Application)
    if ($apps.count -gt '1'){Write-Error -Message "multiple apps found, selecting app 1 $($apps[0].Id)"
    $appId = $apps[0].Id}
    else {$appId = $apps.Id}
    }

    PROCESS {
    Invoke-CommandInDesktopPackage -PackageFamilyName $PackageFamilyName -PreventBreakaway -command $command -AppId $appId
    }

    END {
    Clear-Variable appx, packagename, AppXManifest
    }
}

Function update-MsixSigner {
<#
.SYNOPSIS
    signs MSIX with new certificate and updates publisher.


.NOTES
    Name: update-MsixSigner
    Author: Sander de Wit
    Version: 1.0
    DateCreated: 04-05-2021


.EXAMPLE
    update-MsixSigner -PackagePath app.msix -publisher 'OU=Demo, O=Demo, C=NL' -pfx 'signer.pfx' -pfxpassword Password

.EXAMPLE
    update-MsixSigner -PackagePath app.msix -publisher 'OU=Demo, O=Demo, C=NL'

#>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackagePath,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
            )]
        [string[]]  $publisher,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2
            )]
        [string[]]  $pfx,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 3
            )]
        [string[]]  $pfxpassword
    )

    BEGIN {
    $msix_module_ver = (Get-Module msix -ListAvailable |select -ExpandProperty version|Sort-Object)[-1]
    $msixmodule = Get-Module msix -ListAvailable|Where-Object {$_.version -eq $msix_module_ver}
    $msixtool = $msixmodule.ModuleBase
    Write-Verbose -Message "unpacking msix to temp folder"
    $fileinfo = Get-Item -Path $PackagePath
    $tempdir = "$env:temp\msix\$($fileinfo.BaseName)"
    if (!(Test-Path -Path $tempdir)){
    $null = New-Item -ItemType Directory -force -path $tempdir}
    else
    {
    Write-Verbose -Message "temp directory already unpacked, cleaning up"
    Remove-Item -Path $tempdir\* -Force -Recurse}
    write-verbose -Message 'calling makeappx to unpack package'
    $null = start-MsixProcess -Process "$msixtool\Tools\MakeAppx.exe" -arguments "unpack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
    }

    PROCESS {
    #modify to AppXManifest when necessary
    Write-Verbose -Message "reading $($tempdir)\AppxManifest.xml"
    [xml]$appinfo = Get-Content -Path "$tempdir\AppxManifest.xml"
    if ($publisher)
     {
        if ($($appinfo.Package.Identity.Publisher) -ceq $publisher)
            {
             Write-Output -InputObject "not changing the publisher, as it is already a match"
             #Microsoft MSIX team recommends to use of signtool over powershell Get-AuthenticodeSignature
             start-Msixsigntool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
        }
        else
        {
         $appinfo.Package.Identity.Publisher = [string]$publisher
         Write-Output -InputObject "modifying msix publisher"
         $appinfo.Save("$tempdir\AppxManifest.xml")
         Write-Output -InputObject "packing up MSIX again"
         $null = start-MsixProcess -Process "$msixtool\tools\MakeAppx.exe" -arguments "pack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
         start-Msixsigntool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
        }
     }
     #no publisher specified
    else {
     start-Msixsigntool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
     }
    }
    END {
    Write-Verbose -Message "cleaning up"
    Remove-Item -Path $tempdir -Force -Recurse
    Remove-Variable fileinfo, appinfo
    }
}

Function add-MsixPsf {
<#
.SYNOPSIS
    adds to Package Support Framework to msix package


.NOTES
    Name: add-MsixPsf
    Author: Sander de Wit
    Version: 1.0
    DateCreated: 16-06-2021


.EXAMPLE
    add-MsixPsf -PackagePath npp.msix

.EXAMPLE
    add-MsixPsf -PackagePath npp.msix -pfx cert.pfx -pfxpassword P$ssw0rd
#>

    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackagePath,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
            )]
        [string[]]  $pfx,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2
            )]
        [string[]]  $pfxpassword,
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 3
            )]
            [validateset('FileRedirectionFixup','TraceFixup','WaitForDebuggerFixup','DynamicLibraryFixup','EnvVarFixup','KernelTraceControl','RegLegacyFixups')]
        [string] $fixup,
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 4
            )]
        [string[]] $patterns,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 5
            )]
        [validateset('HKCU','HKLM')]
        [string] $hive,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 6
            )]
        [validateset('FULL2RW','FULL2R','Full2MaxAllowed','RW2R','RW2MaxAllowed')]
        [string] $access,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 7
            )]
        [string] $base
    )

    BEGIN {
    $msix_module_ver = (Get-Module msix -ListAvailable |select -ExpandProperty version|Sort-Object)[-1]
    $msixmodule = Get-Module msix -ListAvailable|Where-Object {$_.version -eq $msix_module_ver}
    $msixtool = $msixmodule.ModuleBase
    
    $fileinfo = Get-Item -Path $PackagePath
    $tempdir = "$env:temp\msix\$($fileinfo.BaseName)"
    if (!(Test-Path -Path $tempdir)){
    $null = New-Item -ItemType Directory -force -path $tempdir}
    else
    {
    Write-Verbose -Message "temp directory already unpacked, cleaning up"
    Remove-Item -Path $tempdir\* -Force -Recurse}
    write-verbose -Message 'calling makeappx to unpack package'
    $unpack = start-MsixProcess -Process "$msixtool\Tools\MakeAppx.exe" -arguments "unpack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
    if ($unpack.exitcode -ne '0'){Write-Error -Message "something went wrong: $($unpack.stderr)"}
    }
    PROCESS {
    #reading AppXManifest to find applications
    Write-Verbose -Message "reading $($tempdir)\AppxManifest.xml"
    [xml]$appinfo = Get-Content -Path "$tempdir\AppxManifest.xml"
    Write-Verbose -Message "generating config.json"
    if ($appinfo.Package.Applications.Application.gettype().name -eq 'XMLElement'){
    $appfolder = "$tempdir\$($appinfo.Package.Applications.Application.Executable.substring(0,$($appinfo.Package.Applications.Application.Executable.LastIndexOf('\'))))"
    }
    else{
    $appfolder = "$tempdir\$($appinfo.Package.Applications.Application[0].Executable.substring(0,$($appinfo.Package.Applications.Application[0].Executable.LastIndexOf('\'))))"
    }
    if($PSCmdlet.ShouldProcess("$appfolder\config.json", "Writing config.json")){
    $json = new-MsixPsfJson -AppxManiFest "$tempdir\AppxManifest.xml" -fixup $fixup -patterns $patterns -base $base -hive $hive -access $access 
    Write-Verbose $json
    $json|Out-File "$appfolder\config.json"
    }
    #copy items to relevant folders
    Write-Verbose "copying PSF files, add check for x86 or x64"
    if ($appfolder -like '*ProgramFilesX64*'){
    if($PSCmdlet.ShouldProcess("psfrundll64.exe, psfruntime64.dll", "copying Psf files")){
    Copy-Item "$msixtool\PSF\PsfRunDll64.exe" $appfolder
    Copy-Item "$msixtool\PSF\PsfRuntime64.dll" $appfolder
    Copy-Item "$msixtool\PSF\$($fixup)64.dll" "$appfolder\$($fixup).dll"
    }}else {
    if($PSCmdlet.ShouldProcess("psfrundll32.exe, psfruntime32.dll", "copying Psf files")){
    Copy-Item "$msixtool\PSF\PsfRunDll32.exe" $appfolder
    Copy-Item "$msixtool\PSF\PsfRuntime32.dll" $appfolder
    Copy-Item "$msixtool\PSF\$($fixup)32.dll" "$appfolder\$($fixup).dll"
    }}
    $i = 0
    foreach ($application in $appinfo.Package.Applications.Application){
    $i++
        if ($i -gt '1'){
        if($PSCmdlet.ShouldProcess($application.Executable.replace($application.Executable.split('\')[-1],"PsfLauncher$($I).exe"), "copying and adding in manifest")){
        if ($application.Executable -like '*ProgramFilesX64*'){
         Copy-Item -Path "$msixtool\PSF\PsfLauncher64.exe" -Destination "$appfolder\PsfLauncher$($I).exe"
         }else {
         Copy-Item -Path "$msixtool\PSF\PsfLauncher32.exe" -Destination "$appfolder\PsfLauncher$($I).exe"}
         $application.Executable =  $application.Executable.replace($application.Executable.split('\')[-1],"PsfLauncher$($I).exe")
         }
        }
        else
        {
        if($PSCmdlet.ShouldProcess($application.Executable.replace($application.Executable.split('\')[-1],"PsfLauncher.exe"), "copying and adding in manifest")){
         $application.Executable = $application.Executable.replace($application.Executable.split('\')[-1],"PsfLauncher.exe$($I)")
        if ($application.Executable -like '*ProgramFilesX64*'){
         Copy-Item -Path "$msixtool\PSF\PsfLauncher64.exe" -Destination "$appfolder\PsfLauncher$($I).exe"
         }else {
         Copy-Item -Path "$msixtool\PSF\PsfLauncher32.exe" -Destination "$appfolder\PsfLauncher$($I).exe"}         }
        }
    }
    if($PSCmdlet.ShouldProcess("AppXManifest.XML", "updating manifest")){
    $appinfo.Save("$tempdir\AppxManifest.xml")
    }
    Write-Output "opening config.json for verification/modifcation"
    if($PSCmdlet.ShouldProcess("$appfolder\config.json", "invoking notepad")){
     $choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
     $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
     $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

    #detect PSF executables

     $decision = $Host.UI.PromptForChoice($($app.executable), "edit the config.json before packing", $choices, 1) 
     if ($decision -eq '0'){
    Start-Process -FilePath 'notepad.exe' -Wait -ArgumentList "$appfolder\config.json"
    }
    Write-Output "validating config.json"
    try {$null = get-content -Path "$appfolder\config.json"|ConvertFrom-Json}
    catch {Write-Error "invalid json"}
    }
    #pack application again
     Write-Output -InputObject "packing up MSIX again"
     if($PSCmdlet.ShouldProcess("packaging to msix", "invoke makeappx")){
     $null = start-MsixProcess -Process "$msixtool\tools\MakeAppx.exe" -arguments "pack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
     }
     if($PSCmdlet.ShouldProcess("signing msix", "invoke signtool")){
     start-Msixsigntool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
     }

    }
    END {
    Write-Verbose -Message "cleaning up"
    #Remove-Item -Path $tempdir -Force -Recurse
    Remove-Variable fileinfo, appinfo
    }
}
function add-MsixAlias {
   <#
.SYNOPSIS
    add msix execution alias for msix applications


.NOTES
    Name: Add-MsixAlias
    Author: Sander de Wit
    Version: 1.0
    DateCreated: 09-06-2021


.EXAMPLE
    add-MsixAlias -PackagePath c:\temp\app.msix

.EXAMPLE
    add-MsixAlias -PackagePath c:\temp\app.msix -force

#>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackagePath,
        [string[]]  $pfx,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 3
            )]
        [string[]]  $pfxpassword
    )
    BEGIN {
    $msix_module_ver = (Get-Module msix -ListAvailable |select -ExpandProperty version|Sort-Object)[-1]
    $msixmodule = Get-Module msix -ListAvailable|Where-Object {$_.version -eq $msix_module_ver}
    $msixtool = $msixmodule.ModuleBase
    Write-Verbose -Message "unpacking msix to temp folder"
    $fileinfo = Get-Item -Path $PackagePath
    $tempdir = "$env:temp\msix\$($fileinfo.BaseName)"
    if (!(Test-Path -Path $tempdir)){
    $null = New-Item -ItemType Directory -force -path $tempdir}
    else
    {
    Write-Verbose -Message "temp directory already unpacked, cleaning up"
    Remove-Item -Path $tempdir\* -Force -Recurse}
    write-verbose -Message 'calling makeappx to unpack package'
    Write-Verbose "$($fileinfo.fullname)"
    $null = start-MsixProcess -Process "$msixtool\Tools\MakeAppx.exe" -arguments "unpack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
    if ($pfx -and $pfxpassword -eq $null){throw 'missing pfx password when pfx specified'}
    }

    PROCESS {
    Write-Verbose -Message "reading $($tempdir)\AppxManifest.xml"
    [xml]$appinfo = Get-Content -Path "$tempdir\AppxManifest.xml"

    #check schema for desktop
    if ($appinfo.Package.Attributes.'#text' -notcontains 'http://schemas.microsoft.com/appx/manifest/desktop/windows10'){
     Write-Verbose -Message "adding desktop in schema"
     $appinfo.Package.IgnorableNamespaces += ' desktop'
     $appinfo.Package.SetAttribute('xmlns:desktop','http://schemas.microsoft.com/appx/manifest/desktop/windows10')
    }
    #check schema for uap3
    if ($appinfo.Package.Attributes.'#text' -notcontains 'http://schemas.microsoft.com/appx/manifest/uap/windows10/3'){
     Write-Verbose -Message "adding uap in schema"
     $appinfo.Package.IgnorableNamespaces += ' uap3'
     $appinfo.Package.SetAttribute('xmlns:uap3','http://schemas.microsoft.com/appx/manifest/uap/windows10/3')
    }

    foreach ($app in $($appinfo.Package.Applications.Application))
    {
    #add child per app
     $choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
     $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
     $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

    #detect PSF executables

     $decision = $Host.UI.PromptForChoice($($app.executable), "add alias for $($app.executable)?", $choices, 1) 
     #detecting if alias already exists
     if ($app.Extensions.Extension.AppExecutionAlias.ExecutionAlias){$detected = '1'
     Write-Warning -Message "alias already detected for $($app.Extensions.Extension.AppExecutionAlias.ExecutionAlias.alias)"
     }else {$detected = '0'}

    if ($decision -eq 0 -and $detected -eq '0') {
      Write-Verbose -Message "adding alias for $($app.executable)"
     $executable = $app.Executable.Replace('\','/')
      if ($executable -like '*PSFLauncher*.exe'){
     write-verbose -Message "PSF detected, reading config.json"
     $config = get-content "$tempdir\$($executable.Substring(0,$executable.IndexOf($executable.Split('/')[-1])))\config.json"|ConvertFrom-Json
     $executable = ($config.applications|Where-Object {$_.id -eq $app.Id}).executable.replace('\','/')
     }
     $ExtensionChild = $appinfo.CreateElement('Extensions',$appinfo.Package.NamespaceURI)
     $uap3 = $appinfo.CreateElement('uap3:Extension',$appinfo.Package.uap3)
     $uap3.SetAttribute('EntryPoint','Windows.FullTrustApplication')
     $uap3.SetAttribute('desktop:Executable',$Executable)
     $uap3.SetAttribute('Category','windows.appExecutionAlias')
     $UAP3executionalias = $appinfo.CreateElement('uap3:AppExecutionAlias',$uap3.NamespaceURI)
     $Desktopexecutionalias = $appinfo.CreateElement('desktop:ExecutionAlias','http://schemas.microsoft.com/appx/manifest/desktop/windows10')
     $Desktopexecutionalias.SetAttribute('Alias',$($executable.Split('/')[-1]))

     $extension = $app.AppendChild($ExtensionChild)
     $ext = $extension.AppendChild($uap3)
     $uap3alias = $ext.AppendChild($UAP3executionalias)
     $null = $uap3alias.AppendChild($Desktopexecutionalias)
     } else {
      Write-Verbose -Message "skipping $($app.executable)"
     }
    }
    $appinfo.Save("$tempdir\AppxManifest.xml")
    Write-Output -InputObject "packing msix again"
    $null = start-MsixProcess -Process "$msixtool\tools\MakeAppx.exe" -arguments "pack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
    Write-Output -InputObject "signing msix"
    start-Msixsigntool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
    }
    END {
    Write-Verbose -Message "cleaning up"
    Remove-Item -Path $tempdir -Force -Recurse
    Remove-Variable fileinfo, appinfo, detected
    }
}

function remove-MsixStartMenuEntry {
   <#
.SYNOPSIS
    remove msix start menu entry from application


.NOTES
    Name: remove-MsixStartMenuEntry
    Author: Sander de Wit
    Version: 1.0
    DateCreated: 09-06-2021


.EXAMPLE
    remove-MsixStartMenuEntry -PackagePath c:\temp\app.msix

.EXAMPLE
    remove-MsixStartMenuEntry -PackagePath c:\temp\app.msix -pfx cert.pfx -pfxpassword 'secret'

#>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackagePath,
        [string[]]  $pfx,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 3
            )]
        [string[]]  $pfxpassword
    )
    BEGIN {
    $msix_module_ver = (Get-Module msix -ListAvailable |select -ExpandProperty version|Sort-Object)[-1]
    $msixmodule = Get-Module msix -ListAvailable|Where-Object {$_.version -eq $msix_module_ver}
    $msixtool = $msixmodule.ModuleBase
    Write-Verbose -Message "unpacking msix to temp folder"
    $fileinfo = Get-Item -Path $PackagePath
    $tempdir = "$env:temp\msix\$($fileinfo.BaseName)"
    if (!(Test-Path -Path $tempdir)){
    $null = New-Item -ItemType Directory -force -path $tempdir}
    else
    {
    Write-Verbose -Message "temp directory already unpacked, cleaning up"
    Remove-Item -Path $tempdir\* -Force -Recurse}
    write-verbose -Message 'calling makeappx to unpack package'
    Write-Verbose "$($fileinfo.fullname)"
    $null = start-MsixProcess -Process "$msixtool\Tools\MakeAppx.exe" -arguments "unpack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
    if ($pfx -and $pfxpassword -eq $null){throw 'missing pfx password when pfx specified'}
    }

    PROCESS {
    Write-Verbose -Message "reading $($tempdir)\AppxManifest.xml"
    [xml]$appinfo = Get-Content -Path "$tempdir\AppxManifest.xml"

    #check schema for uap3
    if ($appinfo.Package.Attributes.'#text' -notcontains 'http://schemas.microsoft.com/appx/manifest/uap/windows10/3'){
     Write-Verbose -Message "adding uap in schema"
     $appinfo.Package.IgnorableNamespaces += ' uap3'
     $appinfo.Package.SetAttribute('xmlns:uap3','http://schemas.microsoft.com/appx/manifest/uap/windows10/3')
    }

    $AppListEntry = $appinfo.CreateAttribute('AppListEntry')
    $AppListEntry.value = 'none'

    foreach ($app in $($appinfo.Package.Applications.Application))
    {
    #add child per app
     $choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
     $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
     $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

     $decision = $Host.UI.PromptForChoice($($app.executable), "remove startmenu entry for $($app.executable)?", $choices, 1) 
     #detecting if alias already exists

        if ($decision -eq 0) {
            $app.VisualElements.Attributes.Append($AppListEntry)
        }
    }
    $appinfo.Save("$tempdir\AppxManifest.xml")
    Write-Output -InputObject "packing msix again"
    $null = start-MsixProcess -Process "$msixtool\tools\MakeAppx.exe" -arguments "pack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
    Write-Output -InputObject "signing msix"
    start-Msixsigntool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
    }
    END {
    Write-Verbose -Message "cleaning up"
    Remove-Item -Path $tempdir -Force -Recurse
    Remove-Variable fileinfo, appinfo, decision
    }
}
function add-MsixStartMenuFolder {
   <#
.SYNOPSIS
    remove msix start menu entry from application


.NOTES
    Name: remove-MsixStartMenuEntry
    Author: Sander de Wit
    Version: 1.0
    DateCreated: 09-06-2021


.EXAMPLE
    add-MsixStartMenuFolder -PackagePath c:\temp\app.msix -FolderName 'appfolder'

.EXAMPLE
    add-MsixStartMenuFolder -PackagePath c:\temp\app.msix -FolderName 'appfolder' -pfx cert.pfx -pfxpassword 'secret'

#>

    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackagePath,
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 1
            )]
        [string[]]  $FolderName,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 2
            )]
        [string[]]  $pfx,
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 3
            )]
        [string[]]  $pfxpassword
    )
    BEGIN {
    $msix_module_ver = (Get-Module msix -ListAvailable |select -ExpandProperty version|Sort-Object)[-1]
    $msixmodule = Get-Module msix -ListAvailable|Where-Object {$_.version -eq $msix_module_ver}
    $msixtool = $msixmodule.ModuleBase
    Write-Verbose -Message "unpacking msix to temp folder"
    $fileinfo = Get-Item -Path $PackagePath
    $tempdir = "$env:temp\msix\$($fileinfo.BaseName)"
        if (!(Test-Path -Path $tempdir)){
         $null = New-Item -ItemType Directory -force -path $tempdir}
        else
        {
         Write-Verbose -Message "temp directory already unpacked, cleaning up"
         Remove-Item -Path $tempdir\* -Force -Recurse
        }
    write-verbose -Message 'calling makeappx to unpack package'
    Write-Verbose "$($fileinfo.fullname)"
    $null = start-MsixProcess -Process "$msixtool\Tools\MakeAppx.exe" -arguments "unpack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
    if ($pfx -and $pfxpassword -eq $null){throw 'missing pfx password when pfx specified'}
    }

    PROCESS {
    Write-Verbose -Message "reading $($tempdir)\AppxManifest.xml"
    [xml]$appinfo = Get-Content -Path "$tempdir\AppxManifest.xml"

    #check schema for uap3
    if ($appinfo.Package.Attributes.'#text' -notcontains 'http://schemas.microsoft.com/appx/manifest/uap/windows10/3'){
     Write-Verbose -Message "adding uap in schema"
     $appinfo.Package.IgnorableNamespaces += ' uap3'
     $appinfo.Package.SetAttribute('xmlns:uap3','http://schemas.microsoft.com/appx/manifest/uap/windows10/3')
    }

    $VisualGroup = $appinfo.CreateAttribute('VisualGroup')
    $VisualGroup.value = $FolderName

    foreach ($app in $($appinfo.Package.Applications.Application))
    {
     $app.VisualElements.Attributes.Append($VisualGroup)
    }
    $appinfo.Save("$tempdir\AppxManifest.xml")
    Write-Output -InputObject "packing msix again"
    $null = start-MsixProcess -Process "$msixtool\tools\MakeAppx.exe" -arguments "pack /p `"$($fileinfo.FullName)`" /d $tempdir /o"
    Write-Output -InputObject "signing msix"
    start-Msixsigntool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
    }
    END {
    Write-Verbose -Message "cleaning up"
    Remove-Item -Path $tempdir -Force -Recurse
    Remove-Variable fileinfo, appinfo, VisualGroup
    }
}

Export-ModuleMember -Function get-MsixAppXManifest, start-MsixProcess, start-MsixSigntool, Get-MsixInfo, update-MsixSigner, start-MsixCmd, Add-MsixPsf, add-MsixAlias, new-MsixPsfJson, remove-MsixStartMenuEntry, add-MsixStartMenuFolder