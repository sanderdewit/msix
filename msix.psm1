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
    $zip.Entries | Where-Object {$_.Name -eq 'AppxManifest.xml'} | foreach {[System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$extractfolder\AppxManifest.xml", $true)}
    $zip.Dispose()
    }
    END {
    Clear-Variable sourcefile, extractfolder, item, zip
    }
}

function start-MsixProcess {
    [CmdletBinding()]
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

function start-MsiXSigntool {
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
    $signing = start-MsixProcess -Process "$env:msixtool\tools\signtool.exe" -arguments $arguments
    if ($($signing.exitcode) -ne '0'){write-error "signing went wrong, please check eventlog Microsoft\Windows\AppxPackagingom: $($signing.stderr)"}    
    }
    END {
    Clear-Variable fileinfo, PackagePath
    }

}

function new-MsixPsfJson {

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
 

#>
 
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackagePath
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

    [pscustomobject]@{
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
 
    [CmdletBinding()]
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
    if ($apps.count -gt '1'){Write-Error "multiple apps found, selecting app 1 $($apps[0].Id)"
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
    if (!($env:msixtool)){throw 'user environmental variable Msixtool not found, please run prep-environment.ps1'}
    Write-Verbose "unpacking msix to temp folder"
    $fileinfo = Get-Item -Path $PackagePath
    $tempdir = "$env:temp\msix\$($fileinfo.BaseName)"
    if (!(Test-Path -Path $tempdir)){
    $null = New-Item -ItemType Directory -force -path $tempdir}
    else 
    {
    Write-Verbose "temp directory already unpacked, cleaning up"
    Remove-Item -Path $tempdir\* -Force -Recurse}
    write-verbose 'calling makeappx to unpack package'
    $null = start-MsixProcess -Process "$env:msixtool\Tools\MakeAppx.exe" -arguments "unpack /p $($fileinfo.FullName) /d $tempdir /o"
    }

    PROCESS {
    #modify to AppXManifest when necessary
    Write-Verbose "reading $($tempdir)\AppxManifest.xml"
    [xml]$appinfo = Get-Content -Path "$tempdir\AppxManifest.xml"
    if ($publisher)
     {
        if ($($appinfo.Package.Identity.Publisher) -ceq $publisher)
            {
             Write-Output "not changing the publisher, as it already a match"
             #Microsoft MSIX team recommends to use of signtool over powershell Get-AuthenticodeSignature
             start-signtool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
        }
        else 
        {
         $appinfo.Package.Identity.Publisher = [string]$publisher
         Write-Output "modifying msix publisher"
         $appinfo.Save("$tempdir\AppxManifest.xml")
         Write-Output "packing up MSIX again"
         $null = start-MsixProcess -Process "$env:msixtool\tools\MakeAppx.exe" -arguments "pack /p $($fileinfo.FullName) /d $tempdir /o"
         start-signtool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
        }
     }
     #no publisher specified
    else {
     start-signtool -PackagePath $($fileinfo.FullName) -pfx $pfx -pfxpassword $pfxpassword
     }
    }
    END {
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
    DateCreated: 05-05-2021
 
 
.EXAMPLE
    add-MsixPsf -PackagePath npp.msix

#>
 
    [CmdletBinding()]
    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            Position = 0
            )]
        [string[]]  $PackagePath
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
    write-verbose 'calling makeappx to unpack package'
    $unpack = start-MsixProcess -Process "$env:msixtool\Tools\MakeAppx.exe" -arguments "unpack /p $($fileinfo.FullName) /d $tempdir /o"
    if ($unpack.exitcode -ne '0'){Write-Error "something went wrong: $($unpack.stderr)"}
    }
    PROCESS {
    #reading AppXManifest to find applications
    Write-Verbose "reading $($tempdir)\AppxManifest.xml"
    [xml]$appinfo = Get-Content -Path "$tempdir\AppxManifest.xml"
    $i = 0
    $apps = @()
    foreach ($app in $appinfo.Package.Applications.Application){
    $i++
    Write-Output "found app $($app.id) with $($app.executable)"
    $apps += @{
    'id' = $($app.id)
    'executable' = $($app.executable)
    }
    }
    $json = @{
    'Applications' = @($apps)}|ConvertTo-Json
    $json
    #copy items to relevant folders
    }
    END {
    }
}


Export-ModuleMember -Function get-MsixAppXManifest, start-MsixProcess, start-MsixSigntool, Get-MsixInfo, update-MsixSigner, start-MsixCmd, Add-MsixPsf