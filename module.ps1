function get-appxmanifest ($sourcefile, $extractfolder) {
Add-Type -Assembly System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($sourceFile)
$zip.Entries | Where-Object {$_.Name -eq 'AppxManifest.xml'} | foreach {[System.IO.Compression.ZipFileExtensions]::ExtractToFile($_, "$extractfolder\AppxManifest.xml", $true)}
$zip.Dispose()
}

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
    get-appxmanifest -sourcefile $fileinfo.FullName -extractfolder $tempdir
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
    start cmd.exe in specific package
 
 
.NOTES
    Name: start-MsixCmd
    Author: Sander de Wit
    Version: 1.0
    DateCreated: 04-05-2021
 
 
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
        [string[]]  $PackageName
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
    Invoke-CommandInDesktopPackage -PackageFamilyName $PackageFamilyName -PreventBreakaway -command cmd.exe -AppId $appId
    }

    END {
    Clear-Variable appx, packagename, appinfo, AppXManifest
    }
}


Function sign-Msix {
<#
.SYNOPSIS
    signs MSIX with new certificate and updates publisher
 
 
.NOTES
    Name: sign-Msix
    Author: Sander de Wit
    Version: 1.0
    DateCreated: 04-05-2021
 
 
.EXAMPLE
    sign-Msix -PackagePath app.msix -signer cert.pfx
 

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
        [string[]]  $signer
    )
 
    BEGIN {
    #Microsoft MSIX team recommends to use of signtool over powershell Get-AuthenticodeSignature
    #to fix
    #signtool.exe verify /pa app.msix

    }

    PROCESS {
    }

    END {
    }
}