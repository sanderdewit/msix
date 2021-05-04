write-output "download msix-toolkit"
invoke-webrequest -uri 'https://github.com/microsoft/MSIX-Toolkit/archive/refs/heads/master.zip' -out msix.zip

write-output "Expanding MSIX toolkit download"
Expand-Archive -Path .\msix.zip -DestinationPath . -Force

write-output "Creating Tools Directory"
New-Item -Type Directory -Name Tools
 if ($env:PROCESSOR_ARCHITECTURE -eq 'AMD64')
	{
	 Move-Item -Path .\MSIX-Toolkit-master\Redist.x64\* -Destination tools\ -Force
	} else 
	{
	 Move-Item -Path .\MSIX-Toolkit-master\Redist.x86\* -Destination tools\ -Force
	}
write-output "Cleaning up MSIX toolkit download"
remove-item -path msix-toolkit-master -Recurse -Force

write-output "downloading Package Support Framework"
#Install-Package -Name Microsoft.PackageSupportFramework -ProviderName NuGet -source 'https://www.nuget.org/api/v2' -scope CurrentUser
invoke-webrequest -uri 'https://www.nuget.org/api/v2/package/Microsoft.PackageSupportFramework/1.0.200410.1' -out package.zip

write-output "expanding Package Support Framework (with error supressing)"
expand-archive -path .\package.zip -ErrorAction SilentlyContinue

write-output "moving PSF to specific folder"
New-Item -Type Directory -Name Psf
Move-Item -Path .\package\bin\* -Destination PSF\ -Force

write-output "cleaning up Package Support Framework"
remove-item -path package -Recurse -Force

write-output "download msixmgr tool"
invoke-webrequest -uri 'https://aka.ms/msixmgr' -out msixmgr.zip
expand-archive -path .\msixmgr.zip