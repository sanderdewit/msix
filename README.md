# msix
Cmdlets to make msix packaging easier

Still work in progress.

First run the prepare-environment.ps1
This will install download several modules;
- msix-toolkit redist files. https://github.com/microsoft/MSIX-Toolkit
- Package Support Framework. https://github.com/microsoft/MSIX-PackageSupportFramework
- msixmgr. https://aka.ms/msixmgr 

**Important: It will place an user environmental variable, which is used in the module to call these files.**

import-module msix.psm1

Current cmdlets;
- get-MsixInfo
- update-MsixSigner
- start-MsixCmd

current in progress:
- Add-MsixPsf (incl monitor & fixups options)

todo:
- new-MsixAAImage (AppAttach)
- option to auto debug issues in the Msix package
- add-MsixAlias

get-MsixInfo -PackagePath c:\temp\app.msix
This will retrieve information around the Msix package.

Get-MsixInfo .\npp.msix

name                  : npp \
DisplayName           : Notepad ++ \
Publisher             : CN=Demo, O=Demo Org, C=NL \
PublisherDisplayName  : Demo \
Version               : 7.9.5.0 \
ProcessorArchitecture : x64 \
Description           : None \
Signed                : UnknownError \
SignedBy              : CN=Demo, O=Demo Org, C=NL \
ThumbPrint            : 857489953F579DE234D180D04C7ED25DDFE5D8A8 \
TimeStampCertificate  : 

In this example the timestamp server was not specified.
