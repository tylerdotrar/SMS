<#
----------------------------------
AUTHOR:  Tyler McCann (@tyler.rar)
----------------------------------

This module has been added to expedite the process of loading scripts into PowerShell sessions via the user's
$PROFILE, as well as alleviate the process of having to find and update hardcoded scripts inside of the $PROFILE;
whereas once that file becomes a few thousand (or even a few hundred) lines long, the process of updating
quickly becomes tedious.

The below syntax will recursively find all PowerShell script module files within the specified directory and
load them into your terminal; just set $GitDirectory to the desired folder. Rather than setting that variable to
the main repo folder, set it to the folder containing all of your repos so you only have to put the below code
into your $PROFILE a single time.  If you don't want *every* .psm1 to be imported, specify only the specific
modules you want to import.

------------------------
Windows $PROFILE Syntax:
------------------------
$GitDirectory = 'C:\Users\Bobby\Documents\GitHub'
(Get-ChildItem -Path $GitDirectory -Include $List -Recurse).Fullname | % { Import-Module $_ -DisableNameChecking }

[or]

$List = @('SMS-Suite.psm1')
$GitDirectory = 'C:\Users\Bobby\Documents\GitHub'
(Get-ChildItem -Path $GitDirectory -Include $List -Recurse).Fullname | % { Import-Module $_ -DisableNameChecking }


-----------------------------------
Linux Syntax to Configure $PROFILE:
-----------------------------------
if (!(Test-Path $PROFILE)) { New-Item $PROFILE -Force }
cd SMS/lib
Set-Content $PROFILE -Value "Import-Module $PWD/SMS-Suite.psm1"

#>

. $PSScriptRoot\..\SecureMessagingSystem.ps1
# . $PSScriptRoot\Fucky64-Abridged.ps1