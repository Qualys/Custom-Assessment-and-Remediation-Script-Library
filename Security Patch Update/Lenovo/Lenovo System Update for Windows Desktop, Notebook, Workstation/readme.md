Description  
  
This script is for Lenovo System Update for Windows 11, 10 and 7, 32-bit, 64-bit - Desktop, Notebook, Workstation.  
System Update enables IT administrators to distribute updates for software, drivers, and BIOS in a managed environment using CAR.  
System Update downloads data updates for software, drivers, and BIOS from a Lenovo server directly over the Internet without requiring specific user knowledge of where the package is located or if it is needed by the target system.  
  
Working  
  
Checks for vulnerable BIOS version on host  
Checks for the latest Lenovo system update version, if a vulnerable BIOS version is detected  
Pushes the critical and recommended updates based on system-update version 5.7.0.139 or greater  
Installs the latest system update i.e., system_update_5.07.0139.exe and push the Critical and Recommended updates  
Patches the system and triggers reboot if user clicks on 'OK' for 'Lenovo System Update' alert  
  
Pre-requisites for the script  
  
Host should have internet connectivity to download the system update  
PowerShell Execution policy should not be 'Restricted'  