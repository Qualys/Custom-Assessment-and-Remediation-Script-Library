If ($null -eq (Get-Module -Name PSWindowsUpdate -ListAvailable) ) {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module PSWindowsUpdate -Force
    Import-Module PSWindowsUpdate
}

Get-WUInstall -AcceptAll –IgnoreReboot