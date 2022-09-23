#Get Date
$d=Get-Date
Write-Host "Date: " $d
#Get OS detail
$os=(Get-WmiObject -class Win32_OperatingSystem).Caption
Write-Host "OS detail: " $os
#Get Architecture
Write-Host "Architecture: " $ENV:PROCESSOR_ARCHITECTURE
#Get Hostname
$hostname = hostname
Write-Host "Hostname: " $hostname
#Get IPv4 address
Get-NetIPAddress -AddressFamily IPv4 | Select-Object "IPAddress"