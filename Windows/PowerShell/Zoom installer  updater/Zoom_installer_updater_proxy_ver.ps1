# Proxy credentials
$pass = ConvertTo-SecureString "<Password>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList "<user>", $pass
# Download the latest version of ZOOM
Invoke-WebRequest -Uri "https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64" -Proxy http://<ip:port> -ProxyCredential $cred -UseBasicParsing -OutFile $env:TEMP\ZoomInstallerFull.msi
# Will update the current version or install the latest version of ZOOM
msiexec /i $env:TEMP\ZoomInstallerFull.msi /quiet /qn /norestart ALLUSERS=1 /log $env:TEMP\zoom_install.log | Out-Null
Write-Host "Log file is created under"
ls $env:TEMP\zoom_install.log
Remove-Item -Path $env:TEMP\ZoomInstallerFull.msi