# Proxy credentials
$pass = ConvertTo-SecureString "<Password>" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList "<user>", $pass
# Download ZOOM uninstaller
Invoke-WebRequest -Uri "https://support.zoom.us/hc/en-us/article_attachments/360084068792/CleanZoom.zip" -Proxy http://<ip:port> -ProxyCredential $cred -UseBasicParsing -OutFile $env:TEMP\CleanZoom.zip
# Unzip the downloaded file
Expand-Archive $env:TEMP\CleanZoom.zip -DestinationPath $env:TEMP\CleanZoom
# Start uninstall process
Start-Process -Wait -FilePath $env:TEMP\CleanZoom\CleanZoom.exe
Move-Item $env:TEMP\CleanZoom\cleanzoom.log $env:TEMP\cleanzoom.log -Force
Write-Host "Log file is created under"
ls $env:TEMP\cleanzoom.log
# Clean temp. file
Remove-Item -Path $env:TEMP\CleanZoom -Recurse -Force
Remove-Item -Path $env:TEMP\CleanZoom.zip -Force
""
""
Write-Host "ZOOM is uninstalled"