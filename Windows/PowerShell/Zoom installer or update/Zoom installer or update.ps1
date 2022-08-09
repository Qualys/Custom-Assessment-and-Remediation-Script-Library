# Download latest version of ZOOM
Invoke-WebRequest -Uri "https://zoom.us/client/latest/ZoomInstallerFull.msi?archType=x64" -UseBasicParsing -OutFile $env:TEMP\ZoomInstallerFull.msi

# Will update the current version or install latest version of ZOOM
msiexec /i $env:TEMP\ZoomInstallerFull.msi /quiet /qn /norestart ALLUSERS=1 /log c:\zoom_install.log