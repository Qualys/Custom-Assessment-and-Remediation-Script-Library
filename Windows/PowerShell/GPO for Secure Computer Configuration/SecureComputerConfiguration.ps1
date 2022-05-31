New-GPO -Name "Secure_computer"

# Prevent changing desktop background
Set-GPRegistryValue -Name "Secure_computer" -Key 'HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\ActiveDesktop'   -ValueName 'NoChangingWallPaper' -Value 1   -Type Dword

#Do Prevent changing desktop icons
Set-GPRegistryValue -Name "Secure_computer" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName 'NoDispBackgroundPage' -Value 1 -Type Dword

#Disable Remove Recycle Bin icon from desktop
Set-GPregistryValue -Name "Secure_computer" -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\NonEnum" -ValueName '{645FF040-5081-101B-9F08-00AA002F954E}' -Value '0' -Type Binary

"GPO for Secure Computer Configuration is created"