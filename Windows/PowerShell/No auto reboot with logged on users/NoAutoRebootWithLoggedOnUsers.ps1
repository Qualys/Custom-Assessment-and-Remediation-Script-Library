New-GPO -Name "Windows Update"

Set-GPRegistryValue -Name "Windows Update" -Key "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoRebootWithLoggedOnUsers" -Value 1 -Type DWord

"Auto reboot is disabled after windows update"