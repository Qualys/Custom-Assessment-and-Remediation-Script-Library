# Control ID - 18962
$v = 1 
$regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\SecondaryAuthenticationFactor'
$name = "AllowSecondaryAuthenticationDevice"
if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore)
{
    Set-Itemproperty -path $regkey -Name $name -Value $v -Force
}
else
{
    New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft" -Name 'SecondaryAuthenticationFactor'
    New-ItemProperty -Path $regkey -Name $name -Value $v -PropertyType "DWORD" -Force 
}
Get-ItemProperty -Path $regkey -Name $name

# Control ID - 11282
Set-SmbServerConfiguration -EnableSMB2Protocol $false
Get-SmbServerConfiguration | Select-Object EnableSMB2Protocol
#shutdown /r

# Control ID - 11281
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
#shutdown /r

# Control ID - 8365
net user administrator /active:no

# Control ID - 7805
$v = 0 
$regkey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$name = "NoAutoUpdate"
if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore)
{
    Set-Itemproperty -path $regkey -Name $name -Value $v -Force
}
else
{
    New-ItemProperty -Path $regkey -Name $name -Value $v -PropertyType "DWORD" -Force 
}
Get-ItemProperty -Path $regkey -Name $name

# Control ID - 7519
$v = 1 
$regkey = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
$name = "fDenyTSConnections"
if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore)
{
    Set-Itemproperty -path $regkey -Name $name -Value $v -Force
}
else
{
    New-ItemProperty -Path $regkey -Name $name -Value $v -PropertyType "DWORD" -Force 
}
Get-ItemProperty -Path $regkey -Name $name

# Control ID - 3949
$v = 1 
$regkey = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\DomainProfile'
$name = "DefaultInboundAction"
if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore)
{
    Set-Itemproperty -path $regkey -Name $name -Value $v -Force
}
else
{
    if (!(Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name 'DomainProfile' -ErrorAction Ignore))
    {
        New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft" -Name 'WindowsFirewall'-ErrorAction Ignore
        New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name 'DomainProfile'-ErrorAction Ignore
        New-ItemProperty -Path $regkey -Name $name -Value $v -PropertyType "DWORD" -Force
        New-ItemProperty -Path $regkey -Name 'EnableFirewall' -Value $v -PropertyType "DWORD" -Force 
    }
}
Get-ItemProperty -Path $regkey -Name $name

# Control ID - 3948
$v = 1 
$regkey = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PrivateProfile'
$name = "DefaultInboundAction"
if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore)
{
    Set-Itemproperty -path $regkey -Name $name -Value $v -Force
}
else
{
    if (!(Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name 'PrivateProfile' -ErrorAction Ignore))
    {
        New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft" -Name 'WindowsFirewall'-ErrorAction Ignore
        New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name 'PrivateProfile'-ErrorAction Ignore
        New-ItemProperty -Path $regkey -Name $name -Value $v -PropertyType "DWORD" -Force
        New-ItemProperty -Path $regkey -Name 'EnableFirewall' -Value $v -PropertyType "DWORD" -Force 
    }
}
Get-ItemProperty -Path $regkey -Name $name

# Control ID - 3932
$v = 1 
$regkey = 'HKLM:\Software\Policies\Microsoft\WindowsFirewall\PublicProfile'
$name = "DefaultInboundAction"
if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore)
{
    Set-Itemproperty -path $regkey -Name $name -Value $v -Force
}
else
{
    if (!(Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name 'PublicProfile' -ErrorAction Ignore))
    {
        New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft" -Name 'WindowsFirewall'-ErrorAction Ignore
        New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft\WindowsFirewall" -Name 'PublicProfile'-ErrorAction Ignore
        New-ItemProperty -Path $regkey -Name $name -Value $v -PropertyType "DWORD" -Force
        New-ItemProperty -Path $regkey -Name 'EnableFirewall' -Value $v -PropertyType "DWORD" -Force 
    }
}
Get-ItemProperty -Path $regkey -Name $name

#Restart Computer
shutdown /r