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

"Windows Firewall: Domain: Inbound connections is set to Block"

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

"Windows Firewall: Private: Inbound connections is set to Block"
 
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

"Windows Firewall: Public: Inbound connections is set to Block"