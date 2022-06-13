$v = 1 
$regkey = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Real-time Protection'
$name = "DisableRealtimeMonitoring"
if (Get-ItemProperty -Path $regkey -Name $name -ErrorAction Ignore)
{
    Set-Itemproperty -path $regkey -Name $name -Value $v -Force
}
else
{
    if (!(Get-ItemProperty -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender\Real-time Protection" -Name 'DisableRealtimeMonitoring' -ErrorAction Ignore))
    {
        New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft" -Name 'Windows Defender'-ErrorAction Ignore
        New-Item -Path "HKLM:SOFTWARE\Policies\Microsoft\Windows Defender" -Name 'Real-time Protection'-ErrorAction Ignore
        New-ItemProperty -Path $regkey -Name $name -Value $v -PropertyType "DWORD" -Force
    }
}
Get-ItemProperty -Path $regkey -Name $name

"Real time protection is enabled as per CIS guide line"