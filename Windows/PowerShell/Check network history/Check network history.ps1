$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

$Key = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures'
Get-ChildItem $Key -Rec -EA SilentlyContinue | ForEach-Object {
    $p=$_.PsPath -split '::'
    $p2=$_.PsPath
    reg query $p[1] | % { if($_ -match "REG_BINARY") 
    {
        $temp1=$_ -split "REG_BINARY"
        $temp2=$temp1[0].Trim()
        "`n"
        $p2
        $temp3 = Get-ItemProperty -Path $p2
        $hex = [System.BitConverter]::ToString($temp3.$temp2)
        Write-host Default Gateway Mac : $hex
        $net=Get-ItemPropertyvalue -Path $p2 -Name FirstNetwork
        Write-host Network Name : $net      
        $dns=Get-ItemPropertyvalue -Path $p2 -Name DnsSuffix
        Write-host DNS : $dns
        $profileGuid=Get-ItemPropertyvalue -Path $p2 -Name ProfileGuid
                                                        
        function GetRegDate ($path, $key){
            function GVl ($ar){
                return [uint32]('0x'+(($ar|ForEach-Object ToString X2) -join ''))
            }
            $ar=Get-ItemPropertyValue $path $key
            [array]::reverse($ar)
            $time = New-Object DateTime (GVl $ar[14..15]),(GVl $ar[12..13]),(GVl $ar[8..9]),(GVl $ar[6..7]),(GVl $ar[4..5]),(GVl $ar[2..3]),(GVl $ar[0..1])
            return $time
        }
        
        $path='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\'+$profileguid
        $key1='DateCreated'
        $key2="DateLastConnected"
        $DateCreated=GetRegDate $path $key1
        Write-host Date First Connected : $DateCreated
        $DateLastConnected=GetRegDate $path $key2
        Write-host Date Last Connected : $DateLastConnected
        #Get-Date $DateLastConnected -Format "ddd, dd.MM.yyyy HH:mm:ss,fff"

        $managed = Get-ItemPropertyvalue -Path $path -Name Managed
        if($managed -match 0)
        {
            "Unmanaged (Wireless)"
        }
        else
        {
            "Managed (Connected to VPN or wired)"}
        }
    }
}