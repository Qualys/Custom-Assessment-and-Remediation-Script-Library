$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

function ROT13($data) {
    $data.ToCharArray() | ForEach-Object {
        if((([int] $_ -ge 97) -and ([int] $_ -le 109)) -or (([int] $_ -ge 65) -and ([int] $_ -le 77)))
        {
            $string += [char] ([int] $_ + 13);
        }
        elseif((([int] $_ -ge 110) -and ([int] $_ -le 122)) -or (([int] $_ -ge 78) -and ([int] $_ -le 90)))
        {
            $string += [char] ([int] $_ - 13);
        }
            else
        {
            $string += $_
        }        
    }
    return $string
}

$Key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\"
Get-ChildItem $Key -Rec -EA SilentlyContinue | ForEach-Object {
    $p=$_.PsPath -split '::'
    $p2=$_.PsPath
    reg query $p[1] | % { if($_ -match "REG_BINARY") 
        {
            $p[1]
            $temp1=$_ -split "REG_BINARY"
            $temp2=$temp1[0].Trim()
            $ROT13 = ROT13 $temp2
            Write-Host app name : $ROT13

            $temp3 = Get-ItemProperty -Path $p2
            $hex = [System.BitConverter]::ToString($temp3.$temp2)
            $reverse = $hex.Split('-')[67..60].foreach{$_}
            $reverse = [string]::join("",($reverse.Split("`n")))
            $decimal=[convert]::toint64($reverse,16)
            Write-Host Last execution: (Get-Date 1/1/1601).AddDays($decimal/864000000000)
        
            $reverse = $hex.Split('-')[7..4].foreach{$_}
            $reverse = [string]::join("",($reverse.Split("`n")))
            $decimal=[convert]::toint64($reverse,16)
            Write-Host Number of executions : $decimal
            "`n"
        }
    }
}