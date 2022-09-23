$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

$Key = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\"
Get-ChildItem $Key -Rec -EA SilentlyContinue | ForEach-Object {
    $p=$_.PsPath -split '::'
    $p2=$_.PsPath
    reg query $p[1] | % { if($_ -match "REG_BINARY") 
        {
            $temp1=$_ -split "REG_BINARY"
            $temp2=$temp1[0].Trim()
            Write-Host "Full path of the executable file : " $temp2
            $temp3 = Get-ItemProperty -Path $p2
            $hex = [System.BitConverter]::ToString($temp3.$temp2)
            $reverse = $hex.Split('-')[7..0].foreach{$_}
            $reverse = [string]::join("",($reverse.Split("`n")))
            $decimal=[convert]::toint64($reverse,16)
            Write-Host "Last execution date/time : " (Get-Date 1/1/1601).AddDays($decimal/864000000000)
            "`n"
        }
    } 
}