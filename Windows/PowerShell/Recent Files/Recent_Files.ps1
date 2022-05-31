$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

$Key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\'
$k = Get-ItemProperty -Path $key
$hex = [System.BitConverter]::ToString($k.MRUListEx)
$reverse = $hex.Split('-')
$count = $reverse.count
Write-Host File Name That Recently Access First `n
for ($i=0; $i -lt $count-4; $i=$i+4){
    $j=$i+3
    $reverse = $hex.Split('-')[$j..$i].foreach{$_}
    $reverse = [string]::join("",($reverse.Split("`n")))
    $decimal=[convert]::toint64($reverse,16)
    $hexstring=(Get-ItemProperty $key | Select -ExpandProperty $decimal) -join ','
    $convert=($hexstring.Split(",",[System.StringSplitOptions]::RemoveEmptyEntries) | ?{$_ -gt '0'} | ForEach{[char][int]"$($_)"}) -join ''
    $pattern = '[^a-zA-Z.0-9 {}()-_]'
    $pattern2 = '\b[A-Za-z0-9_ {}()-]+\.((pdf|7z|csv|db|docx|iso|jpg|json|one|pdf|png|ps1|rar|sh|TXT|vhd|xlsx|xml|zip|bin|csproj|hve|jar|log|py|sln|sqlite)+\.lnk|lnk).$'
    $convert=$convert -replace $pattern, ' '
    $temp1=$convert -match $pattern2
    Write-Host Key name : $decimal
    write-host File or Folder Name : $matches[0]
    "`n"
}