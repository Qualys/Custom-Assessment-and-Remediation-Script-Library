$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";
$temp4=0
$Key = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\'
Get-ChildItem $Key -Rec -EA SilentlyContinue | ForEach-Object {
    $p=$_.PsPath -split '::'
    $p2=$_.PsPath
    
    reg query $p[1] | % { if($_ -match "REG_BINARY") 
        { 
            $temp1=$_ -split "REG_BINARY"
            $temp2=$temp1[0].Trim()
            $temp3 = Get-ItemProperty -Path $p2
            $hex = [System.BitConverter]::ToString($temp3.$temp2)
            $hexstring=(Get-ItemProperty $p2 | Select -ExpandProperty $temp2) -join ','
            $convert=($hexstring.Split(",",[System.StringSplitOptions]::RemoveEmptyEntries) | ?{$_ -gt '0'} | ForEach{[char][int]"$($_)"}) -join ''
            $pattern = '[^a-zA-Z.0-9 ]'
            $pattern2 = '\b[A-Za-z0-9_ ]+\.(pdf|7z|csv|db|docx|iso|jpg|json|one|pdf|png|ps1|rar|sh|TXT|vhd|xlsx|xml|zip).$'
            $convert2=$convert -replace $pattern, ' '
            $path=$convert2 -match $pattern2
            if (!($matches[0] -match "REG_BINARY")){"`n";$p[1];$matches[0];$temp4++}
        }
    }
}
    
if ($temp4 -le 0){"No files are open on this system"}