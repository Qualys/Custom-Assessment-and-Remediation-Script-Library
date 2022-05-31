$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

$temp = 0
$hash = '6506733C74A8B4A31B11C52B1C1DF944','93582D496061E4F7E3368CC7FD0A3CC0' # Add your hashes here
$path = "C:\users\" # Add your path which you want to scan

if ((Get-Command get-filehash)){
    try{
        Get-ChildItem -Path $path -file -Recurse | ForEach-Object{$file = $_.FullName
            $fileHash = Get-FileHash $file -Algorithm MD5
            if ( $hash -contains $fileHash.hash) {
                $file
                $temp = 1
            }
        }
    }
    catch{
        "Not able to scan system"
        $temp = 2
    }
    if ($temp -eq 0){"No File Found"}
}
else{"Get-FileHash cmdlet not present"}