$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

function Get-LogonEvents ($id,$evetnType,$uAccount,$swName,$packageName,$status,$temp){

    Get-WinEvent  -MaxEvents 2 -FilterHashtable @{LogName = "Security"; ID = $id} | ForEach-Object {
        [PSCustomObject]@{             
            LogonTime = $_.TimeCreated
            EvetnType = $evetnType
            EventId= $id
            UserAccount = $_.Properties.Value[$uAccount]
            SourceWorkstationName = $_.Properties.Value[$swName]
            PackageName = $_.Properties.Value[$packageName]
            Status = $_.Properties.Value[$status]
        }
        "---------"
        $temp++
    }
    if ($temp -eq 0){"No Events found for $evetnType"}
}

$evetnType = "Successful/Failed account authentication";$uAccount=1;$swName=2;$packageName=0;$status=3;$id=4776
$temp=0
$evetnType
"-------------------------------------------------------------------------"
Get-LogonEvents $id $evetnType $uAccount $swName $packageName $status $temp