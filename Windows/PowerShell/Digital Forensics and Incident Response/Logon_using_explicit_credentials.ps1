$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

function Get-LogonEvents ($id,$evetnType,$snAddress,$uAccount,$uDomain,$targetServerName){

    Get-WinEvent -MaxEvents 2 -FilterHashtable @{LogName = "Security"; ID = $id} | ForEach-Object {
        [PSCustomObject]@{         
            LogonTime = $_.TimeCreated
            EvetnType = $evetnType
            EventId= $id
            TargetUserName = $_.Properties.Value[$uAccount]
            TargetDomainName = $_.Properties.Value[$uDomain]
            TargetServerName = $_.Properties.Value[$targetServerName]
            SourceNetworkAddress = $_.Properties.Value[$snAddress]
        }
        "---------"
        $temp++
    }
    if ($temp -eq 0){"No Events found for $evetnType"}
}

$evetnType = "Logon using explicit credentials (Runas)";$targetServerName=8;$snAddress=12;$uAccount=5;$uDomain=6;$id=4648
$temp=0
$evetnType
"-------------------------------------------------------------------------"
Get-LogonEvents $id $evetnType $snAddress $uAccount $uDomain $targetServerName $temp