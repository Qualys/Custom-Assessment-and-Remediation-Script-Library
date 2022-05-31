$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

function Get-LogonEvents ($id,$evetnType,$snAddress,$uAccount,$uDomain,$serviceName,$status,$ipPort,$transmittedServices,$temp){
    Get-WinEvent -MaxEvents 15 -FilterHashtable @{LogName = "Security"; ID = $id} | ForEach-Object {      
        [PSCustomObject]@{                  
            LogonTime = $_.TimeCreated
            EvetnType = $evetnType
            EventId= $id
            TargetUserName = $_.Properties.Value[$uAccount]
            TargetDomainName = $_.Properties.Value[$uDomain]
            SourceNetworkAddress = $_.Properties.Value[$snAddress]
            IpPort = $_.Properties.Value[$ipPort]
            Status = $_.Properties.Value[$status]
            ServiceName = $_.Properties.Value[$serviceName]
            TransmittedServices = $_.Properties.Value[$transmittedServices]
        }
        "---------"
        $temp++
    }
    if ($temp -eq 0){"No Events found for $evetnType"}
}

$evetnType = " Service Ticket requested";$snAddress=6;$uAccount=0;$uDomain=1;$serviceName=2;$status=8;$ipPort=7;$transmittedServices=10;$id=4769
$temp=0
$evetnType
"-------------------------------------------------------------------------"
Get-LogonEvents $id $evetnType $snAddress $uAccount $uDomain $serviceName $status $ipPort $transmittedServices $temp