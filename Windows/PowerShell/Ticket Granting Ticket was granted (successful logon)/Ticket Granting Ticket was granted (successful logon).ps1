$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

function Get-LogonEvents ($id,$evetnType,$snAddress,$uAccount,$uDomain,$serviceName,$status,$certIssuerName,$certSerialNumber,$certThumbprint,$temp){
    Get-WinEvent -MaxEvents 2 -FilterHashtable @{LogName = "Security"; ID = $id} | ForEach-Object {
        [PSCustomObject]@{         
            LogonTime = $_.TimeCreated
            EvetnType = $evetnType
            EventId= $id
            TargetUserName = $_.Properties.Value[$uAccount]
            TargetDomainName = $_.Properties.Value[$uDomain]
            SourceNetworkAddress = $_.Properties.Value[$snAddress]
            Status = $_.Properties.Value[$status]
            ServiceName = $_.Properties.Value[$serviceName]
            CertIssuerName = $_.Properties.Value[$certIssuerName]
            CertSerialNumber = $_.Properties.Value[$certSerialNumber]
            CertThumbprint = $_.Properties.Value[$certThumbprint]
        }
        "---------"
        $temp++
    }
    if ($temp -eq 0){"No Events found for $evetnType"}
}

$evetnType = "Ticket Granting Ticket was granted (successful logon)";$snAddress=9;$uAccount=0;$uDomain=1;$serviceName=3;$status=6;$certIssuerName=11;$certSerialNumber=12;$certThumbprint=13;$id=4768
$temp=0
$evetnType
"-------------------------------------------------------------------------"
Get-LogonEvents $id $evetnType $snAddress $uAccount $uDomain $serviceName $status $certIssuerName $certSerialNumber $certThumbprint $temp