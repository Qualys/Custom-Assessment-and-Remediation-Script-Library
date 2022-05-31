$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

function Get-LogonEvents ($id,$evetnType,$lType,$swName,$snAddress,$uAccount,$uDomain,$temp){

    Get-WinEvent -MaxEvents 2 -FilterHashtable @{LogName = "Security"; ID = $id} | ForEach-Object {
        
        switch ($_) {
            {$_.properties[$lType].value -eq 2} {$logonType = "Interactive"}
            {$_.properties[$lType].value -eq 3} {$logonType = "Network"}
            {$_.properties[$lType].value -eq 4} {$logonType = "Batch"}
            {$_.properties[$lType].value -eq 5} {$logonType = "Service"}
            {$_.properties[$lType].value -eq 7} {$logonType = "Unlock"}
            {$_.properties[$lType].value -eq 8} {$logonType = "NetworkCleartext"}
            {$_.properties[$lType].value -eq 9} {$logonType = "NewCredentials"}
            {$_.properties[$lType].value -eq 10} {$logonType = "RemoteInteractive"}
            {$_.properties[$lType].value -eq 11} {$logonType = "CachedInteractive"}
            default {$logonType = "Undetermined"}
        }

        [PSCustomObject]@{
            LogonTime = $_.TimeCreated
            EvetnType = $evetnType
            EventId= $id
            TargetUserName = $_.Properties.Value[$uAccount]
            TargetDomainName = $_.Properties.Value[$uDomain]
            SourceWorkstationName = $_.Properties.Value[$swName]
            SourceNetworkAddress = $_.Properties.Value[$snAddress]
            LogonType = $logonType
        }
        "---------"
        $temp++
    }
    if ($temp -eq 0){"No Events found for $evetnType"}
}

$evetnType = "Failed Logon";$lType=10;$swName=13;$snAddress=19;$uAccount=5;$uDomain=6;$id=4625
$temp=0
$evetnType
"-------------------------------------------------------------------------"       
Get-LogonEvents $id $evetnType $lType $swName $snAddress $uAccount $uDomain $temp