$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

function Get-LogonEvents ($id,$evetnType,$lType,$uAccount,$uDomain,$temp){

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
            LogonType = $logonType
        }
        "---------"
        $temp++
    }
    if ($temp -le 0){"No Events found for Evetn Type = $evetnType and Event ID = $id"}
}

$temp=0

for ($i=0; $i -lt 2; $i++ ){
    $eventID=@(4634,4647)
    switch ($i) {
        {$i -eq 0} {$evetnType = "Successful Logoff";$lType=4;$uAccount=1;$uDomain=2}
        1{$evetnType = "Successful Logoff";$lType=4;$uAccount=1;$uDomain=2}
    }
    "`n"
    $evetnType
    "-------------------------------------------------------------------------"
    "`n"
    $id=$eventID[$i]
    Get-LogonEvents $id $evetnType $lType $uAccount $uDomain $temp
}