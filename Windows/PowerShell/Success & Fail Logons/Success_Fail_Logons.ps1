function Get-LogonEvents ($id,$evetnType,$lType,$swName,$snAddress,$uAccount,$uDomain){

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
    }
}

for ($i=0; $i -lt 7; $i++ ){
        $eventID=@(4624,4625,4634,4647,4648,4672,4720)
        

        switch ($i) {
            0{$evetnType = "Successful Logon";$lType=8;$swName=11;$snAddress=18;$uAccount=5;$uDomain=6}
            1{$evetnType = "Failed Logon";$lType=10;$swName=13;$snAddress=19;$uAccount=5;$uDomain=6}
            {$i -eq 2} {$evetnType = "Successful Logoff";$lType=4;$swName=100;$snAddress=100;$uAccount=1;$uDomain=2}
            3{$evetnType = "Successful Logoff";$lType=4;$swName=100;$snAddress=100;$uAccount=1;$uDomain=2}
            4{$evetnType = "Logon using explicit credentials (Runas)";$lType=4;$swName=100;$snAddress=12;$uAccount=5;$uDomain=6}
            5{$evetnType = "Account logon with superuser rights (Administrator)";$lType=8;$swName=100;$snAddress=100;$uAccount=1;$uDomain=2}
            6{$evetnType = "An account was created";$lType=8;$swName=100;$snAddress=100;$uAccount=0;$uDomain=1}
            }
        "`n"
        $evetnType
        "-------------------------------------------------------------------------"
        "`n"
        $id=$eventID[$i]
Get-LogonEvents $id $evetnType $lType $swName $snAddress $uAccount $uDomain
}