$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

function Get-LogonEvents ($id,$evetnType,$uAccount,$uDomain,$privilegeList,$uCreatedBy,$temp){
    Get-WinEvent  -MaxEvents 2 -FilterHashtable @{LogName = "Security"; ID = $id} | ForEach-Object {
            [PSCustomObject]@{               
            LogonTime = $_.TimeCreated
            EvetnType = $evetnType
            EventId= $id
            UserAccount = $_.Properties.Value[$uAccount]
            UserDomain = $_.Properties.Value[$uDomain]
            UserCreatedBy = $_.Properties.Value[$uCreatedBy]
            PrivilegeList = $_.Properties.Value[$privilegeList]
        }
        "---------"
        $temp++
    }
    if ($temp -eq 0){"No Events found for $evetnType"}
}

$evetnType = "An account was created";$uAccount=0;$uDomain=1;$privilegeList=7;$uCreatedBy=4;$id=4720
$temp=0
$evetnType
"-------------------------------------------------------------------------"
Get-LogonEvents $id $evetnType $uAccount $uDomain $privilegeList $uCreatedBy $temp