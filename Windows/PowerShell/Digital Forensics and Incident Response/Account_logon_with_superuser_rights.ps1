$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

function Get-LogonEvents ($id,$evetnType,$uAccount,$uDomain,$privilegeList,$temp){
    Get-WinEvent  -MaxEvents 2 -FilterHashtable @{LogName = "Security"; ID = $id} | ForEach-Object {
        [PSCustomObject]@{
            LogonTime = $_.TimeCreated
            EvetnType = $evetnType
            EventId= $id
                UserAccount = $_.Properties.Value[$uAccount]
                UserDomain = $_.Properties.Value[$uDomain]
                PrivilegeList = $_.Properties.Value[$privilegeList]
        }
        "---------"
        $temp++
    }
    if ($temp -eq 0){"No Events found for $evetnType"}
}


$evetnType = "Account logon with superuser rights (Administrator)";$uAccount=1;$uDomain=2;$privilegeList=4;$id=4672
$temp=0
$evetnType
"-------------------------------------------------------------------------"        
Get-LogonEvents $id $evetnType $uAccount $uDomain $privilegeList