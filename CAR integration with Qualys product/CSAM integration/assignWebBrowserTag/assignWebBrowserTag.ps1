$credContentInBytes = [System.Text.Encoding]::UTF8.GetBytes("<user>:<password>") # Need to provide cred
$script:credEncoded = [System.Convert]::ToBase64String($credContentInBytes)
$script:tagID = <TAG ID> # Need to provide TAG ID that need to be assign

$count = 0
$ipV4 = Test-Connection -ComputerName (hostname) -Count 1  | Select -ExpandProperty IPV4Address 
$script:ip=$ipV4.IPAddressToString
# $ip

function Get-AssetID{
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/xml")
    $headers.Add("X-Requested-With", "QualysPostman")
    $headers.Add("Authorization", "Basic $credEncoded")
    
    $body = "<ServiceRequest>`n  <filters>`n    <Criteria field=`"address`" operator=`"EQUALS`">$ip</Criteria>`n  </filters>`n</ServiceRequest>"
    
    $response = [xml](Invoke-RestMethod -uri 'https://qualysapi.qg2.apps.qualys.com/qps/rest/2.0/search/am/hostasset/' -Method 'POST' -Headers $headers -Body $body).OuterXml
    $out = Select-Xml -xml $response -XPath "/ServiceResponse/data/HostAsset[1]" | Select -ExpandProperty Node
    $script:assetID = $out.id
    # $assetID
}

function Set-Tag{
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("X-Requested-With", "QualysPostman")
    $headers.Add("Authorization", "Basic $credEncoded")
    $headers.Add("Content-Type", "application/json")
    $uri = 'https://qualysapi.qg2.apps.qualys.com/qps/rest/2.0/update/am/hostasset/'+$assetID
    $body = "{`n    `"ServiceRequest`": {`n        `"data`": {`n            `"HostAsset`": {`n                `"tags`": {`n                    `"add`": {`n                        `"TagSimple`": {`n                            `"id`": `"$tagID`"`n                        }`n                    }`n                }`n            }`n        }`n    }`n}"
    $response = (Invoke-RestMethod -uri $uri -Method 'POST' -Headers $headers -Body $body).OuterXml
    $response = [xml](Invoke-RestMethod -uri $uri -Method 'POST' -Headers $headers -Body $body).OuterXml
    $out = Select-Xml -xml $response -XPath "/ServiceResponse" | Select -ExpandProperty Node
    if ($out.responseCode -eq 'SUCCESS') {
        Write-Host "`n`nTAG added successfully"
    }
}

$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
$apps = Get-ChildItem -Path $RegPath | Get-ItemProperty
forEach ($app in $apps){
    $appName=$app.DisplayName
    if (($appName -match "chrome") -or ($appName -match "firefox")){
        $count++
    }
}
if ( $count -gt 0 ) {
    Get-AssetID
    Set-Tag
}