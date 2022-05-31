$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";
$users = Get-ChildItem c:\users | ?{ $_.PSIsContainer } #Enumerate All local users
foreach ($user in $users)
{
    $objUser = New-Object System.Security.Principal.NTAccount("$user")
    $strSID = $objUser.Translate([System.Security.Principal.SecurityIdentifier])
    $uid = $strSID.Value
    $list = Get-ChildItem -Path "C:\Users\$user\AppData\Local\Google\Chrome\User Data\Default\Extensions" -Name `
    -Exclude ("aapocclcgogkmnckokdopfmhonfmgoek", "aohghmighlieiainnegkcijnfilokake", "apdfllckaahabafndbhieahigkjlhalf", "blpcfgokakmgnkcojhhkbfbldkacnbeo", "felcaaldnbdncclmgdcncolpebgiejap", "ghbmnnjooekpmoecnnnilnnbdlolhkhi", "nmmhkkegccagdldgiimedpiccmgmieda", "pjkljhegncpnkpknbcohdijeoejaedia")

    # Loops through $list items to removes to remove chrome extension
    foreach ($item in $list) 
    { 
        $ExtensionId = $item 

        $extension_folders = Get-ChildItem -Path "C:\Users\$user\AppData\Local\Google\Chrome\User Data\Default\Extensions"
        foreach ($extension_folder in $extension_folders ) 
        {
            ##: Get the version specific folder within this extension folder
            $version_folders = Get-ChildItem -Path "$($extension_folder.FullName)"

            ##: Loop through the version folders found
            foreach ($version_folder in $version_folders) 
            {
                ##: The extension folder name is the app id in the Chrome web store
                $appid = $extension_folder.BaseName
                #$appid

                ##: First check the manifest for a name
                $name = ""
                if( (Test-Path -Path "$($version_folder.FullName)\manifest.json") ) 
                {
                    try 
                    {
                        $json = Get-Content -Raw -Path "$($version_folder.FullName)\manifest.json" | ConvertFrom-Json
                        $name = $json.name
                        #$name
                    } 
                    catch 
                    {
                        #$_
                        $name = ""
                    }
                }

                ##: If we can't get a name from the extension use the app id instead
                if( !$name ) 
                {
                    $name = "[$($appid)]"
                }

                ##: Removing Extension which are not default
                if( $ExtensionId -and ($appid -eq $ExtensionId) ) 
                {
                    echo "Removing item: [Appid = $appid and Name = $name] at path: [$($extension_folder.FullName)]"
                    if(!($WhatIf)) 
                    {
                        ##: Remove the extension folder
                        if (Test-Path -Path $extension_folder.FullName) 
                        { 
                            Remove-Item -Path $extension_folder.FullName -Recurse -Force            
                        }

                        ##: Remove the extension registry key
                        if (Test-Path -Path "HKCU:\SOFTWARE\Google\Chrome\PreferenceMACs\Default\extensions.settings") 
                        {
                            if( Get-ItemProperty -Name "$appid" -Path "HKCU:\SOFTWARE\Google\Chrome\PreferenceMACs\Default\extensions.settings" ) 
                            {
                                Remove-ItemProperty -Name "$appid" -Path "HKCU:\SOFTWARE\Google\Chrome\PreferenceMACs\Default\extensions.settings"
                            }
                        }
                    }
                } 
            }
        }
    }
}