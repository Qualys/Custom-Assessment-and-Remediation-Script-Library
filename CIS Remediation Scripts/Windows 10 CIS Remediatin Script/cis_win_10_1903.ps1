<# 
-CID: 10008
STMT: Status of the 'Local Admin Password Management' setting
If the AdmPwdEnabled key exists, set the value to 1 (Enabled); otherwise, create the AdmPwdEnabled key and update the value.
#>

$regkey_10008 = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
$name_10008 = "AdmPwdEnabled"
$rvalue_10008 = "1"
$type_10008 = "DWord"
$path_10008 = Test-path $regkey_10008
 if($path_10008){
	$exist_10008=(Get-Item $regkey_10008).Property -contains $name_10008
	If($exist_10008){
		Set-ItemProperty -Path $regkey_10008 -Name $name_10008 -Value $rvalue_10008
		Write-Output "$name_10008 key is set to $rvalue_10008 for CID: 10008"
		}
	if(!$exist_10008){
		New-ItemProperty -Path $regkey_10008 -Name $name_10008 -PropertyType $type_10008 -Value $rvalue_10008 | Out-Null
		Write-Output "$name_10008 key is created and set to $rvalue_10008 for CID: 10008"
		}
  }
 else{
 New-item -Path $regkey_10008 -Force | Out-Null
  New-ItemProperty -Path $regkey_10008 -Name $name_10008 -PropertyType $type_10008 -Value $rvalue_10008 | Out-Null
  Write-Output "Created $regkey_10008  and $name_10008 key and set to $rvalue_10008 for CID: 10008"
 }

#----------------------- EOS CID 10008 -----------------------#

<# 
-CID: 10009
STMT: Status of the 'Password Complexity' Local Administrator Password Solution (LAPS)
If the PasswordComplexity key exists, set the value to 4; otherwise, create the PasswordComplexity key and update the value.
Impact: LAPS-generated passwords will be required to contain large letters + small letters + numbers + special characters.
#>

$regkey_10009 = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
$name_10009 = "PasswordComplexity"
$rvalue_10009 = "4"
$type_10009 = "DWord"
$path_10009 = Test-path $regkey_10009
 if($path_10009){
	$exist_10009=(Get-Item $regkey_10009).Property -contains $name_10009
	If($exist_10009){
		Set-ItemProperty -Path $regkey_10009 -Name $name_10009 -Value $rvalue_10009
		Write-Output "$name_10009 key is set to $rvalue_10009 for CID: 10009"
		}
	if(!$exist_10009){
		New-ItemProperty -Path $regkey_10009 -Name $name_10009 -PropertyType $type_10009 -Value $rvalue_10009 | Out-Null
		Write-Output "$name_10009 key is created and set to $rvalue_10009 for CID: 10009"
		}
  }
 else{
 New-item -Path $regkey_10009 -Force | Out-Null
  New-ItemProperty -Path $regkey_10009 -Name $name_10009 -PropertyType $type_10009 -Value $rvalue_10009 | Out-Null
  Write-Output "Created $regkey_10009  and $name_10009 key and set to $rvalue_10009 for CID: 10009"
 }

#----------------------- EOS CID 10009 -----------------------#

<# 
-CID: 10015
STMT: Status of the 'Do not allow password expiration time longer than required by policy' setting
If the PwdExpirationProtectionEnabled key exists, set the value to 1 (Enabled); otherwise, create the PwdExpirationProtectionEnabled key and update the value.
Impact: Password expiration dates that are longer than the password age specified by the "Password Settings" policy are not permitted.
#>

$regkey_10015 = "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd"
$name_10015 = "PwdExpirationProtectionEnabled"
$rvalue_10015 = "1"
$type_10015 = "DWord"
$path_10015 = Test-path $regkey_10015
 if($path_10015){
	$exist_10015=(Get-Item $regkey_10015).Property -contains $name_10015
	If($exist_10015){
		Set-ItemProperty -Path $regkey_10015 -Name $name_10015 -Value $rvalue_10015
		Write-Output "$name_10015 key is set to $rvalue_10015 for CID: 10015"
		}
	if(!$exist_10015){
		New-ItemProperty -Path $regkey_10015 -Name $name_10015 -PropertyType $type_10015 -Value $rvalue_10015 | Out-Null
		Write-Output "$name_10015 key is created and set to $rvalue_10015 for CID: 10015"
		}
  }
 else{
 New-item -Path $regkey_10015 -Force | Out-Null
  New-ItemProperty -Path $regkey_10015 -Name $name_10015 -PropertyType $type_10015 -Value $rvalue_10015 | Out-Null
  Write-Output "Created $regkey_10015  and $name_10015 key and set to $rvalue_10015 for CID: 10015"
 }

#----------------------- EOS CID 10015 -----------------------#

<# 
-CID: 10016
STMT: Status of the 'Turn off KMS Client Online AVS Validation' setting
If the NoGenTicket key exists, set the value to 1 (Enabled); otherwise, create the NoGenTicket key and update the value.
Impact: The computer is prevented from sending data to Microsoft regarding its KMS client activation state.
#>

$regkey_10016 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform"
$name_10016 = "NoGenTicket"
$rvalue_10016 = "1"
$type_10016 = "DWord"
$path_10016 = Test-path $regkey_10016
 if($path_10016){
	$exist_10016=(Get-Item $regkey_10016).Property -contains $name_10016
	If($exist_10016){
		Set-ItemProperty -Path $regkey_10016 -Name $name_10016 -Value $rvalue_10016
		Write-Output "$name_10016 key is set to $rvalue_10016 for CID: 10016"
		}
	if(!$exist_10016){
		New-ItemProperty -Path $regkey_10016 -Name $name_10016 -PropertyType $type_10016 -Value $rvalue_10016 | Out-Null
		Write-Output "$name_10016 key is created and set to $rvalue_10016 for CID: 10016"
		}
  }
 else{
 New-item -Path $regkey_10016 -Force | Out-Null
  New-ItemProperty -Path $regkey_10016 -Name $name_10016 -PropertyType $type_10016 -Value $rvalue_10016 | Out-Null
  Write-Output "Created $regkey_10016  and $name_10016 key and set to $rvalue_10016 for CID: 10016"
 }

#----------------------- EOS CID 10016 -----------------------#

<# 
-CID: 10081
STMT: Status of the 'Require domain users to elevate when setting a network's location' setting
If the NC_StdDomainUserSetLocation key exists, set the value to 1 (Enabled); otherwise, create the NC_StdDomainUserSetLocation key and update the value.
Impact: When setting the location of a network, domain users must elevate.
#>

$regkey_10081 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$name_10081 = "NC_StdDomainUserSetLocation"
$rvalue_10081 = "1"
$type_10081 = "DWord"
$path_10081 = Test-path $regkey_10081
 if($path_10081){
	$exist_10081=(Get-Item $regkey_10081).Property -contains $name_10081
	If($exist_10081){
		Set-ItemProperty -Path $regkey_10081 -Name $name_10081 -Value $rvalue_10081
		Write-Output "$name_10081 key is set to $rvalue_10081 for CID: 10081"
		}
	if(!$exist_10081){
		New-ItemProperty -Path $regkey_10081 -Name $name_10081 -PropertyType $type_10081 -Value $rvalue_10081 | Out-Null
		Write-Output "$name_10081 key is created and set to $rvalue_10081 for CID: 10081"
		}
  }
 else{
 New-item -Path $regkey_10081 -Force | Out-Null
  New-ItemProperty -Path $regkey_10081 -Name $name_10081 -PropertyType $type_10081 -Value $rvalue_10081 | Out-Null
  Write-Output "Created $regkey_10081  and $name_10081 key and set to $rvalue_10081 for CID: 10081"
 }

#----------------------- EOS CID 10081 -----------------------#

<# 
-CID: 10082
STMT: Status of the 'Turn off handwriting personalization data sharing' setting
If the PreventHandwritingDataSharing key exists, set the value to 1 (Enabled); otherwise, create the PreventHandwritingDataSharing key and update the value.
Impact: Tablet PC users cannot choose to share writing samples from the handwriting recognition personalization tool with Microsoft.
#>

$regkey_10082 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC"
$name_10082 = "PreventHandwritingDataSharing"
$rvalue_10082 = "1"
$type_10082 = "DWord"
$path_10082 = Test-path $regkey_10082
 if($path_10082){
	$exist_10082=(Get-Item $regkey_10082).Property -contains $name_10082
	If($exist_10082){
		Set-ItemProperty -Path $regkey_10082 -Name $name_10082 -Value $rvalue_10082
		Write-Output "$name_10082 key is set to $rvalue_10082 for CID: 10082"
		}
	if(!$exist_10082){
		New-ItemProperty -Path $regkey_10082 -Name $name_10082 -PropertyType $type_10082 -Value $rvalue_10082 | Out-Null
		Write-Output "$name_10082 key is created and set to $rvalue_10082 for CID: 10082"
		}
  }
 else{
 New-item -Path $regkey_10082 -Force | Out-Null
  New-ItemProperty -Path $regkey_10082 -Name $name_10082 -PropertyType $type_10082 -Value $rvalue_10082 | Out-Null
  Write-Output "Created $regkey_10082  and $name_10082 key and set to $rvalue_10082 for CID: 10082"
 }

#----------------------- EOS CID 10082 -----------------------#

<# 
-CID: 10083
STMT: Status of the 'Turn off handwriting recognition error reporting' setting
If the PreventHandwritingErrorReports key exists, set the value to 1 (Enabled); otherwise, create the PreventHandwritingErrorReports key and update the value.
Impact: Users cannot start the handwriting recognition error reporting tool or send error reports to Microsoft.
#>

$regkey_10083 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports"
$name_10083 = "PreventHandwritingErrorReports"
$rvalue_10083 = "1"
$type_10083 = "DWord"
$path_10083 = Test-path $regkey_10083
 if($path_10083){
	$exist_10083=(Get-Item $regkey_10083).Property -contains $name_10083
	If($exist_10083){
		Set-ItemProperty -Path $regkey_10083 -Name $name_10083 -Value $rvalue_10083
		Write-Output "$name_10083 key is set to $rvalue_10083 for CID: 10083"
		}
	if(!$exist_10083){
		New-ItemProperty -Path $regkey_10083 -Name $name_10083 -PropertyType $type_10083 -Value $rvalue_10083 | Out-Null
		Write-Output "$name_10083 key is created and set to $rvalue_10083 for CID: 10083"
		}
  }
 else{
 New-item -Path $regkey_10083 -Force | Out-Null
  New-ItemProperty -Path $regkey_10083 -Name $name_10083 -PropertyType $type_10083 -Value $rvalue_10083 | Out-Null
  Write-Output "Created $regkey_10083  and $name_10083 key and set to $rvalue_10083 for CID: 10083"
 }

#----------------------- EOS CID 10083 -----------------------#

<# 
-CID: 10084
STMT: Status of the 'Turn off Windows Customer Experience Improvement Program (CEIPEnable)' setting
If the CEIPEnable key exists, set the value to 0 (Enabled); otherwise, create the CEIPEnable key and update the value.
Impact: All users are opted out of the Windows Customer Experience Improvement Program.
#>

$regkey_10084 = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
$name_10084 = "CEIPEnable"
$rvalue_10084 = "0"
$type_10084 = "DWord"
$path_10084 = Test-path $regkey_10084
 if($path_10084){
	$exist_10084=(Get-Item $regkey_10084).Property -contains $name_10084
	If($exist_10084){
		Set-ItemProperty -Path $regkey_10084 -Name $name_10084 -Value $rvalue_10084
		Write-Output "$name_10084 key is set to $rvalue_10084 for CID: 10084"
		}
	if(!$exist_10084){
		New-ItemProperty -Path $regkey_10084 -Name $name_10084 -PropertyType $type_10084 -Value $rvalue_10084 | Out-Null
		Write-Output "$name_10084 key is created and set to $rvalue_10084 for CID: 10084"
		}
  }
 else{
 New-item -Path $regkey_10084 -Force | Out-Null
  New-ItemProperty -Path $regkey_10084 -Name $name_10084 -PropertyType $type_10084 -Value $rvalue_10084 | Out-Null
  Write-Output "Created $regkey_10084  and $name_10084 key and set to $rvalue_10084 for CID: 10084"
 }

#----------------------- EOS CID 10084 -----------------------#

<# 
-CID: 10085
STMT: Status of the 'Disallow copying of user input methods to the system account for sign-in' setting
If the BlockUserInputMethodsForSignIn key exists, set the value to 1 (Enabled); otherwise, create the BlockUserInputMethodsForSignIn key and update the value.
Impact: Users will have input methods enabled for the system account on the sign-in page.
#>

$regkey_10085 = "HKLM:\SOFTWARE\Policies\Microsoft\Control Panel\International"
$name_10085 = "BlockUserInputMethodsForSignIn"
$rvalue_10085 = "1"
$type_10085 = "DWord"
$path_10085 = Test-path $regkey_10085
 if($path_10085){
	$exist_10085=(Get-Item $regkey_10085).Property -contains $name_10085
	If($exist_10085){
		Set-ItemProperty -Path $regkey_10085 -Name $name_10085 -Value $rvalue_10085
		Write-Output "$name_10085 key is set to $rvalue_10085 for CID: 10085"
		}
	if(!$exist_10085){
		New-ItemProperty -Path $regkey_10085 -Name $name_10085 -PropertyType $type_10085 -Value $rvalue_10085 | Out-Null
		Write-Output "$name_10085 key is created and set to $rvalue_10085 for CID: 10085"
		}
  }
 else{
 New-item -Path $regkey_10085 -Force | Out-Null
  New-ItemProperty -Path $regkey_10085 -Name $name_10085 -PropertyType $type_10085 -Value $rvalue_10085 | Out-Null
  Write-Output "Created $regkey_10085  and $name_10085 key and set to $rvalue_10085 for CID: 10085"
 }

#----------------------- EOS CID 10085 -----------------------#

<# 
-CID: 10086
STMT: Status of the 'Enable/Disable PerfTrack' setting
If the ScenarioExecutionEnabled key exists, set the value to 0 (Disabled); otherwise, create the ScenarioExecutionEnabled key and update the value.
#>

$regkey_10086 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}"
$name_10086 = "ScenarioExecutionEnabled"
$rvalue_10086 = "0"
$type_10086 = "DWord"
$path_10086 = Test-path $regkey_10086
 if($path_10086){
	$exist_10086=(Get-Item $regkey_10086).Property -contains $name_10086
	If($exist_10086){
		Set-ItemProperty -Path $regkey_10086 -Name $name_10086 -Value $rvalue_10086
		Write-Output "$name_10086 key is set to $rvalue_10086 for CID: 10086"
		}
	if(!$exist_10086){
		New-ItemProperty -Path $regkey_10086 -Name $name_10086 -PropertyType $type_10086 -Value $rvalue_10086 | Out-Null
		Write-Output "$name_10086 key is created and set to $rvalue_10086 for CID: 10086"
		}
  }
 else{
 New-item -Path $regkey_10086 -Force | Out-Null
  New-ItemProperty -Path $regkey_10086 -Name $name_10086 -PropertyType $type_10086 -Value $rvalue_10086 | Out-Null
  Write-Output "Created $regkey_10086  and $name_10086 key and set to $rvalue_10086 for CID: 10086"
 }

#----------------------- EOS CID 10086 -----------------------#

<# 
-CID: 10087
STMT: Status of the 'Enable Windows NTP Client' setting
If the Enabled key exists, set the value to 1 (Enabled); otherwise, create the Enabled key and update the value.
Impact: Can set the local computer clock to synchronize time with NTP servers.
#>

$regkey_10087 = "HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient"
$name_10087 = "Enabled"
$rvalue_10087 = "1"
$type_10087 = "DWord"
$path_10087 = Test-path $regkey_10087
 if($path_10087){
	$exist_10087=(Get-Item $regkey_10087).Property -contains $name_10087
	If($exist_10087){
		Set-ItemProperty -Path $regkey_10087 -Name $name_10087 -Value $rvalue_10087
		Write-Output "$name_10087 key is set to $rvalue_10087 for CID: 10087"
		}
	if(!$exist_10087){
		New-ItemProperty -Path $regkey_10087 -Name $name_10087 -PropertyType $type_10087 -Value $rvalue_10087 | Out-Null
		Write-Output "$name_10087 key is created and set to $rvalue_10087 for CID: 10087"
		}
  }
 else{
 New-item -Path $regkey_10087 -Force | Out-Null
  New-ItemProperty -Path $regkey_10087 -Name $name_10087 -PropertyType $type_10087 -Value $rvalue_10087 | Out-Null
  Write-Output "Created $regkey_10087  and $name_10087 key and set to $rvalue_10087 for CID: 10087"
 }

#----------------------- EOS CID 10087 -----------------------#

<# 
-CID: 10098
STMT: Status of the 'Allow Input Personalization' setting
If the AllowInputPersonalization key exists, set the value to 0; otherwise, create the AllowInputPersonalization key and update the value.
Impact: Automatic learning of speech, inking, and typing stops and users are unable to alter the value via PC settings.
#>

$regkey_10098 = "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization"
$name_10098 = "AllowInputPersonalization"
$rvalue_10098 = "0"
$type_10098 = "DWord"
$path_10098 = Test-path $regkey_10098
 if($path_10098){
	$exist_10098=(Get-Item $regkey_10098).Property -contains $name_10098
	If($exist_10098){
		Set-ItemProperty -Path $regkey_10098 -Name $name_10098 -Value $rvalue_10098
		Write-Output "$name_10098 key is set to $rvalue_10098 for CID: 10098"
		}
	if(!$exist_10098){
		New-ItemProperty -Path $regkey_10098 -Name $name_10098 -PropertyType $type_10098 -Value $rvalue_10098 | Out-Null
		Write-Output "$name_10098 key is created and set to $rvalue_10098 for CID: 10098"
		}
  }
 else{
 New-item -Path $regkey_10098 -Force | Out-Null
  New-ItemProperty -Path $regkey_10098 -Name $name_10098 -PropertyType $type_10098 -Value $rvalue_10098 | Out-Null
  Write-Output "Created $regkey_10098  and $name_10098 key and set to $rvalue_10098 for CID: 10098"
 }

#----------------------- EOS CID 10098 -----------------------#

<# 
-CID: 10106
STMT: Status of 'Toggle user control over Insider builds'
If the AllowBuildPreview key exists, set the value to 0 (DIsabled); otherwise, create the AllowBuildPreview key and update the value.
#>

$regkey_10106 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds"
$name_10106 = "AllowBuildPreview"
$rvalue_10106 = "0"
$type_10106 = "DWord"
$path_10106 = Test-path $regkey_10106
 if($path_10106){
	$exist_10106=(Get-Item $regkey_10106).Property -contains $name_10106
	If($exist_10106){
		Set-ItemProperty -Path $regkey_10106 -Name $name_10106 -Value $rvalue_10106
		Write-Output "$name_10106 key is set to $rvalue_10106 for CID: 10106"
		}
	if(!$exist_10106){
		New-ItemProperty -Path $regkey_10106 -Name $name_10106 -PropertyType $type_10106 -Value $rvalue_10106 | Out-Null
		Write-Output "$name_10106 key is created and set to $rvalue_10106 for CID: 10106"
		}
  }
 else{
 New-item -Path $regkey_10106 -Force | Out-Null
  New-ItemProperty -Path $regkey_10106 -Name $name_10106 -PropertyType $type_10106 -Value $rvalue_10106 | Out-Null
  Write-Output "Created $regkey_10106  and $name_10106 key and set to $rvalue_10106 for CID: 10106"
 }

#----------------------- EOS CID 10106 -----------------------#

<# 
-CID: 10108
STMT: Status of the 'Allow search and Cortana to use location' setting
If the AllowSearchToUseLocation key exists, set the value to 0 (Disabled); otherwise, create the AllowSearchToUseLocation key and update the value.
Impact: Search and Cortana will not have access to location information.
#>

$regkey_10108 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$name_10108 = "AllowSearchToUseLocation"
$rvalue_10108 = "0"
$type_10108 = "DWord"
$path_10108 = Test-path $regkey_10108
 if($path_10108){
	$exist_10108=(Get-Item $regkey_10108).Property -contains $name_10108
	If($exist_10108){
		Set-ItemProperty -Path $regkey_10108 -Name $name_10108 -Value $rvalue_10108
		Write-Output "$name_10108 key is set to $rvalue_10108 for CID: 10108"
		}
	if(!$exist_10108){
		New-ItemProperty -Path $regkey_10108 -Name $name_10108 -PropertyType $type_10108 -Value $rvalue_10108 | Out-Null
		Write-Output "$name_10108 key is created and set to $rvalue_10108 for CID: 10108"
		}
  }
 else{
 New-item -Path $regkey_10108 -Force | Out-Null
  New-ItemProperty -Path $regkey_10108 -Name $name_10108 -PropertyType $type_10108 -Value $rvalue_10108 | Out-Null
  Write-Output "Created $regkey_10108  and $name_10108 key and set to $rvalue_10108 for CID: 10108"
 }

#----------------------- EOS CID 10108 -----------------------#

<# 
-CID: 10125
STMT: Status of the 'Allow Windows to automatically connect to suggested open hotspots' setting
If the AutoConnectAllowedOEM key exists, set the value to 0 (Disabled); otherwise, create the AutoConnectAllowedOEM key and update the value.
Impact: Connect to suggested open hotspots, Connect to networks shared by my contacts, and Enable paid services will each be turned off and users on the device will be prevented from enabling them.
#>

$regkey_10125 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
$name_10125 = "AutoConnectAllowedOEM"
$rvalue_10125 = "0"
$type_10125 = "DWord"
$path_10125 = Test-path $regkey_10125
 if($path_10125){
	$exist_10125=(Get-Item $regkey_10125).Property -contains $name_10125
	If($exist_10125){
		Set-ItemProperty -Path $regkey_10125 -Name $name_10125 -Value $rvalue_10125
		Write-Output "$name_10125 key is set to $rvalue_10125 for CID: 10125"
		}
	if(!$exist_10125){
		New-ItemProperty -Path $regkey_10125 -Name $name_10125 -PropertyType $type_10125 -Value $rvalue_10125 | Out-Null
		Write-Output "$name_10125 key is created and set to $rvalue_10125 for CID: 10125"
		}
  }
 else{
 New-item -Path $regkey_10125 -Force | Out-Null
  New-ItemProperty -Path $regkey_10125 -Name $name_10125 -PropertyType $type_10125 -Value $rvalue_10125 | Out-Null
  Write-Output "Created $regkey_10125  and $name_10125 key and set to $rvalue_10125 for CID: 10125"
 }

#----------------------- EOS CID 10125 -----------------------#

<# 
-CID: 10348
STMT: Status of the 'Do not show feedback notifications' setting
If the DoNotShowFeedbackNotifications key exists, set the value to 1 (Enabled); otherwise, create the DoNotShowFeedbackNotifications key and update the value.
Impact: Users will no longer see feedback notifications through the Windows Feedback app.
#>

$regkey_10348 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$name_10348 = "DoNotShowFeedbackNotifications"
$rvalue_10348 = "1"
$type_10348 = "DWord"
$path_10348 = Test-path $regkey_10348
 if($path_10348){
	$exist_10348=(Get-Item $regkey_10348).Property -contains $name_10348
	If($exist_10348){
		Set-ItemProperty -Path $regkey_10348 -Name $name_10348 -Value $rvalue_10348
		Write-Output "$name_10348 key is set to $rvalue_10348 for CID: 10348"
		}
	if(!$exist_10348){
		New-ItemProperty -Path $regkey_10348 -Name $name_10348 -PropertyType $type_10348 -Value $rvalue_10348 | Out-Null
		Write-Output "$name_10348 key is created and set to $rvalue_10348 for CID: 10348"
		}
  }
 else{
 New-item -Path $regkey_10348 -Force | Out-Null
  New-ItemProperty -Path $regkey_10348 -Name $name_10348 -PropertyType $type_10348 -Value $rvalue_10348 | Out-Null
  Write-Output "Created $regkey_10348  and $name_10348 key and set to $rvalue_10348 for CID: 10348"
 }

#----------------------- EOS CID 10348 -----------------------#

<# 
-CID: 10353
STMT: Status of the 'Turn off Microsoft consumer experiences' setting
If the DisableWindowsConsumerFeatures key exists, set the value to 1 (Enabled); otherwise, create the DisableWindowsConsumerFeatures key and update the value.
Impact: Users will no longer see personalized recommendations from Microsoft and notifications about their Microsoft account.
#>

$regkey_10353 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
$name_10353 = "DisableWindowsConsumerFeatures"
$rvalue_10353 = "1"
$type_10353 = "DWord"
$path_10353 = Test-path $regkey_10353
 if($path_10353){
	$exist_10353=(Get-Item $regkey_10353).Property -contains $name_10353
	If($exist_10353){
		Set-ItemProperty -Path $regkey_10353 -Name $name_10353 -Value $rvalue_10353
		Write-Output "$name_10353 key is set to $rvalue_10353 for CID: 10353"
		}
	if(!$exist_10353){
		New-ItemProperty -Path $regkey_10353 -Name $name_10353 -PropertyType $type_10353 -Value $rvalue_10353 | Out-Null
		Write-Output "$name_10353 key is created and set to $rvalue_10353 for CID: 10353"
		}
  }
 else{
 New-item -Path $regkey_10353 -Force | Out-Null
  New-ItemProperty -Path $regkey_10353 -Name $name_10353 -PropertyType $type_10353 -Value $rvalue_10353 | Out-Null
  Write-Output "Created $regkey_10353  and $name_10353 key and set to $rvalue_10353 for CID: 10353"
 }

#----------------------- EOS CID 10353 -----------------------#

<# 
-CID: 10362
STMT: Status of the 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' setting
If the DisableQueryRemoteServer key exists, set the value to 0 (Disabled); otherwise, create the DisableQueryRemoteServer key and update the value.
Impact: MSDT cannot run in support mode, and no data can be collected or sent to the support provider.
#>

$regkey_10362 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy"
$name_10362 = "DisableQueryRemoteServer"
$rvalue_10362 = "0"
$type_10362 = "DWord"
$path_10362 = Test-path $regkey_10362
 if($path_10362){
	$exist_10362=(Get-Item $regkey_10362).Property -contains $name_10362
	If($exist_10362){
		Set-ItemProperty -Path $regkey_10362 -Name $name_10362 -Value $rvalue_10362
		Write-Output "$name_10362 key is set to $rvalue_10362 for CID: 10362"
		}
	if(!$exist_10362){
		New-ItemProperty -Path $regkey_10362 -Name $name_10362 -PropertyType $type_10362 -Value $rvalue_10362 | Out-Null
		Write-Output "$name_10362 key is created and set to $rvalue_10362 for CID: 10362"
		}
  }
 else{
 New-item -Path $regkey_10362 -Force | Out-Null
  New-ItemProperty -Path $regkey_10362 -Name $name_10362 -PropertyType $type_10362 -Value $rvalue_10362 | Out-Null
  Write-Output "Created $regkey_10362  and $name_10362 key and set to $rvalue_10362 for CID: 10362"
 }

#----------------------- EOS CID 10362 -----------------------#

<# 
-CID: 10370
STMT: Status of the 'Enable insecure guest logons' setting
If the AllowInsecureGuestAuth key exists, set the value to 0 (Disabled); otherwise, create the AllowInsecureGuestAuth key and update the value.
Impact: The SMB client will reject insecure guest logons.
#>

$regkey_10370 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation"
$name_10370 = "AllowInsecureGuestAuth"
$rvalue_10370 = "0"
$type_10370 = "DWord"
$path_10370 = Test-path $regkey_10370
 if($path_10370){
	$exist_10370=(Get-Item $regkey_10370).Property -contains $name_10370
	If($exist_10370){
		Set-ItemProperty -Path $regkey_10370 -Name $name_10370 -Value $rvalue_10370
		Write-Output "$name_10370 key is set to $rvalue_10370 for CID: 10370"
		}
	if(!$exist_10370){
		New-ItemProperty -Path $regkey_10370 -Name $name_10370 -PropertyType $type_10370 -Value $rvalue_10370 | Out-Null
		Write-Output "$name_10370 key is created and set to $rvalue_10370 for CID: 10370"
		}
  }
 else{
 New-item -Path $regkey_10370 -Force | Out-Null
  New-ItemProperty -Path $regkey_10370 -Name $name_10370 -PropertyType $type_10370 -Value $rvalue_10370 | Out-Null
  Write-Output "Created $regkey_10370  and $name_10370 key and set to $rvalue_10370 for CID: 10370"
 }

#----------------------- EOS CID 10370 -----------------------#

<# 
-CID: 10404
STMT: Status of the 'Require user authentication for remote connections by using Network Level Authentication' setting
If the UserAuthentication key exists, set the value to 1 (Enabled); otherwise, create the UserAuthentication key and update the value.
Impact: Only client computers that support Network Level Authentication can connect to the RD Session Host server.
#>

$regkey_10404 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_10404 = "UserAuthentication"
$rvalue_10404 = "1"
$type_10404 = "DWord"
$path_10404 = Test-path $regkey_10404
 if($path_10404){
	$exist_10404=(Get-Item $regkey_10404).Property -contains $name_10404
	If($exist_10404){
		Set-ItemProperty -Path $regkey_10404 -Name $name_10404 -Value $rvalue_10404
		Write-Output "$name_10404 key is set to $rvalue_10404 for CID: 10404"
		}
	if(!$exist_10404){
		New-ItemProperty -Path $regkey_10404 -Name $name_10404 -PropertyType $type_10404 -Value $rvalue_10404 | Out-Null
		Write-Output "$name_10404 key is created and set to $rvalue_10404 for CID: 10404"
		}
  }
 else{
 New-item -Path $regkey_10404 -Force | Out-Null
  New-ItemProperty -Path $regkey_10404 -Name $name_10404 -PropertyType $type_10404 -Value $rvalue_10404 | Out-Null
  Write-Output "Created $regkey_10404  and $name_10404 key and set to $rvalue_10404 for CID: 10404"
 }

#----------------------- EOS CID 10404 -----------------------#

<# 
-CID: 10431
STMT: Status of the 'Require use of specific security layer for remote (RDP) connections' setting
If the SecurityLayer key exists, set the value to 2 (SSL); otherwise, create the SecurityLayer key and update the value.
Impact: TLS 1.0 will be required to authenticate to the RD Session Host server. If TLS is not supported, the connection fails.
#>

$regkey_10431 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_10431 = "SecurityLayer"
$rvalue_10431 = "2"
$type_10431 = "DWord"
$path_10431 = Test-path $regkey_10431
 if($path_10431){
	$exist_10431=(Get-Item $regkey_10431).Property -contains $name_10431
	If($exist_10431){
		Set-ItemProperty -Path $regkey_10431 -Name $name_10431 -Value $rvalue_10431
		Write-Output "$name_10431 key is set to $rvalue_10431 for CID: 10431"
		}
	if(!$exist_10431){
		New-ItemProperty -Path $regkey_10431 -Name $name_10431 -PropertyType $type_10431 -Value $rvalue_10431 | Out-Null
		Write-Output "$name_10431 key is created and set to $rvalue_10431 for CID: 10431"
		}
  }
 else{
 New-item -Path $regkey_10431 -Force | Out-Null
  New-ItemProperty -Path $regkey_10431 -Name $name_10431 -PropertyType $type_10431 -Value $rvalue_10431 | Out-Null
  Write-Output "Created $regkey_10431  and $name_10431 key and set to $rvalue_10431 for CID: 10431"
 }

#----------------------- EOS CID 10431 -----------------------#

<# 
-CID: 1052
STMT: Status of the 'Devices: Allowed to format and eject removable media' setting (NTFS formatted devices)
If the AllocateDASD key exists, set the value to 2 (Administrators and Interactive Users); otherwise, create the AllocateDASD key and update the value.
Impact: Administrators and Interactive Users will be able to format and eject removable NTFS media.
#>

$regkey_1052 = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
$name_1052 = "AllocateDASD"
$rvalue_1052 = "2"
$type_1052 = "DWord"
$path_1052 = Test-path $regkey_1052
 if($path_1052){
	$exist_1052=(Get-Item $regkey_1052).Property -contains $name_1052
	If($exist_1052){
		Set-ItemProperty -Path $regkey_1052 -Name $name_1052 -Value $rvalue_1052
		Write-Output "$name_1052 key is set to $rvalue_1052 for CID: 1052"
		}
	if(!$exist_1052){
		New-ItemProperty -Path $regkey_1052 -Name $name_1052 -PropertyType $type_1052 -Value $rvalue_1052 | Out-Null
		Write-Output "$name_1052 key is created and set to $rvalue_1052 for CID: 1052"
		}
  }
 else{
 New-item -Path $regkey_1052 -Force | Out-Null
  New-ItemProperty -Path $regkey_1052 -Name $name_1052 -PropertyType $type_1052 -Value $rvalue_1052 | Out-Null
  Write-Output "Created $regkey_1052  and $name_1052 key and set to $rvalue_1052 for CID: 1052"
 }

#----------------------- EOS CID 1052 -----------------------#

<# 
-CID: 11052
STMT: Status of Structured Exception Handling Overwrite Protection (SEHOP) feature in Windows
If the DisableExceptionChainValidation key exists, set the value to 0 (Enabled); otherwise, create the DisableExceptionChainValidation key and update the value.
Impact: Existing versions of Cygwin, Skype, and Armadillo-protected applications may not function properly after you enable SEHOP.
#>

$regkey_11052 = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel"
$name_11052 = "DisableExceptionChainValidation"
$rvalue_11052 = "0"
$type_11052 = "DWord"
$path_11052 = Test-path $regkey_11052
 if($path_11052){
	$exist_11052=(Get-Item $regkey_11052).Property -contains $name_11052
	If($exist_11052){
		Set-ItemProperty -Path $regkey_11052 -Name $name_11052 -Value $rvalue_11052
		Write-Output "$name_11052 key is set to $rvalue_11052 for CID: 11052"
		}
	if(!$exist_11052){
		New-ItemProperty -Path $regkey_11052 -Name $name_11052 -PropertyType $type_11052 -Value $rvalue_11052 | Out-Null
		Write-Output "$name_11052 key is created and set to $rvalue_11052 for CID: 11052"
		}
  }
 else{
 New-item -Path $regkey_11052 -Force | Out-Null
  New-ItemProperty -Path $regkey_11052 -Name $name_11052 -PropertyType $type_11052 -Value $rvalue_11052 | Out-Null
  Write-Output "Created $regkey_11052  and $name_11052 key and set to $rvalue_11052 for CID: 11052"
 }

#----------------------- EOS CID 11052 -----------------------#

<# 
-CID: 11192
STMT: Status of the 'Turn off multicast name resolution' setting
If the EnableMulticast key exists, set the value to 0 (Enabled); otherwise, create the EnableMulticast key and update the value.
Impact: In the event DNS is unavailable a system will be unable to request it from other systems on the same subnet.
#>

$regkey_11192 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
$name_11192 = "EnableMulticast"
$rvalue_11192 = "0"
$type_11192 = "DWord"
$path_11192 = Test-path $regkey_11192
 if($path_11192){
	$exist_11192=(Get-Item $regkey_11192).Property -contains $name_11192
	If($exist_11192){
		Set-ItemProperty -Path $regkey_11192 -Name $name_11192 -Value $rvalue_11192
		Write-Output "$name_11192 key is set to $rvalue_11192 for CID: 11192"
		}
	if(!$exist_11192){
		New-ItemProperty -Path $regkey_11192 -Name $name_11192 -PropertyType $type_11192 -Value $rvalue_11192 | Out-Null
		Write-Output "$name_11192 key is created and set to $rvalue_11192 for CID: 11192"
		}
  }
 else{
 New-item -Path $regkey_11192 -Force | Out-Null
  New-ItemProperty -Path $regkey_11192 -Name $name_11192 -PropertyType $type_11192 -Value $rvalue_11192 | Out-Null
  Write-Output "Created $regkey_11192  and $name_11192 key and set to $rvalue_11192 for CID: 11192"
 }

#----------------------- EOS CID 11192 -----------------------#

<# 
-CID: 11193
STMT: Status of the 'Continue experiences on this device' setting
If the EnableCdp key exists, set the value to 0 (Disabled); otherwise, create the EnableCdp key and update the value.
Impact: The Windows device will not be discoverable by other devices, and cannot participate in cross-device experiences.
#>

$regkey_11193 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_11193 = "EnableCdp"
$rvalue_11193 = "0"
$type_11193 = "DWord"
$path_11193 = Test-path $regkey_11193
 if($path_11193){
	$exist_11193=(Get-Item $regkey_11193).Property -contains $name_11193
	If($exist_11193){
		Set-ItemProperty -Path $regkey_11193 -Name $name_11193 -Value $rvalue_11193
		Write-Output "$name_11193 key is set to $rvalue_11193 for CID: 11193"
		}
	if(!$exist_11193){
		New-ItemProperty -Path $regkey_11193 -Name $name_11193 -PropertyType $type_11193 -Value $rvalue_11193 | Out-Null
		Write-Output "$name_11193 key is created and set to $rvalue_11193 for CID: 11193"
		}
  }
 else{
 New-item -Path $regkey_11193 -Force | Out-Null
  New-ItemProperty -Path $regkey_11193 -Name $name_11193 -PropertyType $type_11193 -Value $rvalue_11193 | Out-Null
  Write-Output "Created $regkey_11193  and $name_11193 key and set to $rvalue_11193 for CID: 11193"
 }

#----------------------- EOS CID 11193 -----------------------#

<# 
-CID: 11194
STMT: Status of the 'Block user from showing account details on sign-in' setting
If the BlockUserFromShowingAccountDetailsOnSignin key exists, set the value to 1 (Enabled); otherwise, create the BlockUserFromShowingAccountDetailsOnSignin key and update the value.
Impact: Users cannot choose to show account details on the sign-in screen.
#>

$regkey_11194 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_11194 = "BlockUserFromShowingAccountDetailsOnSignin"
$rvalue_11194 = "1"
$type_11194 = "DWord"
$path_11194 = Test-path $regkey_11194
 if($path_11194){
	$exist_11194=(Get-Item $regkey_11194).Property -contains $name_11194
	If($exist_11194){
		Set-ItemProperty -Path $regkey_11194 -Name $name_11194 -Value $rvalue_11194
		Write-Output "$name_11194 key is set to $rvalue_11194 for CID: 11194"
		}
	if(!$exist_11194){
		New-ItemProperty -Path $regkey_11194 -Name $name_11194 -PropertyType $type_11194 -Value $rvalue_11194 | Out-Null
		Write-Output "$name_11194 key is created and set to $rvalue_11194 for CID: 11194"
		}
  }
 else{
 New-item -Path $regkey_11194 -Force | Out-Null
  New-ItemProperty -Path $regkey_11194 -Name $name_11194 -PropertyType $type_11194 -Value $rvalue_11194 | Out-Null
  Write-Output "Created $regkey_11194  and $name_11194 key and set to $rvalue_11194 for CID: 11194"
 }

#----------------------- EOS CID 11194 -----------------------#

<# 
-CID: 11195
STMT: Status of the 'NetBIOS node type' setting
If the NodeType key exists, set the value to 2 (p-node); otherwise, create the NodeType key and update the value.
Impact: External NetBIOS name resolution queries will necessitate the use of a defined and available WINS server.
#>

$regkey_11195 = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$name_11195 = "NodeType"
$rvalue_11195 = "2"
$type_11195 = "DWord"
$path_11195 = Test-path $regkey_11195
 if($path_11195){
	$exist_11195=(Get-Item $regkey_11195).Property -contains $name_11195
	If($exist_11195){
		Set-ItemProperty -Path $regkey_11195 -Name $name_11195 -Value $rvalue_11195
		Write-Output "$name_11195 key is set to $rvalue_11195 for CID: 11195"
		}
	if(!$exist_11195){
		New-ItemProperty -Path $regkey_11195 -Name $name_11195 -PropertyType $type_11195 -Value $rvalue_11195 | Out-Null
		Write-Output "$name_11195 key is created and set to $rvalue_11195 for CID: 11195"
		}
  }
 else{
 New-item -Path $regkey_11195 -Force | Out-Null
  New-ItemProperty -Path $regkey_11195 -Name $name_11195 -PropertyType $type_11195 -Value $rvalue_11195 | Out-Null
  Write-Output "Created $regkey_11195  and $name_11195 key and set to $rvalue_11195 for CID: 11195"
 }

#----------------------- EOS CID 11195 -----------------------#

<# 
-CID: 11197
STMT: Status of the 'Allow Cortana above lock screen' setting
If the AllowCortanaAboveLock key exists, set the value to 0 (Disabled); otherwise, create the AllowCortanaAboveLock key and update the value.
Impact: The system will need to be unlocked for the user to interact with Cortana using speech.
#>

$regkey_11197 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$name_11197 = "AllowCortanaAboveLock"
$rvalue_11197 = "0"
$type_11197 = "DWord"
$path_11197 = Test-path $regkey_11197
 if($path_11197){
	$exist_11197=(Get-Item $regkey_11197).Property -contains $name_11197
	If($exist_11197){
		Set-ItemProperty -Path $regkey_11197 -Name $name_11197 -Value $rvalue_11197
		Write-Output "$name_11197 key is set to $rvalue_11197 for CID: 11197"
		}
	if(!$exist_11197){
		New-ItemProperty -Path $regkey_11197 -Name $name_11197 -PropertyType $type_11197 -Value $rvalue_11197 | Out-Null
		Write-Output "$name_11197 key is created and set to $rvalue_11197 for CID: 11197"
		}
  }
 else{
 New-item -Path $regkey_11197 -Force | Out-Null
  New-ItemProperty -Path $regkey_11197 -Name $name_11197 -PropertyType $type_11197 -Value $rvalue_11197 | Out-Null
  Write-Output "Created $regkey_11197  and $name_11197 key and set to $rvalue_11197 for CID: 11197"
 }

#----------------------- EOS CID 11197 -----------------------#

<# 
-CID: 11204
STMT: Status of the 'Enable Font Providers' setting
If the EnableFontProviders key exists, set the value to 0 (Disabled); otherwise, create the EnableFontProviders key and update the value.
Impact: Windows will not connect to an online font provider and will only enumerate locally-installed fonts.
#>

$regkey_11204 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_11204 = "EnableFontProviders"
$rvalue_11204 = "0"
$type_11204 = "DWord"
$path_11204 = Test-path $regkey_11204
 if($path_11204){
	$exist_11204=(Get-Item $regkey_11204).Property -contains $name_11204
	If($exist_11204){
		Set-ItemProperty -Path $regkey_11204 -Name $name_11204 -Value $rvalue_11204
		Write-Output "$name_11204 key is set to $rvalue_11204 for CID: 11204"
		}
	if(!$exist_11204){
		New-ItemProperty -Path $regkey_11204 -Name $name_11204 -PropertyType $type_11204 -Value $rvalue_11204 | Out-Null
		Write-Output "$name_11204 key is created and set to $rvalue_11204 for CID: 11204"
		}
  }
 else{
 New-item -Path $regkey_11204 -Force | Out-Null
  New-ItemProperty -Path $regkey_11204 -Name $name_11204 -PropertyType $type_11204 -Value $rvalue_11204 | Out-Null
  Write-Output "Created $regkey_11204  and $name_11204 key and set to $rvalue_11204 for CID: 11204"
 }

#----------------------- EOS CID 11204 -----------------------#

<# 
-CID: 11205
STMT: Status of the 'Allow network connectivity during connected-standby (on battery)' setting
If the DCSettingIndex key exists, set the value to 0 (Disabled); otherwise, create the DCSettingIndex key and update the value.
Impact: Network connectivity in standby (while on battery) is not guaranteed. This connectivity restriction currently only applies to WLAN networks only.
#>

$regkey_11205 = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$name_11205 = "DCSettingIndex"
$rvalue_11205 = "0"
$type_11205 = "DWord"
$path_11205 = Test-path $regkey_11205
 if($path_11205){
	$exist_11205=(Get-Item $regkey_11205).Property -contains $name_11205
	If($exist_11205){
		Set-ItemProperty -Path $regkey_11205 -Name $name_11205 -Value $rvalue_11205
		Write-Output "$name_11205 key is set to $rvalue_11205 for CID: 11205"
		}
	if(!$exist_11205){
		New-ItemProperty -Path $regkey_11205 -Name $name_11205 -PropertyType $type_11205 -Value $rvalue_11205 | Out-Null
		Write-Output "$name_11205 key is created and set to $rvalue_11205 for CID: 11205"
		}
  }
 else{
 New-item -Path $regkey_11205 -Force | Out-Null
  New-ItemProperty -Path $regkey_11205 -Name $name_11205 -PropertyType $type_11205 -Value $rvalue_11205 | Out-Null
  Write-Output "Created $regkey_11205  and $name_11205 key and set to $rvalue_11205 for CID: 11205"
 }

#----------------------- EOS CID 11205 -----------------------#

<# 
-CID: 11206
STMT: Status of the 'Allow network connectivity during connected-standby (plugged in)' setting
If the ACSettingIndex key exists, set the value to 0 (Disabled); otherwise, create the ACSettingIndex key and update the value.
Impact: Network connectivity in standby (while plugged in) is not guaranteed. This connectivity restriction currently only applies to WLAN networks only.
#>

$regkey_11206 = "HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\f15576e8-98b7-4186-b944-eafa664402d9"
$name_11206 = "ACSettingIndex"
$rvalue_11206 = "0"
$type_11206 = "DWord"
$path_11206 = Test-path $regkey_11206
 if($path_11206){
	$exist_11206=(Get-Item $regkey_11206).Property -contains $name_11206
	If($exist_11206){
		Set-ItemProperty -Path $regkey_11206 -Name $name_11206 -Value $rvalue_11206
		Write-Output "$name_11206 key is set to $rvalue_11206 for CID: 11206"
		}
	if(!$exist_11206){
		New-ItemProperty -Path $regkey_11206 -Name $name_11206 -PropertyType $type_11206 -Value $rvalue_11206 | Out-Null
		Write-Output "$name_11206 key is created and set to $rvalue_11206 for CID: 11206"
		}
  }
 else{
 New-item -Path $regkey_11206 -Force | Out-Null
  New-ItemProperty -Path $regkey_11206 -Name $name_11206 -PropertyType $type_11206 -Value $rvalue_11206 | Out-Null
  Write-Output "Created $regkey_11206  and $name_11206 key and set to $rvalue_11206 for CID: 11206"
 }

#----------------------- EOS CID 11206 -----------------------#

<# 
-CID: 11207
STMT: Status of the 'Allow Use of Camera' setting
If the AllowCamera key exists, set the value to 0 (Disabled); otherwise, create the AllowCamera key and update the value.
Impact: Users will not be able to utilize the camera on a system.
#>

$regkey_11207 = "HKLM:\SOFTWARE\Policies\Microsoft\Camera"
$name_11207 = "AllowCamera"
$rvalue_11207 = "0"
$type_11207 = "DWord"
$path_11207 = Test-path $regkey_11207
 if($path_11207){
	$exist_11207=(Get-Item $regkey_11207).Property -contains $name_11207
	If($exist_11207){
		Set-ItemProperty -Path $regkey_11207 -Name $name_11207 -Value $rvalue_11207
		Write-Output "$name_11207 key is set to $rvalue_11207 for CID: 11207"
		}
	if(!$exist_11207){
		New-ItemProperty -Path $regkey_11207 -Name $name_11207 -PropertyType $type_11207 -Value $rvalue_11207 | Out-Null
		Write-Output "$name_11207 key is created and set to $rvalue_11207 for CID: 11207"
		}
  }
 else{
 New-item -Path $regkey_11207 -Force | Out-Null
  New-ItemProperty -Path $regkey_11207 -Name $name_11207 -PropertyType $type_11207 -Value $rvalue_11207 | Out-Null
  Write-Output "Created $regkey_11207  and $name_11207 key and set to $rvalue_11207 for CID: 11207"
 }

#----------------------- EOS CID 11207 -----------------------#

<# 
-CID: 11254
STMT: Status of 'Bluetooth Support' Windows service startup type
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_11254 = "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv"
$name_11254 = "Start"
$rvalue_11254 = "4"
$type_11254 = "DWord"
$path_11254 = Test-path $regkey_11254
 if($path_11254){
	$exist_11254=(Get-Item $regkey_11254).Property -contains $name_11254
	If($exist_11254){
		Set-ItemProperty -Path $regkey_11254 -Name $name_11254 -Value $rvalue_11254
		Write-Output "$name_11254 key is set to $rvalue_11254 for CID: 11254"
		}
	if(!$exist_11254){
		New-ItemProperty -Path $regkey_11254 -Name $name_11254 -PropertyType $type_11254 -Value $rvalue_11254 | Out-Null
		Write-Output "$name_11254 key is created and set to $rvalue_11254 for CID: 11254"
		}
  }
 else{
 New-item -Path $regkey_11254 -Force | Out-Null
  New-ItemProperty -Path $regkey_11254 -Name $name_11254 -PropertyType $type_11254 -Value $rvalue_11254 | Out-Null
  Write-Output "Created $regkey_11254  and $name_11254 key and set to $rvalue_11254 for CID: 11254"
 }

#----------------------- EOS CID 11254 -----------------------#

<# 
-CID: 1163
STMT: Status of the 'Prevent users from installing printer drivers' setting
If the addprinterdrivers key exists, set the value to 1 (Enabled); otherwise, create the addprinterdrivers key and update the value.
Impact: Only Administrators will be able to install a printer driver as part of connecting to a shared printer.
#>

$regkey_1163 = "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\servers"
$name_1163 = "addprinterdrivers"
$rvalue_1163 = "1"
$type_1163 = "DWord"
$path_1163 = Test-path $regkey_1163
 if($path_1163){
	$exist_1163=(Get-Item $regkey_1163).Property -contains $name_1163
	If($exist_1163){
		Set-ItemProperty -Path $regkey_1163 -Name $name_1163 -Value $rvalue_1163
		Write-Output "$name_1163 key is set to $rvalue_1163 for CID: 1163"
		}
	if(!$exist_1163){
		New-ItemProperty -Path $regkey_1163 -Name $name_1163 -PropertyType $type_1163 -Value $rvalue_1163 | Out-Null
		Write-Output "$name_1163 key is created and set to $rvalue_1163 for CID: 1163"
		}
  }
 else{
 New-item -Path $regkey_1163 -Force | Out-Null
  New-ItemProperty -Path $regkey_1163 -Name $name_1163 -PropertyType $type_1163 -Value $rvalue_1163 | Out-Null
  Write-Output "Created $regkey_1163  and $name_1163 key and set to $rvalue_1163 for CID: 1163"
 }

#----------------------- EOS CID 1163 -----------------------#

<# 
-CID: 1172
STMT: Status of the 'MSS: (DisableIPSourceRouting) IP source routing protection level (protects against packet spoofing)' setting
If the DisableIPSourceRouting key exists, set the value to 2 (IP source routing disabled); otherwise, create the DisableIPSourceRouting key and update the value.
Impact: All packets routed from the source will be dropped.
#>

$regkey_1172 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$name_1172 = "DisableIPSourceRouting"
$rvalue_1172 = "2"
$type_1172 = "DWord"
$path_1172 = Test-path $regkey_1172
 if($path_1172){
	$exist_1172=(Get-Item $regkey_1172).Property -contains $name_1172
	If($exist_1172){
		Set-ItemProperty -Path $regkey_1172 -Name $name_1172 -Value $rvalue_1172
		Write-Output "$name_1172 key is set to $rvalue_1172 for CID: 1172"
		}
	if(!$exist_1172){
		New-ItemProperty -Path $regkey_1172 -Name $name_1172 -PropertyType $type_1172 -Value $rvalue_1172 | Out-Null
		Write-Output "$name_1172 key is created and set to $rvalue_1172 for CID: 1172"
		}
  }
 else{
 New-item -Path $regkey_1172 -Force | Out-Null
  New-ItemProperty -Path $regkey_1172 -Name $name_1172 -PropertyType $type_1172 -Value $rvalue_1172 | Out-Null
  Write-Output "Created $regkey_1172  and $name_1172 key and set to $rvalue_1172 for CID: 1172"
 }

#----------------------- EOS CID 1172 -----------------------#

<# 
-CID: 1184
STMT: Status of the 'MSS: (PerformRouterDiscovery) Allow IRDP to detect and configure Default Gateway addresses (could lead to DoS)' setting
If the PerformRouterDiscovery key exists, set the value to 0 (Disabled); otherwise, create the PerformRouterDiscovery key and update the value.
Impact: Windows will not automatically detect and configure default gateway addresses on the computer.
#>

$regkey_1184 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$name_1184 = "PerformRouterDiscovery"
$rvalue_1184 = "0"
$type_1184 = "DWord"
$path_1184 = Test-path $regkey_1184
 if($path_1184){
	$exist_1184=(Get-Item $regkey_1184).Property -contains $name_1184
	If($exist_1184){
		Set-ItemProperty -Path $regkey_1184 -Name $name_1184 -Value $rvalue_1184
		Write-Output "$name_1184 key is set to $rvalue_1184 for CID: 1184"
		}
	if(!$exist_1184){
		New-ItemProperty -Path $regkey_1184 -Name $name_1184 -PropertyType $type_1184 -Value $rvalue_1184 | Out-Null
		Write-Output "$name_1184 key is created and set to $rvalue_1184 for CID: 1184"
		}
  }
 else{
 New-item -Path $regkey_1184 -Force | Out-Null
  New-ItemProperty -Path $regkey_1184 -Name $name_1184 -PropertyType $type_1184 -Value $rvalue_1184 | Out-Null
  Write-Output "Created $regkey_1184  and $name_1184 key and set to $rvalue_1184 for CID: 1184"
 }

#----------------------- EOS CID 1184 -----------------------#

<# 
-CID: 1190
STMT: Status of the Security Options 'Accounts: Block Microsoft accounts' setting
If the DontDisplayLastUserName key exists, set the value to 1; otherwise, create the DontDisplayLastUserName key and update the value.
Impact: The name of the last user to successfully log on will not be displayed in the Windows logon screen.
#>

$regkey_1190 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$name_1190 = "DontDisplayLastUserName"
$rvalue_1190 = "1"
$type_1190 = "DWord"
$path_1190 = Test-path $regkey_1190
 if($path_1190){
	$exist_1190=(Get-Item $regkey_1190).Property -contains $name_1190
	If($exist_1190){
		Set-ItemProperty -Path $regkey_1190 -Name $name_1190 -Value $rvalue_1190
		Write-Output "$name_1190 key is set to $rvalue_1190 for CID: 1190"
		}
	if(!$exist_1190){
		New-ItemProperty -Path $regkey_1190 -Name $name_1190 -PropertyType $type_1190 -Value $rvalue_1190 | Out-Null
		Write-Output "$name_1190 key is created and set to $rvalue_1190 for CID: 1190"
		}
  }
 else{
 New-item -Path $regkey_1190 -Force | Out-Null
  New-ItemProperty -Path $regkey_1190 -Name $name_1190 -PropertyType $type_1190 -Value $rvalue_1190 | Out-Null
  Write-Output "Created $regkey_1190  and $name_1190 key and set to $rvalue_1190 for CID: 1190"
 }

#----------------------- EOS CID 1190 -----------------------#

<# 
-CID: 1193
STMT: Status of the 'MSS: Allow ICMP redirects to override OSPF generated routes (EnableICMPRedirect)' setting
If the EnableICMPRedirect key exists, set the value to 0 (Disabled); otherwise, create the EnableICMPRedirect key and update the value.
#>

$regkey_1193 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$name_1193 = "EnableICMPRedirect"
$rvalue_1193 = "0"
$type_1193 = "DWord"
$path_1193 = Test-path $regkey_1193
 if($path_1193){
	$exist_1193=(Get-Item $regkey_1193).Property -contains $name_1193
	If($exist_1193){
		Set-ItemProperty -Path $regkey_1193 -Name $name_1193 -Value $rvalue_1193
		Write-Output "$name_1193 key is set to $rvalue_1193 for CID: 1193"
		}
	if(!$exist_1193){
		New-ItemProperty -Path $regkey_1193 -Name $name_1193 -PropertyType $type_1193 -Value $rvalue_1193 | Out-Null
		Write-Output "$name_1193 key is created and set to $rvalue_1193 for CID: 1193"
		}
  }
 else{
 New-item -Path $regkey_1193 -Force | Out-Null
  New-ItemProperty -Path $regkey_1193 -Name $name_1193 -PropertyType $type_1193 -Value $rvalue_1193 | Out-Null
  Write-Output "Created $regkey_1193  and $name_1193 key and set to $rvalue_1193 for CID: 1193"
 }

#----------------------- EOS CID 1193 -----------------------#

<# 
-CID: 11963
STMT: Applications will be prevented from accessing maps data
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Users will not be able to log onto the computer with their Microsoft account.
#>

$regkey_11963 = "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker"
$name_11963 = "Start"
$rvalue_11963 = "4"
$type_11963 = "DWord"
$path_11963 = Test-path $regkey_11963
 if($path_11963){
	$exist_11963=(Get-Item $regkey_11963).Property -contains $name_11963
	If($exist_11963){
		Set-ItemProperty -Path $regkey_11963 -Name $name_11963 -Value $rvalue_11963
		Write-Output "$name_11963 key is set to $rvalue_11963 for CID: 11963"
		}
	if(!$exist_11963){
		New-ItemProperty -Path $regkey_11963 -Name $name_11963 -PropertyType $type_11963 -Value $rvalue_11963 | Out-Null
		Write-Output "$name_11963 key is created and set to $rvalue_11963 for CID: 11963"
		}
  }
 else{
 New-item -Path $regkey_11963 -Force | Out-Null
  New-ItemProperty -Path $regkey_11963 -Name $name_11963 -PropertyType $type_11963 -Value $rvalue_11963 | Out-Null
  Write-Output "Created $regkey_11963  and $name_11963 key and set to $rvalue_11963 for CID: 11963"
 }

#----------------------- EOS CID 11963 -----------------------#

<# 
-CID: 11965
STMT: Status of the 'Peer Networking Grouping' (p2psvc) Windows Service 'Startup type'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_11965 = "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc"
$name_11965 = "Start"
$rvalue_11965 = "4"
$type_11965 = "DWord"
$path_11965 = Test-path $regkey_11965
 if($path_11965){
	$exist_11965=(Get-Item $regkey_11965).Property -contains $name_11965
	If($exist_11965){
		Set-ItemProperty -Path $regkey_11965 -Name $name_11965 -Value $rvalue_11965
		Write-Output "$name_11965 key is set to $rvalue_11965 for CID: 11965"
		}
	if(!$exist_11965){
		New-ItemProperty -Path $regkey_11965 -Name $name_11965 -PropertyType $type_11965 -Value $rvalue_11965 | Out-Null
		Write-Output "$name_11965 key is created and set to $rvalue_11965 for CID: 11965"
		}
  }
 else{
 New-item -Path $regkey_11965 -Force | Out-Null
  New-ItemProperty -Path $regkey_11965 -Name $name_11965 -PropertyType $type_11965 -Value $rvalue_11965 | Out-Null
  Write-Output "Created $regkey_11965  and $name_11965 key and set to $rvalue_11965 for CID: 11965"
 }

#----------------------- EOS CID 11965 -----------------------#

<# 
-CID: 11966
STMT: Status of the 'Windows Mobile Hotspot Service' (icssvc) Windows Service 'Startup type'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_11966 = "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc"
$name_11966 = "Start"
$rvalue_11966 = "4"
$type_11966 = "DWord"
$path_11966 = Test-path $regkey_11966
 if($path_11966){
	$exist_11966=(Get-Item $regkey_11966).Property -contains $name_11966
	If($exist_11966){
		Set-ItemProperty -Path $regkey_11966 -Name $name_11966 -Value $rvalue_11966
		Write-Output "$name_11966 key is set to $rvalue_11966 for CID: 11966"
		}
	if(!$exist_11966){
		New-ItemProperty -Path $regkey_11966 -Name $name_11966 -PropertyType $type_11966 -Value $rvalue_11966 | Out-Null
		Write-Output "$name_11966 key is created and set to $rvalue_11966 for CID: 11966"
		}
  }
 else{
 New-item -Path $regkey_11966 -Force | Out-Null
  New-ItemProperty -Path $regkey_11966 -Name $name_11966 -PropertyType $type_11966 -Value $rvalue_11966 | Out-Null
  Write-Output "Created $regkey_11966  and $name_11966 key and set to $rvalue_11966 for CID: 11966"
 }

#----------------------- EOS CID 11966 -----------------------#

<# 
-CID: 11967
STMT: Status of the 'Xbox Live Game Save' (XblGameSave) Windows Service 'Startup type'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_11967 = "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave"
$name_11967 = "Start"
$rvalue_11967 = "4"
$type_11967 = "DWord"
$path_11967 = Test-path $regkey_11967
 if($path_11967){
	$exist_11967=(Get-Item $regkey_11967).Property -contains $name_11967
	If($exist_11967){
		Set-ItemProperty -Path $regkey_11967 -Name $name_11967 -Value $rvalue_11967
		Write-Output "$name_11967 key is set to $rvalue_11967 for CID: 11967"
		}
	if(!$exist_11967){
		New-ItemProperty -Path $regkey_11967 -Name $name_11967 -PropertyType $type_11967 -Value $rvalue_11967 | Out-Null
		Write-Output "$name_11967 key is created and set to $rvalue_11967 for CID: 11967"
		}
  }
 else{
 New-item -Path $regkey_11967 -Force | Out-Null
  New-ItemProperty -Path $regkey_11967 -Name $name_11967 -PropertyType $type_11967 -Value $rvalue_11967 | Out-Null
  Write-Output "Created $regkey_11967  and $name_11967 key and set to $rvalue_11967 for CID: 11967"
 }

#----------------------- EOS CID 11967 -----------------------#

<# 
-CID: 11969
STMT: Status of the 'Xbox Live Auth Manager' (XblAuthManager) Windows Service 'Startup type'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_11969 = "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager"
$name_11969 = "Start"
$rvalue_11969 = "4"
$type_11969 = "DWord"
$path_11969 = Test-path $regkey_11969
 if($path_11969){
	$exist_11969=(Get-Item $regkey_11969).Property -contains $name_11969
	If($exist_11969){
		Set-ItemProperty -Path $regkey_11969 -Name $name_11969 -Value $rvalue_11969
		Write-Output "$name_11969 key is set to $rvalue_11969 for CID: 11969"
		}
	if(!$exist_11969){
		New-ItemProperty -Path $regkey_11969 -Name $name_11969 -PropertyType $type_11969 -Value $rvalue_11969 | Out-Null
		Write-Output "$name_11969 key is created and set to $rvalue_11969 for CID: 11969"
		}
  }
 else{
 New-item -Path $regkey_11969 -Force | Out-Null
  New-ItemProperty -Path $regkey_11969 -Name $name_11969 -PropertyType $type_11969 -Value $rvalue_11969 | Out-Null
  Write-Output "Created $regkey_11969  and $name_11969 key and set to $rvalue_11969 for CID: 11969"
 }

#----------------------- EOS CID 11969 -----------------------#

<# 
-CID: 11970
STMT: Status of the 'Xbox Live Networking Service' (XboxNetApiSvc) Windows Service 'Startup type'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_11970 = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc"
$name_11970 = "Start"
$rvalue_11970 = "4"
$type_11970 = "DWord"
$path_11970 = Test-path $regkey_11970
 if($path_11970){
	$exist_11970=(Get-Item $regkey_11970).Property -contains $name_11970
	If($exist_11970){
		Set-ItemProperty -Path $regkey_11970 -Name $name_11970 -Value $rvalue_11970
		Write-Output "$name_11970 key is set to $rvalue_11970 for CID: 11970"
		}
	if(!$exist_11970){
		New-ItemProperty -Path $regkey_11970 -Name $name_11970 -PropertyType $type_11970 -Value $rvalue_11970 | Out-Null
		Write-Output "$name_11970 key is created and set to $rvalue_11970 for CID: 11970"
		}
  }
 else{
 New-item -Path $regkey_11970 -Force | Out-Null
  New-ItemProperty -Path $regkey_11970 -Name $name_11970 -PropertyType $type_11970 -Value $rvalue_11970 | Out-Null
  Write-Output "Created $regkey_11970  and $name_11970 key and set to $rvalue_11970 for CID: 11970"
 }

#----------------------- EOS CID 11970 -----------------------#

<# 
-CID: 12007
STMT: Status of the 'Windows Push Notifications System Service' (WpnService) Windows Service 'Startup type'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_12007 = "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService"
$name_12007 = "Start"
$rvalue_12007 = "4"
$type_12007 = "DWord"
$path_12007 = Test-path $regkey_12007
 if($path_12007){
	$exist_12007=(Get-Item $regkey_12007).Property -contains $name_12007
	If($exist_12007){
		Set-ItemProperty -Path $regkey_12007 -Name $name_12007 -Value $rvalue_12007
		Write-Output "$name_12007 key is set to $rvalue_12007 for CID: 12007"
		}
	if(!$exist_12007){
		New-ItemProperty -Path $regkey_12007 -Name $name_12007 -PropertyType $type_12007 -Value $rvalue_12007 | Out-Null
		Write-Output "$name_12007 key is created and set to $rvalue_12007 for CID: 12007"
		}
  }
 else{
 New-item -Path $regkey_12007 -Force | Out-Null
  New-ItemProperty -Path $regkey_12007 -Name $name_12007 -PropertyType $type_12007 -Value $rvalue_12007 | Out-Null
  Write-Output "Created $regkey_12007  and $name_12007 key and set to $rvalue_12007 for CID: 12007"
 }

#----------------------- EOS CID 12007 -----------------------#

<# 
-CID: 12008
STMT: Status of the 'Xbox Accessory Management Service' (XboxGipSvc) Windows Service 'Startup type'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_12008 = "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc"
$name_12008 = "Start"
$rvalue_12008 = "4"
$type_12008 = "DWord"
$path_12008 = Test-path $regkey_12008
 if($path_12008){
	$exist_12008=(Get-Item $regkey_12008).Property -contains $name_12008
	If($exist_12008){
		Set-ItemProperty -Path $regkey_12008 -Name $name_12008 -Value $rvalue_12008
		Write-Output "$name_12008 key is set to $rvalue_12008 for CID: 12008"
		}
	if(!$exist_12008){
		New-ItemProperty -Path $regkey_12008 -Name $name_12008 -PropertyType $type_12008 -Value $rvalue_12008 | Out-Null
		Write-Output "$name_12008 key is created and set to $rvalue_12008 for CID: 12008"
		}
  }
 else{
 New-item -Path $regkey_12008 -Force | Out-Null
  New-ItemProperty -Path $regkey_12008 -Name $name_12008 -PropertyType $type_12008 -Value $rvalue_12008 | Out-Null
  Write-Output "Created $regkey_12008  and $name_12008 key and set to $rvalue_12008 for CID: 12008"
 }

#----------------------- EOS CID 12008 -----------------------#

<# 
-CID: 12013
STMT: Status of the 'Remote host allows delegation of non-exportable credentials' (AllowProtectedCreds) setting
If the AllowProtectedCreds key exists, set the value to 1 (Enabled); otherwise, create the AllowProtectedCreds key and update the value.
Impact: The host will support the Restricted Admin Mode and Windows Defender Remote Credential Guard features.
#>

$regkey_12013 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
$name_12013 = "AllowProtectedCreds"
$rvalue_12013 = "1"
$type_12013 = "DWord"
$path_12013 = Test-path $regkey_12013
 if($path_12013){
	$exist_12013=(Get-Item $regkey_12013).Property -contains $name_12013
	If($exist_12013){
		Set-ItemProperty -Path $regkey_12013 -Name $name_12013 -Value $rvalue_12013
		Write-Output "$name_12013 key is set to $rvalue_12013 for CID: 12013"
		}
	if(!$exist_12013){
		New-ItemProperty -Path $regkey_12013 -Name $name_12013 -PropertyType $type_12013 -Value $rvalue_12013 | Out-Null
		Write-Output "$name_12013 key is created and set to $rvalue_12013 for CID: 12013"
		}
  }
 else{
 New-item -Path $regkey_12013 -Force | Out-Null
  New-ItemProperty -Path $regkey_12013 -Name $name_12013 -PropertyType $type_12013 -Value $rvalue_12013 | Out-Null
  Write-Output "Created $regkey_12013  and $name_12013 key and set to $rvalue_12013 for CID: 12013"
 }

#----------------------- EOS CID 12013 -----------------------#

<# 
-CID: 12026
STMT: Status of the 'Configure Authenticated Proxy usage for the Connected User Experience and Telemetry service'
If the DisableEnterpriseAuthProxy key exists, set the value to 1 (Disable Authenticated Proxy usage); otherwise, create the DisableEnterpriseAuthProxy key and update the value.
Impact: The Connected User Experience and Telemetry service will be blocked from automatically using an authenticated proxy.
#>

$regkey_12026 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
$name_12026 = "DisableEnterpriseAuthProxy"
$rvalue_12026 = "1"
$type_12026 = "DWord"
$path_12026 = Test-path $regkey_12026
 if($path_12026){
	$exist_12026=(Get-Item $regkey_12026).Property -contains $name_12026
	If($exist_12026){
		Set-ItemProperty -Path $regkey_12026 -Name $name_12026 -Value $rvalue_12026
		Write-Output "$name_12026 key is set to $rvalue_12026 for CID: 12026"
		}
	if(!$exist_12026){
		New-ItemProperty -Path $regkey_12026 -Name $name_12026 -PropertyType $type_12026 -Value $rvalue_12026 | Out-Null
		Write-Output "$name_12026 key is created and set to $rvalue_12026 for CID: 12026"
		}
  }
 else{
 New-item -Path $regkey_12026 -Force | Out-Null
  New-ItemProperty -Path $regkey_12026 -Name $name_12026 -PropertyType $type_12026 -Value $rvalue_12026 | Out-Null
  Write-Output "Created $regkey_12026  and $name_12026 key and set to $rvalue_12026 for CID: 12026"
 }

#----------------------- EOS CID 12026 -----------------------#

<# 
-CID: 1376
STMT: Status of the Security Options 'Accounts: Block Microsoft accounts' setting
If the DisableCAD key exists, set the value to 0; otherwise, create the DisableCAD key and update the value.
Impact: Users must press CTRL+ALT+DEL before they log on to Windows unless they use a smart card for Windows logon.
#>

$regkey_1376 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$name_1376 = "DisableCAD"
$rvalue_1376 = "0"
$type_1376 = "DWord"
$path_1376 = Test-path $regkey_1376
 if($path_1376){
	$exist_1376=(Get-Item $regkey_1376).Property -contains $name_1376
	If($exist_1376){
		Set-ItemProperty -Path $regkey_1376 -Name $name_1376 -Value $rvalue_1376
		Write-Output "$name_1376 key is set to $rvalue_1376 for CID: 1376"
		}
	if(!$exist_1376){
		New-ItemProperty -Path $regkey_1376 -Name $name_1376 -PropertyType $type_1376 -Value $rvalue_1376 | Out-Null
		Write-Output "$name_1376 key is created and set to $rvalue_1376 for CID: 1376"
		}
  }
 else{
 New-item -Path $regkey_1376 -Force | Out-Null
  New-ItemProperty -Path $regkey_1376 -Name $name_1376 -PropertyType $type_1376 -Value $rvalue_1376 | Out-Null
  Write-Output "Created $regkey_1376  and $name_1376 key and set to $rvalue_1376 for CID: 1376"
 }

#----------------------- EOS CID 1376 -----------------------#

<# 
-CID: 1387
STMT: Status of the 'Network Security: LAN Manager Authentication Level' setting
If the LmCompatibilityLevel key exists, set the value to 5 (Send NTLMv2 response only/refuse LM and NTLM); otherwise, create the LmCompatibilityLevel key and update the value.
Impact: Clients use NTLMv2 authentication only;
#>

$regkey_1387 = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$name_1387 = "LmCompatibilityLevel"
$rvalue_1387 = "5"
$type_1387 = "DWord"
$path_1387 = Test-path $regkey_1387
 if($path_1387){
	$exist_1387=(Get-Item $regkey_1387).Property -contains $name_1387
	If($exist_1387){
		Set-ItemProperty -Path $regkey_1387 -Name $name_1387 -Value $rvalue_1387
		Write-Output "$name_1387 key is set to $rvalue_1387 for CID: 1387"
		}
	if(!$exist_1387){
		New-ItemProperty -Path $regkey_1387 -Name $name_1387 -PropertyType $type_1387 -Value $rvalue_1387 | Out-Null
		Write-Output "$name_1387 key is created and set to $rvalue_1387 for CID: 1387"
		}
  }
 else{
 New-item -Path $regkey_1387 -Force | Out-Null
  New-ItemProperty -Path $regkey_1387 -Name $name_1387 -PropertyType $type_1387 -Value $rvalue_1387 | Out-Null
  Write-Output "Created $regkey_1387  and $name_1387 key and set to $rvalue_1387 for CID: 1387"
 }

#----------------------- EOS CID 1387 -----------------------#

<# 
-CID: 1389
STMT: Status of the 'Network Security: Minimum session security for NTLM SSP based (including secure RPC) clients' setting
If the NTLMMinClientSec key exists, set the value to 537395200 (Require NTLMv2 session security, Require 128-bit encryption); otherwise, create the NTLMMinClientSec key and update the value.
Impact: NTLM connections will fail if NTLMv2 protocol and strong encryption (128-bit) are not both negotiated.
Note: This setting is dependent on the Network security: LAN Manager Authentication Level security setting value (CID: 1387).
#>

$regkey_1389 = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$name_1389 = "NTLMMinClientSec"
$rvalue_1389 = "537395200"
$type_1389 = "DWord"
$path_1389 = Test-path $regkey_1389
 if($path_1389){
	$exist_1389=(Get-Item $regkey_1389).Property -contains $name_1389
	If($exist_1389){
		Set-ItemProperty -Path $regkey_1389 -Name $name_1389 -Value $rvalue_1389
		Write-Output "$name_1389 key is set to $rvalue_1389 for CID: 1389"
		}
	if(!$exist_1389){
		New-ItemProperty -Path $regkey_1389 -Name $name_1389 -PropertyType $type_1389 -Value $rvalue_1389 | Out-Null
		Write-Output "$name_1389 key is created and set to $rvalue_1389 for CID: 1389"
		}
  }
 else{
 New-item -Path $regkey_1389 -Force | Out-Null
  New-ItemProperty -Path $regkey_1389 -Name $name_1389 -PropertyType $type_1389 -Value $rvalue_1389 | Out-Null
  Write-Output "Created $regkey_1389  and $name_1389 key and set to $rvalue_1389 for CID: 1389"
 }

#----------------------- EOS CID 1389 -----------------------#

<# 
-CID: 1390
STMT: Status of the 'Network Security: Minimum session security for NTLM SSP based (including secure RPC) clients' setting
If the NTLMMinServerSec key exists, set the value to 537395200 (Require NTLMv2 session security, Require 128-bit encryption); otherwise, create the NTLMMinServerSec key and update the value.
Impact: NTLM connections will fail if NTLMv2 protocol and strong encryption (128-bit) are not both negotiated.
Note: This setting is dependent on the Network security: LAN Manager Authentication Level security setting value (CID: 1387).
#>

$regkey_1390 = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$name_1390 = "NTLMMinServerSec"
$rvalue_1390 = "537395200"
$type_1390 = "DWord"
$path_1390 = Test-path $regkey_1390
 if($path_1390){
	$exist_1390=(Get-Item $regkey_1390).Property -contains $name_1390
	If($exist_1390){
		Set-ItemProperty -Path $regkey_1390 -Name $name_1390 -Value $rvalue_1390
		Write-Output "$name_1390 key is set to $rvalue_1390 for CID: 1390"
		}
	if(!$exist_1390){
		New-ItemProperty -Path $regkey_1390 -Name $name_1390 -PropertyType $type_1390 -Value $rvalue_1390 | Out-Null
		Write-Output "$name_1390 key is created and set to $rvalue_1390 for CID: 1390"
		}
  }
 else{
 New-item -Path $regkey_1390 -Force | Out-Null
  New-ItemProperty -Path $regkey_1390 -Name $name_1390 -PropertyType $type_1390 -Value $rvalue_1390 | Out-Null
  Write-Output "Created $regkey_1390  and $name_1390 key and set to $rvalue_1390 for CID: 1390"
 }

#----------------------- EOS CID 1390 -----------------------#

<# 
-CID: 13922
STMT: Status of 'Attack Surface Reduction' group policy
If the ExploitGuard_ASR_Rules key exists, set the value to 1 (Enabled); otherwise, create the ExploitGuard_ASR_Rules key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_13922 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
$name_13922 = "ExploitGuard_ASR_Rules"
$rvalue_13922 = "1"
$type_13922 = "DWord"
$path_13922 = Test-path $regkey_13922
 if($path_13922){
	$exist_13922=(Get-Item $regkey_13922).Property -contains $name_13922
	If($exist_13922){
		Set-ItemProperty -Path $regkey_13922 -Name $name_13922 -Value $rvalue_13922
		Write-Output "$name_13922 key is set to $rvalue_13922 for CID: 13922"
		}
	if(!$exist_13922){
		New-ItemProperty -Path $regkey_13922 -Name $name_13922 -PropertyType $type_13922 -Value $rvalue_13922 | Out-Null
		Write-Output "$name_13922 key is created and set to $rvalue_13922 for CID: 13922"
		}
  }
 else{
 New-item -Path $regkey_13922 -Force | Out-Null
  New-ItemProperty -Path $regkey_13922 -Name $name_13922 -PropertyType $type_13922 -Value $rvalue_13922 | Out-Null
  Write-Output "Created $regkey_13922  and $name_13922 key and set to $rvalue_13922 for CID: 13922"
 }

#----------------------- EOS CID 13922 -----------------------#

<# 
-CID: 13923
STMT: Status of 'Block Office applications from injecting code into other processes' ASR rule (75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84)
If the 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 key exists, set the value to 1 (Block); otherwise, create the 75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84 key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_13923 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_13923 = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
$rvalue_13923 = "1"
$type_13923 = "DWord"
$path_13923 = Test-path $regkey_13923
 if($path_13923){
	$exist_13923=(Get-Item $regkey_13923).Property -contains $name_13923
	If($exist_13923){
		Set-ItemProperty -Path $regkey_13923 -Name $name_13923 -Value $rvalue_13923
		Write-Output "$name_13923 key is set to $rvalue_13923 for CID: 13923"
		}
	if(!$exist_13923){
		New-ItemProperty -Path $regkey_13923 -Name $name_13923 -PropertyType $type_13923 -Value $rvalue_13923 | Out-Null
		Write-Output "$name_13923 key is created and set to $rvalue_13923 for CID: 13923"
		}
  }
 else{
 New-item -Path $regkey_13923 -Force | Out-Null
  New-ItemProperty -Path $regkey_13923 -Name $name_13923 -PropertyType $type_13923 -Value $rvalue_13923 | Out-Null
  Write-Output "Created $regkey_13923  and $name_13923 key and set to $rvalue_13923 for CID: 13923"
 }

#----------------------- EOS CID 13923 -----------------------#

<# 
-CID: 13924
STMT: Status of 'Block all Office applications from creating child processes' ASR rule (D4F940AB-401B-4EFC-AADC-AD5F3C50688A)
If the D4F940AB-401B-4EFC-AADC-AD5F3C50688A key exists, set the value to 1 (Block); otherwise, create the D4F940AB-401B-4EFC-AADC-AD5F3C50688A key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_13924 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_13924 = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
$rvalue_13924 = "1"
$type_13924 = "DWord"
$path_13924 = Test-path $regkey_13924
 if($path_13924){
	$exist_13924=(Get-Item $regkey_13924).Property -contains $name_13924
	If($exist_13924){
		Set-ItemProperty -Path $regkey_13924 -Name $name_13924 -Value $rvalue_13924
		Write-Output "$name_13924 key is set to $rvalue_13924 for CID: 13924"
		}
	if(!$exist_13924){
		New-ItemProperty -Path $regkey_13924 -Name $name_13924 -PropertyType $type_13924 -Value $rvalue_13924 | Out-Null
		Write-Output "$name_13924 key is created and set to $rvalue_13924 for CID: 13924"
		}
  }
 else{
 New-item -Path $regkey_13924 -Force | Out-Null
  New-ItemProperty -Path $regkey_13924 -Name $name_13924 -PropertyType $type_13924 -Value $rvalue_13924 | Out-Null
  Write-Output "Created $regkey_13924  and $name_13924 key and set to $rvalue_13924 for CID: 13924"
 }

#----------------------- EOS CID 13924 -----------------------#

<# 
-CID: 13925
STMT: Status of 'Block Win32 API calls from Office macro' ASR rule (92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B)
If the 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B key exists, set the value to 1 (Block); otherwise, create the 92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_13925 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_13925 = "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B"
$rvalue_13925 = "1"
$type_13925 = "DWord"
$path_13925 = Test-path $regkey_13925
 if($path_13925){
	$exist_13925=(Get-Item $regkey_13925).Property -contains $name_13925
	If($exist_13925){
		Set-ItemProperty -Path $regkey_13925 -Name $name_13925 -Value $rvalue_13925
		Write-Output "$name_13925 key is set to $rvalue_13925 for CID: 13925"
		}
	if(!$exist_13925){
		New-ItemProperty -Path $regkey_13925 -Name $name_13925 -PropertyType $type_13925 -Value $rvalue_13925 | Out-Null
		Write-Output "$name_13925 key is created and set to $rvalue_13925 for CID: 13925"
		}
  }
 else{
 New-item -Path $regkey_13925 -Force | Out-Null
  New-ItemProperty -Path $regkey_13925 -Name $name_13925 -PropertyType $type_13925 -Value $rvalue_13925 | Out-Null
  Write-Output "Created $regkey_13925  and $name_13925 key and set to $rvalue_13925 for CID: 13925"
 }

#----------------------- EOS CID 13925 -----------------------#

<# 
-CID: 13926
STMT: Status of 'Block execution of potentially obfuscated scripts' ASR rule (5BEB7EFE-FD9A-4556-801D-275E5FFC04CC)
If the 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC key exists, set the value to 1 (Block); otherwise, create the 5BEB7EFE-FD9A-4556-801D-275E5FFC04CC key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_13926 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_13926 = "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC"
$rvalue_13926 = "1"
$type_13926 = "DWord"
$path_13926 = Test-path $regkey_13926
 if($path_13926){
	$exist_13926=(Get-Item $regkey_13926).Property -contains $name_13926
	If($exist_13926){
		Set-ItemProperty -Path $regkey_13926 -Name $name_13926 -Value $rvalue_13926
		Write-Output "$name_13926 key is set to $rvalue_13926 for CID: 13926"
		}
	if(!$exist_13926){
		New-ItemProperty -Path $regkey_13926 -Name $name_13926 -PropertyType $type_13926 -Value $rvalue_13926 | Out-Null
		Write-Output "$name_13926 key is created and set to $rvalue_13926 for CID: 13926"
		}
  }
 else{
 New-item -Path $regkey_13926 -Force | Out-Null
  New-ItemProperty -Path $regkey_13926 -Name $name_13926 -PropertyType $type_13926 -Value $rvalue_13926 | Out-Null
  Write-Output "Created $regkey_13926  and $name_13926 key and set to $rvalue_13926 for CID: 13926"
 }

#----------------------- EOS CID 13926 -----------------------#

<# 
-CID: 13927
STMT: Status of 'Block JavaScript or VBScript from launching downloaded executable content' ASR rule (D3E037E1-3EB8-44C8-A917-57927947596D)
If the D3E037E1-3EB8-44C8-A917-57927947596D key exists, set the value to 1 (Block); otherwise, create the D3E037E1-3EB8-44C8-A917-57927947596D key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_13927 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_13927 = "D3E037E1-3EB8-44C8-A917-57927947596D"
$rvalue_13927 = "1"
$type_13927 = "DWord"
$path_13927 = Test-path $regkey_13927
 if($path_13927){
	$exist_13927=(Get-Item $regkey_13927).Property -contains $name_13927
	If($exist_13927){
		Set-ItemProperty -Path $regkey_13927 -Name $name_13927 -Value $rvalue_13927
		Write-Output "$name_13927 key is set to $rvalue_13927 for CID: 13927"
		}
	if(!$exist_13927){
		New-ItemProperty -Path $regkey_13927 -Name $name_13927 -PropertyType $type_13927 -Value $rvalue_13927 | Out-Null
		Write-Output "$name_13927 key is created and set to $rvalue_13927 for CID: 13927"
		}
  }
 else{
 New-item -Path $regkey_13927 -Force | Out-Null
  New-ItemProperty -Path $regkey_13927 -Name $name_13927 -PropertyType $type_13927 -Value $rvalue_13927 | Out-Null
  Write-Output "Created $regkey_13927  and $name_13927 key and set to $rvalue_13927 for CID: 13927"
 }

#----------------------- EOS CID 13927 -----------------------#

<# 
-CID: 13928
STMT: Status of 'Block executable content from email client and webmail' ASR rule (BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550)
If the BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 key exists, set the value to 1 (Block); otherwise, create the BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550 key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_13928 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_13928 = "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550"
$rvalue_13928 = "1"
$type_13928 = "DWord"
$path_13928 = Test-path $regkey_13928
 if($path_13928){
	$exist_13928=(Get-Item $regkey_13928).Property -contains $name_13928
	If($exist_13928){
		Set-ItemProperty -Path $regkey_13928 -Name $name_13928 -Value $rvalue_13928
		Write-Output "$name_13928 key is set to $rvalue_13928 for CID: 13928"
		}
	if(!$exist_13928){
		New-ItemProperty -Path $regkey_13928 -Name $name_13928 -PropertyType $type_13928 -Value $rvalue_13928 | Out-Null
		Write-Output "$name_13928 key is created and set to $rvalue_13928 for CID: 13928"
		}
  }
 else{
 New-item -Path $regkey_13928 -Force | Out-Null
  New-ItemProperty -Path $regkey_13928 -Name $name_13928 -PropertyType $type_13928 -Value $rvalue_13928 | Out-Null
  Write-Output "Created $regkey_13928  and $name_13928 key and set to $rvalue_13928 for CID: 13928"
 }

#----------------------- EOS CID 13928 -----------------------#

<# 
-CID: 13929
STMT: Status of 'Block untrusted and unsigned processes that run from USB' ASR rule (b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4)
If the b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 key exists, set the value to 1 (Block); otherwise, create the b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_13929 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_13929 = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
$rvalue_13929 = "1"
$type_13929 = "DWord"
$path_13929 = Test-path $regkey_13929
 if($path_13929){
	$exist_13929=(Get-Item $regkey_13929).Property -contains $name_13929
	If($exist_13929){
		Set-ItemProperty -Path $regkey_13929 -Name $name_13929 -Value $rvalue_13929
		Write-Output "$name_13929 key is set to $rvalue_13929 for CID: 13929"
		}
	if(!$exist_13929){
		New-ItemProperty -Path $regkey_13929 -Name $name_13929 -PropertyType $type_13929 -Value $rvalue_13929 | Out-Null
		Write-Output "$name_13929 key is created and set to $rvalue_13929 for CID: 13929"
		}
  }
 else{
 New-item -Path $regkey_13929 -Force | Out-Null
  New-ItemProperty -Path $regkey_13929 -Name $name_13929 -PropertyType $type_13929 -Value $rvalue_13929 | Out-Null
  Write-Output "Created $regkey_13929  and $name_13929 key and set to $rvalue_13929 for CID: 13929"
 }

#----------------------- EOS CID 13929 -----------------------#

<# 
-CID: 13930
STMT: Status of 'Block credential stealing from the Windows local security authority subsystem (lsass.exe)' ASR rule
If the 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 key exists, set the value to 1 (Block); otherwise, create the 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_13930 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_13930 = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
$rvalue_13930 = "1"
$type_13930 = "DWord"
$path_13930 = Test-path $regkey_13930
 if($path_13930){
	$exist_13930=(Get-Item $regkey_13930).Property -contains $name_13930
	If($exist_13930){
		Set-ItemProperty -Path $regkey_13930 -Name $name_13930 -Value $rvalue_13930
		Write-Output "$name_13930 key is set to $rvalue_13930 for CID: 13930"
		}
	if(!$exist_13930){
		New-ItemProperty -Path $regkey_13930 -Name $name_13930 -PropertyType $type_13930 -Value $rvalue_13930 | Out-Null
		Write-Output "$name_13930 key is created and set to $rvalue_13930 for CID: 13930"
		}
  }
 else{
 New-item -Path $regkey_13930 -Force | Out-Null
  New-ItemProperty -Path $regkey_13930 -Name $name_13930 -PropertyType $type_13930 -Value $rvalue_13930 | Out-Null
  Write-Output "Created $regkey_13930  and $name_13930 key and set to $rvalue_13930 for CID: 13930"
 }

#----------------------- EOS CID 13930 -----------------------#

<# 
-CID: 14883
STMT: Status of 'Block Office applications from creating executable content' ASR rule (3B576869-A4EC-4529-8536-B80A7769E899)
If the 3B576869-A4EC-4529-8536-B80A7769E899 key exists, set the value to 1 (Block); otherwise, create the 3B576869-A4EC-4529-8536-B80A7769E899 key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_14883 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_14883 = "3B576869-A4EC-4529-8536-B80A7769E899"
$rvalue_14883 = "1"
$type_14883 = "DWord"
$path_14883 = Test-path $regkey_14883
 if($path_14883){
	$exist_14883=(Get-Item $regkey_14883).Property -contains $name_14883
	If($exist_14883){
		Set-ItemProperty -Path $regkey_14883 -Name $name_14883 -Value $rvalue_14883
		Write-Output "$name_14883 key is set to $rvalue_14883 for CID: 14883"
		}
	if(!$exist_14883){
		New-ItemProperty -Path $regkey_14883 -Name $name_14883 -PropertyType $type_14883 -Value $rvalue_14883 | Out-Null
		Write-Output "$name_14883 key is created and set to $rvalue_14883 for CID: 14883"
		}
  }
 else{
 New-item -Path $regkey_14883 -Force | Out-Null
  New-ItemProperty -Path $regkey_14883 -Name $name_14883 -PropertyType $type_14883 -Value $rvalue_14883 | Out-Null
  Write-Output "Created $regkey_14883  and $name_14883 key and set to $rvalue_14883 for CID: 14883"
 }

#----------------------- EOS CID 14883 -----------------------#

<# 
-CID: 13938
STMT: Startup type of 'Windows PushToInstall Service' (PushToInstall) service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_13938 = "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall"
$name_13938 = "Start"
$rvalue_13938 = "4"
$type_13938 = "DWord"
$path_13938 = Test-path $regkey_13938
 if($path_13938){
	$exist_13938=(Get-Item $regkey_13938).Property -contains $name_13938
	If($exist_13938){
		Set-ItemProperty -Path $regkey_13938 -Name $name_13938 -Value $rvalue_13938
		Write-Output "$name_13938 key is set to $rvalue_13938 for CID: 13938"
		}
	if(!$exist_13938){
		New-ItemProperty -Path $regkey_13938 -Name $name_13938 -PropertyType $type_13938 -Value $rvalue_13938 | Out-Null
		Write-Output "$name_13938 key is created and set to $rvalue_13938 for CID: 13938"
		}
  }
 else{
 New-item -Path $regkey_13938 -Force | Out-Null
  New-ItemProperty -Path $regkey_13938 -Name $name_13938 -PropertyType $type_13938 -Value $rvalue_13938 | Out-Null
  Write-Output "Created $regkey_13938  and $name_13938 key and set to $rvalue_13938 for CID: 13938"
 }

#----------------------- EOS CID 13938 -----------------------#

<# 
-CID: 13939
STMT: Status of Windows Store Install Service (InstallService)
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_13939 = "HKLM:\SYSTEM\CurrentControlSet\Services\InstallService"
$name_13939 = "Start"
$rvalue_13939 = "4"
$type_13939 = "DWord"
$path_13939 = Test-path $regkey_13939
 if($path_13939){
	$exist_13939=(Get-Item $regkey_13939).Property -contains $name_13939
	If($exist_13939){
		Set-ItemProperty -Path $regkey_13939 -Name $name_13939 -Value $rvalue_13939
		Write-Output "$name_13939 key is set to $rvalue_13939 for CID: 13939"
		}
	if(!$exist_13939){
		New-ItemProperty -Path $regkey_13939 -Name $name_13939 -PropertyType $type_13939 -Value $rvalue_13939 | Out-Null
		Write-Output "$name_13939 key is created and set to $rvalue_13939 for CID: 13939"
		}
  }
 else{
 New-item -Path $regkey_13939 -Force | Out-Null
  New-ItemProperty -Path $regkey_13939 -Name $name_13939 -PropertyType $type_13939 -Value $rvalue_13939 | Out-Null
  Write-Output "Created $regkey_13939  and $name_13939 key and set to $rvalue_13939 for CID: 13939"
 }

#----------------------- EOS CID 13939 -----------------------#

<# 
-CID: 13940
STMT: Status of 'Allow Online Tips' group policy
If the AllowOnlineTips key exists, set the value to 0 (Disabled); otherwise, create the AllowOnlineTips key and update the value.
Impact: Settings will not contact Microsoft content services to retrieve tips and help content.
#>

$regkey_13940 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$name_13940 = "AllowOnlineTips"
$rvalue_13940 = "0"
$type_13940 = "DWord"
$path_13940 = Test-path $regkey_13940
 if($path_13940){
	$exist_13940=(Get-Item $regkey_13940).Property -contains $name_13940
	If($exist_13940){
		Set-ItemProperty -Path $regkey_13940 -Name $name_13940 -Value $rvalue_13940
		Write-Output "$name_13940 key is set to $rvalue_13940 for CID: 13940"
		}
	if(!$exist_13940){
		New-ItemProperty -Path $regkey_13940 -Name $name_13940 -PropertyType $type_13940 -Value $rvalue_13940 | Out-Null
		Write-Output "$name_13940 key is created and set to $rvalue_13940 for CID: 13940"
		}
  }
 else{
 New-item -Path $regkey_13940 -Force | Out-Null
  New-ItemProperty -Path $regkey_13940 -Name $name_13940 -PropertyType $type_13940 -Value $rvalue_13940 | Out-Null
  Write-Output "Created $regkey_13940  and $name_13940 key and set to $rvalue_13940 for CID: 13940"
 }

#----------------------- EOS CID 13940 -----------------------#

<# 
-CID: 13941
STMT: Status of 'Allow Message Service Cloud Sync' group policy
If the AllowMessageSync key exists, set the value to 0 (Disabled); otherwise, create the AllowMessageSync key and update the value.
Impact: Cellular text messages will not be backed up to Microsoft's cloud services.
#>

$regkey_13941 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging"
$name_13941 = "AllowMessageSync"
$rvalue_13941 = "0"
$type_13941 = "DWord"
$path_13941 = Test-path $regkey_13941
 if($path_13941){
	$exist_13941=(Get-Item $regkey_13941).Property -contains $name_13941
	If($exist_13941){
		Set-ItemProperty -Path $regkey_13941 -Name $name_13941 -Value $rvalue_13941
		Write-Output "$name_13941 key is set to $rvalue_13941 for CID: 13941"
		}
	if(!$exist_13941){
		New-ItemProperty -Path $regkey_13941 -Name $name_13941 -PropertyType $type_13941 -Value $rvalue_13941 | Out-Null
		Write-Output "$name_13941 key is created and set to $rvalue_13941 for CID: 13941"
		}
  }
 else{
 New-item -Path $regkey_13941 -Force | Out-Null
  New-ItemProperty -Path $regkey_13941 -Name $name_13941 -PropertyType $type_13941 -Value $rvalue_13941 | Out-Null
  Write-Output "Created $regkey_13941  and $name_13941 key and set to $rvalue_13941 for CID: 13941"
 }

#----------------------- EOS CID 13941 -----------------------#

<# 
-CID: 13942
STMT: Status of 'Turn off Push To Install service' group policy
If the DisablePushToInstall key exists, set the value to 1 (Enabled); otherwise, create the DisablePushToInstall key and update the value.
Impact: Users will not be able to push Apps to this device from the Microsoft Store running on other devices or the web.
#>

$regkey_13942 = "HKLM:\SOFTWARE\Policies\Microsoft\PushToInstall"
$name_13942 = "DisablePushToInstall"
$rvalue_13942 = "1"
$type_13942 = "DWord"
$path_13942 = Test-path $regkey_13942
 if($path_13942){
	$exist_13942=(Get-Item $regkey_13942).Property -contains $name_13942
	If($exist_13942){
		Set-ItemProperty -Path $regkey_13942 -Name $name_13942 -Value $rvalue_13942
		Write-Output "$name_13942 key is set to $rvalue_13942 for CID: 13942"
		}
	if(!$exist_13942){
		New-ItemProperty -Path $regkey_13942 -Name $name_13942 -PropertyType $type_13942 -Value $rvalue_13942 | Out-Null
		Write-Output "$name_13942 key is created and set to $rvalue_13942 for CID: 13942"
		}
  }
 else{
 New-item -Path $regkey_13942 -Force | Out-Null
  New-ItemProperty -Path $regkey_13942 -Name $name_13942 -PropertyType $type_13942 -Value $rvalue_13942 | Out-Null
  Write-Output "Created $regkey_13942  and $name_13942 key and set to $rvalue_13942 for CID: 13942"
 }

#----------------------- EOS CID 13942 -----------------------#

<# 
-CID: 1430
STMT: Status of the 'Terminal Services' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_1430 = "HKLM:\SYSTEM\CurrentControlSet\Services\TermService"
$name_1430 = "Start"
$rvalue_1430 = "4"
$type_1430 = "DWord"
$path_1430 = Test-path $regkey_1430
 if($path_1430){
	$exist_1430=(Get-Item $regkey_1430).Property -contains $name_1430
	If($exist_1430){
		Set-ItemProperty -Path $regkey_1430 -Name $name_1430 -Value $rvalue_1430
		Write-Output "$name_1430 key is set to $rvalue_1430 for CID: 1430"
		}
	if(!$exist_1430){
		New-ItemProperty -Path $regkey_1430 -Name $name_1430 -PropertyType $type_1430 -Value $rvalue_1430 | Out-Null
		Write-Output "$name_1430 key is created and set to $rvalue_1430 for CID: 1430"
		}
  }
 else{
 New-item -Path $regkey_1430 -Force | Out-Null
  New-ItemProperty -Path $regkey_1430 -Name $name_1430 -PropertyType $type_1430 -Value $rvalue_1430 | Out-Null
  Write-Output "Created $regkey_1430  and $name_1430 key and set to $rvalue_1430 for CID: 1430"
 }

#----------------------- EOS CID 1430 -----------------------#

<# 
-CID: 14415
STMT: Status of the 'Encryption Oracle Remediation' group policy
If the AllowEncryptionOracle key exists, set the value to 0 (Forced Updated Clients); otherwise, create the AllowEncryptionOracle key and update the value.
Impact: Client applications which use CredSSP will not be able to fall back to the insecure versions and services using CredSSP will not accept unpatched clients.
#>

$regkey_14415 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters"
$name_14415 = "AllowEncryptionOracle"
$rvalue_14415 = "0"
$type_14415 = "DWord"
$path_14415 = Test-path $regkey_14415
 if($path_14415){
	$exist_14415=(Get-Item $regkey_14415).Property -contains $name_14415
	If($exist_14415){
		Set-ItemProperty -Path $regkey_14415 -Name $name_14415 -Value $rvalue_14415
		Write-Output "$name_14415 key is set to $rvalue_14415 for CID: 14415"
		}
	if(!$exist_14415){
		New-ItemProperty -Path $regkey_14415 -Name $name_14415 -PropertyType $type_14415 -Value $rvalue_14415 | Out-Null
		Write-Output "$name_14415 key is created and set to $rvalue_14415 for CID: 14415"
		}
  }
 else{
 New-item -Path $regkey_14415 -Force | Out-Null
  New-ItemProperty -Path $regkey_14415 -Name $name_14415 -PropertyType $type_14415 -Value $rvalue_14415 | Out-Null
  Write-Output "Created $regkey_14415  and $name_14415 key and set to $rvalue_14415 for CID: 14415"
 }

#----------------------- EOS CID 14415 -----------------------#

<# 
-CID: 1449
STMT: Status of the 'MSS: (TcpMaxDataRetransmissions) How many times unacknowledged data is retransmitted (3 recommended, 5 is default)' setting
If the TcpMaxDataRetransmissions key exists, set the value to 3 (Enabled); otherwise, create the TcpMaxDataRetransmissions key and update the value.
Impact: TCP starts a retransmission timer when each outbound segment is passed to the IP. If no acknowledgment is received for the data in a given segment before the timer expires, then the segment is retransmitted up to three times.
#>

$regkey_1449 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$name_1449 = "TcpMaxDataRetransmissions"
$rvalue_1449 = "3"
$type_1449 = "DWord"
$path_1449 = Test-path $regkey_1449
 if($path_1449){
	$exist_1449=(Get-Item $regkey_1449).Property -contains $name_1449
	If($exist_1449){
		Set-ItemProperty -Path $regkey_1449 -Name $name_1449 -Value $rvalue_1449
		Write-Output "$name_1449 key is set to $rvalue_1449 for CID: 1449"
		}
	if(!$exist_1449){
		New-ItemProperty -Path $regkey_1449 -Name $name_1449 -PropertyType $type_1449 -Value $rvalue_1449 | Out-Null
		Write-Output "$name_1449 key is created and set to $rvalue_1449 for CID: 1449"
		}
  }
 else{
 New-item -Path $regkey_1449 -Force | Out-Null
  New-ItemProperty -Path $regkey_1449 -Name $name_1449 -PropertyType $type_1449 -Value $rvalue_1449 | Out-Null
  Write-Output "Created $regkey_1449  and $name_1449 key and set to $rvalue_1449 for CID: 1449"
 }

#----------------------- EOS CID 1449 -----------------------#

<# 
-CID: 1475
STMT: Status of the 'Remote Access Auto Connection Manager' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_1475 = "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto"
$name_1475 = "Start"
$rvalue_1475 = "4"
$type_1475 = "DWord"
$path_1475 = Test-path $regkey_1475
 if($path_1475){
	$exist_1475=(Get-Item $regkey_1475).Property -contains $name_1475
	If($exist_1475){
		Set-ItemProperty -Path $regkey_1475 -Name $name_1475 -Value $rvalue_1475
		Write-Output "$name_1475 key is set to $rvalue_1475 for CID: 1475"
		}
	if(!$exist_1475){
		New-ItemProperty -Path $regkey_1475 -Name $name_1475 -PropertyType $type_1475 -Value $rvalue_1475 | Out-Null
		Write-Output "$name_1475 key is created and set to $rvalue_1475 for CID: 1475"
		}
  }
 else{
 New-item -Path $regkey_1475 -Force | Out-Null
  New-ItemProperty -Path $regkey_1475 -Name $name_1475 -PropertyType $type_1475 -Value $rvalue_1475 | Out-Null
  Write-Output "Created $regkey_1475  and $name_1475 key and set to $rvalue_1475 for CID: 1475"
 }

#----------------------- EOS CID 1475 -----------------------#

<# 
-CID: 1479
STMT: Status of the 'Remote Procedure Call (RPC) Locater' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_1479 = "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator"
$name_1479 = "Start"
$rvalue_1479 = "4"
$type_1479 = "DWord"
$path_1479 = Test-path $regkey_1479
 if($path_1479){
	$exist_1479=(Get-Item $regkey_1479).Property -contains $name_1479
	If($exist_1479){
		Set-ItemProperty -Path $regkey_1479 -Name $name_1479 -Value $rvalue_1479
		Write-Output "$name_1479 key is set to $rvalue_1479 for CID: 1479"
		}
	if(!$exist_1479){
		New-ItemProperty -Path $regkey_1479 -Name $name_1479 -PropertyType $type_1479 -Value $rvalue_1479 | Out-Null
		Write-Output "$name_1479 key is created and set to $rvalue_1479 for CID: 1479"
		}
  }
 else{
 New-item -Path $regkey_1479 -Force | Out-Null
  New-ItemProperty -Path $regkey_1479 -Name $name_1479 -PropertyType $type_1479 -Value $rvalue_1479 | Out-Null
  Write-Output "Created $regkey_1479  and $name_1479 key and set to $rvalue_1479 for CID: 1479"
 }

#----------------------- EOS CID 1479 -----------------------#

<# 
-CID: 14876
STMT: Ensure 'Bluetooth Audio Gateway Service (BTAGService)' is set to 'Disabled'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth hands-free devices will not function properly with the computer.
#>

$regkey_14876 = "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService"
$name_14876 = "Start"
$rvalue_14876 = "4"
$type_14876 = "DWord"
$path_14876 = Test-path $regkey_14876
 if($path_14876){
	$exist_14876=(Get-Item $regkey_14876).Property -contains $name_14876
	If($exist_14876){
		Set-ItemProperty -Path $regkey_14876 -Name $name_14876 -Value $rvalue_14876
		Write-Output "$name_14876 key is set to $rvalue_14876 for CID: 14876"
		}
	if(!$exist_14876){
		New-ItemProperty -Path $regkey_14876 -Name $name_14876 -PropertyType $type_14876 -Value $rvalue_14876 | Out-Null
		Write-Output "$name_14876 key is created and set to $rvalue_14876 for CID: 14876"
		}
  }
 else{
 New-item -Path $regkey_14876 -Force | Out-Null
  New-ItemProperty -Path $regkey_14876 -Name $name_14876 -PropertyType $type_14876 -Value $rvalue_14876 | Out-Null
  Write-Output "Created $regkey_14876  and $name_14876 key and set to $rvalue_14876 for CID: 14876"
 }

#----------------------- EOS CID 14876 -----------------------#

<# 
-CID: 14878
STMT: Status of 'Turn off notifications network usage'
If the NoCloudApplicationNotification key exists, set the value to 1 (Enabled); otherwise, create the NoCloudApplicationNotification key and update the value.
Impact: Applications and system features will not be able receive notifications from the network from WNS or via notification polling APIs.
#>

$regkey_14878 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
$name_14878 = "NoCloudApplicationNotification"
$rvalue_14878 = "1"
$type_14878 = "DWord"
$path_14878 = Test-path $regkey_14878
 if($path_14878){
	$exist_14878=(Get-Item $regkey_14878).Property -contains $name_14878
	If($exist_14878){
		Set-ItemProperty -Path $regkey_14878 -Name $name_14878 -Value $rvalue_14878
		Write-Output "$name_14878 key is set to $rvalue_14878 for CID: 14878"
		}
	if(!$exist_14878){
		New-ItemProperty -Path $regkey_14878 -Name $name_14878 -PropertyType $type_14878 -Value $rvalue_14878 | Out-Null
		Write-Output "$name_14878 key is created and set to $rvalue_14878 for CID: 14878"
		}
  }
 else{
 New-item -Path $regkey_14878 -Force | Out-Null
  New-ItemProperty -Path $regkey_14878 -Name $name_14878 -PropertyType $type_14878 -Value $rvalue_14878 | Out-Null
  Write-Output "Created $regkey_14878  and $name_14878 key and set to $rvalue_14878 for CID: 14878"
 }

#----------------------- EOS CID 14878 -----------------------#

<# 
-CID: 14879
STMT: Status of 'Allow upload of User Activities'
If the UploadUserActivities key exists, set the value to 0 (Disabled); otherwise, create the UploadUserActivities key and update the value.
Impact: Activities of type User Activity are not allowed to be uploaded to the cloud. The Timeline feature will not function across devices.
#>

$regkey_14879 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_14879 = "UploadUserActivities"
$rvalue_14879 = "0"
$type_14879 = "DWord"
$path_14879 = Test-path $regkey_14879
 if($path_14879){
	$exist_14879=(Get-Item $regkey_14879).Property -contains $name_14879
	If($exist_14879){
		Set-ItemProperty -Path $regkey_14879 -Name $name_14879 -Value $rvalue_14879
		Write-Output "$name_14879 key is set to $rvalue_14879 for CID: 14879"
		}
	if(!$exist_14879){
		New-ItemProperty -Path $regkey_14879 -Name $name_14879 -PropertyType $type_14879 -Value $rvalue_14879 | Out-Null
		Write-Output "$name_14879 key is created and set to $rvalue_14879 for CID: 14879"
		}
  }
 else{
 New-item -Path $regkey_14879 -Force | Out-Null
  New-ItemProperty -Path $regkey_14879 -Name $name_14879 -PropertyType $type_14879 -Value $rvalue_14879 | Out-Null
  Write-Output "Created $regkey_14879  and $name_14879 key and set to $rvalue_14879 for CID: 14879"
 }

#----------------------- EOS CID 14879 -----------------------#

<# 
-CID: 14880
STMT: Ensure 'Only display the private store within the Microsoft Store' is set to 'Enabled'
If the RequirePrivateStoreOnly key exists, set the value to 1 (Enabled); otherwise, create the RequirePrivateStoreOnly key and update the value.
Impact: Users will not be able to view the retail catalog in the Microsoft Store, but they will be able to view apps in the private store.
#>

$regkey_14880 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$name_14880 = "RequirePrivateStoreOnly"
$rvalue_14880 = "1"
$type_14880 = "DWord"
$path_14880 = Test-path $regkey_14880
 if($path_14880){
	$exist_14880=(Get-Item $regkey_14880).Property -contains $name_14880
	If($exist_14880){
		Set-ItemProperty -Path $regkey_14880 -Name $name_14880 -Value $rvalue_14880
		Write-Output "$name_14880 key is set to $rvalue_14880 for CID: 14880"
		}
	if(!$exist_14880){
		New-ItemProperty -Path $regkey_14880 -Name $name_14880 -PropertyType $type_14880 -Value $rvalue_14880 | Out-Null
		Write-Output "$name_14880 key is created and set to $rvalue_14880 for CID: 14880"
		}
  }
 else{
 New-item -Path $regkey_14880 -Force | Out-Null
  New-ItemProperty -Path $regkey_14880 -Name $name_14880 -PropertyType $type_14880 -Value $rvalue_14880 | Out-Null
  Write-Output "Created $regkey_14880  and $name_14880 key and set to $rvalue_14880 for CID: 14880"
 }

#----------------------- EOS CID 14880 -----------------------#

<# 
-CID: 14883
STMT: Status of Office communication application from creating child processes
If the 26190899-1602-49e8-8b27-eb1d0a1ce869 key exists, set the value to 1 (Block); otherwise, create the 26190899-1602-49e8-8b27-eb1d0a1ce869 key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_14883 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_14883 = "26190899-1602-49e8-8b27-eb1d0a1ce869"
$rvalue_14883 = "1"
$type_14883 = "DWord"
$path_14883 = Test-path $regkey_14883
 if($path_14883){
	$exist_14883=(Get-Item $regkey_14883).Property -contains $name_14883
	If($exist_14883){
		Set-ItemProperty -Path $regkey_14883 -Name $name_14883 -Value $rvalue_14883
		Write-Output "$name_14883 key is set to $rvalue_14883 for CID: 14883"
		}
	if(!$exist_14883){
		New-ItemProperty -Path $regkey_14883 -Name $name_14883 -PropertyType $type_14883 -Value $rvalue_14883 | Out-Null
		Write-Output "$name_14883 key is created and set to $rvalue_14883 for CID: 14883"
		}
  }
 else{
 New-item -Path $regkey_14883 -Force | Out-Null
  New-ItemProperty -Path $regkey_14883 -Name $name_14883 -PropertyType $type_14883 -Value $rvalue_14883 | Out-Null
  Write-Output "Created $regkey_14883  and $name_14883 key and set to $rvalue_14883 for CID: 14883"
 }

#----------------------- EOS CID 14883 -----------------------#

<# 
-CID: 14884
STMT: Status of 'Block Adobe Reader from creating child processes' ASR rule (7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c)
If the 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c key exists, set the value to 1 (Block); otherwise, create the 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c key and update the value.
Impact: When a rule is triggered, a notification will be displayed from the Action Center.
#>

$regkey_14884 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules"
$name_14884 = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
$rvalue_14884 = "1"
$type_14884 = "DWord"
$path_14884 = Test-path $regkey_14884
 if($path_14884){
	$exist_14884=(Get-Item $regkey_14884).Property -contains $name_14884
	If($exist_14884){
		Set-ItemProperty -Path $regkey_14884 -Name $name_14884 -Value $rvalue_14884
		Write-Output "$name_14884 key is set to $rvalue_14884 for CID: 14884"
		}
	if(!$exist_14884){
		New-ItemProperty -Path $regkey_14884 -Name $name_14884 -PropertyType $type_14884 -Value $rvalue_14884 | Out-Null
		Write-Output "$name_14884 key is created and set to $rvalue_14884 for CID: 14884"
		}
  }
 else{
 New-item -Path $regkey_14884 -Force | Out-Null
  New-ItemProperty -Path $regkey_14884 -Name $name_14884 -PropertyType $type_14884 -Value $rvalue_14884 | Out-Null
  Write-Output "Created $regkey_14884  and $name_14884 key and set to $rvalue_14884 for CID: 14884"
 }

#----------------------- EOS CID 14884 -----------------------#

<# 
-CID: 1512
STMT: Status of the 'Universal Plug and Play Device Host (UPnP)' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_1512 = "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost"
$name_1512 = "Start"
$rvalue_1512 = "4"
$type_1512 = "DWord"
$path_1512 = Test-path $regkey_1512
 if($path_1512){
	$exist_1512=(Get-Item $regkey_1512).Property -contains $name_1512
	If($exist_1512){
		Set-ItemProperty -Path $regkey_1512 -Name $name_1512 -Value $rvalue_1512
		Write-Output "$name_1512 key is set to $rvalue_1512 for CID: 1512"
		}
	if(!$exist_1512){
		New-ItemProperty -Path $regkey_1512 -Name $name_1512 -PropertyType $type_1512 -Value $rvalue_1512 | Out-Null
		Write-Output "$name_1512 key is created and set to $rvalue_1512 for CID: 1512"
		}
  }
 else{
 New-item -Path $regkey_1512 -Force | Out-Null
  New-ItemProperty -Path $regkey_1512 -Name $name_1512 -PropertyType $type_1512 -Value $rvalue_1512 | Out-Null
  Write-Output "Created $regkey_1512  and $name_1512 key and set to $rvalue_1512 for CID: 1512"
 }

#----------------------- EOS CID 1512 -----------------------#

<# 
-CID: 1513
STMT: Status of the 'RPC Endpoint Mapper Client Authentication' setting
If the EnableAuthEpResolution key exists, set the value to 1 (Enabled); otherwise, create the EnableAuthEpResolution key and update the value.
Impact: RPC clients will authenticate to the Endpoint Mapper Service for calls that contain authentication information. Clients making such calls will not be able to communicate with the Windows NT4 Server Endpoint Mapper Service.
#>

$regkey_1513 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
$name_1513 = "EnableAuthEpResolution"
$rvalue_1513 = "1"
$type_1513 = "DWord"
$path_1513 = Test-path $regkey_1513
 if($path_1513){
	$exist_1513=(Get-Item $regkey_1513).Property -contains $name_1513
	If($exist_1513){
		Set-ItemProperty -Path $regkey_1513 -Name $name_1513 -Value $rvalue_1513
		Write-Output "$name_1513 key is set to $rvalue_1513 for CID: 1513"
		}
	if(!$exist_1513){
		New-ItemProperty -Path $regkey_1513 -Name $name_1513 -PropertyType $type_1513 -Value $rvalue_1513 | Out-Null
		Write-Output "$name_1513 key is created and set to $rvalue_1513 for CID: 1513"
		}
  }
 else{
 New-item -Path $regkey_1513 -Force | Out-Null
  New-ItemProperty -Path $regkey_1513 -Name $name_1513 -PropertyType $type_1513 -Value $rvalue_1513 | Out-Null
  Write-Output "Created $regkey_1513  and $name_1513 key and set to $rvalue_1513 for CID: 1513"
 }

#----------------------- EOS CID 1513 -----------------------#

<# 
-CID: 1514
STMT: Status of the 'Restrictions for Unauthenticated RPC clients' setting
If the RestrictRemoteClients key exists, set the value to 1 (Authenticated); otherwise, create the RestrictRemoteClients key and update the value.
#>

$regkey_1514 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"
$name_1514 = "RestrictRemoteClients"
$rvalue_1514 = "1"
$type_1514 = "DWord"
$path_1514 = Test-path $regkey_1514
 if($path_1514){
	$exist_1514=(Get-Item $regkey_1514).Property -contains $name_1514
	If($exist_1514){
		Set-ItemProperty -Path $regkey_1514 -Name $name_1514 -Value $rvalue_1514
		Write-Output "$name_1514 key is set to $rvalue_1514 for CID: 1514"
		}
	if(!$exist_1514){
		New-ItemProperty -Path $regkey_1514 -Name $name_1514 -PropertyType $type_1514 -Value $rvalue_1514 | Out-Null
		Write-Output "$name_1514 key is created and set to $rvalue_1514 for CID: 1514"
		}
  }
 else{
 New-item -Path $regkey_1514 -Force | Out-Null
  New-ItemProperty -Path $regkey_1514 -Name $name_1514 -PropertyType $type_1514 -Value $rvalue_1514 | Out-Null
  Write-Output "Created $regkey_1514  and $name_1514 key and set to $rvalue_1514 for CID: 1514"
 }

#----------------------- EOS CID 1514 -----------------------#

<# 
-CID: 16106
STMT: Status of the 'Let Windows apps activate with voice while the system is locked' setting
If the LetAppsActivateWithVoiceAboveLock key exists, set the value to 2 (Force Deny); otherwise, create the LetAppsActivateWithVoiceAboveLock key and update the value.
Impact: Users will not be able to activate apps while the computer is locked.
#>

$regkey_16106 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy"
$name_16106 = "LetAppsActivateWithVoiceAboveLock"
$rvalue_16106 = "2"
$type_16106 = "DWord"
$path_16106 = Test-path $regkey_16106
 if($path_16106){
	$exist_16106=(Get-Item $regkey_16106).Property -contains $name_16106
	If($exist_16106){
		Set-ItemProperty -Path $regkey_16106 -Name $name_16106 -Value $rvalue_16106
		Write-Output "$name_16106 key is set to $rvalue_16106 for CID: 16106"
		}
	if(!$exist_16106){
		New-ItemProperty -Path $regkey_16106 -Name $name_16106 -PropertyType $type_16106 -Value $rvalue_16106 | Out-Null
		Write-Output "$name_16106 key is created and set to $rvalue_16106 for CID: 16106"
		}
  }
 else{
 New-item -Path $regkey_16106 -Force | Out-Null
  New-ItemProperty -Path $regkey_16106 -Name $name_16106 -PropertyType $type_16106 -Value $rvalue_16106 | Out-Null
  Write-Output "Created $regkey_16106  and $name_16106 key and set to $rvalue_16106 for CID: 16106"
 }

#----------------------- EOS CID 16106 -----------------------#

<# 
-CID: 16469
STMT: Status of Allow Clipboard synchronization across devices
If the AllowCrossDeviceClipboard key exists, set the value to 0 (Disabled); otherwise, create the AllowCrossDeviceClipboard key and update the value.
Impact: Clipboard contents will not be shareable to other devices.
#>

$regkey_16469 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_16469 = "AllowCrossDeviceClipboard"
$rvalue_16469 = "0"
$type_16469 = "DWord"
$path_16469 = Test-path $regkey_16469
 if($path_16469){
	$exist_16469=(Get-Item $regkey_16469).Property -contains $name_16469
	If($exist_16469){
		Set-ItemProperty -Path $regkey_16469 -Name $name_16469 -Value $rvalue_16469
		Write-Output "$name_16469 key is set to $rvalue_16469 for CID: 16469"
		}
	if(!$exist_16469){
		New-ItemProperty -Path $regkey_16469 -Name $name_16469 -PropertyType $type_16469 -Value $rvalue_16469 | Out-Null
		Write-Output "$name_16469 key is created and set to $rvalue_16469 for CID: 16469"
		}
  }
 else{
 New-item -Path $regkey_16469 -Force | Out-Null
  New-ItemProperty -Path $regkey_16469 -Name $name_16469 -PropertyType $type_16469 -Value $rvalue_16469 | Out-Null
  Write-Output "Created $regkey_16469  and $name_16469 key and set to $rvalue_16469 for CID: 16469"
 }

#----------------------- EOS CID 16469 -----------------------#

<# 
-CID: 17217
STMT: Status of 'Prevent the use of security questions for local accounts'
If the NoLocalPasswordResetQuestions key exists, set the value to 1 (Enabled); otherwise, create the NoLocalPasswordResetQuestions key and update the value.
Impact: Local user accounts will not be able to set up and use security questions to reset their passwords.
#>

$regkey_17217 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_17217 = "NoLocalPasswordResetQuestions"
$rvalue_17217 = "1"
$type_17217 = "DWord"
$path_17217 = Test-path $regkey_17217
 if($path_17217){
	$exist_17217=(Get-Item $regkey_17217).Property -contains $name_17217
	If($exist_17217){
		Set-ItemProperty -Path $regkey_17217 -Name $name_17217 -Value $rvalue_17217
		Write-Output "$name_17217 key is set to $rvalue_17217 for CID: 17217"
		}
	if(!$exist_17217){
		New-ItemProperty -Path $regkey_17217 -Name $name_17217 -PropertyType $type_17217 -Value $rvalue_17217 | Out-Null
		Write-Output "$name_17217 key is created and set to $rvalue_17217 for CID: 17217"
		}
  }
 else{
 New-item -Path $regkey_17217 -Force | Out-Null
  New-ItemProperty -Path $regkey_17217 -Name $name_17217 -PropertyType $type_17217 -Value $rvalue_17217 | Out-Null
  Write-Output "Created $regkey_17217  and $name_17217 key and set to $rvalue_17217 for CID: 17217"
 }

#----------------------- EOS CID 17217 -----------------------#

<# 
-CID: 17241
STMT: Configure 'Minimize the number of simultaneous connections to the Internet or a Windows Domain' Prevent Wi-Fi when on Ethernet
If the fMinimizeConnections key exists, set the value to 3 (Enabled:Prevent Wi-Fi when on Ethernet); otherwise, create the fMinimizeConnections key and update the value.
Impact: While connected to an Ethernet connection, Windows won't allow use of a WLAN (automatically or manually) until Ethernet is disconnected.
#>

$regkey_17241 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy:fMinimizeConnections"
$name_17241 = "fMinimizeConnections"
$rvalue_17241 = "3"
$type_17241 = "DWord"
$path_17241 = Test-path $regkey_17241
 if($path_17241){
	$exist_17241=(Get-Item $regkey_17241).Property -contains $name_17241
	If($exist_17241){
		Set-ItemProperty -Path $regkey_17241 -Name $name_17241 -Value $rvalue_17241
		Write-Output "$name_17241 key is set to $rvalue_17241 for CID: 17241"
		}
	if(!$exist_17241){
		New-ItemProperty -Path $regkey_17241 -Name $name_17241 -PropertyType $type_17241 -Value $rvalue_17241 | Out-Null
		Write-Output "$name_17241 key is created and set to $rvalue_17241 for CID: 17241"
		}
  }
 else{
 New-item -Path $regkey_17241 -Force | Out-Null
  New-ItemProperty -Path $regkey_17241 -Name $name_17241 -PropertyType $type_17241 -Value $rvalue_17241 | Out-Null
  Write-Output "Created $regkey_17241  and $name_17241 key and set to $rvalue_17241 for CID: 17241"
 }

#----------------------- EOS CID 17241 -----------------------#

<# 
-CID: 17242
STMT: Status of the 'Require pin for pairing' Enabled 'First Time OR Always' setting
If the RequirePinForPairing key exists, set the value to 2 (Always); otherwise, create the RequirePinForPairing key and update the value.
Impact: The pairing ceremony for connecting to new wireless display devices will always require a PIN.
#>

$regkey_17242 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Connect"
$name_17242 = "RequirePinForPairing"
$rvalue_17242 = "2"
$type_17242 = "DWord"
$path_17242 = Test-path $regkey_17242
 if($path_17242){
	$exist_17242=(Get-Item $regkey_17242).Property -contains $name_17242
	If($exist_17242){
		Set-ItemProperty -Path $regkey_17242 -Name $name_17242 -Value $rvalue_17242
		Write-Output "$name_17242 key is set to $rvalue_17242 for CID: 17242"
		}
	if(!$exist_17242){
		New-ItemProperty -Path $regkey_17242 -Name $name_17242 -PropertyType $type_17242 -Value $rvalue_17242 | Out-Null
		Write-Output "$name_17242 key is created and set to $rvalue_17242 for CID: 17242"
		}
  }
 else{
 New-item -Path $regkey_17242 -Force | Out-Null
  New-ItemProperty -Path $regkey_17242 -Name $name_17242 -PropertyType $type_17242 -Value $rvalue_17242 | Out-Null
  Write-Output "Created $regkey_17242  and $name_17242 key and set to $rvalue_17242 for CID: 17242"
 }

#----------------------- EOS CID 17242 -----------------------#

<# 
-CID: 2581
STMT: Status of the 'Turn off Microsoft Peer-to-Peer Networking Services' setting
If the Disabled key exists, set the value to 1 (Enabled); otherwise, create the Disabled key and update the value.
Impact: Microsoft Peer-to-Peer Networking Services are turned off in their entirety, and all applications dependent on them will stop working.
#>

$regkey_2581 = "HKLM:\SOFTWARE\Policies\Microsoft\Peernet"
$name_2581 = "Disabled"
$rvalue_2581 = "1"
$type_2581 = "DWord"
$path_2581 = Test-path $regkey_2581
 if($path_2581){
	$exist_2581=(Get-Item $regkey_2581).Property -contains $name_2581
	If($exist_2581){
		Set-ItemProperty -Path $regkey_2581 -Name $name_2581 -Value $rvalue_2581
		Write-Output "$name_2581 key is set to $rvalue_2581 for CID: 2581"
		}
	if(!$exist_2581){
		New-ItemProperty -Path $regkey_2581 -Name $name_2581 -PropertyType $type_2581 -Value $rvalue_2581 | Out-Null
		Write-Output "$name_2581 key is created and set to $rvalue_2581 for CID: 2581"
		}
  }
 else{
 New-item -Path $regkey_2581 -Force | Out-Null
  New-ItemProperty -Path $regkey_2581 -Name $name_2581 -PropertyType $type_2581 -Value $rvalue_2581 | Out-Null
  Write-Output "Created $regkey_2581  and $name_2581 key and set to $rvalue_2581 for CID: 2581"
 }

#----------------------- EOS CID 2581 -----------------------#

<# 
-CID: 2585
STMT: Status of the 'Network access: Do not allow storage of passwords and credentials for network authentication' setting
If the DisableDomainCreds key exists, set the value to 1; otherwise, create the DisableDomainCreds key and update the value.
Impact: Credential Manager will not store passwords and credentials on the computer.
Note: For this change to take effect, Windows must be restarted.
#>

$regkey_2585 = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$name_2585 = "DisableDomainCreds"
$rvalue_2585 = "1"
$type_2585 = "DWord"
$path_2585 = Test-path $regkey_2585
 if($path_2585){
	$exist_2585=(Get-Item $regkey_2585).Property -contains $name_2585
	If($exist_2585){
		Set-ItemProperty -Path $regkey_2585 -Name $name_2585 -Value $rvalue_2585
		Write-Output "$name_2585 key is set to $rvalue_2585 for CID: 2585"
		}
	if(!$exist_2585){
		New-ItemProperty -Path $regkey_2585 -Name $name_2585 -PropertyType $type_2585 -Value $rvalue_2585 | Out-Null
		Write-Output "$name_2585 key is created and set to $rvalue_2585 for CID: 2585"
		}
  }
 else{
 New-item -Path $regkey_2585 -Force | Out-Null
  New-ItemProperty -Path $regkey_2585 -Name $name_2585 -PropertyType $type_2585 -Value $rvalue_2585 | Out-Null
  Write-Output "Created $regkey_2585  and $name_2585 key and set to $rvalue_2585 for CID: 2585"
 }

#----------------------- EOS CID 2585 -----------------------#

<# 
-CID: 2587
STMT: Status of the 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' setting
If the ConsentPromptBehaviorAdmin key exists, set the value to 2 (Prompt for consent on the secure desktop); otherwise, create the ConsentPromptBehaviorAdmin key and update the value.
#>

$regkey_2587 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$name_2587 = "ConsentPromptBehaviorAdmin"
$rvalue_2587 = "2"
$type_2587 = "DWord"
$path_2587 = Test-path $regkey_2587
 if($path_2587){
	$exist_2587=(Get-Item $regkey_2587).Property -contains $name_2587
	If($exist_2587){
		Set-ItemProperty -Path $regkey_2587 -Name $name_2587 -Value $rvalue_2587
		Write-Output "$name_2587 key is set to $rvalue_2587 for CID: 2587"
		}
	if(!$exist_2587){
		New-ItemProperty -Path $regkey_2587 -Name $name_2587 -PropertyType $type_2587 -Value $rvalue_2587 | Out-Null
		Write-Output "$name_2587 key is created and set to $rvalue_2587 for CID: 2587"
		}
  }
 else{
 New-item -Path $regkey_2587 -Force | Out-Null
  New-ItemProperty -Path $regkey_2587 -Name $name_2587 -PropertyType $type_2587 -Value $rvalue_2587 | Out-Null
  Write-Output "Created $regkey_2587  and $name_2587 key and set to $rvalue_2587 for CID: 2587"
 }

#----------------------- EOS CID 2587 -----------------------#

<# 
-CID: 2605
STMT: Status of the 'User Account Control: Behavior of the elevation prompt for standard users' setting
If the ConsentPromptBehaviorUser key exists, set the value to 0 (Automatically deny elevation requests); otherwise, create the ConsentPromptBehaviorUser key and update the value.
#>

$regkey_2605 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$name_2605 = "ConsentPromptBehaviorUser"
$rvalue_2605 = "0"
$type_2605 = "DWord"
$path_2605 = Test-path $regkey_2605
 if($path_2605){
	$exist_2605=(Get-Item $regkey_2605).Property -contains $name_2605
	If($exist_2605){
		Set-ItemProperty -Path $regkey_2605 -Name $name_2605 -Value $rvalue_2605
		Write-Output "$name_2605 key is set to $rvalue_2605 for CID: 2605"
		}
	if(!$exist_2605){
		New-ItemProperty -Path $regkey_2605 -Name $name_2605 -PropertyType $type_2605 -Value $rvalue_2605 | Out-Null
		Write-Output "$name_2605 key is created and set to $rvalue_2605 for CID: 2605"
		}
  }
 else{
 New-item -Path $regkey_2605 -Force | Out-Null
  New-ItemProperty -Path $regkey_2605 -Name $name_2605 -PropertyType $type_2605 -Value $rvalue_2605 | Out-Null
  Write-Output "Created $regkey_2605  and $name_2605 key and set to $rvalue_2605 for CID: 2605"
 }

#----------------------- EOS CID 2605 -----------------------#

<# 
-CID: 2606
STMT: Status of the 'User Account Control: Switch to the secure desktop when prompted for elevation' setting
If the PromptOnSecureDesktop key exists, set the value to 1; otherwise, create the PromptOnSecureDesktop key and update the value.
#>

$regkey_2606 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$name_2606 = "PromptOnSecureDesktop"
$rvalue_2606 = "1"
$type_2606 = "DWord"
$path_2606 = Test-path $regkey_2606
 if($path_2606){
	$exist_2606=(Get-Item $regkey_2606).Property -contains $name_2606
	If($exist_2606){
		Set-ItemProperty -Path $regkey_2606 -Name $name_2606 -Value $rvalue_2606
		Write-Output "$name_2606 key is set to $rvalue_2606 for CID: 2606"
		}
	if(!$exist_2606){
		New-ItemProperty -Path $regkey_2606 -Name $name_2606 -PropertyType $type_2606 -Value $rvalue_2606 | Out-Null
		Write-Output "$name_2606 key is created and set to $rvalue_2606 for CID: 2606"
		}
  }
 else{
 New-item -Path $regkey_2606 -Force | Out-Null
  New-ItemProperty -Path $regkey_2606 -Name $name_2606 -PropertyType $type_2606 -Value $rvalue_2606 | Out-Null
  Write-Output "Created $regkey_2606  and $name_2606 key and set to $rvalue_2606 for CID: 2606"
 }

#----------------------- EOS CID 2606 -----------------------#

<# 
-CID: 2607
STMT: Status of the 'Prohibit use of Internet Connection Sharing on your DNS domain network' setting
If the NC_ShowSharedAccessUI key exists, set the value to 0 (Enabled); otherwise, create the NC_ShowSharedAccessUI key and update the value.
Impact: Mobile Hotspot cannot be enabled or configured by Administrators and non-Administrators alike.
#>

$regkey_2607 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$name_2607 = "NC_ShowSharedAccessUI"
$rvalue_2607 = "0"
$type_2607 = "DWord"
$path_2607 = Test-path $regkey_2607
 if($path_2607){
	$exist_2607=(Get-Item $regkey_2607).Property -contains $name_2607
	If($exist_2607){
		Set-ItemProperty -Path $regkey_2607 -Name $name_2607 -Value $rvalue_2607
		Write-Output "$name_2607 key is set to $rvalue_2607 for CID: 2607"
		}
	if(!$exist_2607){
		New-ItemProperty -Path $regkey_2607 -Name $name_2607 -PropertyType $type_2607 -Value $rvalue_2607 | Out-Null
		Write-Output "$name_2607 key is created and set to $rvalue_2607 for CID: 2607"
		}
  }
 else{
 New-item -Path $regkey_2607 -Force | Out-Null
  New-ItemProperty -Path $regkey_2607 -Name $name_2607 -PropertyType $type_2607 -Value $rvalue_2607 | Out-Null
  Write-Output "Created $regkey_2607  and $name_2607 key and set to $rvalue_2607 for CID: 2607"
 }

#----------------------- EOS CID 2607 -----------------------#

<# 
-CID: 2610
STMT: Status of the 'Prohibit Access of the Windows Connect Now wizards' setting
If the DisableWcnUi key exists, set the value to 1 (Enabled); otherwise, create the DisableWcnUi key and update the value.
Impact: The WCN wizards are turned off and users have no access to any of the wizard tasks.
#>

$regkey_2610 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\UI"
$name_2610 = "DisableWcnUi"
$rvalue_2610 = "1"
$type_2610 = "DWord"
$path_2610 = Test-path $regkey_2610
 if($path_2610){
	$exist_2610=(Get-Item $regkey_2610).Property -contains $name_2610
	If($exist_2610){
		Set-ItemProperty -Path $regkey_2610 -Name $name_2610 -Value $rvalue_2610
		Write-Output "$name_2610 key is set to $rvalue_2610 for CID: 2610"
		}
	if(!$exist_2610){
		New-ItemProperty -Path $regkey_2610 -Name $name_2610 -PropertyType $type_2610 -Value $rvalue_2610 | Out-Null
		Write-Output "$name_2610 key is created and set to $rvalue_2610 for CID: 2610"
		}
  }
 else{
 New-item -Path $regkey_2610 -Force | Out-Null
  New-ItemProperty -Path $regkey_2610 -Name $name_2610 -PropertyType $type_2610 -Value $rvalue_2610 | Out-Null
  Write-Output "Created $regkey_2610  and $name_2610 key and set to $rvalue_2610 for CID: 2610"
 }

#----------------------- EOS CID 2610 -----------------------#

<# 
-CID: 2612
STMT: Status of the 'Turn off downloading of enclosures' setting (Internet Explorer)
If the DisableEnclosureDownload key exists, set the value to 1 (Enabled); otherwise, create the DisableEnclosureDownload key and update the value.
Impact: Users cannot set the Feed Sync Engine to download an enclosure through the Feed property page.
#>

$regkey_2612 = "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds"
$name_2612 = "DisableEnclosureDownload"
$rvalue_2612 = "1"
$type_2612 = "DWord"
$path_2612 = Test-path $regkey_2612
 if($path_2612){
	$exist_2612=(Get-Item $regkey_2612).Property -contains $name_2612
	If($exist_2612){
		Set-ItemProperty -Path $regkey_2612 -Name $name_2612 -Value $rvalue_2612
		Write-Output "$name_2612 key is set to $rvalue_2612 for CID: 2612"
		}
	if(!$exist_2612){
		New-ItemProperty -Path $regkey_2612 -Name $name_2612 -PropertyType $type_2612 -Value $rvalue_2612 | Out-Null
		Write-Output "$name_2612 key is created and set to $rvalue_2612 for CID: 2612"
		}
  }
 else{
 New-item -Path $regkey_2612 -Force | Out-Null
  New-ItemProperty -Path $regkey_2612 -Name $name_2612 -PropertyType $type_2612 -Value $rvalue_2612 | Out-Null
  Write-Output "Created $regkey_2612  and $name_2612 key and set to $rvalue_2612 for CID: 2612"
 }

#----------------------- EOS CID 2612 -----------------------#

<# 
-CID: 2616
STMT: Status of the 'Prohibit installation and configuration of Network Bridge on the DNS domain network' setting
If the NC_AllowNetBridge_NLA key exists, set the value to 0 (Enabled); otherwise, create the NC_AllowNetBridge_NLA key and update the value.
Impact: Users cannot create or configure a Network Bridge.
#>

$regkey_2616 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections"
$name_2616 = "NC_AllowNetBridge_NLA"
$rvalue_2616 = "0"
$type_2616 = "DWord"
$path_2616 = Test-path $regkey_2616
 if($path_2616){
	$exist_2616=(Get-Item $regkey_2616).Property -contains $name_2616
	If($exist_2616){
		Set-ItemProperty -Path $regkey_2616 -Name $name_2616 -Value $rvalue_2616
		Write-Output "$name_2616 key is set to $rvalue_2616 for CID: 2616"
		}
	if(!$exist_2616){
		New-ItemProperty -Path $regkey_2616 -Name $name_2616 -PropertyType $type_2616 -Value $rvalue_2616 | Out-Null
		Write-Output "$name_2616 key is created and set to $rvalue_2616 for CID: 2616"
		}
  }
 else{
 New-item -Path $regkey_2616 -Force | Out-Null
  New-ItemProperty -Path $regkey_2616 -Name $name_2616 -PropertyType $type_2616 -Value $rvalue_2616 | Out-Null
  Write-Output "Created $regkey_2616  and $name_2616 key and set to $rvalue_2616 for CID: 2616"
 }

#----------------------- EOS CID 2616 -----------------------#

<# 
-CID: 2635
STMT: Status of the 'Set Client Connection Encryption Level' setting (Terminal Services)
If the MinEncryptionLevel key exists, set the value to 3 (High); otherwise, create the MinEncryptionLevel key and update the value.
#>

$regkey_2635 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_2635 = "MinEncryptionLevel"
$rvalue_2635 = "3"
$type_2635 = "DWord"
$path_2635 = Test-path $regkey_2635
 if($path_2635){
	$exist_2635=(Get-Item $regkey_2635).Property -contains $name_2635
	If($exist_2635){
		Set-ItemProperty -Path $regkey_2635 -Name $name_2635 -Value $rvalue_2635
		Write-Output "$name_2635 key is set to $rvalue_2635 for CID: 2635"
		}
	if(!$exist_2635){
		New-ItemProperty -Path $regkey_2635 -Name $name_2635 -PropertyType $type_2635 -Value $rvalue_2635 | Out-Null
		Write-Output "$name_2635 key is created and set to $rvalue_2635 for CID: 2635"
		}
  }
 else{
 New-item -Path $regkey_2635 -Force | Out-Null
  New-ItemProperty -Path $regkey_2635 -Name $name_2635 -PropertyType $type_2635 -Value $rvalue_2635 | Out-Null
  Write-Output "Created $regkey_2635  and $name_2635 key and set to $rvalue_2635 for CID: 2635"
 }

#----------------------- EOS CID 2635 -----------------------#

<# 
-CID: 3729
STMT: Status of the 'Server' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_3729 = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer"
$name_3729 = "Start"
$rvalue_3729 = "4"
$type_3729 = "DWord"
$path_3729 = Test-path $regkey_3729
 if($path_3729){
	$exist_3729=(Get-Item $regkey_3729).Property -contains $name_3729
	If($exist_3729){
		Set-ItemProperty -Path $regkey_3729 -Name $name_3729 -Value $rvalue_3729
		Write-Output "$name_3729 key is set to $rvalue_3729 for CID: 3729"
		}
	if(!$exist_3729){
		New-ItemProperty -Path $regkey_3729 -Name $name_3729 -PropertyType $type_3729 -Value $rvalue_3729 | Out-Null
		Write-Output "$name_3729 key is created and set to $rvalue_3729 for CID: 3729"
		}
  }
 else{
 New-item -Path $regkey_3729 -Force | Out-Null
  New-ItemProperty -Path $regkey_3729 -Name $name_3729 -PropertyType $type_3729 -Value $rvalue_3729 | Out-Null
  Write-Output "Created $regkey_3729  and $name_3729 key and set to $rvalue_3729 for CID: 3729"
 }

#----------------------- EOS CID 3729 -----------------------#

<# 
-CID: 3784
STMT: Status of the 'Windows Error Reporting' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_3784 = "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc"
$name_3784 = "Start"
$rvalue_3784 = "4"
$type_3784 = "DWord"
$path_3784 = Test-path $regkey_3784
 if($path_3784){
	$exist_3784=(Get-Item $regkey_3784).Property -contains $name_3784
	If($exist_3784){
		Set-ItemProperty -Path $regkey_3784 -Name $name_3784 -Value $rvalue_3784
		Write-Output "$name_3784 key is set to $rvalue_3784 for CID: 3784"
		}
	if(!$exist_3784){
		New-ItemProperty -Path $regkey_3784 -Name $name_3784 -PropertyType $type_3784 -Value $rvalue_3784 | Out-Null
		Write-Output "$name_3784 key is created and set to $rvalue_3784 for CID: 3784"
		}
  }
 else{
 New-item -Path $regkey_3784 -Force | Out-Null
  New-ItemProperty -Path $regkey_3784 -Name $name_3784 -PropertyType $type_3784 -Value $rvalue_3784 | Out-Null
  Write-Output "Created $regkey_3784  and $name_3784 key and set to $rvalue_3784 for CID: 3784"
 }

#----------------------- EOS CID 3784 -----------------------#

<# 
-CID: 3875
STMT: Status of the 'Do not allow drive redirection' setting (Terminal Services)
If the fDisableCdm key exists, set the value to 1 (Enabled); otherwise, create the fDisableCdm key and update the value.
Impact: Drive redirection will not be possible.
#>

$regkey_3875 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_3875 = "fDisableCdm"
$rvalue_3875 = "1"
$type_3875 = "DWord"
$path_3875 = Test-path $regkey_3875
 if($path_3875){
	$exist_3875=(Get-Item $regkey_3875).Property -contains $name_3875
	If($exist_3875){
		Set-ItemProperty -Path $regkey_3875 -Name $name_3875 -Value $rvalue_3875
		Write-Output "$name_3875 key is set to $rvalue_3875 for CID: 3875"
		}
	if(!$exist_3875){
		New-ItemProperty -Path $regkey_3875 -Name $name_3875 -PropertyType $type_3875 -Value $rvalue_3875 | Out-Null
		Write-Output "$name_3875 key is created and set to $rvalue_3875 for CID: 3875"
		}
  }
 else{
 New-item -Path $regkey_3875 -Force | Out-Null
  New-ItemProperty -Path $regkey_3875 -Name $name_3875 -PropertyType $type_3875 -Value $rvalue_3875 | Out-Null
  Write-Output "Created $regkey_3875  and $name_3875 key and set to $rvalue_3875 for CID: 3875"
 }

#----------------------- EOS CID 3875 -----------------------#

<# 
-CID: 3876
STMT: Status of the 'Do not allow passwords to be saved' setting (Terminal Services)
If the DisablePasswordSaving key exists, set the value to 1 (Enabled); otherwise, create the DisablePasswordSaving key and update the value.
Impact: The password saving checkbox will be disabled for Remote Desktop clients and users will not be able to save passwords.
#>

$regkey_3876 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_3876 = "DisablePasswordSaving"
$rvalue_3876 = "1"
$type_3876 = "DWord"
$path_3876 = Test-path $regkey_3876
 if($path_3876){
	$exist_3876=(Get-Item $regkey_3876).Property -contains $name_3876
	If($exist_3876){
		Set-ItemProperty -Path $regkey_3876 -Name $name_3876 -Value $rvalue_3876
		Write-Output "$name_3876 key is set to $rvalue_3876 for CID: 3876"
		}
	if(!$exist_3876){
		New-ItemProperty -Path $regkey_3876 -Name $name_3876 -PropertyType $type_3876 -Value $rvalue_3876 | Out-Null
		Write-Output "$name_3876 key is created and set to $rvalue_3876 for CID: 3876"
		}
  }
 else{
 New-item -Path $regkey_3876 -Force | Out-Null
  New-ItemProperty -Path $regkey_3876 -Name $name_3876 -PropertyType $type_3876 -Value $rvalue_3876 | Out-Null
  Write-Output "Created $regkey_3876  and $name_3876 key and set to $rvalue_3876 for CID: 3876"
 }

#----------------------- EOS CID 3876 -----------------------#

<# 
-CID: 9008
STMT: Status of the 'Do not display network selection UI' setting
If the DontDisplayNetworkSelectionUI key exists, set the value to 1 (Enabled); otherwise, create the DontDisplayNetworkSelectionUI key and update the value.
Impact: The PC's network connectivity state cannot be changed without signing into Windows.
#>

$regkey_9008 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_9008 = "DontDisplayNetworkSelectionUI"
$rvalue_9008 = "1"
$type_9008 = "DWord"
$path_9008 = Test-path $regkey_9008
 if($path_9008){
	$exist_9008=(Get-Item $regkey_9008).Property -contains $name_9008
	If($exist_9008){
		Set-ItemProperty -Path $regkey_9008 -Name $name_9008 -Value $rvalue_9008
		Write-Output "$name_9008 key is set to $rvalue_9008 for CID: 9008"
		}
	if(!$exist_9008){
		New-ItemProperty -Path $regkey_9008 -Name $name_9008 -PropertyType $type_9008 -Value $rvalue_9008 | Out-Null
		Write-Output "$name_9008 key is created and set to $rvalue_9008 for CID: 9008"
		}
  }
 else{
 New-item -Path $regkey_9008 -Force | Out-Null
  New-ItemProperty -Path $regkey_9008 -Name $name_9008 -PropertyType $type_9008 -Value $rvalue_9008 | Out-Null
  Write-Output "Created $regkey_9008  and $name_9008 key and set to $rvalue_9008 for CID: 9008"
 }

#----------------------- EOS CID 9008 -----------------------#

<# 
-CID: 3899
STMT: Status of the 'Solicited Remote Assistance' policy setting (Terminal Services)
If the fAllowToGetHelp key exists, set the value to 0 (Disabled); otherwise, create the fAllowToGetHelp key and update the value.
Impact: Users on this system are unable to request assistance via e-mail or file transfer.
#>

$regkey_3899 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_3899 = "fAllowToGetHelp"
$rvalue_3899 = "0"
$type_3899 = "DWord"
$path_3899 = Test-path $regkey_3899
 if($path_3899){
	$exist_3899=(Get-Item $regkey_3899).Property -contains $name_3899
	If($exist_3899){
		Set-ItemProperty -Path $regkey_3899 -Name $name_3899 -Value $rvalue_3899
		Write-Output "$name_3899 key is set to $rvalue_3899 for CID: 3899"
		}
	if(!$exist_3899){
		New-ItemProperty -Path $regkey_3899 -Name $name_3899 -PropertyType $type_3899 -Value $rvalue_3899 | Out-Null
		Write-Output "$name_3899 key is created and set to $rvalue_3899 for CID: 3899"
		}
  }
 else{
 New-item -Path $regkey_3899 -Force | Out-Null
  New-ItemProperty -Path $regkey_3899 -Name $name_3899 -PropertyType $type_3899 -Value $rvalue_3899 | Out-Null
  Write-Output "Created $regkey_3899  and $name_3899 key and set to $rvalue_3899 for CID: 3899"
 }

#----------------------- EOS CID 3899 -----------------------#

<# 
-CID: 3907
STMT: Status of the 'Windows Messenger Customer Experience Improvement Program' policy
If the CEIP key exists, set the value to 2 (Enabled); otherwise, create the CEIP key and update the value.
Impact: Windows Messenger will not collect usage information, and the user settings to enable the collection of usage information will not be shown.
#>

$regkey_3907 = "HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client"
$name_3907 = "CEIP"
$rvalue_3907 = "2"
$type_3907 = "DWord"
$path_3907 = Test-path $regkey_3907
 if($path_3907){
	$exist_3907=(Get-Item $regkey_3907).Property -contains $name_3907
	If($exist_3907){
		Set-ItemProperty -Path $regkey_3907 -Name $name_3907 -Value $rvalue_3907
		Write-Output "$name_3907 key is set to $rvalue_3907 for CID: 3907"
		}
	if(!$exist_3907){
		New-ItemProperty -Path $regkey_3907 -Name $name_3907 -PropertyType $type_3907 -Value $rvalue_3907 | Out-Null
		Write-Output "$name_3907 key is created and set to $rvalue_3907 for CID: 3907"
		}
  }
 else{
 New-item -Path $regkey_3907 -Force | Out-Null
  New-ItemProperty -Path $regkey_3907 -Name $name_3907 -PropertyType $type_3907 -Value $rvalue_3907 | Out-Null
  Write-Output "Created $regkey_3907  and $name_3907 key and set to $rvalue_3907 for CID: 3907"
 }

#----------------------- EOS CID 3907 -----------------------#

<# 
-CID: 3908
STMT: Status of the 'Turn off Search Companion content file updates' service
If the DisableContentFileUpdates key exists, set the value to 1 (Enabled); otherwise, create the DisableContentFileUpdates key and update the value.
Impact: Search Companion does not download content updates during searches.
#>

$regkey_3908 = "HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion"
$name_3908 = "DisableContentFileUpdates"
$rvalue_3908 = "1"
$type_3908 = "DWord"
$path_3908 = Test-path $regkey_3908
 if($path_3908){
	$exist_3908=(Get-Item $regkey_3908).Property -contains $name_3908
	If($exist_3908){
		Set-ItemProperty -Path $regkey_3908 -Name $name_3908 -Value $rvalue_3908
		Write-Output "$name_3908 key is set to $rvalue_3908 for CID: 3908"
		}
	if(!$exist_3908){
		New-ItemProperty -Path $regkey_3908 -Name $name_3908 -PropertyType $type_3908 -Value $rvalue_3908 | Out-Null
		Write-Output "$name_3908 key is created and set to $rvalue_3908 for CID: 3908"
		}
  }
 else{
 New-item -Path $regkey_3908 -Force | Out-Null
  New-ItemProperty -Path $regkey_3908 -Name $name_3908 -PropertyType $type_3908 -Value $rvalue_3908 | Out-Null
  Write-Output "Created $regkey_3908  and $name_3908 key and set to $rvalue_3908 for CID: 3908"
 }

#----------------------- EOS CID 3908 -----------------------#

<# 
-CID: 3919
STMT: Status of the 'Turn off printing over HTTP' service
If the DisableHTTPPrinting key exists, set the value to 1 (Enabled); otherwise, create the DisableHTTPPrinting key and update the value.
Impact: The client computer will not be able to print to Internet printers over HTTP or HTTPS.
#>

$regkey_3919 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$name_3919 = "DisableHTTPPrinting"
$rvalue_3919 = "1"
$type_3919 = "DWord"
$path_3919 = Test-path $regkey_3919
 if($path_3919){
	$exist_3919=(Get-Item $regkey_3919).Property -contains $name_3919
	If($exist_3919){
		Set-ItemProperty -Path $regkey_3919 -Name $name_3919 -Value $rvalue_3919
		Write-Output "$name_3919 key is set to $rvalue_3919 for CID: 3919"
		}
	if(!$exist_3919){
		New-ItemProperty -Path $regkey_3919 -Name $name_3919 -PropertyType $type_3919 -Value $rvalue_3919 | Out-Null
		Write-Output "$name_3919 key is created and set to $rvalue_3919 for CID: 3919"
		}
  }
 else{
 New-item -Path $regkey_3919 -Force | Out-Null
  New-ItemProperty -Path $regkey_3919 -Name $name_3919 -PropertyType $type_3919 -Value $rvalue_3919 | Out-Null
  Write-Output "Created $regkey_3919  and $name_3919 key and set to $rvalue_3919 for CID: 3919"
 }

#----------------------- EOS CID 3919 -----------------------#

<# 
-CID: 3920
STMT: Status of the 'Turn off Internet download for Web publishing and online ordering wizards' setting
If the NoWebServices key exists, set the value to 1 (Enabled); otherwise, create the NoWebServices key and update the value.
Impact: Windows is prevented from downloading providers; only the service providers cached in the local registry are displayed.
#>

$regkey_3920 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$name_3920 = "NoWebServices"
$rvalue_3920 = "1"
$type_3920 = "DWord"
$path_3920 = Test-path $regkey_3920
 if($path_3920){
	$exist_3920=(Get-Item $regkey_3920).Property -contains $name_3920
	If($exist_3920){
		Set-ItemProperty -Path $regkey_3920 -Name $name_3920 -Value $rvalue_3920
		Write-Output "$name_3920 key is set to $rvalue_3920 for CID: 3920"
		}
	if(!$exist_3920){
		New-ItemProperty -Path $regkey_3920 -Name $name_3920 -PropertyType $type_3920 -Value $rvalue_3920 | Out-Null
		Write-Output "$name_3920 key is created and set to $rvalue_3920 for CID: 3920"
		}
  }
 else{
 New-item -Path $regkey_3920 -Force | Out-Null
  New-ItemProperty -Path $regkey_3920 -Name $name_3920 -PropertyType $type_3920 -Value $rvalue_3920 | Out-Null
  Write-Output "Created $regkey_3920  and $name_3920 key and set to $rvalue_3920 for CID: 3920"
 }

#----------------------- EOS CID 3920 -----------------------#

<# 
-CID: 3921
STMT: Status of the 'Turn off the 'Publish to Web' task for files and folders' group policy
If the NoPublishingWizard key exists, set the value to 1 (Enabled); otherwise, create the NoPublishingWizard key and update the value.
Impact: The Publish to Web task is removed from File and Folder tasks in Windows folders.
#>

$regkey_3921 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$name_3921 = "NoPublishingWizard"
$rvalue_3921 = "1"
$type_3921 = "DWord"
$path_3921 = Test-path $regkey_3921
 if($path_3921){
	$exist_3921=(Get-Item $regkey_3921).Property -contains $name_3921
	If($exist_3921){
		Set-ItemProperty -Path $regkey_3921 -Name $name_3921 -Value $rvalue_3921
		Write-Output "$name_3921 key is set to $rvalue_3921 for CID: 3921"
		}
	if(!$exist_3921){
		New-ItemProperty -Path $regkey_3921 -Name $name_3921 -PropertyType $type_3921 -Value $rvalue_3921 | Out-Null
		Write-Output "$name_3921 key is created and set to $rvalue_3921 for CID: 3921"
		}
  }
 else{
 New-item -Path $regkey_3921 -Force | Out-Null
  New-ItemProperty -Path $regkey_3921 -Name $name_3921 -PropertyType $type_3921 -Value $rvalue_3921 | Out-Null
  Write-Output "Created $regkey_3921  and $name_3921 key and set to $rvalue_3921 for CID: 3921"
 }

#----------------------- EOS CID 3921 -----------------------#

<# 
-CID: 3922
STMT: Status of the 'Turn off downloading of print drivers over HTTP' setting
If the DisableWebPnPDownload key exists, set the value to 1 (Enabled); otherwise, create the DisableWebPnPDownload key and update the value.
Impact: Print drivers cannot be downloaded over HTTP.
#>

$regkey_3922 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers"
$name_3922 = "DisableWebPnPDownload"
$rvalue_3922 = "1"
$type_3922 = "DWord"
$path_3922 = Test-path $regkey_3922
 if($path_3922){
	$exist_3922=(Get-Item $regkey_3922).Property -contains $name_3922
	If($exist_3922){
		Set-ItemProperty -Path $regkey_3922 -Name $name_3922 -Value $rvalue_3922
		Write-Output "$name_3922 key is set to $rvalue_3922 for CID: 3922"
		}
	if(!$exist_3922){
		New-ItemProperty -Path $regkey_3922 -Name $name_3922 -PropertyType $type_3922 -Value $rvalue_3922 | Out-Null
		Write-Output "$name_3922 key is created and set to $rvalue_3922 for CID: 3922"
		}
  }
 else{
 New-item -Path $regkey_3922 -Force | Out-Null
  New-ItemProperty -Path $regkey_3922 -Name $name_3922 -PropertyType $type_3922 -Value $rvalue_3922 | Out-Null
  Write-Output "Created $regkey_3922  and $name_3922 key and set to $rvalue_3922 for CID: 3922"
 }

#----------------------- EOS CID 3922 -----------------------#

<# 
-CID: 3988
STMT: Status of the 'Windows Remote Management Service'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_3988 = "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM"
$name_3988 = "Start"
$rvalue_3988 = "4"
$type_3988 = "DWord"
$path_3988 = Test-path $regkey_3988
 if($path_3988){
	$exist_3988=(Get-Item $regkey_3988).Property -contains $name_3988
	If($exist_3988){
		Set-ItemProperty -Path $regkey_3988 -Name $name_3988 -Value $rvalue_3988
		Write-Output "$name_3988 key is set to $rvalue_3988 for CID: 3988"
		}
	if(!$exist_3988){
		New-ItemProperty -Path $regkey_3988 -Name $name_3988 -PropertyType $type_3988 -Value $rvalue_3988 | Out-Null
		Write-Output "$name_3988 key is created and set to $rvalue_3988 for CID: 3988"
		}
  }
 else{
 New-item -Path $regkey_3988 -Force | Out-Null
  New-ItemProperty -Path $regkey_3988 -Name $name_3988 -PropertyType $type_3988 -Value $rvalue_3988 | Out-Null
  Write-Output "Created $regkey_3988  and $name_3988 key and set to $rvalue_3988 for CID: 3988"
 }

#----------------------- EOS CID 3988 -----------------------#

<# 
-CID: 4006
STMT: Status of the 'Windows Event Collector' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4006 = "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc"
$name_4006 = "Start"
$rvalue_4006 = "4"
$type_4006 = "DWord"
$path_4006 = Test-path $regkey_4006
 if($path_4006){
	$exist_4006=(Get-Item $regkey_4006).Property -contains $name_4006
	If($exist_4006){
		Set-ItemProperty -Path $regkey_4006 -Name $name_4006 -Value $rvalue_4006
		Write-Output "$name_4006 key is set to $rvalue_4006 for CID: 4006"
		}
	if(!$exist_4006){
		New-ItemProperty -Path $regkey_4006 -Name $name_4006 -PropertyType $type_4006 -Value $rvalue_4006 | Out-Null
		Write-Output "$name_4006 key is created and set to $rvalue_4006 for CID: 4006"
		}
  }
 else{
 New-item -Path $regkey_4006 -Force | Out-Null
  New-ItemProperty -Path $regkey_4006 -Name $name_4006 -PropertyType $type_4006 -Value $rvalue_4006 | Out-Null
  Write-Output "Created $regkey_4006  and $name_4006 key and set to $rvalue_4006 for CID: 4006"
 }

#----------------------- EOS CID 4006 -----------------------#

<# 
-CID: 4029
STMT: Status of the 'Windows Link-Layer Topology Discovery Mapper' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4029 = "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc"
$name_4029 = "Start"
$rvalue_4029 = "4"
$type_4029 = "DWord"
$path_4029 = Test-path $regkey_4029
 if($path_4029){
	$exist_4029=(Get-Item $regkey_4029).Property -contains $name_4029
	If($exist_4029){
		Set-ItemProperty -Path $regkey_4029 -Name $name_4029 -Value $rvalue_4029
		Write-Output "$name_4029 key is set to $rvalue_4029 for CID: 4029"
		}
	if(!$exist_4029){
		New-ItemProperty -Path $regkey_4029 -Name $name_4029 -PropertyType $type_4029 -Value $rvalue_4029 | Out-Null
		Write-Output "$name_4029 key is created and set to $rvalue_4029 for CID: 4029"
		}
  }
 else{
 New-item -Path $regkey_4029 -Force | Out-Null
  New-ItemProperty -Path $regkey_4029 -Name $name_4029 -PropertyType $type_4029 -Value $rvalue_4029 | Out-Null
  Write-Output "Created $regkey_4029  and $name_4029 key and set to $rvalue_4029 for CID: 4029"
 }

#----------------------- EOS CID 4029 -----------------------#

<# 
-CID: 4035
STMT: Status of the 'Remote Desktop Services UserMode Port Redirector' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4035 = "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService"
$name_4035 = "Start"
$rvalue_4035 = "4"
$type_4035 = "DWord"
$path_4035 = Test-path $regkey_4035
 if($path_4035){
	$exist_4035=(Get-Item $regkey_4035).Property -contains $name_4035
	If($exist_4035){
		Set-ItemProperty -Path $regkey_4035 -Name $name_4035 -Value $rvalue_4035
		Write-Output "$name_4035 key is set to $rvalue_4035 for CID: 4035"
		}
	if(!$exist_4035){
		New-ItemProperty -Path $regkey_4035 -Name $name_4035 -PropertyType $type_4035 -Value $rvalue_4035 | Out-Null
		Write-Output "$name_4035 key is created and set to $rvalue_4035 for CID: 4035"
		}
  }
 else{
 New-item -Path $regkey_4035 -Force | Out-Null
  New-ItemProperty -Path $regkey_4035 -Name $name_4035 -PropertyType $type_4035 -Value $rvalue_4035 | Out-Null
  Write-Output "Created $regkey_4035  and $name_4035 key and set to $rvalue_4035 for CID: 4035"
 }

#----------------------- EOS CID 4035 -----------------------#

<# 
-CID: 4040
STMT: Status of the 'Terminal Services Configuration' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4040 = "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv"
$name_4040 = "Start"
$rvalue_4040 = "4"
$type_4040 = "DWord"
$path_4040 = Test-path $regkey_4040
 if($path_4040){
	$exist_4040=(Get-Item $regkey_4040).Property -contains $name_4040
	If($exist_4040){
		Set-ItemProperty -Path $regkey_4040 -Name $name_4040 -Value $rvalue_4040
		Write-Output "$name_4040 key is set to $rvalue_4040 for CID: 4040"
		}
	if(!$exist_4040){
		New-ItemProperty -Path $regkey_4040 -Name $name_4040 -PropertyType $type_4040 -Value $rvalue_4040 | Out-Null
		Write-Output "$name_4040 key is created and set to $rvalue_4040 for CID: 4040"
		}
  }
 else{
 New-item -Path $regkey_4040 -Force | Out-Null
  New-ItemProperty -Path $regkey_4040 -Name $name_4040 -PropertyType $type_4040 -Value $rvalue_4040 | Out-Null
  Write-Output "Created $regkey_4040  and $name_4040 key and set to $rvalue_4040 for CID: 4040"
 }

#----------------------- EOS CID 4040 -----------------------#

<# 
-CID: 4046
STMT: Status of the 'Microsoft iSCSI Initiator Service'
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4046 = "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI"
$name_4046 = "Start"
$rvalue_4046 = "4"
$type_4046 = "DWord"
$path_4046 = Test-path $regkey_4046
 if($path_4046){
	$exist_4046=(Get-Item $regkey_4046).Property -contains $name_4046
	If($exist_4046){
		Set-ItemProperty -Path $regkey_4046 -Name $name_4046 -Value $rvalue_4046
		Write-Output "$name_4046 key is set to $rvalue_4046 for CID: 4046"
		}
	if(!$exist_4046){
		New-ItemProperty -Path $regkey_4046 -Name $name_4046 -PropertyType $type_4046 -Value $rvalue_4046 | Out-Null
		Write-Output "$name_4046 key is created and set to $rvalue_4046 for CID: 4046"
		}
  }
 else{
 New-item -Path $regkey_4046 -Force | Out-Null
  New-ItemProperty -Path $regkey_4046 -Name $name_4046 -PropertyType $type_4046 -Value $rvalue_4046 | Out-Null
  Write-Output "Created $regkey_4046  and $name_4046 key and set to $rvalue_4046 for CID: 4046"
 }

#----------------------- EOS CID 4046 -----------------------#

<# 
-CID: 4049
STMT: Status of the SSDP Discovery service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4049 = "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV"
$name_4049 = "Start"
$rvalue_4049 = "4"
$type_4049 = "DWord"
$path_4049 = Test-path $regkey_4049
 if($path_4049){
	$exist_4049=(Get-Item $regkey_4049).Property -contains $name_4049
	If($exist_4049){
		Set-ItemProperty -Path $regkey_4049 -Name $name_4049 -Value $rvalue_4049
		Write-Output "$name_4049 key is set to $rvalue_4049 for CID: 4049"
		}
	if(!$exist_4049){
		New-ItemProperty -Path $regkey_4049 -Name $name_4049 -PropertyType $type_4049 -Value $rvalue_4049 | Out-Null
		Write-Output "$name_4049 key is created and set to $rvalue_4049 for CID: 4049"
		}
  }
 else{
 New-item -Path $regkey_4049 -Force | Out-Null
  New-ItemProperty -Path $regkey_4049 -Name $name_4049 -PropertyType $type_4049 -Value $rvalue_4049 | Out-Null
  Write-Output "Created $regkey_4049  and $name_4049 key and set to $rvalue_4049 for CID: 4049"
 }

#----------------------- EOS CID 4049 -----------------------#

<# 
-CID: 4065
STMT: Status of the 'Problem Reports and Solutions Control Panel Support' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4065 = "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport"
$name_4065 = "Start"
$rvalue_4065 = "4"
$type_4065 = "DWord"
$path_4065 = Test-path $regkey_4065
 if($path_4065){
	$exist_4065=(Get-Item $regkey_4065).Property -contains $name_4065
	If($exist_4065){
		Set-ItemProperty -Path $regkey_4065 -Name $name_4065 -Value $rvalue_4065
		Write-Output "$name_4065 key is set to $rvalue_4065 for CID: 4065"
		}
	if(!$exist_4065){
		New-ItemProperty -Path $regkey_4065 -Name $name_4065 -PropertyType $type_4065 -Value $rvalue_4065 | Out-Null
		Write-Output "$name_4065 key is created and set to $rvalue_4065 for CID: 4065"
		}
  }
 else{
 New-item -Path $regkey_4065 -Force | Out-Null
  New-ItemProperty -Path $regkey_4065 -Name $name_4065 -PropertyType $type_4065 -Value $rvalue_4065 | Out-Null
  Write-Output "Created $regkey_4065  and $name_4065 key and set to $rvalue_4065 for CID: 4065"
 }

#----------------------- EOS CID 4065 -----------------------#

<# 
-CID: 4068
STMT: Status of the 'PNRP Machine Name Publication' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4068 = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg"
$name_4068 = "Start"
$rvalue_4068 = "4"
$type_4068 = "DWord"
$path_4068 = Test-path $regkey_4068
 if($path_4068){
	$exist_4068=(Get-Item $regkey_4068).Property -contains $name_4068
	If($exist_4068){
		Set-ItemProperty -Path $regkey_4068 -Name $name_4068 -Value $rvalue_4068
		Write-Output "$name_4068 key is set to $rvalue_4068 for CID: 4068"
		}
	if(!$exist_4068){
		New-ItemProperty -Path $regkey_4068 -Name $name_4068 -PropertyType $type_4068 -Value $rvalue_4068 | Out-Null
		Write-Output "$name_4068 key is created and set to $rvalue_4068 for CID: 4068"
		}
  }
 else{
 New-item -Path $regkey_4068 -Force | Out-Null
  New-ItemProperty -Path $regkey_4068 -Name $name_4068 -PropertyType $type_4068 -Value $rvalue_4068 | Out-Null
  Write-Output "Created $regkey_4068  and $name_4068 key and set to $rvalue_4068 for CID: 4068"
 }

#----------------------- EOS CID 4068 -----------------------#

<# 
-CID: 4073
STMT: Status of the 'Windows Peer Name Resolution Protocol' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4073 = "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc"
$name_4073 = "Start"
$rvalue_4073 = "4"
$type_4073 = "DWord"
$path_4073 = Test-path $regkey_4073
 if($path_4073){
	$exist_4073=(Get-Item $regkey_4073).Property -contains $name_4073
	If($exist_4073){
		Set-ItemProperty -Path $regkey_4073 -Name $name_4073 -Value $rvalue_4073
		Write-Output "$name_4073 key is set to $rvalue_4073 for CID: 4073"
		}
	if(!$exist_4073){
		New-ItemProperty -Path $regkey_4073 -Name $name_4073 -PropertyType $type_4073 -Value $rvalue_4073 | Out-Null
		Write-Output "$name_4073 key is created and set to $rvalue_4073 for CID: 4073"
		}
  }
 else{
 New-item -Path $regkey_4073 -Force | Out-Null
  New-ItemProperty -Path $regkey_4073 -Name $name_4073 -PropertyType $type_4073 -Value $rvalue_4073 | Out-Null
  Write-Output "Created $regkey_4073  and $name_4073 key and set to $rvalue_4073 for CID: 4073"
 }

#----------------------- EOS CID 4073 -----------------------#

<# 
-CID: 4074
STMT: Status of the 'Windows Peer Networking Identity Manager' service
If the Start key exists, set the value to 4 (Disabled); otherwise, create the Start key and update the value.
Impact: Bluetooth devices may fail to operate properly and new devices may be prevented from being discovered or associated.
#>

$regkey_4074 = "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc"
$name_4074 = "Start"
$rvalue_4074 = "4"
$type_4074 = "DWord"
$path_4074 = Test-path $regkey_4074
 if($path_4074){
	$exist_4074=(Get-Item $regkey_4074).Property -contains $name_4074
	If($exist_4074){
		Set-ItemProperty -Path $regkey_4074 -Name $name_4074 -Value $rvalue_4074
		Write-Output "$name_4074 key is set to $rvalue_4074 for CID: 4074"
		}
	if(!$exist_4074){
		New-ItemProperty -Path $regkey_4074 -Name $name_4074 -PropertyType $type_4074 -Value $rvalue_4074 | Out-Null
		Write-Output "$name_4074 key is created and set to $rvalue_4074 for CID: 4074"
		}
  }
 else{
 New-item -Path $regkey_4074 -Force | Out-Null
  New-ItemProperty -Path $regkey_4074 -Name $name_4074 -PropertyType $type_4074 -Value $rvalue_4074 | Out-Null
  Write-Output "Created $regkey_4074  and $name_4074 key and set to $rvalue_4074 for CID: 4074"
 }

#----------------------- EOS CID 4074 -----------------------#

<# 
-CID: 4095
STMT: Status of the 'Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com' Group Policy setting
If the ExitOnMSICW key exists, set the value to 1 (Enabled); otherwise, create the ExitOnMSICW key and update the value.
Impact: This prevents users from retrieving the list of ISPs, which resides on Microsoft servers.
#>

$regkey_4095 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Internet Connection Wizard"
$name_4095 = "ExitOnMSICW"
$rvalue_4095 = "1"
$type_4095 = "DWord"
$path_4095 = Test-path $regkey_4095
 if($path_4095){
	$exist_4095=(Get-Item $regkey_4095).Property -contains $name_4095
	If($exist_4095){
		Set-ItemProperty -Path $regkey_4095 -Name $name_4095 -Value $rvalue_4095
		Write-Output "$name_4095 key is set to $rvalue_4095 for CID: 4095"
		}
	if(!$exist_4095){
		New-ItemProperty -Path $regkey_4095 -Name $name_4095 -PropertyType $type_4095 -Value $rvalue_4095 | Out-Null
		Write-Output "$name_4095 key is created and set to $rvalue_4095 for CID: 4095"
		}
  }
 else{
 New-item -Path $regkey_4095 -Force | Out-Null
  New-ItemProperty -Path $regkey_4095 -Name $name_4095 -PropertyType $type_4095 -Value $rvalue_4095 | Out-Null
  Write-Output "Created $regkey_4095  and $name_4095 key and set to $rvalue_4095 for CID: 4095"
 }

#----------------------- EOS CID 4095 -----------------------#

<# 
-CID: 4097
STMT: Status of the 'Windows Registration Wizard' registry key value
If the NoRegistration key exists, set the value to 1 (Enabled); otherwise, create the NoRegistration key and update the value.
Impact: WCN operations are disabled over all media.
#>

$regkey_4097 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Registration Wizard Control"
$name_4097 = "NoRegistration"
$rvalue_4097 = "1"
$type_4097 = "DWord"
$path_4097 = Test-path $regkey_4097
 if($path_4097){
	$exist_4097=(Get-Item $regkey_4097).Property -contains $name_4097
	If($exist_4097){
		Set-ItemProperty -Path $regkey_4097 -Name $name_4097 -Value $rvalue_4097
		Write-Output "$name_4097 key is set to $rvalue_4097 for CID: 4097"
		}
	if(!$exist_4097){
		New-ItemProperty -Path $regkey_4097 -Name $name_4097 -PropertyType $type_4097 -Value $rvalue_4097 | Out-Null
		Write-Output "$name_4097 key is created and set to $rvalue_4097 for CID: 4097"
		}
  }
 else{
 New-item -Path $regkey_4097 -Force | Out-Null
  New-ItemProperty -Path $regkey_4097 -Name $name_4097 -PropertyType $type_4097 -Value $rvalue_4097 | Out-Null
  Write-Output "Created $regkey_4097  and $name_4097 key and set to $rvalue_4097 for CID: 4097"
 }

#----------------------- EOS CID 4097 -----------------------#

<# 
-CID: 4098
STMT: Status of the 'Order Prints' Group Policy setting
If the NoOnlinePrintsWizard key exists, set the value to 1 (Enabled); otherwise, create the NoOnlinePrintsWizard key and update the value.
Impact: The task Order Prints Online is removed from Picture Tasks in File Explorer folders.
#>

$regkey_4098 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$name_4098 = "NoOnlinePrintsWizard"
$rvalue_4098 = "1"
$type_4098 = "DWord"
$path_4098 = Test-path $regkey_4098
 if($path_4098){
	$exist_4098=(Get-Item $regkey_4098).Property -contains $name_4098
	If($exist_4098){
		Set-ItemProperty -Path $regkey_4098 -Name $name_4098 -Value $rvalue_4098
		Write-Output "$name_4098 key is set to $rvalue_4098 for CID: 4098"
		}
	if(!$exist_4098){
		New-ItemProperty -Path $regkey_4098 -Name $name_4098 -PropertyType $type_4098 -Value $rvalue_4098 | Out-Null
		Write-Output "$name_4098 key is created and set to $rvalue_4098 for CID: 4098"
		}
  }
 else{
 New-item -Path $regkey_4098 -Force | Out-Null
  New-ItemProperty -Path $regkey_4098 -Name $name_4098 -PropertyType $type_4098 -Value $rvalue_4098 | Out-Null
  Write-Output "Created $regkey_4098  and $name_4098 key and set to $rvalue_4098 for CID: 4098"
 }

#----------------------- EOS CID 4098 -----------------------#

<# 
-CID: 4123
STMT: Status of the 'Do not allow COM port redirection' Group Policy setting
If the fDisableCcm key exists, set the value to 1 (Enabled); otherwise, create the fDisableCcm key and update the value.
Impact: Users in a Remote Desktop Services session will not be able to redirect server data to local (client) COM ports.
#>

$regkey_4123 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_4123 = "fDisableCcm"
$rvalue_4123 = "1"
$type_4123 = "DWord"
$path_4123 = Test-path $regkey_4123
 if($path_4123){
	$exist_4123=(Get-Item $regkey_4123).Property -contains $name_4123
	If($exist_4123){
		Set-ItemProperty -Path $regkey_4123 -Name $name_4123 -Value $rvalue_4123
		Write-Output "$name_4123 key is set to $rvalue_4123 for CID: 4123"
		}
	if(!$exist_4123){
		New-ItemProperty -Path $regkey_4123 -Name $name_4123 -PropertyType $type_4123 -Value $rvalue_4123 | Out-Null
		Write-Output "$name_4123 key is created and set to $rvalue_4123 for CID: 4123"
		}
  }
 else{
 New-item -Path $regkey_4123 -Force | Out-Null
  New-ItemProperty -Path $regkey_4123 -Name $name_4123 -PropertyType $type_4123 -Value $rvalue_4123 | Out-Null
  Write-Output "Created $regkey_4123  and $name_4123 key and set to $rvalue_4123 for CID: 4123"
 }

#----------------------- EOS CID 4123 -----------------------#

<# 
-CID: 4124
STMT: Status of the 'Do not allow LPT port redirection' Group Policy setting
If the fDisableLPT key exists, set the value to 1 (Enabled); otherwise, create the fDisableLPT key and update the value.
Impact: Users in a Remote Desktop Services session will not be able to redirect server data to local (client) LPT ports.
#>

$regkey_4124 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_4124 = "fDisableLPT"
$rvalue_4124 = "1"
$type_4124 = "DWord"
$path_4124 = Test-path $regkey_4124
 if($path_4124){
	$exist_4124=(Get-Item $regkey_4124).Property -contains $name_4124
	If($exist_4124){
		Set-ItemProperty -Path $regkey_4124 -Name $name_4124 -Value $rvalue_4124
		Write-Output "$name_4124 key is set to $rvalue_4124 for CID: 4124"
		}
	if(!$exist_4124){
		New-ItemProperty -Path $regkey_4124 -Name $name_4124 -PropertyType $type_4124 -Value $rvalue_4124 | Out-Null
		Write-Output "$name_4124 key is created and set to $rvalue_4124 for CID: 4124"
		}
  }
 else{
 New-item -Path $regkey_4124 -Force | Out-Null
  New-ItemProperty -Path $regkey_4124 -Name $name_4124 -PropertyType $type_4124 -Value $rvalue_4124 | Out-Null
  Write-Output "Created $regkey_4124  and $name_4124 key and set to $rvalue_4124 for CID: 4124"
 }

#----------------------- EOS CID 4124 -----------------------#

<# 
-CID: 4125
STMT: Status of the 'Do not allow supported Plug and Play redirection' Group Policy setting
If the fDisablePNPRedir key exists, set the value to 1 (Enabled); otherwise, create the fDisablePNPRedir key and update the value.
Impact: Users in a Remote Desktop Services session will not be able to redirect their supported (local client) Plug and Play devices to the remote computer.
#>

$regkey_4125 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_4125 = "fDisablePNPRedir"
$rvalue_4125 = "1"
$type_4125 = "DWord"
$path_4125 = Test-path $regkey_4125
 if($path_4125){
	$exist_4125=(Get-Item $regkey_4125).Property -contains $name_4125
	If($exist_4125){
		Set-ItemProperty -Path $regkey_4125 -Name $name_4125 -Value $rvalue_4125
		Write-Output "$name_4125 key is set to $rvalue_4125 for CID: 4125"
		}
	if(!$exist_4125){
		New-ItemProperty -Path $regkey_4125 -Name $name_4125 -PropertyType $type_4125 -Value $rvalue_4125 | Out-Null
		Write-Output "$name_4125 key is created and set to $rvalue_4125 for CID: 4125"
		}
  }
 else{
 New-item -Path $regkey_4125 -Force | Out-Null
  New-ItemProperty -Path $regkey_4125 -Name $name_4125 -PropertyType $type_4125 -Value $rvalue_4125 | Out-Null
  Write-Output "Created $regkey_4125  and $name_4125 key and set to $rvalue_4125 for CID: 4125"
 }

#----------------------- EOS CID 4125 -----------------------#

<# 
-CID: 4133
STMT: Status of the 'Require secure RPC communication' setting
If the fEncryptRPCTraffic key exists, set the value to 1 (Enabled); otherwise, create the fEncryptRPCTraffic key and update the value.
Impact: Remote Desktop Services accepts requests from RPC clients that support secure requests, and does not allow unsecured communication with untrusted clients.
#>

$regkey_4133 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_4133 = "fEncryptRPCTraffic"
$rvalue_4133 = "1"
$type_4133 = "DWord"
$path_4133 = Test-path $regkey_4133
 if($path_4133){
	$exist_4133=(Get-Item $regkey_4133).Property -contains $name_4133
	If($exist_4133){
		Set-ItemProperty -Path $regkey_4133 -Name $name_4133 -Value $rvalue_4133
		Write-Output "$name_4133 key is set to $rvalue_4133 for CID: 4133"
		}
	if(!$exist_4133){
		New-ItemProperty -Path $regkey_4133 -Name $name_4133 -PropertyType $type_4133 -Value $rvalue_4133 | Out-Null
		Write-Output "$name_4133 key is created and set to $rvalue_4133 for CID: 4133"
		}
  }
 else{
 New-item -Path $regkey_4133 -Force | Out-Null
  New-ItemProperty -Path $regkey_4133 -Name $name_4133 -PropertyType $type_4133 -Value $rvalue_4133 | Out-Null
  Write-Output "Created $regkey_4133  and $name_4133 key and set to $rvalue_4133 for CID: 4133"
 }

#----------------------- EOS CID 4133 -----------------------#

<# 
-CID: 4139
STMT: Status of the 'Do not use temporary folders per session' Group Policy setting
If the PerSessionTempDir key exists, set the value to 1 (Disabled); otherwise, create the PerSessionTempDir key and update the value.
#>

$regkey_4139 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_4139 = "PerSessionTempDir"
$rvalue_4139 = "1"
$type_4139 = "DWord"
$path_4139 = Test-path $regkey_4139
 if($path_4139){
	$exist_4139=(Get-Item $regkey_4139).Property -contains $name_4139
	If($exist_4139){
		Set-ItemProperty -Path $regkey_4139 -Name $name_4139 -Value $rvalue_4139
		Write-Output "$name_4139 key is set to $rvalue_4139 for CID: 4139"
		}
	if(!$exist_4139){
		New-ItemProperty -Path $regkey_4139 -Name $name_4139 -PropertyType $type_4139 -Value $rvalue_4139 | Out-Null
		Write-Output "$name_4139 key is created and set to $rvalue_4139 for CID: 4139"
		}
  }
 else{
 New-item -Path $regkey_4139 -Force | Out-Null
  New-ItemProperty -Path $regkey_4139 -Name $name_4139 -PropertyType $type_4139 -Value $rvalue_4139 | Out-Null
  Write-Output "Created $regkey_4139  and $name_4139 key and set to $rvalue_4139 for CID: 4139"
 }

#----------------------- EOS CID 4139 -----------------------#

<# 
-CID: 4140
STMT: Status of the 'Do not delete temp folder upon exit' setting
If the DeleteTempDirsOnExit key exists, set the value to 1 (Disabled); otherwise, create the DeleteTempDirsOnExit key and update the value.
#>

$regkey_4140 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_4140 = "DeleteTempDirsOnExit"
$rvalue_4140 = "1"
$type_4140 = "DWord"
$path_4140 = Test-path $regkey_4140
 if($path_4140){
	$exist_4140=(Get-Item $regkey_4140).Property -contains $name_4140
	If($exist_4140){
		Set-ItemProperty -Path $regkey_4140 -Name $name_4140 -Value $rvalue_4140
		Write-Output "$name_4140 key is set to $rvalue_4140 for CID: 4140"
		}
	if(!$exist_4140){
		New-ItemProperty -Path $regkey_4140 -Name $name_4140 -PropertyType $type_4140 -Value $rvalue_4140 | Out-Null
		Write-Output "$name_4140 key is created and set to $rvalue_4140 for CID: 4140"
		}
  }
 else{
 New-item -Path $regkey_4140 -Force | Out-Null
  New-ItemProperty -Path $regkey_4140 -Name $name_4140 -PropertyType $type_4140 -Value $rvalue_4140 | Out-Null
  Write-Output "Created $regkey_4140  and $name_4140 key and set to $rvalue_4140 for CID: 4140"
 }

#----------------------- EOS CID 4140 -----------------------#

<# 
-CID: 4143
STMT: Status of the 'Disable Windows Error Reporting' setting
If the Disabled key exists, set the value to 1 (Enabled); otherwise, create the Disabled key and update the value.
Impact: Users are not given the option to report errors to Microsoft.
#>

$regkey_4143 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting"
$name_4143 = "Disabled"
$rvalue_4143 = "1"
$type_4143 = "DWord"
$path_4143 = Test-path $regkey_4143
 if($path_4143){
	$exist_4143=(Get-Item $regkey_4143).Property -contains $name_4143
	If($exist_4143){
		Set-ItemProperty -Path $regkey_4143 -Name $name_4143 -Value $rvalue_4143
		Write-Output "$name_4143 key is set to $rvalue_4143 for CID: 4143"
		}
	if(!$exist_4143){
		New-ItemProperty -Path $regkey_4143 -Name $name_4143 -PropertyType $type_4143 -Value $rvalue_4143 | Out-Null
		Write-Output "$name_4143 key is created and set to $rvalue_4143 for CID: 4143"
		}
  }
 else{
 New-item -Path $regkey_4143 -Force | Out-Null
  New-ItemProperty -Path $regkey_4143 -Name $name_4143 -PropertyType $type_4143 -Value $rvalue_4143 | Out-Null
  Write-Output "Created $regkey_4143  and $name_4143 key and set to $rvalue_4143 for CID: 4143"
 }

#----------------------- EOS CID 4143 -----------------------#

<# 
-CID: 4193
STMT: Status of the 'Configuration of wireless settings using Windows Connect Now' group policy setting
If the EnableRegistrars key exists, set the value to 0 (Disabled); otherwise, create the EnableRegistrars key and update the value.
Impact: WCN operations are disabled over all media.
#>

$regkey_4193 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars"
$name_4193 = "EnableRegistrars"
$rvalue_4193 = "0"
$type_4193 = "DWord"
$path_4193 = Test-path $regkey_4193
 if($path_4193){
	$exist_4193=(Get-Item $regkey_4193).Property -contains $name_4193
	If($exist_4193){
		Set-ItemProperty -Path $regkey_4193 -Name $name_4193 -Value $rvalue_4193
		Write-Output "$name_4193 key is set to $rvalue_4193 for CID: 4193"
		}
	if(!$exist_4193){
		New-ItemProperty -Path $regkey_4193 -Name $name_4193 -PropertyType $type_4193 -Value $rvalue_4193 | Out-Null
		Write-Output "$name_4193 key is created and set to $rvalue_4193 for CID: 4193"
		}
  }
 else{
 New-item -Path $regkey_4193 -Force | Out-Null
  New-ItemProperty -Path $regkey_4193 -Name $name_4193 -PropertyType $type_4193 -Value $rvalue_4193 | Out-Null
  Write-Output "Created $regkey_4193  and $name_4193 key and set to $rvalue_4193 for CID: 4193"
 }

#----------------------- EOS CID 4193 -----------------------#

<# 
-CID: 4741
STMT: Status of the 'MSS: (DisableIPSourceRoutingIPv6) IP source routing protection level (protects against packet spoofing)' setting
If the DisableIPSourceRouting key exists, set the value to 2 (Enabled: Highest protection, source routing is completely disabled); otherwise, create the DisableIPSourceRouting key and update the value.
Impact: All incoming packets routed from the source will be dropped.
#>

$regkey_4741 = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$name_4741 = "DisableIPSourceRouting"
$rvalue_4741 = "2"
$type_4741 = "DWord"
$path_4741 = Test-path $regkey_4741
 if($path_4741){
	$exist_4741=(Get-Item $regkey_4741).Property -contains $name_4741
	If($exist_4741){
		Set-ItemProperty -Path $regkey_4741 -Name $name_4741 -Value $rvalue_4741
		Write-Output "$name_4741 key is set to $rvalue_4741 for CID: 4741"
		}
	if(!$exist_4741){
		New-ItemProperty -Path $regkey_4741 -Name $name_4741 -PropertyType $type_4741 -Value $rvalue_4741 | Out-Null
		Write-Output "$name_4741 key is created and set to $rvalue_4741 for CID: 4741"
		}
  }
 else{
 New-item -Path $regkey_4741 -Force | Out-Null
  New-ItemProperty -Path $regkey_4741 -Name $name_4741 -PropertyType $type_4741 -Value $rvalue_4741 | Out-Null
  Write-Output "Created $regkey_4741  and $name_4741 key and set to $rvalue_4741 for CID: 4741"
 }

#----------------------- EOS CID 4741 -----------------------#

<# 
-CID: 4742
STMT: Status of the 'MSS: (TCPMaxDataRetransmissions) IPv6 How many times unacknowledged data is retransmitted' setting
If the TcpMaxDataRetransmissions key exists, set the value to 3 (Enabled); otherwise, create the TcpMaxDataRetransmissions key and update the value.
Impact: When each outbound segment is transmitted to the IP, TCP starts a retransmission timer.
#>

$regkey_4742 = "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters"
$name_4742 = "TcpMaxDataRetransmissions"
$rvalue_4742 = "3"
$type_4742 = "DWord"
$path_4742 = Test-path $regkey_4742
 if($path_4742){
	$exist_4742=(Get-Item $regkey_4742).Property -contains $name_4742
	If($exist_4742){
		Set-ItemProperty -Path $regkey_4742 -Name $name_4742 -Value $rvalue_4742
		Write-Output "$name_4742 key is set to $rvalue_4742 for CID: 4742"
		}
	if(!$exist_4742){
		New-ItemProperty -Path $regkey_4742 -Name $name_4742 -PropertyType $type_4742 -Value $rvalue_4742 | Out-Null
		Write-Output "$name_4742 key is created and set to $rvalue_4742 for CID: 4742"
		}
  }
 else{
 New-item -Path $regkey_4742 -Force | Out-Null
  New-ItemProperty -Path $regkey_4742 -Name $name_4742 -PropertyType $type_4742 -Value $rvalue_4742 | Out-Null
  Write-Output "Created $regkey_4742  and $name_4742 key and set to $rvalue_4742 for CID: 4742"
 }

#----------------------- EOS CID 4742 -----------------------#

<# 
-CID: 4843
STMT: Status of the 'DisableSavePassword in Dial-Up Networking' setting
If the DisableSavePassword key exists, set the value to 1 (Enabled); otherwise, create the DisableSavePassword key and update the value.
Impact: For dial-up and VPN connections, users will not be able to save their logon credentials automatically.
#>

$regkey_4843 = "HKLM:\SYSTEM\CurrentControlSet\Services\RasMan\Parameters"
$name_4843 = "DisableSavePassword"
$rvalue_4843 = "1"
$type_4843 = "DWord"
$path_4843 = Test-path $regkey_4843
 if($path_4843){
	$exist_4843=(Get-Item $regkey_4843).Property -contains $name_4843
	If($exist_4843){
		Set-ItemProperty -Path $regkey_4843 -Name $name_4843 -Value $rvalue_4843
		Write-Output "$name_4843 key is set to $rvalue_4843 for CID: 4843"
		}
	if(!$exist_4843){
		New-ItemProperty -Path $regkey_4843 -Name $name_4843 -PropertyType $type_4843 -Value $rvalue_4843 | Out-Null
		Write-Output "$name_4843 key is created and set to $rvalue_4843 for CID: 4843"
		}
  }
 else{
 New-item -Path $regkey_4843 -Force | Out-Null
  New-ItemProperty -Path $regkey_4843 -Name $name_4843 -PropertyType $type_4843 -Value $rvalue_4843 | Out-Null
  Write-Output "Created $regkey_4843  and $name_4843 key and set to $rvalue_4843 for CID: 4843"
 }

#----------------------- EOS CID 4843 -----------------------#

<# 
-CID: 5270
STMT: Status of the 'Prevent the computer from joining a homegroup' setting
If the DisableHomeGroup key exists, set the value to 1 (Enabled); otherwise, create the DisableHomeGroup key and update the value.
Impact: A user on this computer will not be able to add this computer to a HomeGroup. This setting does not affect other network sharing features.
#>

$regkey_5270 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\HomeGroup"
$name_5270 = "DisableHomeGroup"
$rvalue_5270 = "1"
$type_5270 = "DWord"
$path_5270 = Test-path $regkey_5270
 if($path_5270){
	$exist_5270=(Get-Item $regkey_5270).Property -contains $name_5270
	If($exist_5270){
		Set-ItemProperty -Path $regkey_5270 -Name $name_5270 -Value $rvalue_5270
		Write-Output "$name_5270 key is set to $rvalue_5270 for CID: 5270"
		}
	if(!$exist_5270){
		New-ItemProperty -Path $regkey_5270 -Name $name_5270 -PropertyType $type_5270 -Value $rvalue_5270 | Out-Null
		Write-Output "$name_5270 key is created and set to $rvalue_5270 for CID: 5270"
		}
  }
 else{
 New-item -Path $regkey_5270 -Force | Out-Null
  New-ItemProperty -Path $regkey_5270 -Name $name_5270 -PropertyType $type_5270 -Value $rvalue_5270 | Out-Null
  Write-Output "Created $regkey_5270  and $name_5270 key and set to $rvalue_5270 for CID: 5270"
 }

#----------------------- EOS CID 5270 -----------------------#

<# 
-CID: 8141
STMT: Status of the Security Options 'Accounts: Block Microsoft accounts' setting
If the NoConnectedUser key exists, set the value to 3 (Users cannot add or log in with Microsoft accounts); otherwise, create the NoConnectedUser key and update the value.
Impact: Users will not be able to log onto the computer with their Microsoft account.
#>

$regkey_8141 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System"
$name_8141 = "NoConnectedUser"
$rvalue_8141 = "3"
$type_8141 = "DWord"
$path_8141 = Test-path $regkey_8141
 if($path_8141){
	$exist_8141=(Get-Item $regkey_8141).Property -contains $name_8141
	If($exist_8141){
		Set-ItemProperty -Path $regkey_8141 -Name $name_8141 -Value $rvalue_8141
		Write-Output "$name_8141 key is set to $rvalue_8141 for CID: 8141"
		}
	if(!$exist_8141){
		New-ItemProperty -Path $regkey_8141 -Name $name_8141 -PropertyType $type_8141 -Value $rvalue_8141 | Out-Null
		Write-Output "$name_8141 key is created and set to $rvalue_8141 for CID: 8141"
		}
  }
 else{
 New-item -Path $regkey_8141 -Force | Out-Null
  New-ItemProperty -Path $regkey_8141 -Name $name_8141 -PropertyType $type_8141 -Value $rvalue_8141 | Out-Null
  Write-Output "Created $regkey_8141  and $name_8141 key and set to $rvalue_8141 for CID: 8141"
 }

#----------------------- EOS CID 8141 -----------------------#

<# 
-CID: 8176
STMT: Status of the 'Do not enumerate connected users on domain-joined computers' setting
If the DontEnumerateConnectedUsers key exists, set the value to 1 (Enabled); otherwise, create the DontEnumerateConnectedUsers key and update the value.
Impact: The Logon UI will not enumerate any connected users on domain-joined computers.
#>

$regkey_8176 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_8176 = "DontEnumerateConnectedUsers"
$rvalue_8176 = "1"
$type_8176 = "DWord"
$path_8176 = Test-path $regkey_8176
 if($path_8176){
	$exist_8176=(Get-Item $regkey_8176).Property -contains $name_8176
	If($exist_8176){
		Set-ItemProperty -Path $regkey_8176 -Name $name_8176 -Value $rvalue_8176
		Write-Output "$name_8176 key is set to $rvalue_8176 for CID: 8176"
		}
	if(!$exist_8176){
		New-ItemProperty -Path $regkey_8176 -Name $name_8176 -PropertyType $type_8176 -Value $rvalue_8176 | Out-Null
		Write-Output "$name_8176 key is created and set to $rvalue_8176 for CID: 8176"
		}
  }
 else{
 New-item -Path $regkey_8176 -Force | Out-Null
  New-ItemProperty -Path $regkey_8176 -Name $name_8176 -PropertyType $type_8176 -Value $rvalue_8176 | Out-Null
  Write-Output "Created $regkey_8176  and $name_8176 key and set to $rvalue_8176 for CID: 8176"
 }

#----------------------- EOS CID 8176 -----------------------#

<# 
-CID: 8188
STMT: Status of the 'Boot-Start Driver Initialization Policy' setting
If the DriverLoadPolicy key exists, set the value to 3 (Good, unknown and bad but critical); otherwise, create the DriverLoadPolicy key and update the value.
#>

$regkey_8188 = "HKLM:\SYSTEM\CurrentControlSet\Policies\EarlyLaunch"
$name_8188 = "DriverLoadPolicy"
$rvalue_8188 = "3"
$type_8188 = "DWord"
$path_8188 = Test-path $regkey_8188
 if($path_8188){
	$exist_8188=(Get-Item $regkey_8188).Property -contains $name_8188
	If($exist_8188){
		Set-ItemProperty -Path $regkey_8188 -Name $name_8188 -Value $rvalue_8188
		Write-Output "$name_8188 key is set to $rvalue_8188 for CID: 8188"
		}
	if(!$exist_8188){
		New-ItemProperty -Path $regkey_8188 -Name $name_8188 -PropertyType $type_8188 -Value $rvalue_8188 | Out-Null
		Write-Output "$name_8188 key is created and set to $rvalue_8188 for CID: 8188"
		}
  }
 else{
 New-item -Path $regkey_8188 -Force | Out-Null
  New-ItemProperty -Path $regkey_8188 -Name $name_8188 -PropertyType $type_8188 -Value $rvalue_8188 | Out-Null
  Write-Output "Created $regkey_8188  and $name_8188 key and set to $rvalue_8188 for CID: 8188"
 }

#----------------------- EOS CID 8188 -----------------------#

<# 
-CID: 8395
STMT: Status of the Configure 'Prohibit connection to non-domain networks' setting
If the fBlockNonDomain key exists, set the value to 1 (enabled); otherwise, create the fBlockNonDomain key and update the value.
Impact: Connections to both domain and non-domain networks are simultaneously not allowed.
#>

$regkey_8395 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
$name_8395 = "fBlockNonDomain"
$rvalue_8395 = "1"
$type_8395 = "DWord"
$path_8395 = Test-path $regkey_8395
 if($path_8395){
	$exist_8395=(Get-Item $regkey_8395).Property -contains $name_8395
	If($exist_8395){
		Set-ItemProperty -Path $regkey_8395 -Name $name_8395 -Value $rvalue_8395
		Write-Output "$name_8395 key is set to $rvalue_8395 for CID: 8395"
		}
	if(!$exist_8395){
		New-ItemProperty -Path $regkey_8395 -Name $name_8395 -PropertyType $type_8395 -Value $rvalue_8395 | Out-Null
		Write-Output "$name_8395 key is created and set to $rvalue_8395 for CID: 8395"
		}
  }
 else{
 New-item -Path $regkey_8395 -Force | Out-Null
  New-ItemProperty -Path $regkey_8395 -Name $name_8395 -PropertyType $type_8395 -Value $rvalue_8395 | Out-Null
  Write-Output "Created $regkey_8395  and $name_8395 key and set to $rvalue_8395 for CID: 8395"
 }

#----------------------- EOS CID 8395 -----------------------#

<# 
-CID: 8397
STMT: Status of Configure 'Turn off access to the Store'
If the NoUseStoreOpenWith key exists, set the value to 1 (Enabled); otherwise, create the NoUseStoreOpenWith key and update the value.
Impact: The Look for an app in the Store item in the Open With dialog is removed.
#>

$regkey_8397 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
$name_8397 = "NoUseStoreOpenWith"
$rvalue_8397 = "1"
$type_8397 = "DWord"
$path_8397 = Test-path $regkey_8397
 if($path_8397){
	$exist_8397=(Get-Item $regkey_8397).Property -contains $name_8397
	If($exist_8397){
		Set-ItemProperty -Path $regkey_8397 -Name $name_8397 -Value $rvalue_8397
		Write-Output "$name_8397 key is set to $rvalue_8397 for CID: 8397"
		}
	if(!$exist_8397){
		New-ItemProperty -Path $regkey_8397 -Name $name_8397 -PropertyType $type_8397 -Value $rvalue_8397 | Out-Null
		Write-Output "$name_8397 key is created and set to $rvalue_8397 for CID: 8397"
		}
  }
 else{
 New-item -Path $regkey_8397 -Force | Out-Null
  New-ItemProperty -Path $regkey_8397 -Name $name_8397 -PropertyType $type_8397 -Value $rvalue_8397 | Out-Null
  Write-Output "Created $regkey_8397  and $name_8397 key and set to $rvalue_8397 for CID: 8397"
 }

#----------------------- EOS CID 8397 -----------------------#

<# 
-CID: 8399
STMT: Status of the Configure 'Turn off app notifications on the lock screen'
If the DisableLockScreenAppNotifications key exists, set the value to 1 (Enabled); otherwise, create the DisableLockScreenAppNotifications key and update the value.
Impact: No app notifications are displayed on the lock screen.
#>

$regkey_8399 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_8399 = "DisableLockScreenAppNotifications"
$rvalue_8399 = "1"
$type_8399 = "DWord"
$path_8399 = Test-path $regkey_8399
 if($path_8399){
	$exist_8399=(Get-Item $regkey_8399).Property -contains $name_8399
	If($exist_8399){
		Set-ItemProperty -Path $regkey_8399 -Name $name_8399 -Value $rvalue_8399
		Write-Output "$name_8399 key is set to $rvalue_8399 for CID: 8399"
		}
	if(!$exist_8399){
		New-ItemProperty -Path $regkey_8399 -Name $name_8399 -PropertyType $type_8399 -Value $rvalue_8399 | Out-Null
		Write-Output "$name_8399 key is created and set to $rvalue_8399 for CID: 8399"
		}
  }
 else{
 New-item -Path $regkey_8399 -Force | Out-Null
  New-ItemProperty -Path $regkey_8399 -Name $name_8399 -PropertyType $type_8399 -Value $rvalue_8399 | Out-Null
  Write-Output "Created $regkey_8399  and $name_8399 key and set to $rvalue_8399 for CID: 8399"
 }

#----------------------- EOS CID 8399 -----------------------#

<# 
-CID: 10404
STMT: Status of the 'Require user authentication for remote connections by using Network Level Authentication' setting
If the UserAuthentication key exists, set the value to 1 (Enabled); otherwise, create the UserAuthentication key and update the value.
Impact: Only client computers that support Network Level Authentication can connect to the RD Session Host server.
#>

$regkey_10404 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$name_10404 = "UserAuthentication"
$rvalue_10404 = "1"
$type_10404 = "DWord"
$path_10404 = Test-path $regkey_10404
 if($path_10404){
	$exist_10404=(Get-Item $regkey_10404).Property -contains $name_10404
	If($exist_10404){
		Set-ItemProperty -Path $regkey_10404 -Name $name_10404 -Value $rvalue_10404
		Write-Output "$name_10404 key is set to $rvalue_10404 for CID: 10404"
		}
	if(!$exist_10404){
		New-ItemProperty -Path $regkey_10404 -Name $name_10404 -PropertyType $type_10404 -Value $rvalue_10404 | Out-Null
		Write-Output "$name_10404 key is created and set to $rvalue_10404 for CID: 10404"
		}
  }
 else{
 New-item -Path $regkey_10404 -Force | Out-Null
  New-ItemProperty -Path $regkey_10404 -Name $name_10404 -PropertyType $type_10404 -Value $rvalue_10404 | Out-Null
  Write-Output "Created $regkey_10404  and $name_10404 key and set to $rvalue_10404 for CID: 10404"
 }

#----------------------- EOS CID 10404 -----------------------#

<# 
-CID: 8419
STMT: Status of the 'Turn off Automatic Download of updates' setting
If the AutoDownload key exists, set the value to 4 (Disabled); otherwise, create the AutoDownload key and update the value.
#>

$regkey_8419 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$name_8419 = "AutoDownload"
$rvalue_8419 = "4"
$type_8419 = "DWord"
$path_8419 = Test-path $regkey_8419
 if($path_8419){
	$exist_8419=(Get-Item $regkey_8419).Property -contains $name_8419
	If($exist_8419){
		Set-ItemProperty -Path $regkey_8419 -Name $name_8419 -Value $rvalue_8419
		Write-Output "$name_8419 key is set to $rvalue_8419 for CID: 8419"
		}
	if(!$exist_8419){
		New-ItemProperty -Path $regkey_8419 -Name $name_8419 -PropertyType $type_8419 -Value $rvalue_8419 | Out-Null
		Write-Output "$name_8419 key is created and set to $rvalue_8419 for CID: 8419"
		}
  }
 else{
 New-item -Path $regkey_8419 -Force | Out-Null
  New-ItemProperty -Path $regkey_8419 -Name $name_8419 -PropertyType $type_8419 -Value $rvalue_8419 | Out-Null
  Write-Output "Created $regkey_8419  and $name_8419 key and set to $rvalue_8419 for CID: 8419"
 }

#----------------------- EOS CID 8419 -----------------------#

<# 
-CID: 8420
STMT: Status of the 'Turn off location' setting
If the DisableLocation key exists, set the value to 1 (Enabled); otherwise, create the DisableLocation key and update the value.
Impact: The location feature is turned off, and all programs on the computer are prevented from using location information from the location feature.
#>

$regkey_8420 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors"
$name_8420 = "DisableLocation"
$rvalue_8420 = "1"
$type_8420 = "DWord"
$path_8420 = Test-path $regkey_8420
 if($path_8420){
	$exist_8420=(Get-Item $regkey_8420).Property -contains $name_8420
	If($exist_8420){
		Set-ItemProperty -Path $regkey_8420 -Name $name_8420 -Value $rvalue_8420
		Write-Output "$name_8420 key is set to $rvalue_8420 for CID: 8420"
		}
	if(!$exist_8420){
		New-ItemProperty -Path $regkey_8420 -Name $name_8420 -PropertyType $type_8420 -Value $rvalue_8420 | Out-Null
		Write-Output "$name_8420 key is created and set to $rvalue_8420 for CID: 8420"
		}
  }
 else{
 New-item -Path $regkey_8420 -Force | Out-Null
  New-ItemProperty -Path $regkey_8420 -Name $name_8420 -PropertyType $type_8420 -Value $rvalue_8420 | Out-Null
  Write-Output "Created $regkey_8420  and $name_8420 key and set to $rvalue_8420 for CID: 8420"
 }

#----------------------- EOS CID 8420 -----------------------#

<# 
-CID: 8425
STMT: Status of "Do not display the password reveal button"
If the DisablePasswordReveal key exists, set the value to 1 (Enabled); otherwise, create the DisablePasswordReveal key and update the value.
Impact: The password reveal button will not be displayed after a user types a password in the password entry text box.
#>

$regkey_8425 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredUI"
$name_8425 = "DisablePasswordReveal"
$rvalue_8425 = "1"
$type_8425 = "DWord"
$path_8425 = Test-path $regkey_8425
 if($path_8425){
	$exist_8425=(Get-Item $regkey_8425).Property -contains $name_8425
	If($exist_8425){
		Set-ItemProperty -Path $regkey_8425 -Name $name_8425 -Value $rvalue_8425
		Write-Output "$name_8425 key is set to $rvalue_8425 for CID: 8425"
		}
	if(!$exist_8425){
		New-ItemProperty -Path $regkey_8425 -Name $name_8425 -PropertyType $type_8425 -Value $rvalue_8425 | Out-Null
		Write-Output "$name_8425 key is created and set to $rvalue_8425 for CID: 8425"
		}
  }
 else{
 New-item -Path $regkey_8425 -Force | Out-Null
  New-ItemProperty -Path $regkey_8425 -Name $name_8425 -PropertyType $type_8425 -Value $rvalue_8425 | Out-Null
  Write-Output "Created $regkey_8425  and $name_8425 key and set to $rvalue_8425 for CID: 8425"
 }

#----------------------- EOS CID 8425 -----------------------#

<# 
-CID: 9003
STMT: Status of the 'Lock screen camera' setting
If the NoLockScreenCamera key exists, set the value to 1 (Enabled); otherwise, create the NoLockScreenCamera key and update the value.
Impact: Users will no longer be able to enable or disable lock screen camera access in PC Settings.
#>

$regkey_9003 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$name_9003 = "NoLockScreenCamera"
$rvalue_9003 = "1"
$type_9003 = "DWord"
$path_9003 = Test-path $regkey_9003
 if($path_9003){
	$exist_9003=(Get-Item $regkey_9003).Property -contains $name_9003
	If($exist_9003){
		Set-ItemProperty -Path $regkey_9003 -Name $name_9003 -Value $rvalue_9003
		Write-Output "$name_9003 key is set to $rvalue_9003 for CID: 9003"
		}
	if(!$exist_9003){
		New-ItemProperty -Path $regkey_9003 -Name $name_9003 -PropertyType $type_9003 -Value $rvalue_9003 | Out-Null
		Write-Output "$name_9003 key is created and set to $rvalue_9003 for CID: 9003"
		}
  }
 else{
 New-item -Path $regkey_9003 -Force | Out-Null
  New-ItemProperty -Path $regkey_9003 -Name $name_9003 -PropertyType $type_9003 -Value $rvalue_9003 | Out-Null
  Write-Output "Created $regkey_9003  and $name_9003 key and set to $rvalue_9003 for CID: 9003"
 }

#----------------------- EOS CID 9003 -----------------------#

<# 
-CID: 9004
STMT: Status of the 'Lock screen slide show' setting
If the NoLockScreenSlideshow key exists, set the value to 1 (Enabled); otherwise, create the NoLockScreenSlideshow key and update the value.
Impact: Users will no longer be able to modify slide show settings in PC Settings.
#>

$regkey_9004 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization"
$name_9004 = "NoLockScreenSlideshow"
$rvalue_9004 = "1"
$type_9004 = "DWord"
$path_9004 = Test-path $regkey_9004
 if($path_9004){
	$exist_9004=(Get-Item $regkey_9004).Property -contains $name_9004
	If($exist_9004){
		Set-ItemProperty -Path $regkey_9004 -Name $name_9004 -Value $rvalue_9004
		Write-Output "$name_9004 key is set to $rvalue_9004 for CID: 9004"
		}
	if(!$exist_9004){
		New-ItemProperty -Path $regkey_9004 -Name $name_9004 -PropertyType $type_9004 -Value $rvalue_9004 | Out-Null
		Write-Output "$name_9004 key is created and set to $rvalue_9004 for CID: 9004"
		}
  }
 else{
 New-item -Path $regkey_9004 -Force | Out-Null
  New-ItemProperty -Path $regkey_9004 -Name $name_9004 -PropertyType $type_9004 -Value $rvalue_9004 | Out-Null
  Write-Output "Created $regkey_9004  and $name_9004 key and set to $rvalue_9004 for CID: 9004"
 }

#----------------------- EOS CID 9004 -----------------------#

<# 
-CID: 9009
STMT: Status of the 'Allow Microsoft accounts to be optional' setting
If the MSAOptional key exists, set the value to 1 (Enabled); otherwise, create the MSAOptional key and update the value.
Impact: Windows Store apps that typically require a Microsoft account to sign in will allow users to sign in with an enterprise account instead.
#>

$regkey_9009 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$name_9009 = "MSAOptional"
$rvalue_9009 = "1"
$type_9009 = "DWord"
$path_9009 = Test-path $regkey_9009
 if($path_9009){
	$exist_9009=(Get-Item $regkey_9009).Property -contains $name_9009
	If($exist_9009){
		Set-ItemProperty -Path $regkey_9009 -Name $name_9009 -Value $rvalue_9009
		Write-Output "$name_9009 key is set to $rvalue_9009 for CID: 9009"
		}
	if(!$exist_9009){
		New-ItemProperty -Path $regkey_9009 -Name $name_9009 -PropertyType $type_9009 -Value $rvalue_9009 | Out-Null
		Write-Output "$name_9009 key is created and set to $rvalue_9009 for CID: 9009"
		}
  }
 else{
 New-item -Path $regkey_9009 -Force | Out-Null
  New-ItemProperty -Path $regkey_9009 -Name $name_9009 -PropertyType $type_9009 -Value $rvalue_9009 | Out-Null
  Write-Output "Created $regkey_9009  and $name_9009 key and set to $rvalue_9009 for CID: 9009"
 }

#----------------------- EOS CID 9009 -----------------------#

<# 
-CID: 9388
STMT: Status of the 'Turn off picture password sign-in' setting
If the BlockDomainPicturePassword key exists, set the value to 1 (Enabled); otherwise, create the BlockDomainPicturePassword key and update the value.
Impact: Users will not be able to set up or sign in with a picture password.
#>

$regkey_9388 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
$name_9388 = "BlockDomainPicturePassword"
$rvalue_9388 = "1"
$type_9388 = "DWord"
$path_9388 = Test-path $regkey_9388
 if($path_9388){
	$exist_9388=(Get-Item $regkey_9388).Property -contains $name_9388
	If($exist_9388){
		Set-ItemProperty -Path $regkey_9388 -Name $name_9388 -Value $rvalue_9388
		Write-Output "$name_9388 key is set to $rvalue_9388 for CID: 9388"
		}
	if(!$exist_9388){
		New-ItemProperty -Path $regkey_9388 -Name $name_9388 -PropertyType $type_9388 -Value $rvalue_9388 | Out-Null
		Write-Output "$name_9388 key is created and set to $rvalue_9388 for CID: 9388"
		}
  }
 else{
 New-item -Path $regkey_9388 -Force | Out-Null
  New-ItemProperty -Path $regkey_9388 -Name $name_9388 -PropertyType $type_9388 -Value $rvalue_9388 | Out-Null
  Write-Output "Created $regkey_9388  and $name_9388 key and set to $rvalue_9388 for CID: 9388"
 }

#----------------------- EOS CID 9388 -----------------------#

<# 
-CID: 9402
STMT: Status of the 'Turn off the advertising ID' setting
If the DisabledByGroupPolicy key exists, set the value to 1 (Enabled); otherwise, create the DisabledByGroupPolicy key and update the value.
Impact: The advertising ID is turned off. Apps can't use the ID for experiences across apps.
#>

$regkey_9402 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
$name_9402 = "DisabledByGroupPolicy"
$rvalue_9402 = "1"
$type_9402 = "DWord"
$path_9402 = Test-path $regkey_9402
 if($path_9402){
	$exist_9402=(Get-Item $regkey_9402).Property -contains $name_9402
	If($exist_9402){
		Set-ItemProperty -Path $regkey_9402 -Name $name_9402 -Value $rvalue_9402
		Write-Output "$name_9402 key is set to $rvalue_9402 for CID: 9402"
		}
	if(!$exist_9402){
		New-ItemProperty -Path $regkey_9402 -Name $name_9402 -PropertyType $type_9402 -Value $rvalue_9402 | Out-Null
		Write-Output "$name_9402 key is created and set to $rvalue_9402 for CID: 9402"
		}
  }
 else{
 New-item -Path $regkey_9402 -Force | Out-Null
  New-ItemProperty -Path $regkey_9402 -Name $name_9402 -PropertyType $type_9402 -Value $rvalue_9402 | Out-Null
  Write-Output "Created $regkey_9402  and $name_9402 key and set to $rvalue_9402 for CID: 9402"
 }

#----------------------- EOS CID 9402 -----------------------#

<# 
-CID: 9404
STMT: Status of the 'Prevent the usage of OneDrive for file storage' (Skydrive) group policy setting
If the DisableFileSyncNGSC key exists, set the value to 1 (Enabled); otherwise, create the DisableFileSyncNGSC key and update the value.
#>

$regkey_9404 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive"
$name_9404 = "DisableFileSyncNGSC"
$rvalue_9404 = "1"
$type_9404 = "DWord"
$path_9404 = Test-path $regkey_9404
 if($path_9404){
	$exist_9404=(Get-Item $regkey_9404).Property -contains $name_9404
	If($exist_9404){
		Set-ItemProperty -Path $regkey_9404 -Name $name_9404 -Value $rvalue_9404
		Write-Output "$name_9404 key is set to $rvalue_9404 for CID: 9404"
		}
	if(!$exist_9404){
		New-ItemProperty -Path $regkey_9404 -Name $name_9404 -PropertyType $type_9404 -Value $rvalue_9404 | Out-Null
		Write-Output "$name_9404 key is created and set to $rvalue_9404 for CID: 9404"
		}
  }
 else{
 New-item -Path $regkey_9404 -Force | Out-Null
  New-ItemProperty -Path $regkey_9404 -Name $name_9404 -PropertyType $type_9404 -Value $rvalue_9404 | Out-Null
  Write-Output "Created $regkey_9404  and $name_9404 key and set to $rvalue_9404 for CID: 9404"
 }

#----------------------- EOS CID 9404 -----------------------#

<# 
-CID: 9424
STMT: Status of 'Turn off the offer to update to the latest version of Windows' setting
If the DisableOSUpgrade key exists, set the value to 1 (Enabled); otherwise, create the DisableOSUpgrade key and update the value.
Impact: The Microsoft Store application will not offer updates to the latest version of Windows.
#>

$regkey_9424 = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$name_9424 = "DisableOSUpgrade"
$rvalue_9424 = "1"
$type_9424 = "DWord"
$path_9424 = Test-path $regkey_9424
 if($path_9424){
	$exist_9424=(Get-Item $regkey_9424).Property -contains $name_9424
	If($exist_9424){
		Set-ItemProperty -Path $regkey_9424 -Name $name_9424 -Value $rvalue_9424
		Write-Output "$name_9424 key is set to $rvalue_9424 for CID: 9424"
		}
	if(!$exist_9424){
		New-ItemProperty -Path $regkey_9424 -Name $name_9424 -PropertyType $type_9424 -Value $rvalue_9424 | Out-Null
		Write-Output "$name_9424 key is created and set to $rvalue_9424 for CID: 9424"
		}
  }
 else{
 New-item -Path $regkey_9424 -Force | Out-Null
  New-ItemProperty -Path $regkey_9424 -Name $name_9424 -PropertyType $type_9424 -Value $rvalue_9424 | Out-Null
  Write-Output "Created $regkey_9424  and $name_9424 key and set to $rvalue_9424 for CID: 9424"
 }

#----------------------- EOS CID 9424 -----------------------#

<# 
-CID: 9453
STMT: Status of 'Scan removable drives (Windows Defender)' setting
If the DisableRemovableDriveScanning key exists, set the value to 0 (Enabled); otherwise, create the DisableRemovableDriveScanning key and update the value.
Impact: Removable drives will be scanned during any type of scan by Windows Defender Antivirus.
#>

$regkey_9453 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
$name_9453 = "DisableRemovableDriveScanning"
$rvalue_9453 = "0"
$type_9453 = "DWord"
$path_9453 = Test-path $regkey_9453
 if($path_9453){
	$exist_9453=(Get-Item $regkey_9453).Property -contains $name_9453
	If($exist_9453){
		Set-ItemProperty -Path $regkey_9453 -Name $name_9453 -Value $rvalue_9453
		Write-Output "$name_9453 key is set to $rvalue_9453 for CID: 9453"
		}
	if(!$exist_9453){
		New-ItemProperty -Path $regkey_9453 -Name $name_9453 -PropertyType $type_9453 -Value $rvalue_9453 | Out-Null
		Write-Output "$name_9453 key is created and set to $rvalue_9453 for CID: 9453"
		}
  }
 else{
 New-item -Path $regkey_9453 -Force | Out-Null
  New-ItemProperty -Path $regkey_9453 -Name $name_9453 -PropertyType $type_9453 -Value $rvalue_9453 | Out-Null
  Write-Output "Created $regkey_9453  and $name_9453 key and set to $rvalue_9453 for CID: 9453"
 }

#----------------------- EOS CID 9453 -----------------------#

<# 
-CID: 9469
STMT: Status of the 'Configure Watson events' setting
If the DisableGenericRePorts key exists, set the value to 1 (Disabled); otherwise, create the DisableGenericRePorts key and update the value.
Impact: Only client computers that support Network Level Authentication can connect to the RD Session Host server.
#>

$regkey_9469 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting"
$name_9469 = "DisableGenericRePorts"
$rvalue_9469 = "1"
$type_9469 = "DWord"
$path_9469 = Test-path $regkey_9469
 if($path_9469){
	$exist_9469=(Get-Item $regkey_9469).Property -contains $name_9469
	If($exist_9469){
		Set-ItemProperty -Path $regkey_9469 -Name $name_9469 -Value $rvalue_9469
		Write-Output "$name_9469 key is set to $rvalue_9469 for CID: 9469"
		}
	if(!$exist_9469){
		New-ItemProperty -Path $regkey_9469 -Name $name_9469 -PropertyType $type_9469 -Value $rvalue_9469 | Out-Null
		Write-Output "$name_9469 key is created and set to $rvalue_9469 for CID: 9469"
		}
  }
 else{
 New-item -Path $regkey_9469 -Force | Out-Null
  New-ItemProperty -Path $regkey_9469 -Name $name_9469 -PropertyType $type_9469 -Value $rvalue_9469 | Out-Null
  Write-Output "Created $regkey_9469  and $name_9469 key and set to $rvalue_9469 for CID: 9469"
 }

#----------------------- EOS CID 9469 -----------------------#

<# 
-CID: 9537
STMT: Status of 'Windows Defender - Turn on e-mail scanning' setting
If the DisableEmailScanning key exists, set the value to 0 (Enabled); otherwise, create the DisableEmailScanning key and update the value.
Impact: E-mail scanning by Windows Defender Antivirus will be enabled.
#>

$regkey_9537 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Scan"
$name_9537 = "DisableEmailScanning"
$rvalue_9537 = "0"
$type_9537 = "DWord"
$path_9537 = Test-path $regkey_9537
 if($path_9537){
	$exist_9537=(Get-Item $regkey_9537).Property -contains $name_9537
	If($exist_9537){
		Set-ItemProperty -Path $regkey_9537 -Name $name_9537 -Value $rvalue_9537
		Write-Output "$name_9537 key is set to $rvalue_9537 for CID: 9537"
		}
	if(!$exist_9537){
		New-ItemProperty -Path $regkey_9537 -Name $name_9537 -PropertyType $type_9537 -Value $rvalue_9537 | Out-Null
		Write-Output "$name_9537 key is created and set to $rvalue_9537 for CID: 9537"
		}
  }
 else{
 New-item -Path $regkey_9537 -Force | Out-Null
  New-ItemProperty -Path $regkey_9537 -Name $name_9537 -PropertyType $type_9537 -Value $rvalue_9537 | Out-Null
  Write-Output "Created $regkey_9537  and $name_9537 key and set to $rvalue_9537 for CID: 9537"
 }

#----------------------- EOS CID 9537 -----------------------#

<# 
-CID: 13943
STMT: Status of 'Allow Cloud Search' group policy
If the AllowCloudSearch key exists, set the value to 0 (Disable Cloud Search); otherwise, create the AllowCloudSearch key and update the value.
Impact: Search and Cortana will not be permitted to search cloud sources like OneDrive and SharePoint.
#>

$regkey_13943 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
$name_13943 = "AllowCloudSearch"
$rvalue_13943 = "0"
$type_13943 = "DWord"
$path_13943 = Test-path $regkey_13943
 if($path_13943){
	$exist_13943=(Get-Item $regkey_13943).Property -contains $name_13943
	If($exist_13943){
		Set-ItemProperty -Path $regkey_13943 -Name $name_13943 -Value $rvalue_13943
		Write-Output "$name_13943 key is set to $rvalue_13943 for CID: 13943"
		}
	if(!$exist_13943){
		New-ItemProperty -Path $regkey_13943 -Name $name_13943 -PropertyType $type_13943 -Value $rvalue_13943 | Out-Null
		Write-Output "$name_13943 key is created and set to $rvalue_13943 for CID: 13943"
		}
  }
 else{
 New-item -Path $regkey_13943 -Force | Out-Null
  New-ItemProperty -Path $regkey_13943 -Name $name_13943 -PropertyType $type_13943 -Value $rvalue_13943 | Out-Null
  Write-Output "Created $regkey_13943  and $name_13943 key and set to $rvalue_13943 for CID: 13943"
 }

#----------------------- EOS CID 13943 -----------------------#
