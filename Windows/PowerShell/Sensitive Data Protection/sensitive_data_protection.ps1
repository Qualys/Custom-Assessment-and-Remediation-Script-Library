#Sensitive Data Protection
#The Files with Sensitive Data will be encrypt and attribute will be set to Read-only
#Edit startpath variable as directory path in which data is to be searched for all the files under that directory (Recursively) 
 
$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";
$users = Get-ChildItem c:\users | ?{ $_.PSIsContainer } #Enumerate All local users
foreach ($user in $users)
{
    $startpath = "C:\Users\$user\Documents\" 

    #Credit Card Number Regex 
    $CCNpattern = '\b(?:\d[ -]*?){13,16}\b' 

    #VISA Number Regex 
    $VISApattern = '\b4(?:\d[ -]*?){12,15}\b'

    # MASTERCARD Number Regex
    $MASTERpattern = '\b(?:5[1-5](?:\d[ -]*?){2}|222(?:[1-9][ -]*?)|22(?:[3-9][0-9][ -]*?)|2[3-6](?:[0-9][ -]*?){2}|27[01](?:[0-9][ -]*?)|2[ -]*?7[ -]*?2[ -]*?0[ -]*?)(?:\d[ -]*?){12}\b'

    # American Express Number Regex
    $AEpattern = '\b3[47](?:\d[ -]*?){13}\b'

    # Diners Club Number Regex
    $DCpattern = '\b3[ -]*?(?:0[ -]*?[0-5][ -]*?|[68][ -]*?[0-9][ -]*?)(?:\d[ -]*?){11}\b'

    # DISCOVER Number Regex
    $Dpattern = '\b3[ -]*?[47][ -]*?(?:\d[ -]*?){13}\b'

    # JCB CARD Number Regex
    $JCBpattern = '\b(?:2[ -]*?1[ -]*?3[ -]*?1[ -]*?|1[ -]*?8[ -]*?0[ -]*?0[ -]*?|3[ -]*?5[ -]*?(?:\d[ -]*?){3})(?:\d[ -]*?){11}\b'

    #Social Security Number Regex 
    $SSNpattern = '\b\d{3}([- ]?)\d{2}([- ]?)\d{4}\b' 

    #Birthdate Regex 
    $birth = '\b\d{2}(?:[ \/-])\d{2}(?:[ \/-])\d{4}\b' 
    
    #US Phone number regex 
    $usphone = '\b\+1\d{10}|\+1(?:[ -]*?)\d{3}(?:[ -]*?)\d{3}(?:[ -]*?)\d{4}\b' 

    #US address 
    $usaddress = '\b\d{1,8}\b[\s\S]{10,100}?\b(AK|AL|AR|AZ|CA|CO|CT|DC|DE|FL|GA|HI|IA|ID|IL|IN|KS|KY|LA|MA|MD|ME|MI|MN|MO|MS|MT|NC|ND|NE|NH|NJ|NM|NV|NY|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VA|VT|WA|WI|WV|WY)\b\s\d{5}\b' 
    
    #Email 
    $emailregex = '\b[a-z0-9._%\+\-]+@[a-z0-9.\-]+\.[a-z|]{2,6}\b'

    #Passport regex
    $PASSpattern = '\b[A-Za-z]{1}[0-9]{7}\b'

    #Script Start 
    gci -File $startpath -Recurse | ForEach-Object{$file = $_.FullName 
		
		#Case INDPASS
		$lnPASS = $(Select-String -Path $file -Pattern $PASSpattern | select -ExpandProperty LineNumber).count 
		if($lnPASS -ne 0)
		{
			# Get content of the file
			$FileContent = Get-Content $File
	
			#Get the bytes of the file content with encode
			$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
			# Base64 Encode file 
			$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
			# Save Base64 Encode file with extension .b64
			#$fileContentEncoded | Set-content ($file + ".b64")
			$fileContentEncoded | Set-content ($file)
			Get-Item -Path $file | % { $_.IsReadOnly=$True}
		}
	
		#Case CCN 
		$lnCCN = (Select-String -Path $file -Pattern $CCNpattern | select -ExpandProperty LineNumber).count 
		if($lnCCN -ne 0)
		{
			#echo "CCN|$file|$lnCCN`nCredit Card Vendors are"
	
			$VISA = (Select-String -Path $file -Pattern $VISApattern | select -ExpandProperty LineNumber).count
			if($VISA -ne 0)
			{
				# Get content of the file
				$FileContent = Get-Content $File
	
				#Get the bytes of the file content with encode
				$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
				# Base64 Encode file 
				$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
				# Save Base64 Encode file with extension .b64
				#$fileContentEncoded | Set-content ($file + ".b64")
				$fileContentEncoded | Set-content ($file)
				Get-Item -Path $file | % { $_.IsReadOnly=$True}
			}
	
			$MASTER = (Select-String -Path $file -Pattern $MASTERpattern | select -ExpandProperty LineNumber).count
			if($MASTER -ne 0)
			{
				# Get content of the file
				$FileContent = Get-Content $File
	
				#Get the bytes of the file content with encode
				$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
				# Base64 Encode file 
				$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
				# Save Base64 Encode file with extension .b64
				#$fileContentEncoded | Set-content ($file + ".b64")
				$fileContentEncoded | Set-content ($file)
				Get-Item -Path $file | % { $_.IsReadOnly=$True}
			}
	
			$AE = (Select-String -Path $file -Pattern $AEpattern | select -ExpandProperty LineNumber).count
			if($AE -ne 0)
			{
				# Get content of the file
				$FileContent = Get-Content $File
	
				#Get the bytes of the file content with encode
				$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
				# Base64 Encode file 
				$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
				# Save Base64 Encode file with extension .b64
				#$fileContentEncoded | Set-content ($file + ".b64")
				$fileContentEncoded | Set-content ($file)
				Get-Item -Path $file | % { $_.IsReadOnly=$True}
			}
	
			$Diners = (Select-String -Path $file -Pattern $DCpattern | select -ExpandProperty LineNumber).count
			if($Diners -ne 0)
			{
				# Get content of the file
				$FileContent = Get-Content $File
	
				#Get the bytes of the file content with encode
				$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
				# Base64 Encode file 
				$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
				# Save Base64 Encode file with extension .b64
				#$fileContentEncoded | Set-content ($file + ".b64")
				$fileContentEncoded | Set-content ($file)
				Get-Item -Path $file | % { $_.IsReadOnly=$True}
			}
	
			$Discover = (Select-String -Path $file -Pattern $Dpattern | select -ExpandProperty LineNumber).count
			if($Discover -ne 0)
			{
				# Get content of the file
				$FileContent = Get-Content $File
	
				#Get the bytes of the file content with encode
				$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
				# Base64 Encode file 
				$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
				# Save Base64 Encode file with extension .b64
				#$fileContentEncoded | Set-content ($file + ".b64")
				$fileContentEncoded | Set-content ($file)
				Get-Item -Path $file | % { $_.IsReadOnly=$True}
			}
	
			$JCB = (Select-String -Path $file -Pattern $JCBpattern | select -ExpandProperty LineNumber).count
			if($JCB -ne 0)
			{
				# Get content of the file
				$FileContent = Get-Content $File
	
				#Get the bytes of the file content with encode
				$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
				# Base64 Encode file 
				$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
				# Save Base64 Encode file with extension .b64
				#$fileContentEncoded | Set-content ($file + ".b64")
				$fileContentEncoded | Set-content ($file)
				Get-Item -Path $file | % { $_.IsReadOnly=$True}
			}
	
			$other = $lnCCN - ($VISA+$MASTER+$AE+$Diners+$Discover+$JCB)
			if($other -ne 0)
			{
				# Get content of the file
				$FileContent = Get-Content $File
	
				#Get the bytes of the file content with encode
				$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
				# Base64 Encode file 
				$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
				# Save Base64 Encode file with extension .b64
				#$fileContentEncoded | Set-content ($file + ".b64")
				$fileContentEncoded | Set-content ($file)
				Get-Item -Path $file | % { $_.IsReadOnly=$True}
			}
		} 
	
		#Case SSN 
		$lnSSN = $(Select-String -Path $file -Pattern $SSNpattern | select -ExpandProperty LineNumber).count 
		if($lnSSN -ne 0)
		{
			# Get content of the file
			$FileContent = Get-Content $File
	
			#Get the bytes of the file content with encode
			$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
			# Base64 Encode file 
			$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
			# Save Base64 Encode file with extension .b64
			#$fileContentEncoded | Set-content ($file + ".b64")
			$fileContentEncoded | Set-content ($file)
			Get-Item -Path $file | % { $_.IsReadOnly=$True}
		} 
		#Case Birth data 
		$birthdate = $(Select-String -Path $file -Pattern $birth | select -ExpandProperty LineNumber).count 
		if($birthdate -ne 0)
		{
			# Get content of the file
			$FileContent = Get-Content $File
	
			#Get the bytes of the file content with encode
			$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
			# Base64 Encode file 
			$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
			# Save Base64 Encode file with extension .b64
			#$fileContentEncoded | Set-content ($file + ".b64")
			$fileContentEncoded | Set-content ($file)
			Get-Item -Path $file | % { $_.IsReadOnly=$True}
		}
	
		#Case Email data 
		$email = $(Select-String -Path $file -Pattern $emailregex | select -ExpandProperty LineNumber).count 
		if($email -ne 0)
		{
			# Get content of the file
			$FileContent = Get-Content $File
	
			#Get the bytes of the file content with encode
			$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
			# Base64 Encode file 
			$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
			# Save Base64 Encode file with extension .b64
			#$fileContentEncoded | Set-content ($file + ".b64")
			$fileContentEncoded | Set-content ($file)
			Get-Item -Path $file | % { $_.IsReadOnly=$True}
		}
	
		#Case Address data 
		$address = $(Select-String -Path $file -Pattern $usaddress | select -ExpandProperty LineNumber).count 
		if($address -ne 0)
		{
			# Get content of the file
			$FileContent = Get-Content $File
	
			#Get the bytes of the file content with encode
			$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
			# Base64 Encode file 
			$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
			# Save Base64 Encode file with extension .b64
			#$fileContentEncoded | Set-content ($file + ".b64")
			$fileContentEncoded | Set-content ($file)
			Get-Item -Path $file | % { $_.IsReadOnly=$True}
		}
	
		#Case PhoneNumber 
		$phonenumber = $(Select-String -Path $file -Pattern $usphone | select -ExpandProperty LineNumber).count 
		if($phonenumber -ne 0)
		{
			# Get content of the file
			$FileContent = Get-Content $File
	
			#Get the bytes of the file content with encode
			$fileContentInBytes = [System.Text.Encoding]::UTF8.GetBytes($FileContent)
	
			# Base64 Encode file 
			$fileContentEncoded = [System.Convert]::ToBase64String($fileContentInBytes)
	
			# Save Base64 Encode file with extension .b64
			#$fileContentEncoded | Set-content ($file + ".b64")
			$fileContentEncoded | Set-content ($file)
			Get-Item -Path $file | % { $_.IsReadOnly=$True}
		}
    } 
}

"Files with Sensitive Data have been encrypted and attribute has been set to Read-only"