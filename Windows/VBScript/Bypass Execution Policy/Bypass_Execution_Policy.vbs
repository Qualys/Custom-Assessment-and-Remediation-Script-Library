'Creating base64 file of a script
Set obj = CreateObject("Scripting.FileSystemObject")
Set obj1 = obj.OpenTextFile("C:\Windows\Temp\script.b64", 2, true)
'Add PowerShell script in Base64
obj1.WriteLine("ADD POWERSHELL SCRIPT IN BASE64 HERE")
obj1.Close
 
'Executing PowerShell script
Set objShell = CreateObject("WScript.Shell")
Set executor = objShell.Exec("powershell.exe -noexit -Command ""$data = Get-Content C:\Windows\Temp\script.b64;[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($data)) | Out-File -Encoding ascii C:\Windows\Temp\script.ps1;TYPE C:\Windows\Temp\script.ps1 |  PowerShell.exe -noprofile -""")
executor.StdIn.Close
WScript.StdOut.WriteLine executor.StdOut.ReadAll
Set objShell = Nothing
 
'Deleting temporary Files
Dim b64, scriptfile
b64 = "C:\Windows\Temp\script.b64"
scriptfile = "C:\Windows\Temp\script.ps1"
obj.DeleteFile b64
obj.DeleteFile scriptfile
Set obj = Nothing