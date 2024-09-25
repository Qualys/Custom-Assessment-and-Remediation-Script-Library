# Check if directory C:\Windows\Test exists, if present remove it and create new C:\Windows\Test else create C:\Windows\Test
if (Test-Path -Path "C:\Windows\Test") {
    Remove-Item -Path "C:\Windows\Test" -Recurse -Force
}
New-Item -Path "C:\Windows\Test" -ItemType Directory

# Function to perform various file operations
function Perform-FileOperations {
    param (
        [string]$fileName
    )

    $filePath = "C:\Windows\Test\$fileName"

    # Create a file
    New-Item -Path $filePath -ItemType File -Force

    # Add random data to the file
    $randomData = Get-Random -Minimum 1000 -Maximum 9999
    Add-Content -Path $filePath -Value "Random Data: $randomData"

    # Add attribute to file +r (Read-only)
    Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $true -ErrorAction SilentlyContinue

    # Remove attribute from file -r (Read-only)
    Set-ItemProperty -Path $filePath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue

    # Rename file add new at the starting
    $newFilePath = "C:\Windows\Test\new_$fileName"
    Rename-Item -Path $filePath -NewName "new_$fileName"

    # Remove new from starting
    Rename-Item -Path $newFilePath -NewName $fileName

    # Add permission to all (Full control)
    $acl = Get-Acl -Path $filePath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $filePath -AclObject $acl

    # Delete file
    Remove-Item -Path $filePath -Force
}

# File names for which function is called
$fileNames = @(
    "BASHLITE",
    "CryptoLocker",
    "EternalRocks",
    "MEMZ",
    "docu2.docx_rwuxrek",
    "pict32.jpg_rwuxrek"
)

# Call the function for each file name
foreach ($fileName in $fileNames) {
    Perform-FileOperations -fileName $fileName
}

# Directory operations on C:\Windows\Test
$directoryPath = "C:\Windows\Test"

if (Test-Path -Path $directoryPath) {
    
    # Add attribute Hidden
    Set-ItemProperty -Path $directoryPath -Name Attributes -Value ('Hidden') -ErrorAction SilentlyContinue
    
    # Remove attribute Hidden
    Set-ItemProperty -Path $directoryPath -Name Attributes -Value ('Normal') -ErrorAction SilentlyContinue

    # Add permission to all (Full control)
    $acl = Get-Acl -Path $directoryPath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $directoryPath -AclObject $acl

    # Rename directory from C:\Windows\Test to C:\Windows\NEW_Test
    $newDirectoryPath = "C:\Windows\NEW_Test"
    Rename-Item -Path $directoryPath -NewName "NEW_Test"

    # Rename directory from C:\Windows\NEW_Test to C:\Windows\Test
    Rename-Item -Path $newDirectoryPath -NewName "Test"

    # Delete C:\Windows\Test
    Remove-Item -Path $directoryPath -Recurse -Force
}

write-host ""
write-host "FIM events generated"