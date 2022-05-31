$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";

$users = Get-ChildItem c:\users | ?{ $_.PSIsContainer } #Enumerate All local users
foreach ($user in $users)
{
    Get-Shortcut "C:\Users\$user\AppData\Roaming\Microsoft\Windows\Recent"
    Get-Shortcut "C:\Users\$user\AppData\Roaming\Microsoft\Office\Recent"
}

function Get-Shortcut ($Shortcuts){
    $Shortcuts = Get-ChildItem -Recurse $Shortcuts -Include *.lnk
    $Shell = New-Object -ComObject WScript.Shell
    foreach ($Shortcut in $Shortcuts)
    {
        $Properties = @{
            ShortcutName = $Shortcut.Name;
            ShortcutPath = $Shortcut.FullName;
            TargetPath = $Shell.CreateShortcut($Shortcut).targetpath
            CreationTime = $Shortcut.CreationTime
            LastAccess = $Shortcut.LastAccessTime
            LastModified = $Shortcut.LastWriteTime
        }   
    New-Object PSObject -Property $Properties
    }
    [Runtime.InteropServices.Marshal]::ReleaseComObject($Shell) | Out-Null
}