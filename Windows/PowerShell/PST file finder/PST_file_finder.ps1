$path = C:\    ##To speed up the scan, enter the location here that you want to scan.

$files = Get-ChildItem $path -File -Recurse '*.pst' -ErrorAction Ignore | %{ $_.fullname}
$cn=0
foreach ($file in $files)
{
Get-Acl $file -ErrorAction Ignore
if($file -ne 0){$cn++}
}
if($cn -ne 0){"PST files found"}
else {
    "PST files not found"
}