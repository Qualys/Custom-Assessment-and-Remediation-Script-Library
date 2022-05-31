#Initial flag
$isapache=0
$isVulnSpring = 0
$iswar = 0
$isfluxORmvc = 0
$isJDK = 0

$java=[Environment]::GetEnvironmentVariable('JAVA_HOME', [EnvironmentVariableTarget]::Machine)
$jar="$java/bin/jar.exe"

# Check if apache is present on the system
$data = Get-WmiObject -Query "select CommandLine from Win32_Process where CommandLine like '%apache%'" | Format-List -Property Commandline | Out-String
$data = [string]::join("",($data.Split("`n")))-replace '\s+', ''
$data -split 'Commandline:' | ForEach-Object {
    if ($_ -match "webapps"){
        $path = $_.split("'")[1]
        $isapache = 1     
    }
}

#Find WAR file
#Check for vulnerable version Spring Framework
#Check for webflux or webmvc
$WAR = Get-ChildItem -Path $path -Filter *.war -Recurse -ErrorAction SilentlyContinue -Force | % { $_.FullName } 
ForEach ($i in $war) {
    &$jar -tf $i  | ForEach-Object {
        if ($_ -match "spring\-(beans\-|core|webflux|webmvc).*.jar"){
            "$i`n$_"
            $iswar = 1
            if ($_ -match "spring\-(webflux|webmvc).*.jar"){
            $isfluxORmvc = 1
            }
            if (!($_ -match "5.(?:3|2).(?:1|2)(?:[8:9]|[0-9])")){
            $isVulnSpring = 1
            }
        }
    }
}
#Check for JDK Version
"`n"
Get-WmiObject -Class Win32_Product -Filter "Name like 'Java(TM)%'" | Select -Expand Version | ForEach-Object {
    Write-Host JDK Version : $_
    $ver=$_ -split '\.'
    $ver=[int]$ver[0]
    if ( $ver -gt 8 )
    {$isJDK = 1}
}
"`n"

#Check if all condition for Spring4Shell vulnerability present on the target or not
$isvulnerable = $isapache+$isVulnSpring+$iswar+$isfluxORmvc+$isJDK
if ( $isvulnerable -eq 5 ){
    "Spring4Shell vulnerability present on the target (CVE-2022-22965: Found)"
}
else {
    "Spring4Shell vulnerability not found"
}