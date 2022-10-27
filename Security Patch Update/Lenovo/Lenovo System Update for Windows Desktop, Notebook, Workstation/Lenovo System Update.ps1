function System_update{
    # Download Lenovo System Update Exe
    Invoke-WebRequest -Uri "https://download.lenovo.com/pccbbs/thinkvantage_en/system_update_5.07.0139.exe" -UseBasicParsing -OutFile $env:TEMP\system_update_5.07.0139.exe
    # Start install process
    Start-Process -Wait -FilePath $env:TEMP\system_update_5.07.0139.exe "/verysilent" , "/norestart"
    # Clean temp file
    Remove-Item -Path $env:TEMP\system_update_5.07.0139.exe -Force    
}
 
function Critical_Recommended_Update {
    # Pushing Critical and Recommended updates
    reg add "HKLM\Software\Policies\Lenovo\System Update\UserSettings\General" /v AdminCommandLine /t REG_SZ /d '/CM -search R -action INSTALL -includerebootpackages 1,3,4,5 -noicon -nolicense' /f | Out-Null
    cmd.exe /c "C:\Program Files (x86)\Lenovo\System Update\Tvsu.exe" /CM
    Write-Host "Critical and Recommended updates have been pushed. Press 'OK' if you get 'Lenovo System Update' alert on the host. This might trigger restart" 
}

# Check for Vulnerable BIOS version
$BIOS_Ver = Get-WmiObject -Class Win32_BIOS | Select-Object SMBIOSBIOSVersion | Format-List | Out-String -Stream
if ($BIOS_Ver -match "6VCN43WW|BQCN33WW|BRCN19WW|BSCN36WW|CHCN27WW|CJCN37WW|DJCN27WW|DWCN23WW|ECCN39WW|EPCN27WW|F9CN48WW|FDCN39WW|FXCN35WW|H0CN21WW|HR6N0661|M00KT67A|M05KT93A|M0HKT51A|M11KT54A|M11KT55A|M16KT68A|M16KT69A|M17KT49A|M17KT50A|M18KT36A|M18KT37A|M1AKT56A|M1BKT54A|M1BKT55A|M1CKT49A|M1CKT50A|M1EKT25A|M1EKT27A|M1LKT29A|M1MKT51A|M1NKT58A|M1NKT59A|M1QKT47A|M1QKT49A|M1RKT38A|M1RKT39A|M1UKT67A|M1UKT6BA|M1VKT67A|M1VKT6BA|M1WKT45A|M1WKT46A|M1XKT57A|M1YKT70A|M1YKT72A|M1ZKT38A|M1ZKT39A|M20KT52A|M20KT53A|M22KT47A|M22KT48A|M23KT29A|M25KT61A|M26KT22A|M26KT24A|M28KT37A|M28KT39A|M29KT39A|M29KT40A|M2CKT4DA|M2FKT2DA|M2FKT2EA|M2PKT38A|M2RKT52A|M2RKT55A|M2SKT25A|M2SKT26A|M2TKT50A|M2VKT1DA|M2VKT1FA|M2WKT55A|M2WKT57A|M2XKT20A|M2YKT31A|M2YKT33A|M30KT26A|M30KT27A|M33KT25A|M33KT26A|M36KT28A|M36KT31A|M37KT28A|M37KT29A|M3AKT44A|M3AKT48A|M3BKT29A|M3BKT2AA|M3BKT2DA|M3CKT32A|M3EKT17A|M3FKT29A|M3GKT33A|M3GKT38A|M3JKT34A|M3JKT35A|M3KKT34A|M3KKT36A|M3LKT26A|M3NKT20A|M3NKT21A|M3SKT21A|M3XKT21A|M40KT2DA|M41KT2DA|M42KT40A|M43KT16A|M46KT2BA|M46KT2DA|M46KT2EA|M49KT1DA|M4CKT14A|M4GKT1DA|M4IKT17A|N2CET61W|N2EET56W|N2HET66W|N2IET98W|N2JET97W|N2LET88W|N2MET54W|N2NET49W|N2OET54W|N2QET44W|N2TET71W|N2TET72W|N2UET58W|N2VET34W|N2WET32W|N2XET33W|N2YET34W|N30ET43W|N34ET46W|N35ET43W|N39ET50W|O3NKT32A|O3ZKT41A|O43KT43A|O44KT32A|O46KT36A|O48KT32A|O49KT38A|O4BKT20A|O4BKT21A|O4CKT23A|O4DKT43A|O4DKT44A|O4EKT17A|O4EKT18A|O4FKT29A|O4FKT33A|O4GKT16A|O4GKT17A|O4HKT38A|O4HKT3AA|O4JKT23A|O4KKT16A|O4LKT1EA|O4LKT1FA|O4MKT27A|O4NKT1BA|O4PKT15A|O4RKT29A|O4SKT26A|O4SKT28A|O4TKT29A|O51KT12A|O52KT23A|O54KT1DA|O54KT20A|O55KT14A|O56KT23A|O59KT16A|O5AKT31A|O5BKT24A|O5CKT24A|O5EKT21A|O5FKT14A|O5NKT30A|R0YET48W|R0ZET50W|R10ET51W|R15ET51W|R16ET33W|R17ET33W|R1EET45W|R1GET43W|R1JET53W|S03KT55A|S03KT56A|S04KT62A|S04KT62P|S05KT62A|S05KT62P|S06KT59A|S06KT61A|S07KT25A|S07KT4AA|S08KT50A|S0AKT34A|S0AKT35A|SOAKT35A|VB3TS891|YANGTIAN")
{
    Write-Host "Vulnerable BIOS version present"
    ## Check for Lenovo System Update (File Detection Method)
    If([String](Get-Item -Path "$Env:ProgramFiles\Lenovo\System Update\tvsu.exe","${Env:ProgramFiles(x86)}\Lenovo\System Update\tvsu.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersionRaw -ge "5.7.0.139"){
        Write-Host "Latest system-update ver. 5.7.0.139 or greater is already installed"
        # Pushing Critical and Recommended updates
        Critical_Recommended_Update
    }
    else{
        Write-Host "Installing Latest system-update Ver. 5.7.0.139 or greater"
        System_update
        If([String](Get-Item -Path "$Env:ProgramFiles\Lenovo\System Update\tvsu.exe","${Env:ProgramFiles(x86)}\Lenovo\System Update\tvsu.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersionRaw -ge "5.7.0.139"){
            Write-Host "Latest system-update 5.7.0.139 ver. 5.7.0.139 or greater is installed"
            # Pushing Critical and Recommended updates
            Critical_Recommended_Update
        }
        else {
            Write-Host "Unable to install Lenovo system-update"
        }
    }
}
else {
    Write-Host "Vulnerable BIOS version not present"
}