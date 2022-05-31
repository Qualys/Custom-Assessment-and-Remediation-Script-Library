$ProgressPreference = "SilentlyContinue";
$ErrorActionPreference= "SilentlyContinue";
    
    reg query HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery\ | % { if($_ -match "REG_BINARY") {$t=$_ -split "REG_BINARY"
                                                        $t1=$t[0].Trim()
                                                        
                                                        #$t1

                                                        $p2='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery\'

                                                        #$k = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU\'
                                                        #$hex = [System.BitConverter]::ToString($k.$t1)
                                                        #$hex

                                                        $hexstring=(Get-ItemProperty $p2 | Select -ExpandProperty $t1) -join ','
                                                        $convert=($hexstring.Split(",",[System.StringSplitOptions]::RemoveEmptyEntries) | ?{$_ -gt '0'} | ForEach{[char][int]"$($_)"}) -join ''
                                                            #$convert
                                                       
                                                        $pattern = '[^a-zA-Z.0-9 ]'
                                                        #$p3 = '\b[A-Za-z0-9_ ]+\.(pdf|7z|csv|db|docx|iso|jpg|json|one|pdf|png|ps1|rar|sh|TXT|vhd|xlsx|xml|zip).$'
                                                        $con=$convert -replace $pattern, ' '
                                                        $con
                                                        #$t=$con -match $p3
                                                        #$matches[0]
                                                            }}