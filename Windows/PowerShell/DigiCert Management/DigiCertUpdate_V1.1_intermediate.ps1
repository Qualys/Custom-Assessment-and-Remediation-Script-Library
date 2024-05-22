<#
.NOTES
    DigiCertUpdate_intermediate.ps1
    Copyright (c) 2023 Qualys Inc
    All rights reserved.

.SYNOPSIS
    Updates the DigiCert intermediate 'DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1' Trusted Root Certification Authorities if it is not present.

.DESCRIPTION
    The script will check for the availability of the intermediate 'DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1'in the Trusted Root Certification Authorities first.
    If it is not available, Script will try to fetch it from the digicert website and update to the store. If this step also fails, It will ask
    the customer to provide a local path to the certificate that is already downloaded.

.PARAMETER CertPath
    Path to the cetificate file

.EXAMPLE
    PS C:\> .\DigiCertUpdate_V1.3_intermediate.ps1

.EXAMPLE
    PS C:\> .\DigiCertUpdate_V1.3_intermediate.ps1 -CertPath "C:\DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt" 

.EXAMPLE
  PS C:\> .\DigiCertUpdate_V1.3_intermediate.ps1 -InstallLocalCert                                                                                                                                                                                                                                                                                              
    
#>

#Requires -Version 2.0

param(
    [parameter(Mandatory = $false, Position = 0)]
    [string]$CertPath,

    [parameter(Mandatory = $false, Position = 0)]
    [switch]$InstallLocalCert

)

[string]$CertThumbprint = "7b0f360b775f76c94a12ca48445aa2d2a875701c"
[string]$CertURL = "https://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt"

function Write-Log {
    param(
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        [parameter(Mandatory = $true, Position = 1)]
        [ValidateSet("WARNING", "ERROR", "INFO")]
        [string]$Severity
    )

    [string]$LogMessage = [System.String]::Format("[$(Get-Date)][$Severity] -"), $Message

    switch ($Severity) {
        { $_ -match 'WARNING' } { Write-Host $LogMessage -ForegroundColor Yellow -BackgroundColor Black; Break }
        { $_ -match 'ERROR' } { Write-Host $LogMessage -ForegroundColor Red -BackgroundColor Black; Break }
        { $_ -match 'INFO' } { Write-Host $LogMessage -ForegroundColor Green -BackgroundColor Black; Break }
        default { Write-Host $LogMessage }
    }
}

function Write-Info {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    
    Write-Log -Message $Message -Severity "Info"
}

function Write-Warn {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    
    Write-Log -Message $Message -Severity "Warning"
}

function Write-Err {
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    
    Write-Log -Message $Message -Severity "Error"
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Find-Cert {
    Write-Info "Checking if the certificate is already present in the certificate store.."

    try {
        $ReturnHash = Get-ChildItem "cert:\" -Recurse | Where-Object { $_.Thumbprint -eq $CertThumbprint } | Select-Object -first 1 Thumbprint -ExpandProperty Thumbprint
        return $ReturnHash -eq $CertThumbprint 
    }
    catch {
        Write-Err $_.Exception.Message
        return $false
    }
}

function Add-CertificateFromFilePath {
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string] $FilePath
    )

    $Status = $false

    Write-Info "Importing the certficate from the path: $FilePath"

    try {
        if ((Test-Path -Path $FilePath -PathType leaf) -eq $false) {
            Write-Err "Inavlid file path. File does not exist"
            return $Status
        } 

        if ($PSVersionTable.PSVersion.Major -gt 2) {
            $Status = Import-Certificate -FilePath $FilePath -CertStoreLocation cert:\LocalMachine\CA
        }
        else {
            $ImportCertCommand = "certutil -addstore -f CA '$FilePath'"
            $Status = Invoke-Expression -Command $ImportCertCommand
        }

        if ($Status -eq $false) {
            Write-Err "Unable to import certificate to the root store"
            return $Status
        }

        Write-Info "Successfully imported the certificate to the root store"
    }
    catch {
        Write-Err $_.Exception.Message
    }

    return $Status
}

function Add-CertificateFromContent{
    # Certificate data
$certificateText = @"
-----BEGIN CERTIFICATE-----
MIIGsDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0BAQwFADBi
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3Qg
RzQwHhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYDVQQGEwJV
UzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRy
dXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExMIIC
IjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5WRuxiEL1
M4zrPYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJPDqFX/IiZ
wZHMgQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXzENOLsvsI
8IrgnQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bqHPNlaJGi
TUyCEUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTCfMjqGzLm
ysL0p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaDG7dqZy3S
vUQakhCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urOkfW+0/tv
k2E0XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7ADK5GyNnm+
960IHnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4R+Z1MI3s
MJN2FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlNWdt4z4FK
PkBHX8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0IU0F8WD1H
s/q27IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYBAf8CAQAw
HQYDVR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaAFOzX44LS
cV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEF
BQcDAzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRp
Z2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQu
Y29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYy
aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5j
cmwwHAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcNAQEMBQAD
ggIBADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcTEp6QRJ9L
/Z6jfCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WTauPrINHV
UHmImoqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9ntSZz0rd
KOtfJqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np375SFTWsPK
6Wrxoj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0HKKlS43N
b3Y3LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL6TEa/y4Z
XDlx4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+16oh7cGvm
oLr9Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8M4+uKIw8
y4+ICw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrFhsP2JjMM
B0ug0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy1lKQ/a+F
SCH5Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhO
-----END CERTIFICATE-----
"@
    $Status = $false 

    try {
        $certificateFilePath = "certificate.cer"
        $certificateText | Out-File -FilePath $certificateFilePath -Encoding ASCII

        $Status = certutil -addstore CA $certificateFilePath 
        if ($Status -eq $false) 
        {
            Write-Err "Unable to import certificate to the CA store"
            return $Status
        }

        Write-Info "Successfully imported the certificate to the CA store"

        Write-Info "Cleaning up temporary files"
        Remove-Item $certificateFilePath

        if ($? -eq $false) 
        {
            Write-Warn "Unable to delete the temporary files" 
        }
    }
    catch {
        Write-Err $_.Exception.Message
    }

}

function Add-CertificateFromURL {
    Write-Info "Trying to download the certificate from the digicert website"
    $Status = $false

    try {
        $CertTempPath = $pwd.Path + "\DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt"

        (New-Object Net.WebClient).DownloadFile($CertURL, $CertTempPath) 

        if ($? -eq $false) {
            Write-Err "Unable to download the certificate from the URL" 
            return $Status 
        }

        Write-Info "Downloaded the certificate successfully"
        Write-Info "Trying to import the certificate to the certificate store"

        $Status = Add-CertificateFromFilePath $CertTempPath

        Write-Info "Cleaning up temporary files"

        Remove-Item $CertTempPath

        if ($? -eq $false) { 
            Write-Warn "Unable to delete the temporary files" 
        }
    }
    catch {
        Write-Err $_.Exception.Message
    }

    return $Status
}

function Add-Certificate {
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string]$CertFilePath
    )

    try {
        if (Find-Cert -eq $true) {
            Write-Info "Certificate is already present at the root"
            return $true
        }

        Write-Info "Certificate is not present at the root"

        if ($PSBoundParameters.ContainsKey('CertFilePath') -eq $true) {
            Write-Info "Using the explicitly specified file path: $CertFilePath"
            return $(Add-CertificateFromFilePath -FilePath $CertFilePath)
        }

        if ((Add-CertificateFromURL) -eq $false) {
            Write-Info "Unable to add the certificate to the root store. Please try to download the certificate manually and use the -CertPath option"
            return $false 
        }
    }
    catch {
        Write-Err $_.Exception.Message
    }

    return $true
}

if (Test-IsAdmin -eq $true) {
    if ($PSBoundParameters.ContainsKey("CertPath")) {
        Add-Certificate -CertFilePath $CertPath
    }
    elseif($InstallLocalCert)
    {
         Add-CertificateFromContent
    }
    else {
        Add-Certificate
    }
}
else {
    Write-Err "Please run the script as admin"
}
# SIG # Begin signature block
# MIISUAYJKoZIhvcNAQcCoIISQTCCEj0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAw/M3KVMvgygGg
# X3COYOAZqlTZ1rQrJE6lOxEBoYtYvKCCDncwggawMIIEmKADAgECAhAIrUCyYNKc
# TJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBaFw0z
# NjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc9es0
# JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyAVxJr
# Q5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQIXhF
# LqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/sk+F
# LEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na59zHh
# 3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pgVItJ
# wZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7BzzosmJQay
# g9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQokbI
# YViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jLchAp
# QfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHMIRro
# OBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQABo4IB
# WTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8Rhvv+
# YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeBDAED
# MAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bgAhql
# +Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7FoFF
# UP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZGM1h
# mYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG3Ryw
# YFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5Ubdld
# AhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WIIIJw
# 8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956rEnP
# LqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuWTatE
# QOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3E+bn
# KD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60bhQji
# WQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOImYIbq
# yK+p/pQd52MbOoZWeE4wgge/MIIFp6ADAgECAhAGVNV2ZgQ6MNKaPn5DQGfBMA0G
# CSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcg
# UlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjMwNTIyMDAwMDAwWhcNMjQwNTIx
# MjM1OTU5WjCBxzETMBEGCysGAQQBgjc8AgEDEwJVUzEZMBcGCysGAQQBgjc8AgEC
# EwhEZWxhd2FyZTEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEDAOBgNV
# BAUTBzMxNTIxNDAxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRQw
# EgYDVQQHEwtGb3N0ZXIgQ2l0eTEVMBMGA1UEChMMUXVhbHlzLCBJbmMuMRUwEwYD
# VQQDEwxRdWFseXMsIEluYy4wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC
# AQDLuBWWd15EOihgVyTRl6MlTPk4OaITHvakMy6wfKYpgXShJSozDGcmA4Ud0Hgh
# KgcJ3OLUZt0pUO5tZ6qCheSqaumIzTbxSPHF1qDvy+wfYgRExx8TbH5AajClnYlB
# tHcAF2dtg8TIuT3yLvPu9aq+8QGBQoiTft0fXwQMgAYUsbf0MqbLvt7VTLo092i9
# HPUAKHvjwIfweLtVNO9jiUFKh1TK/cIqahaWXAWTbR96AwHCMt/nhmcgQQTAbUru
# fT4pKCHMqZGhEsDcm8mnd22pZNlbWwtJfqc1zbDCKrcbiUFaNmjbEB9tJ46TN7e0
# U1Rm4lHaDZaxO16rc1/gSVzKqCmrJLeA9MG3xF8VQNvlCeRArA/FnUNDzvvjGJLD
# G+hcKkZZXilgkFPXL3UFflFBVDWr3mRS/8mf0NnnQF7tqGGAEhTD7NkE3qVzKU3N
# xbjInDYdI9hc4l3TYPZ4wMfpTaB3GJMD1VYhsmcZUwhADFTQ+BEEyh60xyqUfVhk
# +9enlRmm2M4DeDSbF3AaIBL7aH+ePI6YCd0fRqVQiRaWbHIbWf12Y3jzNxEXogQV
# Vsz+tuYvvHSyVsONMgkp5ZoD1w/lKF/uhZLiCSawYxDb8D2/WmNfg8Xgjy/t0EDU
# QTzYNF2jvRPoQjLXDua6jD0xZ7dyYirXF2Fvobn5LN521wIDAQABo4ICAjCCAf4w
# HwYDVR0jBBgwFoAUaDfg67Y7+F8Rhvv+YXsIiGX0TkIwHQYDVR0OBBYEFGvEoJOJ
# /0hG/3zbnkR3g/BsFaMaMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF
# BQcDAzCBtQYDVR0fBIGtMIGqMFOgUaBPhk1odHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIx
# Q0ExLmNybDBToFGgT4ZNaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0MDk2U0hBMzg0MjAyMUNBMS5jcmwwPQYD
# VR0gBDYwNDAyBgVngQwBAzApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2lj
# ZXJ0LmNvbS9DUFMwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhhodHRw
# Oi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNlcnRz
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5
# NlNIQTM4NDIwMjFDQTEuY3J0MAkGA1UdEwQCMAAwDQYJKoZIhvcNAQELBQADggIB
# AI9B8qK1USig+E+GK9dmT+2cDYkdF/Ca0CR/6ThXVRQXlz0WN1UxNlwhTpm/A+FO
# w8LyTregCw3h43Ha2pmni69e1lqe+yz42B6c7/xkCmGKJwGj9Nl8dlDxt0RwZqjI
# lmBCY7CUAkLZve2FUN1nGtOzsurUUuziMKdSOO2QYwtO2kUIceCl8ygzPr2AJr70
# pW2Y+9jft7H84lKLyRyRAldJXmhNY6rp6mY60RDwoyHU1z85Ii4JX2bnWD9Jad/p
# XPVgE45gQ5ED7wgumde72I3xnCRdyuO0XsItsBpai1nAdSuqe7QBosZOxyhvWJW2
# JJg27vUz+tXcyKzO4rTSFRdjG7vce4t0skb/qGVoZGQUuIdUaa23oTGOOD0Q47Mj
# vDg/gTzZb3YoEjlq8Z3qkAs94eLO/XEs27Cafa54XbtlvYwqSKmxXtdL1tjtmQTr
# cW+RRXplq6hQCHwnCobSP7VfEgipqgrQmxOnrPs/H2VasCKutLF7aV2haK3QBYsF
# GLFyv8k5jtx1cM4Hd3i11qB5o1ee12OP9i/XwibPWzskazgy5cJAJkDDam5KCn+B
# zEZm83hRfK2fWeF1SDUz9ixG4NZ2e8bhWvV4oeRXX+Bx9GogeDVEXteOgPfykPYy
# dgZMzbO76bgOy4CWSz0EHlXmr4hCd8SZs+9/ju201WPQMYIDLzCCAysCAQEwfTBp
# MQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMT
# OERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0
# IDIwMjEgQ0ExAhAGVNV2ZgQ6MNKaPn5DQGfBMA0GCWCGSAFlAwQCAQUAoIGEMBgG
# CisGAQQBgjcCAQwxCjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcC
# AQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIE
# IDbLmaoU0T7pUD9JTXnrn7cEduYMyVU28qDbPm3NjYE4MA0GCSqGSIb3DQEBAQUA
# BIICAI+bFsphg2MoZFrTPM4gGh+8YdWYlyYK5pbQlZW5BMy8HQKXFjDMcE5zweer
# fM7tJUKn05GLDlBgLlMajTHgXF6BVdqEIaHvzB+wZYUTWOUlycOCc58LzmcElHUa
# w/s2bTe+kkFPzovaJkc8/fvXRTJK/EweJAwepx20ksaGbHAkTr6s0w3N+QcDGHYs
# 3uj5L0XhugLlNKq9pfLN+hvJEsg6HcoC/skQgaIQfZU1M7qcS95j3eYfrZw1hnEU
# vTLjSmEgO6X4k0gSeIGeUVNIMF0s6k5MbcGH2CdklINeOJc3/cwoUqDlFhB2suGl
# Jm5iy4aOe3l571iclFFWMh5VBKctv9crhqd2H6cK0JvzDAo6rPy13gSoAg3PxZGd
# QJJgwtlhLA/4z0Xwd5uEBRDXNnj0ASm8xTaegjMTWuF7TKX9mX0P7AlB0HagaPoH
# tWkkvJtx4nlMhCR7Wy22RTMj0TqeB5yB50Fz3xMguMd6+SJjswiQaLFWq8l8rgoZ
# x8L80zyvkLTV3YDKmyRZqZAd5hSyMv23pzMgB0pX5seVcOc6GNCF930+xHDaEen1
# skcMWs0akDXv2eQG7N7ULh2uksnmjcBtCoV95vLysKUvU5S51KpLaFgoUlAls3Xq
# 1yYZTpt5iLEPjyMrIH9FlQchwHsgdzHtj9+BWGSXuNmo+s6i
# SIG # End signature block

