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
    PS C:\> .\DigiCertUpdate_intermediate.ps1

.EXAMPLE
    PS C:\> .\DigiCertUpdate_intermediate.ps1 -CertPath "C:\DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt" 
    
#>

#Requires -Version 2.0

param(
    [parameter(Mandatory = $false, Position = 0)]
    [string]$CertPath
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
    else {
        Add-Certificate
    }
}
else {
    Write-Err "Please run the script as admin"
}
