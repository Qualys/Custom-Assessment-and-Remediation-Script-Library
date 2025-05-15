function Get-UEFIDatabaseSigner {
<# Integrated code from Matthew Graeber (@mattifestation) under the BSD 3-Clause License #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateScript({ ($_.GetType().Fullname -eq 'Microsoft.SecureBoot.Commands.UEFIEnvironmentVariable') -and (($_.Name -eq 'kek') -or ($_.Name -eq 'pk') -or ($_.Name -eq 'db') -or ($_.Name -eq 'dbx')) })]
        $Variable
    )
    $SignatureTypeMapping = @{
        'C1C41626-504C-4092-ACA9-41F936934328' = 'EFI_CERT_SHA256_GUID' # Most often used for dbx
        'A5C059A1-94E4-4AA7-87B5-AB155C2BF072' = 'EFI_CERT_X509_GUID'   # Most often used for db
    }
    try {
        $MemoryStream = New-Object -TypeName IO.MemoryStream -ArgumentList @(,$Variable.Bytes)
        $BinaryReader = New-Object -TypeName IO.BinaryReader -ArgumentList $MemoryStream, ([Text.Encoding]::Unicode)
    } catch {
        throw $_
        return
    }
    # What follows will be an array of EFI_SIGNATURE_LIST structs
    while ($BinaryReader.PeekChar() -ne -1) {
        $SignatureType = $SignatureTypeMapping[([Guid][Byte[]] $BinaryReader.ReadBytes(16)).Guid]
        $SignatureListSize = $BinaryReader.ReadUInt32()
        $SignatureHeaderSize = $BinaryReader.ReadUInt32()
        $SignatureSize = $BinaryReader.ReadUInt32()
        $SignatureHeader = $BinaryReader.ReadBytes($SignatureHeaderSize)
        # 0x1C is the size of the EFI_SIGNATURE_LIST header
        $SignatureCount = ($SignatureListSize - 0x1C) / $SignatureSize
        $Signature = 1..$SignatureCount | ForEach-Object {
            $SignatureDataBytes = $BinaryReader.ReadBytes($SignatureSize)
            $SignatureOwner = [Guid][Byte[]] $SignatureDataBytes[0..15]
            switch ($SignatureType) {
                'EFI_CERT_SHA256_GUID' {
                    $SignatureData = ([Byte[]] $SignatureDataBytes[0x10..0x2F] | ForEach-Object { $_.ToString('X2') }) -join ''
                }
                'EFI_CERT_X509_GUID' {
                    $SignatureData = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,([Byte[]] $SignatureDataBytes[16..($SignatureDataBytes.Count - 1)]))
                }
            }
            [PSCustomObject] @{
                PSTypeName = 'EFI.SignatureData'
                SignatureOwner = $SignatureOwner
                SignatureData = $SignatureData
            }
        }
        [PSCustomObject] @{
            PSTypeName = 'EFI.SignatureList'
            SignatureType = $SignatureType
            Signature = $Signature
        }
    }
}
(Get-SecureBootUEFI -Name PK | Get-UEFIDatabaseSigner).Signature | Where-Object { $_.SignatureData -match "DO NOT TRUST|DO NOT SHIP" } | Measure-Object | ForEach-Object { $._Count -gt 0 }
