class YubikeyAttestation
{
  [ValidateNotNullOrEmpty()][string]$Version
  [ValidateNotNullOrEmpty()][string]$Serial
  [ValidateNotNullOrEmpty()][string]$Slot
  [ValidateNotNullOrEmpty()][String]$Touchpolicy
  [ValidateNotNullOrEmpty()][String]$PINpolicy
  [ValidateNotNullOrEmpty()][String]$Formfactor
  [ValidateNotNullOrEmpty()][bool]$AttestationCorrect
  hidden [bool]$AttestationChain
  hidden [bool]$AttestationKeySame
  hidden [System.Security.Cryptography.X509Certificates.X509Certificate2] $AttestationCertificate
  hidden [System.Security.Cryptography.X509Certificates.X509Certificate2] $IntermediateCertificate
  hidden [System.Security.Cryptography.X509Certificates.CertificateRequest] $CertificateRequest
  hidden [System.Security.Cryptography.X509Certificates.X509Certificate2] $YubicoPIVAttestationCA
 

  YubikeyAttestation(
    [String] $CertificateSigningRequest
  ) {
    $this.CreateYubicoPIVAttestationCA()
    $this.CertificateRequest = [System.Security.Cryptography.X509Certificates.CertificateRequest]::LoadSigningRequestPEM("-----BEGIN CERTIFICATE REQUEST-----$($CertificateSigningRequest)-----END CERTIFICATE REQUEST-----",'SHA-1',[System.Security.Cryptography.X509Certificates.CertificateRequestLoadOptions]::UnsafeLoadCertificateExtensions)
    ForEach ($Extension in $this.CertificateRequest.CertificateExtensions){
      Switch ($Extension.OID.Value){
        '1.3.6.1.4.1.41482.3.2' {
          $this.IntermediateCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Extension.RawData)
        }
        '1.3.6.1.4.1.41482.3.11' {
          $this.AttestationCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Extension.RawData)
        }
      }
    }
    if ($this.IntermediateCertificate -ne $Null -and $this.AttestationCertificate -ne $Null) {
      $this.ValidateAttestation()
      $this.GetExtensions()
    }
  } # END Constructor

  [void]hidden CreateYubicoPIVAttestationCA(
  ) {
    $YubicoPIVAttestationCAPEM = @'
MIIDFzCCAf+gAwIBAgIDBAZHMA0GCSqGSIb3DQEBCwUAMCsxKTAnBgNVBAMMIFl1
YmljbyBQSVYgUm9vdCBDQSBTZXJpYWwgMjYzNzUxMCAXDTE2MDMxNDAwMDAwMFoY
DzIwNTIwNDE3MDAwMDAwWjArMSkwJwYDVQQDDCBZdWJpY28gUElWIFJvb3QgQ0Eg
U2VyaWFsIDI2Mzc1MTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMN2
cMTNR6YCdcTFRxuPy31PabRn5m6pJ+nSE0HRWpoaM8fc8wHC+Tmb98jmNvhWNE2E
ilU85uYKfEFP9d6Q2GmytqBnxZsAa3KqZiCCx2LwQ4iYEOb1llgotVr/whEpdVOq
joU0P5e1j1y7OfwOvky/+AXIN/9Xp0VFlYRk2tQ9GcdYKDmqU+db9iKwpAzid4oH
BVLIhmD3pvkWaRA2H3DA9t7H/HNq5v3OiO1jyLZeKqZoMbPObrxqDg+9fOdShzgf
wCqgT3XVmTeiwvBSTctyi9mHQfYd2DwkaqxRnLbNVyK9zl+DzjSGp9IhVPiVtGet
X02dxhQnGS7K6BO0Qe8CAwEAAaNCMEAwHQYDVR0OBBYEFMpfyvLEojGc6SJf8ez0
1d8Cv4O/MA8GA1UdEwQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3
DQEBCwUAA4IBAQBc7Ih8Bc1fkC+FyN1fhjWioBCMr3vjneh7MLbA6kSoyWF70N3s
XhbXvT4eRh0hvxqvMZNjPU/VlRn6gLVtoEikDLrYFXN6Hh6Wmyy1GTnspnOvMvz2
lLKuym9KYdYLDgnj3BeAvzIhVzzYSeU77/Cupofj093OuAswW0jYvXsGTyix6B3d
bW5yWvyS9zNXaqGaUmP3U9/b6DlHdDogMLu3VLpBB9bm5bjaKWWJYgWltCVgUbFq
Fqyi4+JE014cSgR57Jcu3dZiehB6UtAPgad9L5cNvua/IWRmm+ANy3O2LH++Pyl8
SREzU8onbBsjMg9QDiSf5oJLKvd/Ren+zGY7
'@
    $this.YubicoPIVAttestationCA = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Convert]::FromBase64String($YubicoPIVAttestationCAPEM))
  }

  [void]hidden GetExtensions(
  ){
    ForEach ($Extension in $this.AttestationCertificate.Extensions) {
      switch ($Extension.Oid.Value) {
        '1.3.6.1.4.1.41482.3.3' {
          $this.Version = [string]::Format("{0}.{1}.{2} ", $Extension.RawData[0], $Extension.RawData[1], $Extension.RawData[2])
         } # 1.3.6.1.4.1.41482.3.3: Firmware version, encoded as 3 bytes, like: 040300 for 4.3.0
        '1.3.6.1.4.1.41482.3.7' {
          $tmpversion = $Extension.RawData[2..5]
          [array]::Reverse($tmpversion)
          $this.Serial = [System.BitConverter]::ToUInt32($tmpversion, 0)
        } # 1.3.6.1.4.1.41482.3.7: Serial number of the YubiKey, encoded as an integer.
        '1.3.6.1.4.1.41482.3.8' {
          $this.PINpolicy = @{1='Never';2='Once';3='Always'}[[int]$Extension.RawData[0]] ?? 'Something failed'
          $this.Touchpolicy = @{1='Never';2='Always';3='Cached'}[[int]$Extension.RawData[1]] ?? 'Something failed'
        } # 1.3.6.1.4.1.41482.3.8: Two bytes, the first encoding pin policy and the second touch policy  
        '1.3.6.1.4.1.41482.3.9' {
          $this.formfactor = @{1='USB-A Keychain';2='USB-A Nano';3='USB-C Keychain';4='USB-C Nano';5='Lightning and USB-C';81='USB-A Keychain (FIPS)';82='USB-A Nano (FIPS)';83='USB-C Keychain (FIPS)';84='USB-C Nano (FIPS)';85='Lightning and USB-C (FIPS)'}[[int]$Extension.RawData[0]] ?? 'Something failed'
        } #END # 1.3.6.1.4.1.41482.3.9 Formfactor, encoded as one byte
      } 
    } # END ForEach
    $this.slot = $this.attestationcertificate.subject -replace '.*([0-9a-z]{2})$','$1' ?? 'Something failed'
  }

  [void]hidden ValidateAttestation(
  ){
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
    $chain.ChainPolicy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
    
    [void]$chain.ChainPolicy.CustomTrustStore.add($this.YubicoPIVAttestationCA)
    [void]$chain.ChainPolicy.ExtraStore.Add($this.IntermediateCertificate)
    

    # Disabled revocation check 
    $chain.ChainPolicy.RevocationFlag = "EntireChain"
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        
    # Validate the chain 
    $isValid = $chain.Build($this.AttestationCertificate)
    $this.AttestationChain = $isValid

    if ([System.BitConverter]::ToString($this.AttestationCertificate.PublicKey.EncodedKeyValue.RawData) -eq [System.BitConverter]::ToString($this.CertificateRequest.PublicKey.EncodedKeyValue.RawData)) {
      $this.AttestationKeySame = $true
    } else {
      $this.AttestationKeySame = $false
    }

    if ($this.AttestationChain -and $this.AttestationKeySame) {
      $this.AttestationCorrect = $True
    } else {
      $this.AttestationCorrect = $False
    }#END Check Pubkey between Certificate Request and Attestation Request AND that the chain is correct
  }

}