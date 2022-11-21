  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $False)]
    [int]$RequestID
  )
  Process {
    $CertificateRequest = Get-CAAutomationCertificate -RequestID $RequestID -Properties 'Request ID','Binary Request','Requester Name'
    $YubikeyAttestation = [YubikeyAttestation]::new($CertificateRequest.'Binary Request')

    #Start with verifying that the request fullfils basic requirements

    if (-not ($YubikeyAttestation.Touchpolicy -in @('Always','Cached'))) {
      #Deny-CAAutomationRequest -RequestID $RequestID
      return 1
    }

    if (-not ($YubikeyAttestation.PINpolicy -in @('Always','Once'))) {
      #Deny-CAAutomationRequest -RequestID $RequestID
      return 1
    }

    if (-not ($YubikeyAttestation.version.major -ge 5 -or ($YubikeyAttestation.version.major -eq 4 -and $YubikeyAttestation.version.minor -gt 2))) {
      #Deny-CAAutomationRequest -RequestID $RequestID
      return 1
    }

    #Get the information for the User from AD
    $UserSID = [System.Security.Principal.NTAccount]::new($CertificateRequest.'Requester Name').Translate([System.Security.Principal.SecurityIdentifier])
    $SearchRoot = [System.DirectoryServices.DirectoryEntry]::new("LDAP://$([System.DirectoryServices.DirectoryEntry]::new('LDAP://RootDSE').rootDomainNamingContext)")
    $User = [System.DirectoryServices.DirectorySearcher]::new($SearchRoot, "(objectsid=$($UserSID.Value))", @('Pwdlastset','AltSecurityIdentities')).FindOne()
    
    if ($user.Properties['altsecurityidentities'] -eq $Null -or $user.Properties['altsecurityidentities'].count -eq 0) #If altsecurityidentities is empty, just allow
    {
      #Grant-CAAutomationRequest -RequestID $RequestID
      return 0
    } elseif ([datetime]::fromfiletime($user.Properties['pwdlastset'][0]) -gt [datetime]::Now.AddMinutes(-15)) { #If there are things in altsecurityidentities, only allow new pwd was just reset (15 min)
      #Grant-CAAutomationRequest -RequestID $RequestID
      return 0
    } else { #Time to check if the old altsecurityidentities was signed by the same yubikey
      Write-Debug 'Checking if old altsecurityidentities for same serial'
      $thumbrprintsInAD = $User.Properties['altsecurityidentities']|Where-Object {$_ -like 'X509:<SHA1-PUKEY>*'}|ForEach {$_ -replace 'X509:<SHA1-PUKEY>'}
      Write-Debug "Found $($thumbrprintsInAD.count) thumbprints in AD"
      $ApprovedSerials = ForEach ($thumb in $thumbrprintsInAD) {
        [YubikeyAttestation]::new((Get-CAAutomationCertificate -Thumbprint $thumb -Properties 'Request ID','Binary Request').'Binary Request')|Select-Object -ExpandProperty Serial
      }
      Write-Debug "Found $($ApprovedSerials.count) attestated serials in CA DB"
      if ($YubikeyAttestation.serial -in $ApprovedSerials) {
        #Grant-CAAutomationRequest -RequestID $RequestID
        return 0
      }
    }
    return 2
  }