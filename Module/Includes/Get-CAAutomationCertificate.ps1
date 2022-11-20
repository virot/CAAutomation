Function Get-CAAutomationCertificate {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $False)]
    [ValidatePattern('.*\\.*')]
    [string]$CALocation = ".\$((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name Active).Active)",
    
    [Parameter(Mandatory = $False)]
    [string]$CertificateTemplate = '',
    
    [Parameter(Mandatory = $False)]
    [string]$RequestID = $Null,

    [Parameter(Mandatory = $False)]
    [ValidateSet('Request_Processed','Request_Under_submission','Certificate_Issued')]
    [string]$Disposition = $Null,

    [Parameter(Mandatory = $False)]
    [string[]]$Properties = @('Request ID','Request Disposition')

  )
  Begin {
    #ZZZ To be replaced with ADSI query to speed up, or atleast be moved to module level to save AD queries
    $CertificateTemplates = @{}
    Get-ADObject -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -filter {objectclass -eq "pKICertificateTemplate"} -Properties "DisplayName", "msPKI-Cert-Template-OID" | ForEach{$CertificateTemplates.Add($_.'msPKI-Cert-Template-OID',$_.'DisplayName');$CertificateTemplates.Add($_.'DisplayName',$_.'msPKI-Cert-Template-OID') }
    $ColumnNames = @'
Archived Key
Attestation Challenge
Binary Certificate
Binary Public Key
Binary Request
Caller Name
Certificate Effective Date
Certificate Expiration Date
Certificate Hash
Certificate Template
Effective Revocation Date
Endorsement Certificate Hash
Endorsement Key Hash
Issued Binary Name
Issued City
Issued Common Name
Issued Country/Region
Issued Device Serial Number
Issued Distinguished Name
Issued Domain Component
Issued Email address
Issued First Name
Issued Initials
Issued Last Name
Issued Organization Unit
Issued Organization
Issued Request ID
Issued State
Issued Street Address
Issued Subject Key Identifier
Issued Title
Issued Unstructured Address
Issued Unstructured Name
Issuer Name ID
Key Recovery Agent Hashes
Officer
Old Certificate
Public Key Algorithm Parameters
Public Key Algorithm
Public Key Length
Publish Expired Certificate in CRL
Request Attributes
Request Binary Name
Request City
Request Common Name
Request Country/Region
Request Device Serial Number
Request Disposition Message
Request Disposition
Request Distinguished Name
Request Domain Component
Request Email Address
Request First Name
Request Flags
Request ID
Request Initials
Request Last Name
Request Organization Unit
Request Organization
Request Resolution Date
Request State
Request Status Code
Request Street Address
Request Submission Date
Request Title
Request Type
Request Unstructured Address
Request Unstructured Name
Requester Name
Revocation Date
Revocation Reason
Serial Number
Signer Application Policies
Signer Policies
Template Enrollment Flags
Template General Flags
User Principal Name
'@ -split [System.Environment]::NewLine

  }
  Process {
    Try {
      $CAView = New-Object -Com CertificateAuthority.View.1
      [void]$CaView.OpenConnection($CAlocation)
    }
    Catch [System.Runtime.InteropServices.COMException] {
      Throw "Failed to connect to Certificate Services"
    }
    Catch {
      Throw "Something went wrong"
    }
    # Hashtable to store Index number and which columns to retrive
    $ColumnIndex = @{}
    #@('Request ID', 'Request Disposition', 'Requester Name', 'Certificate Template', 'Binary Certificate', 'Binary Request')|ForEach {$ColumnIndex[$_] = $CaView.GetColumnIndex($false, $_)}
    $ColumnNames|ForEach {$ColumnIndex[$_] = $CaView.GetColumnIndex($false, $_)}
    #$CAView.SetResultColumnCount($ColumIndex.Count)
    #$ColumnIndex.Values|ForEach {$CAView.SetResultColumn($_)}
    if ($Properties.Contains('Certificate Template Name') -or $Properties.Contains('Certificate Template OID') -and -not $Properties.Contains('Certificate Template')) {
      $SearchProperties = $Properties + 'Certificate Template'
    } else {
      $SearchProperties = $Properties
    }
    $CAView.SetResultColumnCount($SearchProperties.Count)
    $SearchProperties|ForEach {$CAView.SetResultColumn($ColumnIndex[$_])}

    #Manage Restrictions..
    if ($PSBoundParameters.ContainsKey('RequestID')) {
      $CAView.SetRestriction(($ColumnIndex['Request ID']),1,0,[int]($RequestID))
    }
    if ($PSBoundParameters.ContainsKey('Disposition')) {
      switch ($Disposition) {
        'Request_Processed' {$CAView.SetRestriction(($ColumnIndex['Request Disposition']),1,0,[int](8))}
        'Request_Under_submission' {$CAView.SetRestriction(($ColumnIndex['Request Disposition']),1,0,[int](9))}
        'Certificate_Issued' {$CAView.SetRestriction(($ColumnIndex['Request Disposition']),1,0,[int](20))}
      }
    }
    if ($PSBoundParameters.ContainsKey('CertificateTemplate')) {
     if ($CertificateTemplate -match '^[0-9.]*$') {
        $CAView.SetRestriction(($ColumnIndex['Certificate Template']),1,0,[string]($CertificateTemplate))
      }  elseif ($CertificateTemplates.ContainsKey($CertificateTemplate)) {
        $CAView.SetRestriction(($ColumnIndex['Certificate Template']),1,0,[string]($CertificateTemplates[$CertificateTemplate]))
      }
    }

    #Do the search
    $CASearchRow= $CAView.OpenView()

    #$defaultDisplaySet = [System.Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet',[string[]]($Properties|Select -First 4))
    #$defaultDisplaySet = [System.Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet',[string[]]@('Request ID','Request Common Name'))
    $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet(‘DefaultDisplayPropertySet’,[string[]]($Properties|Select -First 4))
    $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

    $ReturnObject = @()

    While ($CASearchRow.Next() -ne -1) {
      $RowColumn = $CASearchRow.EnumCertViewColumn()
      $Certificate = [psobject]::new()
      While ($RowColumn.Next() -ne -1) {
        Add-Member -InputObject $Certificate -MemberType NoteProperty -Name $($RowColumn.GetDisplayName()) -Value $($RowColumn.GetValue(1)) -Force
      }
      if ($Properties.contains('Certificate Template Name'))
      {
        if ($Certificate.'Certificate Template' -ne $Null -and $Certificate.'Certificate Template' -match '^[0-9.]*$' -and $CertificateTemplates.Contains($Certificate.'Certificate Template')) {
          Add-Member -InputObject $Certificate -MemberType NoteProperty -Name 'Certificate Template Name' -Value $CertificateTemplates[$Certificate.'Certificate Template'] -Force
        } elseif ($Certificate.'Certificate Template' -ne $Null) {
          Add-Member -InputObject $Certificate -MemberType NoteProperty -Name 'Certificate Template Name' -Value $Certificate.'Certificate Template' -Force
        } else {
          Add-Member -InputObject $Certificate -MemberType NoteProperty -Name 'Certificate Template Name' -Value 'Unknown' -Force
        }
      }
      if ($Properties.contains('Certificate Template OID'))
      {
        if ($Certificate.'Certificate Template' -ne $Null -and $Certificate.'Certificate Template' -notmatch '^[0-9.]*$' -and $CertificateTemplates.Contains($Certificate.'Certificate Template')) {
          Add-Member -InputObject $Certificate -MemberType NoteProperty -Name 'Certificate Template OID' -Value $CertificateTemplates[$Certificate.'Certificate Template'] -Force
        } elseif ($Certificate.'Certificate Template' -ne $Null) {
          Add-Member -InputObject $Certificate -MemberType NoteProperty -Name 'Certificate Template OID' -Value $Certificate.'Certificate Template' -Force
        } else {
          Add-Member -InputObject $Certificate -MemberType NoteProperty -Name 'Certificate Template OID' -Value 'Unknown' -Force
        }
      }
      Add-Member -InputObject $Certificate -MemberType MemberSet -Name PSStandardMembers $PSStandardMembers
      $ReturnObject += $Certificate
    }
    return $ReturnObject
  }
}