Function Get-CAAutomationCertificate {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $False)]
    [string]$CALocation = ".\$((Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration' -Name Active).Active)",
    
    [Parameter(Mandatory = $False)]
    [Parameter(Mandatory = $True, ParameterSetName = 'CertificateTemplate')]
    [Parameter(Mandatory = $True, ParameterSetName = 'RequestID+CertificateTemplate')]
    [string]$CertificateTemplate = '',
    
    [Parameter(Mandatory = $True, ParameterSetName = 'RequestID')]
    [Parameter(Mandatory = $True, ParameterSetName = 'RequestID+CertificateTemplate')]
    [string]$RequestID = $Null,

    [string[]]$Properties = @('Request ID','Certificate Template','Request Disposition','Issued Common Name')

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
    $CAView.SetResultColumnCount($Properties.Count)
    $Properties|ForEach {$CAView.SetResultColumn($ColumnIndex[$_])}

    Switch ($PSCmdlet.ParameterSetName){
      'RequestID' {$CAView.SetRestriction(($ColumnIndex['Request ID']),1,0,[int]($RequestID)) }
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
      While ($RowColumn.Next() -ne -1){
        Add-Member -InputObject $Certificate -MemberType NoteProperty -Name $($RowColumn.GetDisplayName()) -Value $($RowColumn.GetValue(1)) -Force
      }
      Add-Member -InputObject $Certificate -MemberType MemberSet -Name PSStandardMembers $PSStandardMembers
      $ReturnObject += $Certificate
    }

    return $ReturnObject
  }
}