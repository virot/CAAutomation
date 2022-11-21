Function Grant-CAAutomationRequest {
  [CmdletBinding()]
  Param (
    [Parameter(Mandatory = $True)]
    [string]$RequestID
  )

  Process {
    $output = & "$([System.Environment]::SystemDirectory)\certutil.exe" -resubmit $RequestID  2>&1 | Out-String
  }
}