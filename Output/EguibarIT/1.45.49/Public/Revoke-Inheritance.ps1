function Revoke-Inheritance
{
<#
    .Synopsis
    Function to remove NTFS inheritance of a folder
    .DESCRIPTION
    Function to remove NTFS inheritance of a folder
    .EXAMPLE
    Revoke-Inheritance path
    .INPUTS
    Param1 path = The path to the folder
    .NOTES
    Version:         1.0
    DateModified:    31/Mar/2015
    LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com
#>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
  [OutputType([String])]
  Param
  (
    # Param1 path to the resource|folder
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
        HelpMessage = 'Add help message for user',
    Position = 0)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]
    $path
  )
  Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

  }
  Process {
    Try {
      $isProtected = $true
      $preserveInheritance = $true
      $DirectorySecurity = Get-Acl -Path $path
      # SetAccessRuleProtection, which is a method to control whether inheritance from the parent folder should
      # be blocked ($True means no Inheritance) and if the previously inherited access rules should
      # be preserved ($False means remove previously inherited permissions).
      $DirectorySecurity.SetAccessRuleProtection($isProtected, $preserveInheritance)
      Set-Acl -Path $path -AclObject $DirectorySecurity
    }
    Catch { Throw }
  }
  End {
        Write-Verbose -Message ('The folder {0} was removed inheritance.' -f $path)
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
  }
}