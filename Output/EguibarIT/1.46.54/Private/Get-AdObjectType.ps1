function Get-AdObjectType
{
  [CmdletBinding(ConfirmImpact = 'Medium')]
  Param
  (
    # Param1
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 0)]
    [ValidateNotNullOrEmpty()]
    $Identity
  )
  Begin
  {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

        $ReturnValue = $null
  }
  Process
  {
    If($Identity -is [Microsoft.ActiveDirectory.Management.ADAccount])
    {
      Write-Verbose -Message 'AD User Object'
      return [Microsoft.ActiveDirectory.Management.ADAccount]$ReturnValue = $Identity
    }

    If($Identity -is [Microsoft.ActiveDirectory.Management.ADComputer])
    {
      Write-Verbose -Message 'AD Computer Object'
      return [Microsoft.ActiveDirectory.Management.ADComputer]$ReturnValue = $Identity
    }

    If($Identity -is [Microsoft.ActiveDirectory.Management.AdGroup])
    {
      Write-Verbose -Message 'AD Group Object'
      return [Microsoft.ActiveDirectory.Management.AdGroup]$ReturnValue = $Identity
    }

    If($Identity -is [String])
    {
      Write-Verbose -Message 'Simple String'
      $newObject = get-AdObject -filter {
        SamAccountName -eq $Identity
      }
      Switch ($newObject.ObjectClass)
      {
        'user'
        {
          Write-Verbose -Message 'AD User Object from STRING'
          return [Microsoft.ActiveDirectory.Management.ADAccount]$ReturnValue = Get-AdUser -Identity $Identity
        }
        'group'
        {
          Write-Verbose -Message 'AD Group Object from STRING'
          return [Microsoft.ActiveDirectory.Management.AdGroup]$ReturnValue   = Get-ADGroup -Identity $Identity
        }
        'computer'
        {
          Write-Verbose -Message 'AD Computer Object from STRING'
          return [Microsoft.ActiveDirectory.Management.AdGroup]$ReturnValue   = Get-AdComputer -Identity $Identity
        }
      }
    }
  }
  End {
      Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting AD object type."
      Write-Verbose -Message ''
      Write-Verbose -Message '-------------------------------------------------------------------------------'
      Write-Verbose -Message ''
  }
}