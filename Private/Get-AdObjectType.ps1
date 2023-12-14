function Get-AdObjectType {
  <#
    .SYNOPSIS
        This function retrieves the type of an Active Directory object based on the provided identity.

    .DESCRIPTION
        The Get-AdObjectType function determines the type of an Active Directory object based on the given identity.
        It supports various object types, including AD users, computers, and groups. The function provides verbose output
        and implements the -WhatIf parameter to simulate actions.

    .PARAMETER Identity
        Specifies the identity of the Active Directory object. This parameter is mandatory.

    .EXAMPLE
        Get-AdObjectType -Identity "davader"
        Retrieves the type of the Active Directory object with the SamAccountName "davader".

    .INPUTS
        String: Accepts a string representing the identity of the Active Directory object.

    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADAccount or
        Microsoft.ActiveDirectory.Management.ADComputer or
        Microsoft.ActiveDirectory.Management.AdGroup

    .NOTES
        Version:         1.0
            DateModified:    08/Oct/2021
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
  [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Medium')]

  Param (
    # Param1
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
      HelpMessage = 'Identity of the object',
      Position = 0)]
    [ValidateNotNullOrEmpty()]
    [Alias('ID', 'SamAccountName', 'DistinguishedName', 'DN', 'SID')]
    $Identity
  )

  Begin {
    Write-Verbose -Message '|=> ************************************************************************ <=|'
    Write-Verbose -Message (Get-Date).ToShortDateString()
    Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
    Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

    if (-not (Get-Module -Name 'ActiveDirectory' -ListAvailable)) {
      Import-Module -Name 'ActiveDirectory' -Force -Verbose:$false
    } #end If

    ##############################
    # Variables Definition

    $ReturnValue = $null

  } # End Begin Section

  Process {
    Try {
      If ($Identity -is [Microsoft.ActiveDirectory.Management.ADAccount]) {
        Write-Verbose -Message 'AD User Object'
        return [Microsoft.ActiveDirectory.Management.ADAccount]$ReturnValue = $Identity
      }

      If ($Identity -is [Microsoft.ActiveDirectory.Management.ADComputer]) {
        Write-Verbose -Message 'AD Computer Object'
        return [Microsoft.ActiveDirectory.Management.ADComputer]$ReturnValue = $Identity
      }

      If ($Identity -is [Microsoft.ActiveDirectory.Management.AdGroup]) {
        Write-Verbose -Message 'AD Group Object'
        return [Microsoft.ActiveDirectory.Management.AdGroup]$ReturnValue = $Identity
      }

      If ($Identity -is [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]) {
        Write-Verbose -Message 'Organizational Unit Object'
        return [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]$ReturnValue = $Identity
      }

      If ($Identity -is [String]) {
        Write-Verbose -Message 'Simple String... Try to identify if SamAccountNamem DistinguishedName or SID as string.'

        if (Test-IsValidDN -ObjectDN $Identity) {

          Write-Verbose -Message 'Looking for DistinguishedName'
          $newObject = Get-ADObject -filter { DistinguishedName -eq $Identity }

        }
        elseif (Test-IsValidSID -ObjectSID $Identity) {

          Write-Verbose -Message 'Looking for ObjectSID'
          $newObject = Get-ADObject -filter { ObjectSID -eq $Identity }

        }
        else {

          Write-Verbose -Message 'Looking for SamAccountName'
          $newObject = Get-ADObject -filter { SamAccountName -eq $Identity }

        } # End if

        # once we have the object, lets get it from AD
        Switch ($newObject.ObjectClass) {

          'user' {
            Write-Verbose -Message 'AD User Object from STRING'
            return [Microsoft.ActiveDirectory.Management.ADAccount]$ReturnValue = Get-AdUser -Identity $Identity
          }

          'group' {
            Write-Verbose -Message 'AD Group Object from STRING'
            return [Microsoft.ActiveDirectory.Management.AdGroup]$ReturnValue = Get-ADGroup -Identity $Identity
          }

          'computer' {
            Write-Verbose -Message 'AD Computer Object from STRING'
            return [Microsoft.ActiveDirectory.Management.ADComputer]$ReturnValue = Get-AdComputer -Identity $Identity
          }

          'organizationalUnit' {
            Write-Verbose -Message 'AD Organizational Unit Object from STRING'
            return [Microsoft.ActiveDirectory.Management.organizationalUnit]$ReturnValue = Get-ADOrganizationalUnit -Identity $Identity
          }

          Default {
            Write-Error -Message "Unknown object type for identity: $Identity"
          }
        } # End Switch
      } # End If
    }
    catch {
      Write-Error -Message "Error: $_"
    }
  } # End Process Section

  End {
    Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting AD object type."
    Write-Verbose -Message ''
    Write-Verbose -Message '-------------------------------------------------------------------------------'
    Write-Verbose -Message ''
  } # End End Section

} #end Function
