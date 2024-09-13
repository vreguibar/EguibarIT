function Get-AdObjectType {
    <#
    .SYNOPSIS
        This function retrieves the type of an Active Directory object based on the provided identity.

    .DESCRIPTION
        The Get-AdObjectType function determines the type of an Active Directory object based on the given identity.
        It supports various object types, including AD users, computers, and groups. The function provides verbose output.

    .PARAMETER Identity
        Specifies the identity of the Active Directory object. This parameter is mandatory.

        Possible values are:
          ADAccount object
          ADComputer object
          ADGroup object
          ADOrganizationalUnit object
          String representing DistinguishedName
          String representing SID
          String representing samAccountName


    .EXAMPLE
        Get-AdObjectType -Identity "davader"
        Retrieves the type of the Active Directory object with the SamAccountName "davader".

    .EXAMPLE
        Get-AdObjectType -Identity "CN=davade,OU=Users,OU=BAAD,OU=Sites,DC=EguibarIT,DC=local"
        Retrieves the type of the Active Directory object with the
        DistinguishedName "CN=davade,OU=Users,OU=BAAD,OU=Sites,DC=EguibarIT,DC=local".

    .EXAMPLE
        Get-AdObjectType -Identity "S-1-5-21-3484526001-1877030748-1169500100-1646"
        Retrieves the type of the Active Directory object with the
        SID "S-1-5-21-3484526001-1877030748-1169500100-1646".

    .EXAMPLE
        Get-AdObjectType -Identity "35b764b7-06df-4509-a54f-8fd4c26a0805"
        Retrieves the type of the Active Directory object with the GUID
        "35b764b7-06df-4509-a54f-8fd4c26a0805".

    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADAccount or
        Microsoft.ActiveDirectory.Management.ADComputer or
        Microsoft.ActiveDirectory.Management.AdGroup

    .NOTES
        Version:         1.2
            DateModified:    31/May/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    # return type will be different on each case.

    Param (
        # Param1
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity of the object',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('ID', 'SamAccountName', 'DistinguishedName', 'DN', 'SID')]
        $Identity
    )

    Begin {
        $txt = ($Variables.HeaderHousekeeping -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition

        $ReturnValue = $null
        $newObject = $null

    } # End Begin Section

    Process {

        try {
            # Known Identities OR AD Objects
            if ($Identity -is [Microsoft.ActiveDirectory.Management.ADAccount] -or
                $Identity -is [Microsoft.ActiveDirectory.Management.ADComputer] -or
                $Identity -is [Microsoft.ActiveDirectory.Management.ADGroup] -or
                $Identity -is [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit] -or
                $Identity -is [Microsoft.ActiveDirectory.Management.ADServiceAccount]) {

                Write-Verbose -Message (' ┝━━━━━━► Known AD Object Type: {0}' -f $Identity.GetType().Name)
                $ReturnValue = $Identity

            } elseif ($Identity -is [string]) {

                Write-Verbose -Message ('Identity is a string: {0}. Trying to resolve it!' -f $Identity)

                if (Test-IsValidDN -ObjectDN $Identity) {

                    Write-Verbose -Message 'Looking for DistinguishedName'
                    $newObject = Get-ADObject -Filter { DistinguishedName -like $Identity }

                } elseif (Test-IsValidSID -ObjectSID $Identity) {

                    Write-Verbose -Message 'Looking for ObjectSID'
                    $newObject = Get-ADObject -Filter { ObjectSID -like $Identity }

                } elseif (Test-IsValidGUID -ObjectGUID $Identity) {

                    Write-Verbose -Message 'Looking for ObjectGUID'
                    $newObject = Get-ADObject -Filter { ObjectGUID -like $Identity }

                } else {

                    Write-Verbose -Message 'Looking for SamAccountName'
                    $newObject = Get-ADObject -Filter { (Name -like $identity) -or (SamAccountName -like $identity) }
                } #end If-ElseIf-Else
            } else {
                throw "Unsupported Identity type: $($Identity.GetType().Name)"
                return $null
            } #end If-ElseIf-Else




            If ($newObject -and (-not $ReturnValue)) {
                # once we have the object, lets get it from AD
                Switch ($newObject.ObjectClass) {

                    'user' {
                        Write-Verbose -Message '#     ┝━━━━━━━━━━►  AD User Object from STRING'
                        [Microsoft.ActiveDirectory.Management.ADAccount]$ReturnValue = Get-ADUser -Identity $newObject
                    }

                    'group' {
                        Write-Verbose -Message '#     ┝━━━━━━━━━━►  AD Group Object from STRING'
                        [Microsoft.ActiveDirectory.Management.AdGroup]$ReturnValue = Get-ADGroup -Identity $newObject
                    }

                    'computer' {
                        Write-Verbose -Message '#     ┝━━━━━━━━━━►  AD Computer Object from STRING'
                        [Microsoft.ActiveDirectory.Management.ADComputer]$ReturnValue = Get-ADComputer -Identity $newObject
                    }

                    'organizationalUnit' {
                        Write-Verbose -Message '#     ┝━━━━━━━━━━►  AD Organizational Unit Object from STRING'
                        [Microsoft.ActiveDirectory.Management.organizationalUnit]$ReturnValue = Get-ADOrganizationalUnit -Identity $newObject
                    }

                    'msDS-GroupManagedServiceAccount' {
                        Write-Verbose -Message '#     ┝━━━━━━━━━━►  AD Group Managed Service Account from STRING'
                        [Microsoft.ActiveDirectory.Management.ADServiceAccount]$ReturnValue = Get-ADServiceAccount -Identity $newObject
                    }

                    Default {
                        Write-Error -Message ('#     ┝━━━━━━━━━━►  Unknown object type for identity: {0}' -f $Identity)

                        return $null
                    }
                } # End Switch

            } #end If
        } catch {
            Write-Error -Message ('An error occurred: {0}' -f $_)
            $ReturnValue = $null
        }


    } # End Process Section

    End {
        $txt = ($Variables.FooterHousekeeping -f $MyInvocation.InvocationName,
            'getting AD object type (Private Function).'
        )
        Write-Verbose -Message $txt

        if ($null -ne $ReturnValue) {
            Write-Output $ReturnValue
        } #end If
    } # End End Section

} #end Function
