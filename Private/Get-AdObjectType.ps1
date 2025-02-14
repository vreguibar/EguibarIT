function Get-AdObjectType {
    <#
    .SYNOPSIS
        Retrieves the type of an Active Directory object based on the provided identity.

    .DESCRIPTION
         The Get-AdObjectType function determines the type of an Active Directory object based on the given identity.
        It supports various object types, including AD users, computers, groups, organizational units, and group managed service accounts.
        The function can handle different input formats such as AD objects, DistinguishedName, SamAccountName, SID, and GUID.
        It also includes support for Well-Known SIDs.

    .PARAMETER Identity
        Specifies the identity of the Active Directory object. This parameter is mandatory.

        Accepted values:
        - ADAccount object
        - ADComputer object
        - ADGroup object
        - ADOrganizationalUnit object
        - ADServiceAccount object
        - String representing DistinguishedName
        - String representing SID (including Well-Known SIDs)
        - String representing samAccountName (including Well-Known SID name)
        - String representing GUID


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
        Microsoft.ActiveDirectory.Management.ADGroup or
        Microsoft.ActiveDirectory.Management.ADOrganizationalUnit or
        Microsoft.ActiveDirectory.Management.ADServiceAccount

    .NOTES
        Version:         1.4
            DateModified:    14/Feb/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType(
        [Microsoft.ActiveDirectory.Management.ADAccount],
        [Microsoft.ActiveDirectory.Management.ADComputer],
        [Microsoft.ActiveDirectory.Management.ADGroup],
        [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit],
        [Microsoft.ActiveDirectory.Management.ADServiceAccount],
        [System.Security.Principal.SecurityIdentifier],
        [System.String])
    ]

    Param (
        # Param1
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Identity of the object',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('ID', 'SamAccountName', 'DistinguishedName', 'DN', 'SID', 'GUID')]
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
            # Check if identity is an AD object
            if ($Identity -is [Microsoft.ActiveDirectory.Management.ADObject]) {

                Write-Verbose -Message ('Identity is an AD object of type: {0}' -f $Identity.GetType().Name)
                $ReturnValue = $Identity
            } elseif ($Identity -is [string]) {
                # Check if identity is a string

                Write-Verbose -Message ('Identity is a string: {0}. Resolving it...' -f $Identity)

                # Check if it's a Well-Known SID (by SID or name)
                $wellKnownSid = $null

                if ($Variables.WellKnownSIDs.Keys -contains $Identity) {

                    # Input is a Well-Known SID (e.g., "S-1-1-0")
                    $wellKnownSid = $Identity

                } elseif ($Variables.WellKnownSIDs.Values -contains $Identity) {

                    # Input is a Well-Known SID name (e.g., "Everyone")
                    $wellKnownSid = $Variables.WellKnownSIDs.GetEnumerator() |
                        Where-Object { $_.Value -eq $Identity } |
                            Select-Object -ExpandProperty Key
                } #end If-elseif

                if ($wellKnownSid) {
                    Write-Verbose -Message ('
                        Identity {0} is a Well-Known SID: {1}' -f $Identity, $wellKnownSid)

                    try {
                        # Attempt to create a SecurityIdentifier object
                        $ReturnValue = [System.Security.Principal.SecurityIdentifier]::New($wellKnownSid)
                    } catch {
                        # Fallback to returning the SID as a string
                        $ReturnValue = $wellKnownSid
                    } #end try-catch
                } else {
                    # Resolve identity using AD queries

                    $newObject = Get-ADObject -Filter {
                        (DistinguishedName -eq $Identity) -or
                        (ObjectSID -eq $Identity) -or
                        (ObjectGUID -eq $Identity) -or
                        (SamAccountName -eq $Identity)
                    }

                    if ($newObject) {

                        switch ($newObject.ObjectClass) {
                            'user' {
                                $ReturnValue = Get-ADUser -Identity $newObject
                            }
                            'group' {
                                $ReturnValue = Get-ADGroup -Identity $newObject
                            }
                            'computer' {
                                $ReturnValue = Get-ADComputer -Identity $newObject
                            }
                            'organizationalUnit' {
                                $ReturnValue = Get-ADOrganizationalUnit -Identity $newObject
                            }
                            'msDS-GroupManagedServiceAccount' {
                                $ReturnValue = Get-ADServiceAccount -Identity $newObject
                            }
                            default {
                                Write-Error -Message ('Unsupported object type: {0}' -f $newObject.ObjectClass)
                                return $null
                            }
                        } #end switch

                    } else {

                        Write-Warning -Message ('
                            Identity {0} could not be resolved to a valid AD object.
                            ' -f $Identity
                        )
                        return $null

                    } #end if-else
                } #end if-else
            } else {
                # Unsupported identity type

                Write-Error -Message ('Unsupported identity type: {0}' -f $Identity.GetType().Name)
                return $null

            } #end if-elseif-else

        } catch {

            Write-Error -Message ('
                Failed to resolve identity: {0}.
                Error: {1}' -f
                $Identity, $_.Exception.Message
            )
            Write-Verbose -Message ('StackTrace: {0}' -f $_.Exception.StackTrace)
            return $null

        } #end try-catch

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
