function Get-AdObjectType {

    <#
        .SYNOPSIS
            Retrieves the type of an Active Directory object based on the provided identity.

        .DESCRIPTION
            The Get-AdObjectType function determines the type of an Active Directory object based on the given identity.
            It supports various object types, including AD users, computers, groups, organizational units, and
            group managed service accounts.
            The function can handle different input formats such as AD objects, DistinguishedName, SamAccountName, SID, and GUID.
            It also includes support for Well-Known SIDs.

            The function is optimized for large AD environments and supports batch processing via pipeline input.

        .PARAMETER Identity
            Specifies the identity of the Active Directory object. This parameter is mandatory.

            Accepted values:
            - ADAccount object
            - ADComputer object
            - ADGroup object
            - ADOrganizationalUnit object
            - ADServiceAccount object
            - Security Identifier
            - String representing DistinguishedName
            - String representing SID (including Well-Known SIDs)
            - String representing samAccountName (including Well-Known SID name)
            - String representing GUID

        .PARAMETER Server
            Specifies the Active Directory Domain Services instance to connect to.
            If not specified, the default domain controller for the current domain is used.

        .INPUTS
            System.String
            Microsoft.ActiveDirectory.Management.ADObject
            System.Security.Principal.SecurityIdentifier
            You can pipe an ADObject, string, or SecurityIdentifier to this function.

        .OUTPUTS
            Microsoft.ActiveDirectory.Management.ADAccount or
            Microsoft.ActiveDirectory.Management.ADComputer or
            Microsoft.ActiveDirectory.Management.ADGroup or
            Microsoft.ActiveDirectory.Management.ADOrganizationalUnit or
            Microsoft.ActiveDirectory.Management.ADServiceAccount or
            System.Security.Principal.SecurityIdentifier or
            System.String

            The function returns the appropriate AD object type based on the provided identity.

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

        .EXAMPLE
            Get-AdObjectType -Identity "S-1-1-0"

            Retrieves the Well-Known SID "Everyone" (S-1-1-0) as a SecurityIdentifier object.

        .EXAMPLE
            Get-AdObjectType -Identity "Everyone"

            Retrieves the Well-Known SID "Everyone" by name, returning the SecurityIdentifier object.

        .EXAMPLE
            Get-AdUser "testuser" | Get-AdObjectType

            Pipes an ADUser object to Get-AdObjectType, which returns the same object.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Output                               ║ Microsoft.PowerShell.Utility
                Get-ADObject                               ║ ActiveDirectory
                Get-ADUser                                 ║ ActiveDirectory
                Get-ADGroup                                ║ ActiveDirectory
                Get-ADComputer                             ║ ActiveDirectory
                Get-ADOrganizationalUnit                   ║ ActiveDirectory
                Get-ADServiceAccount                       ║ ActiveDirectory
                Import-MyModule                            ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT

        .NOTES
            Version:         1.1
            DateModified:    03/Jun/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com

        .LINK
            https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adobject
            https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser
            https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup
            https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer
            https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adorganizationalunit
            https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adserviceaccount

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Get-AdObjectType.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Identity Management

        .FUNCTIONALITY
            Active Directory Object Type Resolution
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
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
        # Identity parameter
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Specify the identity of the AD object.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('ID', 'SamAccountName', 'DistinguishedName', 'DN', 'SID', 'GUID')]
        $Identity,

        # Server parameter
        [Parameter(
            Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the Active Directory Domain Services instance to connect to.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController', 'DC')]
        [string]
        $Server
    )

    Begin {

        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition

        [hashtable]$SplatADParams = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [object]$ReturnValue = $null
        [object]$NewObject = $null

        # Add Server parameter to splat parameters if specified
        if ($PSBoundParameters.ContainsKey('Server')) {
            $SplatADParams['Server'] = $PSBoundParameters['Server']
        } #end if

    } # End Begin Section

    Process {

        Write-Verbose -Message ('Attempting to determine the type of AD object for identity: {0}' -f $Identity)

        try {
            # Check if identity is an AD object
            # If the identity is already an AD object, return it as is
            if ($Identity -is [Microsoft.ActiveDirectory.Management.ADAccount] -or
                $Identity -is [Microsoft.ActiveDirectory.Management.ADComputer] -or
                $Identity -is [Microsoft.ActiveDirectory.Management.ADGroup] -or
                $Identity -is [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit] -or
                $Identity -is [Microsoft.ActiveDirectory.Management.ADServiceAccount] -or
                $Identity -is [Microsoft.ActiveDirectory.Management.ADObject]) {

                Write-Debug -Message ('Identity is an AD object of type: {0}' -f $Identity.GetType().Name)
                $ReturnValue = $Identity

            } elseif ($Identity -is [string]) {
                # Check if identity is a string

                Write-Debug -Message ('Identity is a string: {0}. Resolving it...' -f $Identity)

                # Check if it's a Well-Known SID (by SID or name)
                $wellKnownSid = $null

                # Check if string is a Well-Known SID (e.g., "S-1-1-0") or name (e.g., "Everyone")
                if ($Variables.WellKnownSIDs.Contains($Identity)) {

                    # Input is a Well-Known SID (e.g., "S-1-1-0").
                    $wellKnownSid = $Identity

                } elseif ($Variables.WellKnownSIDs.Values -contains $Identity) {

                    # Input is a Well-Known SID name (e.g., "Everyone"). Get SID
                    $wellKnownSid = $Variables.WellKnownSIDs.GetEnumerator() |
                        Where-Object { $_.Value -eq $Identity } |
                            Select-Object -ExpandProperty Key

                } #end If-elseif

                # If we have a Well-Known SID, create a SecurityIdentifier object
                if ($wellKnownSid) {

                    Write-Verbose -Message (
                        'Identity {0} is a Well-Known SID: {1}' -f
                        $Identity, $wellKnownSid
                    )

                    try {

                        # Attempt to create a SecurityIdentifier object
                        $ReturnValue = [System.Security.Principal.SecurityIdentifier]::New($wellKnownSid)

                        Write-Debug -Message (
                            'Successfully created SecurityIdentifier object for Well-Known SID: {0}' -f
                            $ReturnValue.Value
                        )

                    } catch {

                        # Fallback to returning the SID as a string
                        $ReturnValue = $wellKnownSid

                        Write-Debug -Message (
                            'Failed to create SecurityIdentifier object for Well-Known SID: {0}.
                            Returning SID as string.' -f
                            $wellKnownSid
                        )

                    } #end try-catch

                } else {

                    # Not a Well-Known SID, check if it's a DistinguishedName, SID, GUID, or SamAccountName
                    # Resolve identity using AD queries

                    $newObject = Get-ADObject -Filter {
                        (DistinguishedName -eq $Identity) -or
                        (ObjectSID -eq $Identity) -or
                        (ObjectGUID -eq $Identity) -or
                        (SamAccountName -eq $Identity)
                    } @SplatADParams

                    if ($newObject) {

                        switch ($newObject.ObjectClass) {
                            'user' {
                                $ReturnValue = Get-ADUser -Identity $newObject @SplatADParams
                            }
                            'group' {
                                $ReturnValue = Get-ADGroup -Identity $newObject @SplatADParams
                            }
                            'computer' {
                                $ReturnValue = Get-ADComputer -Identity $newObject @SplatADParams
                            }
                            'organizationalUnit' {
                                $ReturnValue = Get-ADOrganizationalUnit -Identity $newObject @SplatADParams
                            }
                            'msDS-GroupManagedServiceAccount' {
                                $ReturnValue = Get-ADServiceAccount -Identity $newObject @SplatADParams
                            }
                            'msDS-ManagedServiceAccount' {
                                $ReturnValue = Get-ADServiceAccount -Identity $newObject @SplatADParams
                            }
                            default {
                                Write-Error -Message ('Unsupported object type: {0}' -f $newObject.ObjectClass)
                                return $null
                            }
                        } #end switch

                    } else {

                        Write-Warning -Message (
                            'Identity {0} could not be resolved to a valid AD object.' -f $Identity
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

            Write-Error -Message (
                'Failed to resolve identity: {0}.
                Error: {1}' -f
                $Identity, $_.Exception.Message
            )
            Write-Verbose -Message ('StackTrace: {0}' -f $_.Exception.StackTrace)
            return $null

        } #end try-catch

    } # End Process Section

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'getting AD object type.'
            )
            Write-Verbose -Message $txt
        } #end if

        if ($null -ne $ReturnValue) {
            Write-Output $ReturnValue
        } #end If
    } # End End Section

} #end Function
