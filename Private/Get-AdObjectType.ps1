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
        Version:         1.3
            DateModified:    2/Oct/2024
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
        [Microsoft.ActiveDirectory.Management.ADServiceAccount])
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

                    # Check if given SID is a Well-Known SID
                    If ($Variables.WellKnownSIDs.Keys.Contains($Identity)) {

                        # Get AdObject using Well-Known SID
                        Write-Verbose -Message 'Identified as Well-Known SID'
                        $newObject = Get-ADObject -Filter { ObjectSID -like $Variables.WellKnownSIDs[$Identity] }

                    } else {

                        $newObject = Get-ADObject -Filter { ObjectSID -like $Identity }

                    } #end If-Else

                } elseif (Test-IsValidGUID -ObjectGUID $Identity) {

                    Write-Verbose -Message 'Looking for ObjectGUID'
                    $newObject = Get-ADObject -Filter { ObjectGUID -like $Identity }

                } else {

                    Write-Verbose -Message 'Looking for SamAccountName'

                    # Check if given Name is a Well-Known SID name
                    if ($Variables.WellKnownSIDs.Values.Contains($Identity)) {

                        Write-Verbose 'Identified as Well-Known SID name'
                        $wellKnownSID = $Variables.WellKnownSIDs.Keys.Where({ $Variables.WellKnownSIDs[$_] -eq $Identity })[0]

                        $newObject = Get-ADObject -Filter { ObjectSID -like $wellKnownSID }
                    } else {
                        $newObject = Get-ADObject -Filter { (Name -like $identity) -or (SamAccountName -like $identity) }
                    }
                } #end If-ElseIf-Else

            } #end If-ElseIf Identity

        } Catch {
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
