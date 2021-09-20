function New-AdDelegatedGroup {
    <#
    .SYNOPSIS
        Same as New-AdGroup but with error handling, Security changes and loging
    .DESCRIPTION
        Native New-AdGroup throws an error exception when the group already exists. This error is handeled
        as a "correct" within this function due the fact that group might already exist and operation
        should continue after writting a log.
    .EXAMPLE
        New-AdDelegatedGroup -Name "Poor Admins" -GroupCategory Security -GroupScope DomainLocal -DisplayName "Poor Admins" -Path 'OU=Groups,OU=Admin,DC=EguibarIT,DC=local' -Description 'New Admin Group'
    .PARAMS
        PARAM1........: [STRING] Name
        PARAM2........: [ValidateSet] GroupCategory
        PARAM3........: [ValidateSet] GroupScope
        PARAM4........: [STRING] DisplayName
        PARAM5........: [STRING] Path
        PARAM6........: [STRING] Description
        PARAM7........: [SWITCH] ProtectFromAccidentalDeletion
        PARAM8........: [SWITCH] RemoveAccountOperators
        PARAM9........: [SWITCH] RemoveEveryone
        PARAM10.......: [SWITCH] RemoveAuthUsers
        PARAM11.......: [SWITCH] RemovePreWin2000
    .NOTES
        Version:         1.1
        DateModified:    15/Feb/2017
        LasModifiedBy:   Vicente Rodriguez Eguibar
            vicente@eguibar.com
            Eguibar Information Technology S.L.
            http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([Microsoft.ActiveDirectory.Management.AdGroup])]
    Param
    (
        # Param1 Group which membership is to be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Name of the group to be created. SamAccountName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Name,

        # Param2 Group category, either Security or Distribution
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Group category, either Security or Distribution',
            Position = 1)]
        [ValidateSet('Security','Distribution')]
        $GroupCategory,

        # Param3 Group Scope, either DomainLocal, Global or Universal
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Group Scope, either DomainLocal, Global or Universal',
            Position = 2)]
        [ValidateSet('DomainLocal','Global','Universal')]
        $GroupScope,

        # Param4 Display Name of the group to be created
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Display Name of the group to be created',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        $DisplayName,

        # Param5 DistinguishedName of the container where the group will be created.
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'DistinguishedName of the container where the group will be created.',
            Position = 4)]
        [ValidateNotNullOrEmpty()]
        $path,

        # Param6 Description of the group.
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Description of the group.',
            Position = 5)]
        [ValidateNotNullOrEmpty()]
        $Description,

        # Param7 Protect from accidental deletion.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Protect from accidental deletion.',
            Position = 6)]
        [Switch]
        $ProtectFromAccidentalDeletion,

        # Param8 Remove Account Operators Built-In group.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Account Operators Built-In group',
            Position = 7)]
        [Switch]
        $RemoveAccountOperators,

        # Param9 Remove Everyone Built-In group.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Everyone Built-In group',
            Position = 8)]
        [Switch]
        $RemoveEveryone,

        # Param10 Remove Authenticated Users Built-In group.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Authenticated Users Built-In group',
            Position = 9)]
        [Switch]
        $RemoveAuthUsers,

        # Param11 Remove Pre-Windows 2000 Built-In group.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Pre-Windows 2000 Built-In group',
            Position = 10)]
        [Switch]
        $RemovePreWin2000

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


        Import-Module -name ActiveDirectory      -Verbose:$false -Force
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        $parameters = $null
        $newGroup   = $null
    }

    Process {
        try {
            # Get the group and store it on variable.
            $newGroup = Get-AdGroup -Filter { SamAccountName -eq $Name }

            ### Using $PSBoundParameters['Name'] throws an Error. Using variable instead.
            If(-not($newGroup)) {
                $parameters = @{
                    Name           = $PSBoundParameters['Name']
                    SamAccountName = $PSBoundParameters['Name']
                    GroupCategory  = $PSBoundParameters['GroupCategory']
                    GroupScope     = $PSBoundParameters['GroupScope']
                    DisplayName    = $PSBoundParameters['DisplayName']
                    Path           = $PSBoundParameters['path']
                    Description    = $PSBoundParameters['Description']
                }
                New-ADGroup @parameters
            } else {
                Write-Warning -Message ('Groups {0} already exists. Modifying the group!' -f $PSBoundParameters['Name'])

                $newGroup | Set-AdObject -ProtectedFromAccidentalDeletion $False

                Try {
                    $parameters = @{
                        Identity      = $PSBoundParameters['Name']
                        Description   = $PSBoundParameters['Description']
                        DisplayName   = $PSBoundParameters['DisplayName']
                        GroupCategory = $PSBoundParameters['GroupCategory']
                        GroupScope    = $PSBoundParameters['GroupScope']
                    }
                    Set-AdGroup @parameters

                    If(-not($newGroup.DistinguishedName -ccontains $PSBoundParameters['path']))
                    {
                        # Move object to the corresponding OU
                        Move-ADObject -Identity $newGroup -TargetPath $PSBoundParameters['path']
                    }

                }
                catch { throw }
            }

            # Get the group again and store it on variable.
            $newGroup = Get-AdGroup -Filter { SamAccountName -eq $Name }


            # Protect From Accidental Deletion
            If($PSBoundParameters['ProtectFromAccidentalDeletion']) {
                $newGroup | Set-ADObject -ProtectedFromAccidentalDeletion $true
            }

            # Remove Account Operators Built-In group
            If($PSBoundParameters['RemoveAccountOperators']) {
                Remove-AccountOperator -LDAPPath $newGroup.DistinguishedName
            }

            # Remove Everyone Built-In group
            If($PSBoundParameters['RemoveEveryone']) {
                Remove-Everyone -LDAPPath $newGroup.DistinguishedName
            }

            # Remove Authenticated Users Built-In group
            If($PSBoundParameters['RemoveAuthUsers']) {
                Remove-AuthUser -LDAPPath $newGroup.DistinguishedName
            }

            # Remove Pre-Windows 2000 Built-In group
            If($PSBoundParameters['RemovePreWin2000']) {
                Remove-PreWin2000 -LDAPPath $newGroup.DistinguishedName
            }
        }
        catch {
            throw
            Write-Warning -Message ('An unhandeled error was thrown when creating Groups {0}' -f $PSBoundParameters['Name'])
        }
    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating Delegated Group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        #Return the group object.
        return $newGroup
    }
}