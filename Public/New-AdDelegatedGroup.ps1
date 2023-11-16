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
    .EXAMPLE
        $splat = @{
            Name                          = 'Poor Admins'
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = 'Poor Admins'
            Path                          = 'OU=Groups,OU=Admin,DC=EguibarIT,DC=local'
            Description                   = 'New Admin Group'
            ProtectFromAccidentalDeletion = $true
        }
        New-AdDelegatedGroup @Splat
    .PARAMETER Name
        [STRING] Name of the group to be created. SamAccountName
    .PARAMETER GroupCategory
        [ValidateSet] Group category, either Security or Distribution
    .PARAMETER GroupScope
        [ValidateSet] Group Scope, either DomainLocal, Global or Universal
    .PARAMETER DisplayName
        [STRING] Display Name of the group to be created
    .PARAMETER path
        [STRING] DistinguishedName of the container where the group will be created.
    .PARAMETER Description
        [STRING] Description of the group.
    .PARAMETER ProtectFromAccidentalDeletion
        [Switch] Protect from accidental deletion.
    .PARAMETER RemoveAccountOperators
        [Switch] Remove Account Operators Built-In group
    .PARAMETER RemoveEveryone
        [Switch] Remove Everyone Built-In group
    .PARAMETER RemoveAuthUsers
        [Switch] Remove Authenticated Users Built-In group
    .PARAMETER RemovePreWin2000
        [Switch] Remove Pre-Windows 2000 Built-In group
    .NOTES
        Used Functions:
            Name                                   | Module
            ---------------------------------------|--------------------------
            Get-CurrentErrorToDisplay              | EguibarIT
            Remove-AccountOperator                 | EguibarIT.Delegation
            Remove-Everyone                        | EguibarIT.Delegation
            Remove-AuthUser                        | EguibarIT.Delegation
            Remove-PreWin2000                      | EguibarIT.Delegation
            Get-AdGroup                            | ActiveDirectory
            Move-ADObject                          | ActiveDirectory
            New-ADGroup                            | ActiveDirectory
            Set-AdGroup                            | ActiveDirectory
            Set-AdObject                           | ActiveDirectory
    .NOTES
        Version:         1.1
        DateModified:    15/Feb/2017
        LasModifiedBy:   Vicente Rodriguez Eguibar
            vicente@eguibar.com
            Eguibar Information Technology S.L.
            http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([Microsoft.ActiveDirectory.Management.AdGroup])]
    Param (
        # Param1 Group which membership is to be changed
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Name of the group to be created. SamAccountName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Name,

        # Param2 Group category, either Security or Distribution
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Group category, either Security or Distribution',
            Position = 1)]
        [ValidateSet('Security', 'Distribution')]
        $GroupCategory,

        # Param3 Group Scope, either DomainLocal, Global or Universal
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Group Scope, either DomainLocal, Global or Universal',
            Position = 2)]
        [ValidateSet('DomainLocal', 'Global', 'Universal')]
        $GroupScope,

        # Param4 Display Name of the group to be created
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Display Name of the group to be created',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        # Param5 DistinguishedName of the container where the group will be created.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'DistinguishedName of the container where the group will be created.',
            Position = 4)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $path,

        # Param6 Description of the group.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Description of the group.',
            Position = 5)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Description,

        # Param7 Protect from accidental deletion.
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Protect from accidental deletion.',
            Position = 6)]
        [Switch]
        $ProtectFromAccidentalDeletion,

        # Param8 Remove Account Operators Built-In group.
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Account Operators Built-In group',
            Position = 7)]
        [Switch]
        $RemoveAccountOperators,

        # Param9 Remove Everyone Built-In group.
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Everyone Built-In group',
            Position = 8)]
        [Switch]
        $RemoveEveryone,

        # Param10 Remove Authenticated Users Built-In group.
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Authenticated Users Built-In group',
            Position = 9)]
        [Switch]
        $RemoveAuthUsers,

        # Param11 Remove Pre-Windows 2000 Built-In group.
        [Parameter(Mandatory = $False, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Pre-Windows 2000 Built-In group',
            Position = 10)]
        [Switch]
        $RemovePreWin2000

    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        if (-not (Get-Module -Name 'ActiveDirectory' -ListAvailable)) {
            Import-Module -Name 'ActiveDirectory' -Force -Verbose:$false
        } #end If

        if (-not (Get-Module -Name 'EguibarIT.Delegation' -ListAvailable)) {
            Import-Module -Name 'EguibarIT.Delegation' -Force -Verbose:$false
        } #end If

        $Splat    = [Hashtable]::New()
        $newGroup = [Microsoft.ActiveDirectory.Management.AdGroup]::New()
    } # End Begin Section

    Process {
        try {
            # Get the group and store it on variable.
            $newGroup = Get-AdGroup -Filter { SamAccountName -eq $Name }

            ### Using $PSBoundParameters['Name'] throws an Error. Using variable instead.
            If (-not($newGroup)) {
                $Splat = @{
                    Name           = $PSBoundParameters['Name']
                    SamAccountName = $PSBoundParameters['Name']
                    GroupCategory  = $PSBoundParameters['GroupCategory']
                    GroupScope     = $PSBoundParameters['GroupScope']
                    DisplayName    = $PSBoundParameters['DisplayName']
                    Path           = $PSBoundParameters['path']
                    Description    = $PSBoundParameters['Description']
                }
                if ($Force -or $PSCmdlet.ShouldProcess("Group does not exist. SHould it be created?")) {
                    New-ADGroup @Splat
                } #end If
            } else {
                Write-Warning -Message ('Groups {0} already exists. Modifying the group!' -f $PSBoundParameters['Name'])

                $newGroup | Set-AdObject -ProtectedFromAccidentalDeletion $False

                Try {
                    $Splat = @{
                        Identity      = $PSBoundParameters['Name']
                        Description   = $PSBoundParameters['Description']
                        DisplayName   = $PSBoundParameters['DisplayName']
                        GroupCategory = $PSBoundParameters['GroupCategory']
                        GroupScope    = $PSBoundParameters['GroupScope']
                    }
                    if ($Force -or $PSCmdlet.ShouldProcess("Group does not exist. SHould it be created?")) {
                        Set-AdGroup @Splat
                    }

                    If (-not($newGroup.DistinguishedName -ccontains $PSBoundParameters['path'])) {
                        # Move object to the corresponding OU
                        Move-ADObject -Identity $newGroup -TargetPath $PSBoundParameters['path']
                    }

                } catch {
                    Get-CurrentErrorToDisplay -CurrentError $error[0]
                } #end Try-Catch
            } # End If

            # Get the group again and store it on variable.
            $newGroup = Get-AdGroup -Filter { SamAccountName -eq $Name }


            # Protect From Accidental Deletion
            If ($PSBoundParameters['ProtectFromAccidentalDeletion']) {
                $newGroup | Set-ADObject -ProtectedFromAccidentalDeletion $true
            }

            # Remove Account Operators Built-In group
            If ($PSBoundParameters['RemoveAccountOperators']) {
                Remove-AccountOperator -LDAPPath $newGroup.DistinguishedName
            }

            # Remove Everyone Built-In group
            If ($PSBoundParameters['RemoveEveryone']) {
                Remove-Everyone -LDAPPath $newGroup.DistinguishedName
            }

            # Remove Authenticated Users Built-In group
            If ($PSBoundParameters['RemoveAuthUsers']) {
                Remove-AuthUser -LDAPPath $newGroup.DistinguishedName
            }

            # Remove Pre-Windows 2000 Built-In group
            If ($PSBoundParameters['RemovePreWin2000']) {
                Remove-PreWin2000 -LDAPPath $newGroup.DistinguishedName
            }
        }
        catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
            Write-Warning -Message ('An unhandeled error was thrown when creating Groups {0}' -f $PSBoundParameters['Name'])
        }
    } # End Process section

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating Delegated Group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        #Return the group object.
        return $newGroup
    } #end End
} #end Function
