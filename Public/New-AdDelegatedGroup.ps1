function New-AdDelegatedGroup {
    <#
    .SYNOPSIS
        Same as New-AdGroup but with error handling, Security changes and login
    .DESCRIPTION
        Native New-AdGroup throws an error exception when the group already exists. This error is handled
        as a "correct" within this function due the fact that group might already exist and operation
        should continue after writing a log.
    .EXAMPLE
        New-AdDelegatedGroup -Name "Poor Admins" -GroupCategory Security -GroupScope DomainLocal
        -DisplayName "Poor Admins" -Path 'OU=Groups,OU=Admin,DC=EguibarIT,DC=local' -Description 'New Admin Group'
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
            Get-FunctionDisplay                    | EguibarIT
            Remove-AccountOperator                 | EguibarIT.DelegationPS
            Remove-Everyone                        | EguibarIT.DelegationPS
            Remove-AuthUser                        | EguibarIT.DelegationPS
            Remove-PreWin2000                      | EguibarIT.DelegationPS
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
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Name of the group to be created. SamAccountName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'GroupID', 'Identity', 'SamAccountName')]
        $Name,

        # Param2 Group category, either Security or Distribution
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Group category, either Security or Distribution',
            Position = 1)]
        [ValidateSet('Security', 'Distribution')]
        [ValidateNotNullOrEmpty()]
        $GroupCategory,

        # Param3 Group Scope, either DomainLocal, Global or Universal
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Group Scope, either DomainLocal, Global or Universal',
            Position = 2)]
        [ValidateSet('DomainLocal', 'Global', 'Universal')]
        [ValidateNotNullOrEmpty()]
        $GroupScope,

        # Param4 Display Name of the group to be created
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Display Name of the group to be created',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        # Param5 DistinguishedName of the container where the group will be created.
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'DistinguishedName of the container where the group will be created.',
            Position = 4)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ })]
        [Alias('DN', 'DistinguishedName', 'LDAPpath')]
        [System.String]
        $path,

        # Param6 Description of the group.
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Description of the group.',
            Position = 5)]
        [ValidateNotNullOrEmpty()]
        [System.String]
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
        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-Module -Name 'ActiveDirectory' -SkipEditionCheck -Force -Verbose:$false | Out-Null
        Import-Module -Name 'EguibarIT.DelegationPS' -SkipEditionCheck -Force -Verbose:$false | Out-Null

        ##############################
        # Variables Definition

        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        $newGroup = [Microsoft.ActiveDirectory.Management.AdGroup]::New()
    } # End Begin Section

    Process {

        #Check if group exist
        $groupExists = Get-ADGroup -Filter { SamAccountName -eq $Name } -ErrorAction SilentlyContinue

        if (-not $groupExists) {

            Write-Verbose -Message ('Group {0} does not exists. Creating it!' -f $Name)

            if ($PSCmdlet.ShouldProcess("$Name", 'Group does not exist. Should it be created?')) {

                Try {
                    $Splat = @{
                        Name           = $Name
                        SamAccountName = $Name
                        GroupCategory  = $PSBoundParameters['GroupCategory']
                        GroupScope     = $PSBoundParameters['GroupScope']
                        DisplayName    = $PSBoundParameters['DisplayName']
                        path           = $PSBoundParameters['path']
                        Description    = $PSBoundParameters['Description']
                        ErrorAction    = 'Stop'
                    }
                    $newGroup = New-ADGroup @Splat
                    Write-Verbose -Message ('Group {0} created successfully.' -f $Name)

                } catch {
                    Write-Error -Message ('An error occurred while creating the group: {0})' -f $_.Exception.Message)
                    throw
                } #end Try-Catch
            } #end If
        } else {
            Write-Warning -Message ('Groups {0} already exists. Modifying the group!' -f $PSBoundParameters['Name'])

            # Remove ProtectedFromAccidentalDeletion flag
            Set-ADObject -Identity $groupExists -ProtectedFromAccidentalDeletion $False

            # Modify existing group
            Try {
                $Splat = @{
                    Identity      = $groupExists
                    Description   = $PSBoundParameters['Description']
                    DisplayName   = $PSBoundParameters['DisplayName']
                    GroupCategory = $PSBoundParameters['GroupCategory']
                    GroupScope    = $PSBoundParameters['GroupScope']
                    Passthru      = $true
                    ErrorAction   = 'Stop'
                }
                if ($Force -or $PSCmdlet.ShouldProcess('Existing group. Should it be Modified?')) {
                    $newGroup = Set-ADGroup @Splat
                    if (-not $newGroup) {
                        Start-Sleep 2
                        $newGroup = Get-ADGroup $groupExists
                    } #end If

                    Write-Verbose -Message ('Existing group {0} modified.' -f $newGroup)
                } #end If

                If (-not($newGroup.DistinguishedName -contains $PSBoundParameters['path'])) {
                    # Move object to the corresponding OU
                    Move-ADObject -Identity $newGroup.DistinguishedName -TargetPath $PSBoundParameters['path'] -ErrorAction Stop
                } #end If
            } catch {
                throw
                Write-Error -Message ('An error occurred while creating the group: {0})' -f $_.Exception.Message)
            } #end Try-Catch

        } #end If-Else



        # Get the group again and store it on variable.
        try {
            $newGroup = Get-ADGroup -Filter { SamAccountName -eq $Name } -ErrorAction Stop
            Write-Verbose -Message ('Refreshing group {0}' -f $name)
        } catch {
            Write-Error -Message ('Error while trying to refresh group {0}' -f $name)
        }


        # Protect From Accidental Deletion
        If ($PSBoundParameters['ProtectFromAccidentalDeletion']) {
            Set-ADObject -Identity $newGroup.DistinguishedName -ProtectedFromAccidentalDeletion $true
            Write-Verbose -Message ('Group {0} Protect From Accidental Deletion' -f $name)
        }

        # Remove Account Operators Built-In group
        If ($PSBoundParameters['RemoveAccountOperators']) {
            Remove-AccountOperator -LDAPPath $newGroup.DistinguishedName
            Write-Verbose -Message ('Group {0} Remove Account Operators' -f $name)
        }

        # Remove Everyone Built-In group
        If ($PSBoundParameters['RemoveEveryone']) {
            Remove-Everyone -LDAPPath $newGroup.DistinguishedName
            Write-Verbose -Message ('Group {0} Remove Everyone' -f $name)
        }

        # Remove Authenticated Users Built-In group
        If ($PSBoundParameters['RemoveAuthUsers']) {
            Remove-AuthUser -LDAPPath $newGroup.DistinguishedName
            Write-Verbose -Message ('Group {0} Remove Authenticated Users' -f $name)
        }

        # Remove Pre-Windows 2000 Built-In group
        If ($PSBoundParameters['RemovePreWin2000']) {
            Remove-PreWin2000 -LDAPPath $newGroup.DistinguishedName
            Write-Verbose -Message ('Group {0} Remove Pre-Windows 2000' -f $name)
        }

    } # End Process section

    End {
        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'creating Delegated Group.'
        )
        Write-Verbose -Message $txt

        #Return the group object.
        return $newGroup
    } #end End
} #end Function
