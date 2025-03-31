﻿function New-AdDelegatedGroup {
    <#
        .SYNOPSIS
            Creates or modifies AD groups with enhanced security settings and error handling.

        .DESCRIPTION
            Creates a new Active Directory group or modifies an existing one with additional security
            settings beyond the standard New-ADGroup cmdlet capabilities. The function:
            - Handles group existence checks gracefully
            - Implements security best practices
            - Removes built-in groups from ACLs
            - Supports tiered administration model
            - Is fully idempotent - running multiple times produces same result

            The function follows the Active Directory tiering model and adheres to security best practices.

        .EXAMPLE
            New-AdDelegatedGroup -Name "Poor Admins" -GroupCategory Security -GroupScope DomainLocal
            -DisplayName "Poor Admins" -Path 'OU=Groups,OU=Admin,DC=EguibarIT,DC=local' -Description 'New Admin Group'
            -ProtectFromAccidentalDeletion -RemoveAuthUsers

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
            Name                                       ║ Module/Namespace
            ═══════════════════════════════════════════╬══════════════════════════════
            Get-FunctionDisplay                        ║ EguibarIT
            Remove-AccountOperator                     ║ EguibarIT.DelegationPS
            Remove-Everyone                            ║ EguibarIT.DelegationPS
            Remove-AuthUser                            ║ EguibarIT.DelegationPS
            Remove-PreWin2000                          ║ EguibarIT.DelegationPS
            Get-AdGroup                                ║ ActiveDirectory
            Move-ADObject                              ║ ActiveDirectory
            New-ADGroup                                ║ ActiveDirectory
            Set-AdGroup                                ║ ActiveDirectory
            Set-AdObject                               ║ ActiveDirectory

        .NOTES
            Version:         1.2
            DateModified:    31/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com

        .LINK
        https://github.com/vreguibar/EguibarIT
        .LINK
            https://www.eguibarit.com
    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([Microsoft.ActiveDirectory.Management.AdGroup])]

    Param (
        # Param1 Group which membership is to be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Name of the group to be created. SamAccountName (1-256 chars, alphanumeric and -_.)',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1, 256)]
        [ValidatePattern('^[A-Za-z0-9\s\-_.]+$')]
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
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
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
        Set-StrictMode -Version Latest

        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToShortDateString(),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Module imports

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        $newGroup = [Microsoft.ActiveDirectory.Management.AdGroup]::New()

    } # End Begin Section

    Process {

        #Check if group exist
        $groupExists = Get-ADGroup -Filter { SamAccountName -eq $Name } -ErrorAction SilentlyContinue

        if (-not $groupExists) {

            Write-Debug -Message ('Group {0} does not exists. Creating it!' -f $Name)

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
                    Write-Debug -Message ('Group {0} created successfully.' -f $Name)

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

                    Write-Debug -Message ('Existing group {0} modified.' -f $newGroup)
                } #end If

                If (-not($newGroup.DistinguishedName -contains $PSBoundParameters['path'])) {

                    # Move object to the corresponding OU
                    Move-ADObject -Identity $newGroup.DistinguishedName -TargetPath $PSBoundParameters['path'] -ErrorAction Stop

                } #end If

            } catch {

                Write-Error -Message ('An error occurred while creating the group: {0})' -f $_.Exception.Message)
                throw

            } #end Try-Catch

        } #end If-Else



        # Get the group again and store it on variable.
        try {

            $newGroup = Get-ADGroup -Filter { SamAccountName -eq $Name } -ErrorAction Stop
            Write-Debug -Message ('Refreshing group {0}' -f $name)

        } catch {

            Write-Error -Message ('Error while trying to refresh group {0}' -f $name)

        } #end Try-Catch


        # Protect From Accidental Deletion
        If ($PSBoundParameters['ProtectFromAccidentalDeletion']) {

            Set-ADObject -Identity $newGroup.DistinguishedName -ProtectedFromAccidentalDeletion $true
            Write-Debug -Message ('Group {0} Protect From Accidental Deletion' -f $name)

        } #end If

        # Remove Account Operators Built-In group
        If ($PSBoundParameters['RemoveAccountOperators']) {

            Remove-AccountOperator -LDAPPath $newGroup.DistinguishedName
            Write-Debug -Message ('Group {0} Remove Account Operators' -f $name)

        } #end If

        # Remove Everyone Built-In group
        If ($PSBoundParameters['RemoveEveryone']) {

            Remove-Everyone -LDAPPath $newGroup.DistinguishedName
            Write-Debug -Message ('Group {0} Remove Everyone' -f $name)

        } #end If

        # Remove Authenticated Users Built-In group
        If ($PSBoundParameters['RemoveAuthUsers']) {

            Remove-AuthUser -LDAPPath $newGroup.DistinguishedName
            Write-Debug -Message ('Group {0} Remove Authenticated Users' -f $name)

        } #end If

        # Remove Pre-Windows 2000 Built-In group
        If ($PSBoundParameters['RemovePreWin2000']) {

            Remove-PreWin2000 -LDAPPath $newGroup.DistinguishedName
            Write-Debug -Message ('Group {0} Remove Pre-Windows 2000' -f $name)

        } #end If

    } # End Process section

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating Delegated Group.'
            )
            Write-Verbose -Message $txt
        } #end If

        #Return the group object.
        return $newGroup
    } #end End

} #end Function New-AdDelegatedGroup
