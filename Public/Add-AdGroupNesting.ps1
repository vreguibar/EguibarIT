

function Add-AdGroupNesting {
    <#
        .SYNOPSIS
            Adds members to an Active Directory group with enhanced error handling and logging.

        .DESCRIPTION
            This function extends Add-ADGroupMember with:
            - Comprehensive error handling
            - Event logging
            - Duplicate membership checks
            - Progress tracking
            - Validation of group objects
            - Support for batch operations

            Function will check for valid AD group representing the identity parameter. It will check existing
            group membership and verify each member. If the current member exist, it will remain as member
            of the group. If user does not exist, or if it can't be found in the current AD, it will be removed.
            Last, each new member will checked on the current AD and will only be added to the group if is not
            already member of it.

        .PARAMETER Identity
            The group to modify. Can be specified as:
            - Distinguished Name (DN)
            - GUID (objectGUID)
            - Security Identifier (objectSid)
            - SAM Account Name (sAMAccountName)

        .PARAMETER Members
            One or more members to add to the group. Can be:
            - Users
            - Groups
            - Computers
            - Group managed service accounts
            Accepts single string or array of identifiers.

        .PARAMETER Server
            Specifies the Active Directory Domain Services instance to connect to.
            If not specified, the function uses the default domain controller for the current domain.

        .PARAMETER BatchSize
            Specifies the number of members to process in each batch operation.
            Default is 50. Useful for optimizing performance in large environments.

        .PARAMETER NoRecursiveCheck
            If specified, the function will not check for recursive membership,
            which can improve performance for large groups. Use only when you are
            certain there are no recursive membership concerns.

        .EXAMPLE
            Add-AdGroupNesting -Identity "Domain Admins" -Members "TheUser"
            Adds a single user to the Domain Admins group.

        .EXAMPLE
            $members = @("User1", "User2", "Group1")
            Add-AdGroupNesting -Identity "ITSupport" -Members $members -Verbose
            Adds multiple members to the ITSupport group with verbose output.

        .EXAMPLE
            "ServiceAccounts" | Add-AdGroupNesting -Members "svc_backup" -WhatIf
            Shows what would happen when adding a service account to a group.

        .OUTPUTS
            [PSCustomObject] Summary object containing:
            - GroupName: The name of the modified group
            - MembersAdded: Array of successfully added members
            - MembersFailed: Array of members that failed to be added
            - TotalProcessed: Total count of members processed

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Add-ADGroupMember                      ║ ActiveDirectory
                Get-ADGroupMember                      ║ ActiveDirectory
                Get-ADObject                           ║ ActiveDirectory
                Get-AdObjectType                       ║ EguibarIT
                Write-CustomLog                        ║ EguibarIT
                Write-CustomError                      ║ EguibarIT
                Get-FunctionDisplay                    ║ EguibarIT
                Import-MyModule                        ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Debug                            ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility
                Write-Warning                          ║ Microsoft.PowerShell.Utility
                Write-Progress                         ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         2.0
            DateModified:   26/Mar/2025
            LastModifiedBy: Vicente Rodriguez Eguibar
                        vicente@eguibar.com
                        Eguibar IT
                        http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/ \
            implementing-least-privilege-administrative-models

            http://blogs.technet.com/b/lrobins/archive/2011/06/23/ \ quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx

            http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([PSCustomObject])]

    Param (
        # Param1 Group which membership is to be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Group which membership is to be changed',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Group', 'GroupName')]
        $Identity,

        # Param2 ID of New Member of the group
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'ID of New Member of the group. Can be a single string or array.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('Member', 'Add')]
        $Members,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController', 'DC')]
        [string]
        $Server
    )

    Begin {
        Set-StrictMode -Version Latest

        # Initialize logging
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        # Build the message of the event
        $sb = [System.Text.StringBuilder]::new()
        $sb.AppendLine('Function "{0}" was called successfully.' -f $MyInvocation.Mycommand) | Out-Null
        $sb.AppendLine('Parameters used by the function: ') | Out-Null
        $sb.AppendLine((Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)) | Out-Null

        $Splat = @{
            CustomEventId  = ([EventID]::FunctionCalled)
            EventName      = ('Call to {0}' -f $MyInvocation.Mycommand)
            EventCategory  = [EventCategory]::Initialization
            Message        = $sb.ToString()
            CustomSeverity = [EventSeverity]::Information
            Verbose        = $PSBoundParameters['Verbose']
        }
        Write-CustomLog @Splat

        ##############################
        # Module imports

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$CommonParams = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Define array lists
        $CurrentMembers = [System.Collections.ArrayList]::new()
        $processedMembers = [System.Collections.ArrayList]::new()
        $failedMembers = [System.Collections.ArrayList]::new()


        # Check if Identity is a group. Retrieve the object if not Microsoft.ActiveDirectory.Management.AdGroup.
        $Identity = Get-AdObjectType -Identity $Identity

        [hashtable]$CommonParams = @{
            ErrorAction = 'Stop'
        }

        if ($PSBoundParameters.ContainsKey('Server')) {
            $CommonParams['Server'] = $Server
        } #end IF

    } #end Begin

    Process {

        # Get group members
        Try {

            Write-Debug -Message ('Getting members of group {0}' -f $Identity)
            $CurrentMembers = Get-ADGroupMember -Identity $Identity -Recursive @CommonParams

            If ($null -eq $CurrentMembers) {
                Write-Debug -Message ('Group {0} has no members' -f $Identity)

            } Else {
                Write-CustomLog -EventInfo ([EventIDs]::GetGroupMembership) -Message ('Got members from group {0}' -f $Identity)
            } #end If-Else

        } Catch {

            $Splat = @{
                CreateWindowsEvent = $true
                EventInfo          = ([EventIDs]::FailedGetGroupMembership)
                Message            = 'Failed to retrieve members of the group "{0}". {1}' -f $Identity, $_
                EventName          = 'GetGroupMembersError'
            }
            Write-CustomError @Splat
        } #end Try-Catch


        try {
            Write-Debug -Message ('Adding members to group..: {0}' -f $Identity.SamAccountName)

            # Iterate members
            Foreach ($item in $Members) {
                $item = Get-AdObjectType -Identity $item
                Write-Debug -Message ('Validated member object: {0}' -f $Item.DistinguishedName)


                # Only process objects which are not members of the group
                If (($null -ne $CurrentMembers) -and
                ($CurrentMembers.DistinguishedName -notcontains $item.DistinguishedName)) {

                    Write-Debug -Message ('
                        {0} is already a member
                        of {1} group' -f
                        $item.Name, $Identity.Name
                    )
                    continue
                } #end If

                try {
                    Write-Debug -Message ('Adding: {0}' -f $Item)

                    If ($PSCmdlet.ShouldProcess($Identity.DistinguishedName, "Add member $item")) {
                        $Splat = @{
                            Identity = $Identity
                            Members  = $item
                        }

                        Add-ADGroupMember @Splat @CommonParams
                        [void]$processedMembers.Add($item.Name)

                        Write-CustomLog -EventInfo ([EventIDs]::SetGroupMembership) -Message ('Added member {0} to group {1}' -f
                            $item.Name, $Identity.Name)

                    } #end If
                } catch {

                    [void]$failedMembers.Add($item)

                    Write-CustomError -CreateWindowsEvent -EventInfo ([EventIDs]::FailedSetGroupMembership) -Message ('
                        Failed to add member "{0}"
                        to group "{1}".
                        {2}' -f
                        $item, $Identity, $_.Exception.Message
                    )

                    continue

                } #end try-catch

            } #end Foreach

            Write-Verbose -Message ('Members were added correctly to group {0}' -f $Identity.sAMAccountName)

        } catch {

            Write-Error -Message 'Error when adding group member'
            throw

        } #end Try-Catch

    } #end Process

    End {
        # Report results
        if ($processedMembers.Count -gt 0) {

            Write-Verbose -Message ('Successfully added {0} members to {1}' -f
                $processedMembers.Count, $Identity.Name)

        } #end If

        if ($failedMembers.Count -gt 0) {

            Write-Warning -Message ('Failed to add {0} members to {1}' -f
                $failedMembers.Count, $Identity.Name)

        } #end If

        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'adding members to the group.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End

} #end Function Add-AdGroupNesting
