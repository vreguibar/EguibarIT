# Clean OU from default BuiltIn groups
function Start-AdCleanOU {
    <#
        .Synopsis
            Clean default OU permissions.
        .DESCRIPTION
            The function will remove some of the default permission on
            the provided OU. It will remove the "Account Operators" and
            "Print Operators" built-in groups.
        .EXAMPLE
            Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveAuthenticatedUsers
        .EXAMPLE
            Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveUnknownSIDs
        .EXAMPLE
            Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveAuthenticatedUsers -RemoveUnknownSIDs
        .PARAMETER LDAPPath
            Distinguished name of the OU to be cleaned.
        .PARAMETER RemoveAuthenticatedUsers
            If present, Remove Authenticated Users.
        .PARAMETER RemoveUnknownSIDs
           If present, Remove Unknown SIDs.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AdAclCreateDeleteUser              | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteComputer          | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGroup             | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteContact           | EguibarIT.DelegationPS
                Set-CreateDeleteInetOrgPerson          | EguibarIT.DelegationPS
                Set-AdAclCreateDeletePrintQueue        | EguibarIT.DelegationPS
                Remove-PreWin2000                      | EguibarIT.DelegationPS
                Remove-PreWin2000FromOU                | EguibarIT.DelegationPS
                Remove-AccountOperator                 | EguibarIT.DelegationPS
                Remove-PrintOperator                   | EguibarIT.DelegationPS
                Remove-AuthUser                        | EguibarIT.DelegationPS
                Remove-UnknownSID                      | EguibarIT.DelegationPS
                Get-CurrentErrorToDisplay              | EguibarIT
                Get-FunctionDisplay                    | EguibarIT
        .NOTES
            Version:         1.2
            DateModified:    19/Dec/2017
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param (
        #PARAM1 Distinguished name of the OU to be cleaned
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished name of the OU to be cleaned.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [validateScript({ Test-IsValidDN -ObjectDN $_ })]
        [String]
        $LDAPpath,

        #PARAM2 Remove Authenticated Users
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remove Authenticated Users.',
            Position = 1)]
        [switch]
        $RemoveAuthenticatedUsers,

        #PARAM3 Remove Unknown SIDs
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remove Unknown SIDs.',
            Position = 2)]
        [switch]
        $RemoveUnknownSIDs
    )

    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        Import-MyModule -Name EguibarIT.DelegationPS -Verbose:$False

        ##############################
        # Variables Definition

        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Get 'Account Operators' group by SID
        $AccountOperators = Get-AdGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-548' }

        $Splat = @{
            Group      = $AccountOperators
            LDAPPath   = $PSBoundParameters['LDAPpath']
            RemoveRule = $true
        }
    } #end Begin

    process {

        if ($Force -or $PSCmdlet.ShouldProcess('Proceed with delegations?')) {
            # Remove the Account Operators group from ACL to Create/Delete Users
            try {
                Set-AdAclCreateDeleteUser @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Remove the Account Operators group from ACL to Create/Delete Computers
            try {
                Set-AdAclCreateDeleteComputer @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Remove the Account Operators group from ACL to Create/Delete Groups
            try {
                Set-AdAclCreateDeleteGroup @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Remove the Account Operators group from ACL to Create/Delete Contacts
            try {
                Set-AdAclCreateDeleteContact @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
            try {
                Set-CreateDeleteInetOrgPerson @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Remove the Print Operators group from ACL to Create/Delete PrintQueues
            try {
                Set-AdAclCreateDeletePrintQueue @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Remove Pre-Windows 2000 Compatible Access group from Admin-User
            try {
                Remove-PreWin2000 -LDAPPath $PSBoundParameters['LDAPPath']
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Remove Pre-Windows 2000 Access group from OU
            try {
                Remove-PreWin2000FromOU -LDAPPath $PSBoundParameters['LDAPPath']
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Remove ACCOUNT OPERATORS 2000 Access group from OU
            try {
                Remove-AccountOperator -LDAPPath $PSBoundParameters['LDAPPath']
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Remove PRINT OPERATORS 2000 Access group from OU
            try {
                Remove-PrintOperator -LDAPPath $PSBoundParameters['LDAPPath']
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            If ($PsBoundParameters['RemoveAuthenticatedUsers']) {
                # Remove AUTHENTICATED USERS group from OU
                try {
                    Remove-AuthUser -LDAPPath $PSBoundParameters['LDAPPath']
                } catch {
                    ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                    throw
                } #end Try-Catch

                Write-Verbose -Message 'Removing Authenticated Users'
            }  #end If

            If ($PsBoundParameters['$RemoveUnknownSIDs']) {
                # Remove Un-Resolvable SID from a given object
                try {
                    Remove-UnknownSID -LDAPPath $PSBoundParameters['LDAPPath'] -RemoveSID
                } catch {
                    ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                    throw
                } #end Try-Catch

                Write-Verbose -Message 'Remove Un-Resolvable / Unknown SIDs'
            } #end If
        } #end If

    } #end Process

    end {
        Write-Verbose -Message('Builtin groups were removed correctly from object {0}.' -f $PSBoundParameters['LDAPPath'])
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End

} #end Function
