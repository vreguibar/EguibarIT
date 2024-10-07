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
    [OutputType([void])]

    param (
        #PARAM1 Distinguished name of the OU to be cleaned
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished name of the OU to be cleaned.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [String]
        $LDAPpath,

        #PARAM2 Remove Authenticated Users
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remove Authenticated Users.',
            Position = 1)]
        [switch]
        $RemoveAuthenticatedUsers,

        #PARAM3 Remove Unknown SIDs
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remove Unknown SIDs.',
            Position = 2)]
        [switch]
        $RemoveUnknownSIDs
    )

    begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

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
                Write-Error -Message 'Error when delegating user Create/Delete cleanup permission'
            } #end Try-Catch

            # Remove the Account Operators group from ACL to Create/Delete Computers
            try {
                Set-AdAclCreateDeleteComputer @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer cleanup permission'
            } #end Try-Catch

            # Remove the Account Operators group from ACL to Create/Delete Groups
            try {
                Set-AdAclCreateDeleteGroup @Splat
            } catch {
                Write-Error -Message 'Error when delegating group cleanup permission'
            } #end Try-Catch

            # Remove the Account Operators group from ACL to Create/Delete Contacts
            try {
                Set-AdAclCreateDeleteContact @Splat
            } catch {
                Write-Error -Message 'Error when delegating contact cleanup permission'
            } #end Try-Catch

            # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
            try {
                Set-CreateDeleteInetOrgPerson @Splat
            } catch {
                Write-Error -Message 'Error when delegating InetOrg cleanup permission'
            } #end Try-Catch

            # Remove the Print Operators group from ACL to Create/Delete PrintQueues
            try {
                Set-AdAclCreateDeletePrintQueue @Splat
            } catch {
                Write-Error -Message 'Error when delegating PrintQueue Create/Delete cleanup permission'
            } #end Try-Catch

            # Remove Pre-Windows 2000 Compatible Access group from Admin-User
            try {
                Remove-PreWin2000 -LDAPPath $PSBoundParameters['LDAPPath']
            } catch {
                Write-Error -Message 'Error when delegating Pre-Win2000 cleanup permission'
            } #end Try-Catch

            # Remove Pre-Windows 2000 Access group from OU
            try {
                Remove-PreWin2000FromOU -LDAPPath $PSBoundParameters['LDAPPath']
            } catch {
                Write-Error -Message 'Error when delegating Pre-Win2000 cleanup from OU permission'
            } #end Try-Catch

            # Remove ACCOUNT OPERATORS 2000 Access group from OU
            try {
                Remove-AccountOperator -LDAPPath $PSBoundParameters['LDAPPath']
            } catch {
                Write-Error -Message 'Error when delegating AccountOperators cleanup permission'
            } #end Try-Catch

            # Remove PRINT OPERATORS 2000 Access group from OU
            try {
                Remove-PrintOperator -LDAPPath $PSBoundParameters['LDAPPath']
            } catch {
                Write-Error -Message 'Error when delegating PrintOperators cleanup permission'
            } #end Try-Catch

            If ($PsBoundParameters['RemoveAuthenticatedUsers']) {
                # Remove AUTHENTICATED USERS group from OU
                try {
                    Remove-AuthUser -LDAPPath $PSBoundParameters['LDAPPath']
                } catch {
                    Write-Error -Message 'Error when delegating Authenticated Users cleanup permission'
                } #end Try-Catch

                Write-Verbose -Message 'Removing Authenticated Users'
            }  #end If

            If ($PsBoundParameters['$RemoveUnknownSIDs']) {
                # Remove Un-Resolvable SID from a given object
                try {
                    Remove-UnknownSID -LDAPPath $PSBoundParameters['LDAPPath'] -RemoveSID
                } catch {
                    Write-Error -Message 'Error when removing Unknown SIDs'
                } #end Try-Catch

                Write-Verbose -Message 'Remove Un-Resolvable / Unknown SIDs'
            } #end If
        } #end If

    } #end Process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'removing Builtin groups.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
