# Clean OU from default BuiltIn groups
function Start-AdCleanOU
{
    <#
        .Synopsis
            Clean default OU permissions.
        .DESCRIPTION
            The function will remove some of the default premission on
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
                Set-AdAclCreateDeleteUser              | EguibarIT.Delegation
                Set-AdAclCreateDeleteComputer          | EguibarIT.Delegation
                Set-AdAclCreateDeleteGroup             | EguibarIT.Delegation
                Set-AdAclCreateDeleteContact           | EguibarIT.Delegation
                Set-CreateDeleteInetOrgPerson          | EguibarIT.Delegation
                Set-AdAclCreateDeletePrintQueue        | EguibarIT.Delegation
                Remove-PreWin2000                      | EguibarIT.Delegation
                Remove-PreWin2000FromOU                | EguibarIT.Delegation
                Remove-AccountOperator                 | EguibarIT.Delegation
                Remove-PrintOperator                   | EguibarIT.Delegation
                Remove-AuthUser                        | EguibarIT.Delegation
                Remove-UnknownSID                      | EguibarIT.Delegation
        .NOTES
            Version:         1.2
            DateModified:    19/Dec/2017
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    param
    (
        #PARAM1 Distinguished name of the OU to be cleaned
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished name of the OU to be cleaned.',
        Position = 0)]
        [ValidateNotNullOrEmpty()]
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
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

        Write-Verbose -Message 'Removing Account Operators and Print Operators'

        $Parameters = $null
    }
    process {
        $parameters = @{
            Group      = 'Account Operators'
            LDAPPath   = $PSBoundParameters['LDAPPath']
            RemoveRule = $true
        }
        # Remove the Account Operators group from ACL to Create/Delete Users
        Set-AdAclCreateDeleteUser @parameters

        # Remove the Account Operators group from ACL to Create/Delete Computers
        Set-AdAclCreateDeleteComputer @parameters

        # Remove the Account Operators group from ACL to Create/Delete Groups
        Set-AdAclCreateDeleteGroup @parameters

        # Remove the Account Operators group from ACL to Create/Delete Contacts
        Set-AdAclCreateDeleteContact @parameters

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-CreateDeleteInetOrgPerson @parameters

        # Remove the Print Operators group from ACL to Create/Delete PrintQueues
        Set-AdAclCreateDeletePrintQueue @parameters

        # Remove Pre-Windows 2000 Compatible Access group from Admin-User
        Remove-PreWin2000 -LDAPPath $PSBoundParameters['LDAPPath']

        # Remove Pre-Windows 2000 Access group from OU
        Remove-PreWin2000FromOU -LDAPPath $PSBoundParameters['LDAPPath']

        # Remove ACCOUNT OPERATORS 2000 Access group from OU
        Remove-AccountOperator -LDAPPath $PSBoundParameters['LDAPPath']

        # Remove PRINT OPERATORS 2000 Access group from OU
        Remove-PrintOperator -LDAPPath $PSBoundParameters['LDAPPath']

        If($PsBoundParameters['RemoveAuthenticatedUsers']) {
            # Remove AUTHENTICATED USERS group from OU
            Remove-AuthUser -LDAPPath $PSBoundParameters['LDAPPath']

            Write-Verbose -Message 'Removing Authenticated Users'
        }

        If($PsBoundParameters['$RemoveUnknownSIDs']) {
            # Remove Un-Resolvable SID from a given object
            Remove-UnknownSID -LDAPPath $PSBoundParameters['LDAPPath'] -RemoveSID

            Write-Verbose -Message 'Remove Un-Resolvable / Unknown SIDs'
        }

    }
    end {
        Write-Verbose -Message('Builtin groups were removed correctly from object {0}.' -f $PSBoundParameters['LDAPPath'])
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}