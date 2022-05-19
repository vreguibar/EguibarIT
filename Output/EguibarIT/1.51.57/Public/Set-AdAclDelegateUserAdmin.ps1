# Group together all USER admin delegations
function Set-AdAclDelegateUserAdmin
{
    <#
        .Synopsis
            Wrapper for all rights used for USER object container.
        .DESCRIPTION
            The function will consolidate all rights used for USER object container.
        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            Delegated Group Name
        .PARAMETER LDAPPath
            Distinguished Name of the OU where given group will fully manage a User object.
        .PARAMETER RemoveRule
            If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AdAclCreateDeleteUser              | EguibarIT.Delegation
                Set-AdAclResetUserPassword             | EguibarIT.Delegation
                Set-AdAclChangeUserPassword            | EguibarIT.Delegation
                Set-AdAclEnableDisableUser             | EguibarIT.Delegation
                Set-AdAclUnlockUser                    | EguibarIT.Delegation
                Set-AdAclUserAccountRestriction        | EguibarIT.Delegation
                Set-AdAclUserLogonInfo                 | EguibarIT.Delegation
        .NOTES
            Version:         1.1
            DateModified:    12/Feb/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group can read the User password
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a User object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )
    begin {
        $error.Clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

        $parameters = $null
    }
    Process {
        try {
            $parameters = @{
                Group    = $PSBoundParameters['Group']
                LDAPPath = $PSBoundParameters['LDAPpath']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }

            # Create/Delete Users
            Set-AdAclCreateDeleteUser @parameters

            # Reset User Password
            Set-AdAclResetUserPassword @parameters

            # Change User Password
            Set-AdAclChangeUserPassword @parameters

            # Enable and/or Disable user right
            Set-AdAclEnableDisableUser @parameters

            # Unlock user account
            Set-AdAclUnlockUser @parameters

            # Change User Restrictions
            Set-AdAclUserAccountRestriction @parameters

            # Change User Account Logon Info
            Set-AdAclUserLogonInfo @parameters
        }
        catch { Get-CurrentErrorToDisplay -CurrentError $error[0] }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating User Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}