# Group together all USER admin delegations
function Set-AdAclDelegateUserAdmin {
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
                Set-AdAclCreateDeleteUser              | EguibarIT.DelegationPS
                Set-AdAclResetUserPassword             | EguibarIT.DelegationPS
                Set-AdAclChangeUserPassword            | EguibarIT.DelegationPS
                Set-AdAclEnableDisableUser             | EguibarIT.DelegationPS
                Set-AdAclUnlockUser                    | EguibarIT.DelegationPS
                Set-AdAclUserAccountRestriction        | EguibarIT.DelegationPS
                Set-AdAclUserLogonInfo                 | EguibarIT.DelegationPS
                Get-CurrentErrorToDisplay              | EguibarIT
                Get-FunctionDisplay                    | EguibarIT
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
        [validateScript({ Test-IsValidDN -ObjectDN $_ })]
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
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        $Splat = @{
            Group    = $PSBoundParameters['Group']
            LDAPPath = $PSBoundParameters['LDAPpath']
        }
    } #end Begin
    Process {
        try {
            # Check if RemoveRule switch is present.
            If ($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            }

            if ($Force -or $PSCmdlet.ShouldProcess('Proceed with delegations?')) {
                # Create/Delete Users
                Set-AdAclCreateDeleteUser @Splat

                # Reset User Password
                Set-AdAclResetUserPassword @Splat

                # Change User Password
                Set-AdAclChangeUserPassword @Splat

                # Enable and/or Disable user right
                Set-AdAclEnableDisableUser @Splat

                # Unlock user account
                Set-AdAclUnlockUser @Splat

                # Change User Restrictions
                Set-AdAclUserAccountRestriction @Splat

                # Change User Account Logon Info
                Set-AdAclUserLogonInfo @Splat
            } #end Id
        } catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch
    } #end Process
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating User Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} #end Function
