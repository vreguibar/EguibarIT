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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group can read the User password
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a User object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    begin {
        $error.Clear()

        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

        $Splat = @{
            Group    = $CurrentGroup
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
            Write-Error -Message 'Error when delegating User permissions'
            throw
        } #end Try-Catch
    } #end Process
    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'delegating User Admin.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
