# Group together all USER admin delegations
function Set-AdAclDelegateUserAdmin {
    <#
        .SYNOPSIS
            Configures comprehensive user object management delegations in Active Directory.

        .DESCRIPTION
            Consolidates all rights used for user object management. The function
            configures permissions for:
            - User account creation and deletion
            - Password reset and change
            - Account enable/disable and unlock
            - Account restrictions and logon information
            Supports both granting and removing delegations via -RemoveRule.

        .PARAMETER Group
            [Object] Security group receiving the user administration delegation rights.
            Accepts SamAccountName, DistinguishedName, SID, or ADGroup object.

        .PARAMETER LDAPPath
            [String] Distinguished Name of the OU where permissions will be applied.
            Must be a valid AD path.

        .PARAMETER RemoveRule
            [Switch] When specified, removes delegated permissions instead of granting them.

        .EXAMPLE
            Set-AdAclDelegateUserAdmin -Group 'SG_SiteAdmins_XXXX' -LDAPPath 'OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local'

            Grants full user management rights to the specified group.

        .EXAMPLE
            Set-AdAclDelegateUserAdmin -Group 'SG_SiteAdmins_XXXX' -LDAPPath 'OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local' -RemoveRule

            Removes user management rights from the specified group.

        .EXAMPLE
            $Splat = @{
                Group    = 'SG_SiteAdmins_GOOD'
                LDAPPath = 'OU=Users,OU=GOOD,OU=Sites,DC=EguibarIT,DC=local'
            }
            Set-AdAclDelegateUserAdmin @Splat -WhatIf

            Shows what would happen when granting user admin rights.

        .INPUTS
            [System.String]
            You can pipe the group name or LDAP path to this function.

        .OUTPUTS
            [void]
            This function does not return any output.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Set-AdAclCreateDeleteUser              ║ EguibarIT.DelegationPS
                Set-AdAclResetUserPassword             ║ EguibarIT.DelegationPS
                Set-AdAclChangeUserPassword            ║ EguibarIT.DelegationPS
                Set-AdAclEnableDisableUser             ║ EguibarIT.DelegationPS
                Set-AdAclUnlockUser                    ║ EguibarIT.DelegationPS
                Set-AdAclUserAccountRestriction        ║ EguibarIT.DelegationPS
                Set-AdAclUserLogonInfo                 ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:    21/Sep/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Set-AdAclDelegateUserAdmin.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Security Administration

        .FUNCTIONALITY
            User Object Delegation Management
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation. Accepts SamAccountName, DistinguishedName, SID, or ADGroup object.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [object]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group can read the User password
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a User object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
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
        $RemoveRule,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'If present, the function will not ask for confirmation when performing actions.',
            Position = 3)]
        [Switch]
        $Force
    )

    begin {
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

    process {
        try {
            # Check if RemoveRule switch is present.
            if ($PSBoundParameters['RemoveRule']) {
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
    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'delegating User Admin.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
