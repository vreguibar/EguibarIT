# Group together all USER admin delegations
function Set-AdAclDelegateGalAdmin {
    <#
        .Synopsis
            Wrapper for all rights used for GAL admin.
        .DESCRIPTION
            The function will consolidate all rights used for GAL admin.
        .EXAMPLE
            Set-AdAclDelegateGalAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdAclDelegateGalAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            Delegated Group Name
        .PARAMETER LDAPPath
            Distinguished Name of the OU where given group will manage a User GAL.
        .PARAMETER RemoveRule
            If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AdAclUserGroupMembership           | EguibarIT.DelegationPS
                Set-AdAclUserPersonalInfo              | EguibarIT.DelegationPS
                Set-AdAclUserPublicInfo                | EguibarIT.DelegationPS
                Set-AdAclUserGeneralInfo               | EguibarIT.DelegationPS
                Set-AdAclUserWebInfo                   | EguibarIT.DelegationPS
                Set-AdAclUserEmailInfo                 | EguibarIT.DelegationPS
                Get-CurrentErrorToDisplay              | EguibarIT
                Get-FunctionDisplay                    | EguibarIT
        .NOTES
        .NOTES
            Version:         1.1
            DateModified:    12/Feb/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group will manage a User GAL.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will manage a User GAL.',
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
                # Change Group Membership
                Set-AdAclUserGroupMembership @Splat

                # Change Personal Information
                Set-AdAclUserPersonalInfo @Splat

                # Change Public Information
                Set-AdAclUserPublicInfo @Splat

                # Change General Information
                Set-AdAclUserGeneralInfo @Splat

                # Change Web Info
                Set-AdAclUserWebInfo @Splat

                # Change Email Info
                Set-AdAclUserEmailInfo @Splat
            } #end If
        } catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        }
    } #end Process
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating GAL Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} #end Function
