# Group together all USER admin delegations
function Set-AdAclDelegateGalAdmin
{
    <#
        .Synopsis
            The function will consolidate all rights used for GAL admin.
        .DESCRIPTION

        .EXAMPLE
            Set-AdAclDelegateGalAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            Set-AdAclDelegateGalAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .INPUTS
            Param1 Group:........[STRING] for the Delegated Group Name
            Param2 LDAPPath:.....[STRING] Distinguished Name of the OU where given group will manage a User GAL.
            Param3 RemoveRule:...[SWITCH] If present, the access rule will be removed
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

        # PARAM2 Distinguished Name of the OU where given group will manage a User GAL.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will manage a User GAL.',
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
    begin
    {
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
    Process
    {
        try
        {
            $parameters = @{
                Group    = $PSBoundParameters['Group']
                LDAPPath = $PSBoundParameters['LDAPpath']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule'])
            {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }

            # Change Group Membership
            Set-AdAclUserGroupMembership @parameters

            # Change Personal Information
            Set-AdAclUserPersonalInfo @parameters

            # Change Public Information
            Set-AdAclUserPublicInfo @parameters

            # Change General Information
            Set-AdAclUserGeneralInfo @parameters

            # Change Web Info
            Set-AdAclUserWebInfo @parameters

            # Change Email Info
            Set-AdAclUserEmailInfo @parameters
        }
        catch { throw }
    }
    End
    {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating GAL Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}