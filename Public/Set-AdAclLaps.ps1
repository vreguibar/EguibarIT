# Delegate Local Administration Password Service (LAPS)
function Set-AdAclLaps {
    <#
        .Synopsis
            Wrapper for all rights used for LAPS on a given container.
        .DESCRIPTION
            The function will consolidate all rights used for LAPS on a given container.
        .EXAMPLE
            Set-AdAclLaps -ResetGroup "SG_SiteAdmins_XXXX" -ReadGroup "SG_GalAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdAclLaps -ResetGroup "SG_SiteAdmins_XXXX" -ReadGroup "SG_GalAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER ReadGroup
            Identity of the group getting being able to READ the password
        .PARAMETER ResetGroup
            Identity of the group getting being able to RESET the password
        .PARAMETER LDAPPath
            Distinguished Name of the OU where LAPS will apply to computer object.
        .PARAMETER RemoveRule
            If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AdmPwdComputerSelfPermission       | EguibarIT.DelegationPS
                Set-AdmPwdReadPasswordPermission       | EguibarIT.DelegationPS
                Set-AdmPwdResetPasswordPermission      | EguibarIT.DelegationPS
                Get-AttributeSchemaHashTable           | EguibarIT.DelegationPS
                Get-CurrentErrorToDisplay              | EguibarIT
                Get-FunctionDisplay                    | EguibarIT
                Set-AdmPwdComputerSelfPermission       | AdmPwd.PS
                Set-AdmPwdReadPasswordPermission       | AdmPwd.PS
                Set-AdmPwdResetPasswordPermission      | AdmPwd.PS
        .NOTES
            Version:         1.0
            DateModified:    19/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting being able to READ the password.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $ReadGroup,

        # PARAM2 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting being able to RESET the password.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        $ResetGroup,

        # PARAM3 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where LAPS will apply to computer object',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [validateScript({ Test-IsValidDN -ObjectDN $_ })]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        # PARAM4 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )

    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        Import-MyModule -name 'AdmPwd.PS' -Force -Verbose:$false
        Import-MyModule -name 'LAPS' -Force -Verbose:$false
        Import-MyModule -name 'EguibarIT.DelegationPS' -Force -Verbose:$false

        ##############################
        # Variables Definition

        Get-AttributeSchemaHashTable

        # Get the SID of the group
        $currentResetGroup = Get-AdObjectType -Identity $PSBoundParameters['ResetGroup']
        $currentReadGroup = Get-AdObjectType -Identity $PSBoundParameters['ReadGroup']

    } #end Begin

    Process {

        Write-Verbose -Message 'LAPS is supported on this environment. We can proceed to configure it.'

        if ($null -eq $Variables.guidmap['ms-Mcs-AdmPwd']) {
            # AdmPwd.PS CMDlets
            Set-AdmPwdComputerSelfPermission -Identity $LDAPpath
            Set-AdmPwdReadPasswordPermission -AllowedPrincipals $currentReadGroup -Identity $PSBoundParameters['LDAPpath']
            Set-AdmPwdResetPasswordPermission -AllowedPrincipals $currentResetGroup -Identity $PSBoundParameters['LDAPpath']
        } else {
            Write-Error -Message 'Not Implemented. Schema does not contains the required attributes for legacy LAPS.'
        } #end If-Else

        if ($null -ne $Variables.GuidMap['ms-Mcs-AdmPwdExpirationTime']) {
            # LAPS CMDlets
            Set-LapsADComputerSelfPermission -Identity $LDAPpath
            Set-LapsADReadPasswordPermission -AllowedPrincipals $currentReadGroup.SID -Identity $PSBoundParameters['LDAPpath']
            Set-LapsADResetPasswordPermission -AllowedPrincipals $currentResetGroup.SID -Identity $PSBoundParameters['LDAPpath']

        } else {
            Write-Error -Message 'Not Implemented. Schema does not contains the required attributes for new Windows LAPS.'
        } #end If-Else
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating LAPS Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End

} #end Function
