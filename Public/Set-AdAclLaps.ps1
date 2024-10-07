# Delegate Local Administration Password Service (LAPS)
function Set-AdAclLaps {
    <#
        .Synopsis
            Wrapper for all rights used for LAPS on a given container.
        .DESCRIPTION
            The function will consolidate all rights used for LAPS on a given container.
        .EXAMPLE
            Set-AdAclLaps -ResetGroup "SG_SiteAdmins_XXXX" -ReadGroup "SG_GalAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .PARAMETER ReadGroup
            Identity of the group getting being able to READ the password
        .PARAMETER ResetGroup
            Identity of the group getting being able to RESET the password
        .PARAMETER LDAPPath
            Distinguished Name of the OU where LAPS will apply to computer object.
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
    [OutputType([void])]

    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting being able to READ the password.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $ReadGroup,

        # PARAM2 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting being able to RESET the password.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        $ResetGroup,

        # PARAM3 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where LAPS will apply to computer object',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath
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
        Import-Module -Name 'LAPS' -Verbose:$false

        ##############################
        # Variables Definition

        Get-AttributeSchemaHashTable

        # Get the SID of the group
        $currentResetGroup = Get-AdObjectType -Identity $PSBoundParameters['ResetGroup']
        $currentReadGroup = Get-AdObjectType -Identity $PSBoundParameters['ReadGroup']

    } #end Begin

    Process {
        <#
        LEGACY LAPS not used anymore.

        if ($Variables.guidmap['ms-Mcs-AdmPwd']) {
            # AdmPwd.PS CMDlets
            Set-AdmPwdComputerSelfPermission -LDAPpath $LDAPpath
            Set-AdmPwdReadPasswordPermission -Group $currentReadGroup -LDAPpath $PSBoundParameters['LDAPpath']
            Set-AdmPwdResetPasswordPermission -Group $currentResetGroup -LDAPpath $PSBoundParameters['LDAPpath']
        } else {
            Write-Error -Message 'Not Implemented. Schema does not contains the required attributes for legacy LAPS.'
        } #end If-Else
        #>

        if ($Variables.GuidMap['ms-Mcs-AdmPwdExpirationTime']) {

            Write-Verbose -Message 'LAPS is supported on this environment. We can proceed to configure it.'

            # LAPS CMDlets
            Set-LapsADComputerSelfPermission -Identity $LDAPpath
            Set-LapsADReadPasswordPermission -AllowedPrincipals $currentReadGroup.SID -Identity $PSBoundParameters['LDAPpath']
            Set-LapsADResetPasswordPermission -AllowedPrincipals $currentResetGroup.SID -Identity $PSBoundParameters['LDAPpath']

        } else {
            Write-Error -Message 'Not Implemented. Schema does not contains the required attributes for Windows LAPS.'
        } #end If-Else
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'delegating LAPS Admin.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
