# Delegate Local Administration Password Service (LAPS)
function Set-AdAclLaps
{
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
                Set-AdmPwdComputerSelfPermission       | EguibarIT.Delegation
                Set-AdmPwdReadPasswordPermission       | EguibarIT.Delegation
                Set-AdmPwdResetPasswordPermission      | EguibarIT.Delegation
                Get-AttributeSchemaHashTable           | EguibarIT.Delegation
        .NOTES
            Version:         1.0
            DateModified:    19/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    Param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting being able to READ the password.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ReadGroup,

        # PARAM2 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting being able to RESET the password.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ResetGroup,

        # PARAM3 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where LAPS will apply to computer object',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
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

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

        Import-Module -Name 'AdmPwd.PS' -Force -Verbose:$false

        $guidmap = $null
        $guidmap = @{}
        $guidmap = Get-AttributeSchemaHashTable
    }
    Process {
        if(-not($null -eq $guidmap["ms-Mcs-AdmPwdExpirationTime"])) {
            Write-Verbose -Message "LAPS is supported on this environment. We can proceed to configure it."

            Set-AdmPwdComputerSelfPermission -Identity $LDAPpath

            Set-AdmPwdReadPasswordPermission -AllowedPrincipals $ReadGroup -Identity $LDAPpath

            Set-AdmPwdResetPasswordPermission -AllowedPrincipals $ResetGroup -Identity $LDAPpath
        } else {
            Write-Error -Message "Not Implemented. Schema does not contains the requiered attributes."
        }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating LAPS Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
