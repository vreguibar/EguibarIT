# Delegate Local Administration Password Service (LAPS)
function Set-AdAclLaps {
    <#
        .SYNOPSIS
            Configures all delegated rights for Local Administrator Password Solution (LAPS) on a container.

        .DESCRIPTION
            Consolidates all rights used for LAPS on a given container. Configures:
            - Computer self-permission to update own LAPS password
            - Read permission for the specified read group
            - Reset permission for the specified reset group

        .PARAMETER ReadGroup
            [Object] Identity of the group that is allowed to READ the LAPS password.
            Accepts SamAccountName, DistinguishedName, SID, or ADGroup object.

        .PARAMETER ResetGroup
            [Object] Identity of the group that is allowed to RESET the LAPS password.
            Accepts SamAccountName, DistinguishedName, SID, or ADGroup object.

        .PARAMETER LDAPPath
            [String] Distinguished Name of the OU where LAPS will apply to computer objects.

        .EXAMPLE
            Set-AdAclLaps -ResetGroup 'SG_SiteAdmins_XXXX' -ReadGroup 'SG_GalAdmins_XXXX' -LDAPPath 'OU=Computers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local'

            Configures LAPS delegation on the specified OU.

        .EXAMPLE
            $Splat = @{
                ResetGroup = 'SG_SiteAdmins_GOOD'
                ReadGroup  = 'SG_GalAdmins_GOOD'
                LDAPPath   = 'OU=Computers,OU=GOOD,OU=Sites,DC=EguibarIT,DC=local'
            }
            Set-AdAclLaps @Splat

            Configures LAPS delegation using splatting.

        .EXAMPLE
            Set-AdAclLaps -ResetGroup 'SG_SiteAdmins_XXXX' -ReadGroup 'SG_GalAdmins_XXXX' -LDAPPath 'OU=Computers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local' -WhatIf

            Shows what would happen when configuring LAPS delegation.

        .INPUTS
            [System.String]
            You can pipe the group names or LDAP path to this function.

        .OUTPUTS
            [void]
            This function does not return any output.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Set-AdmPwdComputerSelfPermission       ║ EguibarIT.DelegationPS
                Set-AdmPwdReadPasswordPermission       ║ EguibarIT.DelegationPS
                Set-AdmPwdResetPasswordPermission      ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    21/Sep/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Set-AdAclLaps.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Security Administration

        .FUNCTIONALITY
            LAPS Delegation Management
    #>

    [System.Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseSingularNouns', '', Justification = 'LAPS is an acronym; the trailing S is not a plural suffix')]
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group allowed to READ the LAPS password. Accepts SamAccountName, DistinguishedName, SID, or ADGroup object.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [object]
        $ReadGroup,

        # PARAM2 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group allowed to RESET the LAPS password. Accepts SamAccountName, DistinguishedName, SID, or ADGroup object.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [object]
        $ResetGroup,

        # PARAM3 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where LAPS will apply to computer object',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath
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
        } #end if

        ##############################
        # Module imports
        Import-Module -Name 'LAPS' -Verbose:$false

        ##############################
        # Variables Definition

        Get-AttributeSchemaHashTable

        # Get the SID of the group
        $currentResetGroup = Get-AdObjectType -Identity $PSBoundParameters['ResetGroup']
        $currentReadGroup = Get-AdObjectType -Identity $PSBoundParameters['ReadGroup']

    } #end begin

    process {
        <#
        LEGACY LAPS not used anymore.

        if ($Variables.guidmap['ms-Mcs-AdmPwd']) {
            # AdmPwd.PS CMDlets
            Set-AdmPwdComputerSelfPermission -LDAPpath $LDAPpath
            Set-AdmPwdReadPasswordPermission -Group $currentReadGroup -LDAPpath $PSBoundParameters['LDAPpath']
            Set-AdmPwdResetPasswordPermission -Group $currentResetGroup -LDAPpath $PSBoundParameters['LDAPpath']
        } else {
            Write-Error -Message 'Not Implemented. Schema does not contains the required attributes for legacy LAPS.'
        } #end if-Else
        #>

        if ($PSCmdlet.ShouldProcess($LDAPpath, 'Configure LAPS delegation')) {

            if ($Variables.GuidMap['msLAPS-Password']) {

                Write-Verbose -Message 'LAPS is supported on this environment. We can proceed to configure it.'

                # LAPS CMDlets
                Set-LapsADComputerSelfPermission -Identity $LDAPpath
                Set-LapsADReadPasswordPermission -AllowedPrincipals $currentReadGroup.SID -Identity $PSBoundParameters['LDAPpath']
                Set-LapsADResetPasswordPermission -AllowedPrincipals $currentResetGroup.SID -Identity $PSBoundParameters['LDAPpath']

            } else {
                Write-Error -Message 'Not Implemented. Schema does not contains the required attributes for Windows LAPS.'
            } #end if-Else

        } #end if ShouldProcess
    } #end process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'delegating LAPS Admin.'
        )
        Write-Verbose -Message $txt
    } #end end

} #end function
