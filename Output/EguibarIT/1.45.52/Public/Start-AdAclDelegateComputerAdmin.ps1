# Group together all COMPUTER admin delegations
function Set-AdAclDelegateComputerAdmin
{
    <#
        .Synopsis
            The function will consolidate all rights used for Computer object container.
        .DESCRIPTION

        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .INPUTS
            Param1 Group:........[STRING] for the Delegated Group Name
            Param2 LDAPPath:.....[STRING] Distinguished Name of the OU where given group will fully manage a computer object.
            Param3 RemoveRule:...[SWITCH] If present, the access rule will be removed
        .NOTES
            Version:         1.0
            DateModified:    19/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a computer object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM3 Distinguished Name of the quarantine OU
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the quarantine OU',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String]
        $QuarantineDN,

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


        $parameters = $null

        # Active Directory Domain Distinguished Name
        If(-Not (Test-Path -Path variable:AdDn))
        {
            New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
        }
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

            # Create/Delete Computers
            Set-AdAclCreateDeleteComputer @parameters

            # Reset Computer Password
            Set-AdAclResetComputerPassword @parameters

            # Change Computer Password
            Set-AdAclChangeComputerPassword @parameters

            # Validated write to DNS host name
            Set-AdAclValidateWriteDnsHostName @parameters

            # Validated write to SPN
            Set-AdAclValidateWriteSPN @parameters

            # Change Computer Account Restriction
            Set-AdAclComputerAccountRestriction @parameters

            # Change DNS Hostname Info
            Set-AdAclDnsInfo @parameters

            # Change MS TerminalServices info
            Set-AdAclMsTsGatewayInfo @parameters

            # Access to BitLocker & TMP info
            Set-AdAclBitLockerTPM @parameters

            # Grant the right to delete computers from default container. Move Computers
            Set-DeleteOnlyComputer -Group $PSBoundParameters['Group'] -LDAPPath $PSBoundParameters['QuarantineDN']

            # Set LAPS
            Set-AdAclLaps -ResetGroup $PSBoundParameters['Group'] -ReadGroup $PSBoundParameters['Group'] -LDAPPath $PSBoundParameters['LDAPpath']

        }
        catch { throw }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Computer Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}