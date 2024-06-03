# Group together all COMPUTER admin delegations
function Set-AdAclDelegateComputerAdmin {
    <#
        .Synopsis
            Wrapper for all rights used for Computer object container.
        .DESCRIPTION
            The function will consolidate all rights used for Computer object container.
        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .PARAMETER Group
            Delegated Group Name
        .PARAMETER LDAPPath
            Distinguished Name of the OU where given group will fully manage a computer object.
        .PARAMETER RemoveRule
            If present, the access rule will be removed
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AdAclCreateDeleteComputer          | EguibarIT.DelegationPS
                Set-AdAclResetComputerPassword         | EguibarIT.DelegationPS
                Set-AdAclChangeComputerPassword        | EguibarIT.DelegationPS
                Set-AdAclValidateWriteDnsHostName      | EguibarIT.DelegationPS
                Set-AdAclValidateWriteSPN              | EguibarIT.DelegationPS
                Set-AdAclComputerAccountRestriction    | EguibarIT.DelegationPS
                Set-AdAclDnsInfo                       | EguibarIT.DelegationPS
                Set-AdAclMsTsGatewayInfo               | EguibarIT.DelegationPS
                Set-AdAclBitLockerTPM                  | EguibarIT.DelegationPS
                Set-DeleteOnlyComputer                 | EguibarIT.DelegationPS
                Set-AdAclLaps                          | EguibarIT
                Get-CurrentErrorToDisplay              | EguibarIT
                Get-FunctionDisplay                    | EguibarIT
                Test-IsValidDN -ObjectDN               | EguibarIT
        .NOTES
            Version:         1.0
            DateModified:    19/Oct/2016
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

        # PARAM2 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a computer object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [validateScript({ Test-IsValidDN -ObjectDN $_ })]
        [String]
        $LDAPpath,

        # PARAM3 Distinguished Name of the quarantine OU
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the quarantine OU',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [validateScript({ Test-IsValidDN -ObjectDN $_ })]
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
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $Splat.Add('RemoveRule', $true)
            }

            if ($Force -or $PSCmdlet.ShouldProcess("Proceed with delegations?")) {
            # Create/Delete Computers
                Set-AdAclCreateDeleteComputer @Splat

                # Reset Computer Password
                Set-AdAclResetComputerPassword @Splat

                # Change Computer Password
                Set-AdAclChangeComputerPassword @Splat

                # Validated write to DNS host name
                Set-AdAclValidateWriteDnsHostName @Splat

                # Validated write to SPN
                Set-AdAclValidateWriteSPN @Splat

                # Change Computer Account Restriction
                Set-AdAclComputerAccountRestriction @Splat

                # Change DNS Hostname Info
                Set-AdAclDnsInfo @Splat

                # Change MS TerminalServices info
                Set-AdAclMsTsGatewayInfo @Splat

                # Access to BitLocker & TMP info
                Set-AdAclBitLockerTPM @Splat

                # Grant the right to delete computers from default container. Move Computers
                Set-DeleteOnlyComputer -Group $PSBoundParameters['Group'] -LDAPPath $PSBoundParameters['QuarantineDN']

                # Set LAPS
                Set-AdAclLaps -ResetGroup $PSBoundParameters['Group'] -ReadGroup $PSBoundParameters['Group'] -LDAPPath $PSBoundParameters['LDAPpath']
            } #end If

        } catch {
            ###Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } #end Try-Catch
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Computer Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} #end Function
