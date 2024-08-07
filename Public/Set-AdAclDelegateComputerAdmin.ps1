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
        .EXAMPLE
            $Splat = @{
                Group      = "SG_SiteAdmins_XXXX"
                LDAPPath   = "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                RemoveRule = $true
            }
            Set-AdAclDelegateComputerAdmin @Splat
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
        $Group,

        # PARAM2 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a computer object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [validateScript({ Test-IsValidDN -ObjectDN $_ })]
        [Alias('DN', 'DistinguishedName')]
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

        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
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

        # Check if RemoveRule switch is present.
        If ($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $Splat.Add('RemoveRule', $true)
        } #end If

        if ($Force -or $PSCmdlet.ShouldProcess('Proceed with delegations?')) {

            # Create/Delete Computers
            try {
                Set-AdAclCreateDeleteComputer @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Reset Computer Password
            try {
                Set-AdAclResetComputerPassword @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Change Computer Password
            try {
                Set-AdAclChangeComputerPassword @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Validated write to DNS host name
            try {
                Set-AdAclValidateWriteDnsHostName @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Validated write to SPN
            try {
                Set-AdAclValidateWriteSPN @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Change Computer Account Restriction
            try {
                Set-AdAclComputerAccountRestriction @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Change DNS Hostname Info
            try {
                Set-AdAclDnsInfo @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Change MS TerminalServices info
            try {
                Set-AdAclMsTsGatewayInfo @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Access to BitLocker & TMP info
            try {
                Set-AdAclBitLockerTPM @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Grant the right to delete computers from default container. Move Computers
            try {
                Set-DeleteOnlyComputer @Splat
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch

            # Set LAPS
            try {
                Set-AdAclLaps -ResetGroup $CurrentGroup -ReadGroup $CurrentGroup -LDAPpath $PSBoundParameters['LDAPpath']
            } catch {
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            } #end Try-Catch
        } #end If
    } #end Process
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Computer Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} #end Function
