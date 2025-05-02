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
    [OutputType([void])]

    Param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a computer object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
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
        $error.Clear()

        $txt = ($Variables.Header -f
            (Get-Date).ToString('dd/MMM/yyyy'),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
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
                Write-Error -Message 'Error when delegating Create/Delete computer permission'
            } #end Try-Catch

            # Reset Computer Password
            try {
                Set-AdAclResetComputerPassword @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer password reset permission'
            } #end Try-Catch

            # Change Computer Password
            try {
                Set-AdAclChangeComputerPassword @Splat
            } catch {
                Write-Error -Message 'Error when delegating change computer password permission'
            } #end Try-Catch

            # Validated write to DNS host name
            try {
                Set-AdAclValidateWriteDnsHostName @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer validate write host DNS permission'
            } #end Try-Catch

            # Validated write to SPN
            try {
                Set-AdAclValidateWriteSPN @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer validate write SPN permission'
            } #end Try-Catch

            # Change Computer Account Restriction
            try {
                Set-AdAclComputerAccountRestriction @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer account restriction permission'
            } #end Try-Catch

            # Change DNS Hostname Info
            try {
                Set-AdAclDnsInfo @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer DNS info permission'
            } #end Try-Catch

            # Change MS TerminalServices info
            try {
                Set-AdAclMsTsGatewayInfo @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer MS TS gateway permission'
            } #end Try-Catch

            # Access to BitLocker & TMP info
            try {
                Set-AdAclBitLockerTPM @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer Bitlocker & TPM permission'
            } #end Try-Catch

            # Grant the right to delete computers from default container. Move Computers
            try {
                Set-DeleteOnlyComputer @Splat
            } catch {
                Write-Error -Message 'Error when delegating delete computer permission'
            } #end Try-Catch

            # Set LAPS
            try {
                Set-AdAclLaps -ResetGroup $CurrentGroup -ReadGroup $CurrentGroup -LDAPpath $PSBoundParameters['LDAPpath']
            } catch {
                Write-Error -Message 'Error when delegating LAPS reset group permission'
            } #end Try-Catch
        } #end If

    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'delegating Computer Admin.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
