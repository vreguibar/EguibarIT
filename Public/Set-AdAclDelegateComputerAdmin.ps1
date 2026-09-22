# Group together all COMPUTER admin delegations
function Set-AdAclDelegateComputerAdmin {
    <#
        .SYNOPSIS
            Configures comprehensive computer management delegations in Active Directory.

        .DESCRIPTION
            This function consolidates all rights needed for complete computer object management
            in Active Directory. It configures permissions for:
            - Computer creation and deletion
            - Password management
            - DNS and SPN management
            - Account restrictions
            - BitLocker and TPM
            - LAPS (Local Administrator Password Solution)
            - Remote Desktop Gateway settings

            The function supports both granting and removing these delegations, making it
            suitable for managing the complete lifecycle of computer administration rights.

        .PARAMETER Group
            The security group receiving the delegation rights.
            Should be a domain local group following the naming convention "SG_xxx".
            This group will receive all computer management permissions.

        .PARAMETER LDAPPath
            Distinguished Name of the OU where permissions will be applied.
            All computer objects within this OU will be manageable by the specified group.

        .PARAMETER RemoveRule
            When specified, removes the delegated permissions instead of granting them.
            Use this for cleanup or permission revocation.

        .INPUTS
            System.String
            You can pipe group names and LDAP paths to this function.

        .OUTPUTS
            System.Void
            This function does not generate any output.

        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Computers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"

            Grants full computer management rights to the specified group in the given OU.

        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Computers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule

            Removes all computer management delegations from the specified group.

        .EXAMPLE
            $Splat = @{
                Group      = "SG_SiteAdmins_XXXX"
                LDAPPath   = "OU=Computers,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
                RemoveRule = $true
            }
            Set-AdAclDelegateComputerAdmin @Splat

            Using splatting to remove delegations with better code readability.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Set-AdAclCreateDeleteComputer          ║ EguibarIT.DelegationPS
                Set-AdAclResetComputerPassword         ║ EguibarIT.DelegationPS
                Set-AdAclChangeComputerPassword        ║ EguibarIT.DelegationPS
                Set-AdAclValidateWriteDnsHostName      ║ EguibarIT.DelegationPS
                Set-AdAclValidateWriteSPN              ║ EguibarIT.DelegationPS
                Set-AdAclComputerAccountRestriction    ║ EguibarIT.DelegationPS
                Set-AdAclDnsInfo                       ║ EguibarIT.DelegationPS
                Set-AdAclMsTsGatewayInfo              ║ EguibarIT.DelegationPS
                Set-AdAclBitLockerTPM                  ║ EguibarIT.DelegationPS
                Set-DeleteOnlyComputer                 ║ EguibarIT.DelegationPS
                Set-AdAclLaps                          ║ EguibarIT
                Get-CurrentErrorToDisplay              ║ EguibarIT
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Debug                            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Set-AdAclDelegateComputerAdmin.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Security Administration

        .FUNCTIONALITY
            Computer Management Delegation
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation. Accepts SamAccountName, DistinguishedName, SID, or ADGroup object.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [object]
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

        # PARAM3 SWITCH if present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'if present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'if present, the function will not ask for confirmation when performing actions.',
            Position = 3)]
        [Switch]
        $Force

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

        ##############################
        # Variables Definition

        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        $CurrentGroup = Get-AdObjectType -Identity $PSBoundParameters['Group']

        $Splat = @{
            Group    = $CurrentGroup
            LDAPPath = $PSBoundParameters['LDAPpath']
        }

    } #end begin

    process {

        # Check if RemoveRule switch is present.
        if ($PSBoundParameters['RemoveRule']) {
            # Add the parameter to remove the rule
            $Splat.Add('RemoveRule', $true)
        } #end if

        if ($Force -or $PSCmdlet.ShouldProcess('Proceed with delegations?')) {

            # Create/Delete Computers
            try {
                Set-AdAclCreateDeleteComputer @Splat
            } catch {
                Write-Error -Message 'Error when delegating Create/Delete computer permission'
            } #end try-catch

            # Reset Computer Password
            try {
                Set-AdAclResetComputerPassword @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer password reset permission'
            } #end try-catch

            # Change Computer Password
            try {
                Set-AdAclChangeComputerPassword @Splat
            } catch {
                Write-Error -Message 'Error when delegating change computer password permission'
            } #end try-catch

            # Validated write to DNS host name
            try {
                Set-AdAclValidateWriteDnsHostName @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer validate write host DNS permission'
            } #end try-catch

            # Validated write to SPN
            try {
                Set-AdAclValidateWriteSPN @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer validate write SPN permission'
            } #end try-catch

            # Change Computer Account Restriction
            try {
                Set-AdAclComputerAccountRestriction @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer account restriction permission'
            } #end try-catch

            # Change DNS Hostname Info
            try {
                Set-AdAclDnsInfo @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer DNS info permission'
            } #end try-catch

            # Change MS TerminalServices info
            try {
                Set-AdAclMsTsGatewayInfo @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer MS TS gateway permission'
            } #end try-catch

            # Access to BitLocker & TMP info
            try {
                Set-AdAclBitLockerTPM @Splat
            } catch {
                Write-Error -Message 'Error when delegating computer Bitlocker & TPM permission'
            } #end try-catch

            # Grant the right to delete computers from default container. Move Computers
            try {
                Set-DeleteOnlyComputer @Splat
            } catch {
                Write-Error -Message 'Error when delegating delete computer permission'
            } #end try-catch

            # Set LAPS
            try {
                Set-AdAclLaps -ResetGroup $CurrentGroup -ReadGroup $CurrentGroup -LDAPpath $PSBoundParameters['LDAPpath']
            } catch {
                Write-Error -Message 'Error when delegating LAPS reset group permission'
            } #end try-catch
        } #end if

    } #end process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'delegating Computer Admin.'
        )
        Write-Verbose -Message $txt
    } #end end

} #end function
