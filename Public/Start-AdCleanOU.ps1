# Clean OU from default BuiltIn groups
function Start-AdCleanOU {
    <#
        .SYNOPSIS
            Cleans default OU permissions by removing built-in groups.

        .DESCRIPTION
            Removes default permissions from specified OU, including:
            - Account Operators built-in group
            - Print Operators built-in group
            - Pre-Windows 2000 Compatible Access group
            - Optionally removes Authenticated Users
            - Optionally removes unresolvable SIDs

            Implements comprehensive error handling and logging for each operation.

        .PARAMETER LDAPPath
            [String] Distinguished name of the OU to clean.
            Must be a valid LDAP path in the current domain.

        .PARAMETER RemoveAuthenticatedUsers
            [Switch] Remove Authenticated Users group.
            CAUTION: May affect GPO application.

        .PARAMETER RemoveUnknownSIDs
            [Switch] Remove unresolvable SIDs from ACL.
            Helps clean up orphaned permissions.

        .EXAMPLE
            Start-AdCleanOU -LDAPPath "OU=IT,DC=EguibarIT,DC=local"

            Removes built-in groups from IT OU.

        .EXAMPLE
            $params = @{
                LDAPPath = "OU=Admin,DC=EguibarIT,DC=local"
                RemoveAuthenticatedUsers = $true
                RemoveUnknownSIDs = $true
            }
            Start-AdCleanOU @params -Verbose

            Removes all default groups and unknown SIDs with verbose logging.

        .OUTPUTS
            [void]

        .NOTES
            Used Functions:
                Name                                   ║ Module
                ═══════════════════════════════════════╬════════════════════════
                Set-AdAclCreateDeleteUser              ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteComputer          ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGroup             ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteContact           ║ EguibarIT.DelegationPS
                Set-CreateDeleteInetOrgPerson          ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeletePrintQueue        ║ EguibarIT.DelegationPS
                Remove-PreWin2000                      ║ EguibarIT.DelegationPS
                Remove-PreWin2000FromOU                ║ EguibarIT.DelegationPS
                Remove-AccountOperator                 ║ EguibarIT.DelegationPS
                Remove-PrintOperator                   ║ EguibarIT.DelegationPS
                Remove-AuthUser                        ║ EguibarIT.DelegationPS
                Remove-UnknownSID                      ║ EguibarIT.DelegationPS
                Get-CurrentErrorToDisplay              ║ EguibarIT
                Get-FunctionDisplay                    ║ EguibarIT
                Get-ADGroup                            ║ ActiveDirectory
        .NOTES
            Version:         1.3
            DateModified:   31/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT
        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models

    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([void])]

    param (
        #PARAM1 Distinguished name of the OU to be cleaned
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished name of the OU to be cleaned.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        #PARAM2 Remove Authenticated Users
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remove Authenticated Users.',
            Position = 1)]
        [switch]
        $RemoveAuthenticatedUsers,

        #PARAM3 Remove Unknown SIDs
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remove Unknown SIDs.',
            Position = 2)]
        [switch]
        $RemoveUnknownSIDs,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'If present, the function will not ask for confirmation when performing actions.',
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
                (Get-Date).ToShortDateString(),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Module imports

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Get Account Operators group
        try {

            $AccountOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-548' }

            $Splat = @{
                Group      = $AccountOperators
                LDAPPath   = $PSBoundParameters['LDAPpath']
                RemoveRule = $true
            }

        } catch {

            Write-Error -Message ('Failed to get Account Operators group: {0}' -f $_.Exception.Message)
            throw

        } #end try-catch
    } #end Begin

    process {

        if ($PSCmdlet.ShouldProcess($LDAPpath, 'Clean OU permissions')) {

            # For operations that need additional confirmation
            if ($Force -or $PSCmdlet.ShouldContinue(
                    "This will remove all built-in groups from OU '$LDAPpath', which may affect permissions. Continue?",
                    'Confirm Permission Changes')) {

                # Remove the Account Operators group from ACL to Create/Delete Users
                try {
                    Set-AdAclCreateDeleteUser @Splat
                } catch {
                    Write-Error -Message 'Error when delegating user Create/Delete cleanup permission'
                } #end Try-Catch


                # Remove the Account Operators group from ACL to Create/Delete Computers
                try {
                    Set-AdAclCreateDeleteComputer @Splat
                } catch {
                    Write-Error -Message 'Error when delegating computer cleanup permission'
                } #end Try-Catch


                # Remove the Account Operators group from ACL to Create/Delete Groups
                try {
                    Set-AdAclCreateDeleteGroup @Splat
                } catch {
                    Write-Error -Message 'Error when delegating group cleanup permission'
                } #end Try-Catch


                # Remove the Account Operators group from ACL to Create/Delete Contacts
                try {
                    Set-AdAclCreateDeleteContact @Splat
                } catch {
                    Write-Error -Message 'Error when delegating contact cleanup permission'
                } #end Try-Catch


                # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
                try {
                    Set-CreateDeleteInetOrgPerson @Splat
                } catch {
                    Write-Error -Message 'Error when delegating InetOrg cleanup permission'
                } #end Try-Catch


                # Remove the Print Operators group from ACL to Create/Delete PrintQueues
                try {
                    Set-AdAclCreateDeletePrintQueue @Splat
                } catch {
                    Write-Error -Message 'Error when delegating PrintQueue Create/Delete cleanup permission'
                } #end Try-Catch


                # Remove Pre-Windows 2000 Compatible Access group from Admin-User
                try {
                    Remove-PreWin2000 -LDAPPath $PSBoundParameters['LDAPPath']
                } catch {
                    Write-Error -Message 'Error when delegating Pre-Win2000 cleanup permission'
                } #end Try-Catch


                # Remove Pre-Windows 2000 Access group from OU
                try {
                    Remove-PreWin2000FromOU -LDAPPath $PSBoundParameters['LDAPPath']
                } catch {
                    Write-Error -Message 'Error when delegating Pre-Win2000 cleanup from OU permission'
                } #end Try-Catch


                # Remove ACCOUNT OPERATORS 2000 Access group from OU
                try {
                    Remove-AccountOperator -LDAPPath $PSBoundParameters['LDAPPath']
                } catch {
                    Write-Error -Message 'Error when delegating AccountOperators cleanup permission'
                } #end Try-Catch


                # Remove PRINT OPERATORS 2000 Access group from OU
                try {
                    Remove-PrintOperator -LDAPPath $PSBoundParameters['LDAPPath']
                } catch {
                    Write-Error -Message 'Error when delegating PrintOperators cleanup permission'
                } #end Try-Catch


                If ($PsBoundParameters['RemoveAuthenticatedUsers']) {
                    # Remove AUTHENTICATED USERS group from OU
                    try {
                        Remove-AuthUser -LDAPPath $PSBoundParameters['LDAPPath']
                    } catch {
                        Write-Error -Message 'Error when delegating Authenticated Users cleanup permission'
                    } #end Try-Catch

                    Write-VerboseDebug -Message 'Removing Authenticated Users'
                }  #end If

                If ($PsBoundParameters['$RemoveUnknownSIDs']) {
                    # Remove Un-Resolvable SID from a given object
                    try {
                        Remove-UnknownSID -LDAPPath $PSBoundParameters['LDAPPath'] -RemoveSID
                    } catch {
                        Write-Error -Message 'Error when removing Unknown SIDs'
                    } #end Try-Catch

                    Write-Debug -Message 'Remove Un-Resolvable / Unknown SIDs'
                } #end If
            } #end if ShouldContinue
        } #end If

    } #end Process

    end {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'removing Builtin groups.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End

} #end Function Start-ADCleanOU
