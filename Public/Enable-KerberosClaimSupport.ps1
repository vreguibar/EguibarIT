function Enable-KerberosClaimSupport {
    <#
        .SYNOPSIS
            Enable claim support in the entire domain.

        .DESCRIPTION
            This function enables claim-based authentication (Cbac) and Armor for Kerberos
            by configuring group policies on domain controllers and clients.

        .PARAMETER DomainDNSName
            The fully qualified domain name (FQDN) of the domain where claim support will be enabled.

        .PARAMETER GeneralGPO
            The name or GUID of the domain-wide general GPO to use. Falls back to the Default Domain Policy if not provided.

        .PARAMETER DomainControllerGPO
            The name or GUID of the domain controller-specific GPO to use.
            Falls back to the Default Domain Controller Policy if not provided.

        .EXAMPLE
            Enable-KerberosClaimSupport -DomainDNSName "EguibarIT.local" -GeneralGPO "Custom-GeneralGPO" -DomainControllerGPO "Custom-DC-GPO"

            Enables claim support in the specified domain using custom GPOs.

        .INPUTS
            [string] - Fully qualified domain name (FQDN) of the domain.
            [string] - Name or GUID of the GPOs.

        .OUTPUTS
            [Void]

        .NOTES
            Used Cmdlets:
                Name                 | Module
                ---------------------|-------------------------
                Get-GPO              | GroupPolicy
                Set-GPRegistryValue  | GroupPolicy
                Write-Verbose        | Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.0
            DateModified:    17/Dec/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([void])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'The fully qualified domain name (FQDN) of the domain where claim support will be enabled.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainDNSName,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'The name or GUID of the domain-wide general GPO. Falls back to Default Domain Policy if not provided.',
            Position = 1)]
        [AllowNull()]
        [string]
        $GeneralGPO,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'The name or GUID of the domain controller-specific GPO. Falls back to Default Domain Controller Policy if not provided.',
            Position = 2)]
        [AllowNull()]
        [string]
        $DomainControllerGPO
    )

    Begin {
        Set-StrictMode -Version Latest
        $error.clear()

        $txt = ($Variables.Header -f
            (Get-Date).ToString('dd/MMM/yyyy'),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false


        ##############################
        # Variables Definition

        $DefaultDomainControllerPolicy = '6AC1786C-016F-11D2-945F-00C04FB984F9'
        $DefaultDomainPolicy = '31B2F340-016D-11D2-945F-00C04FB984F9'

        # Check if domain GPO was parsed
        If ($GeneralGPO) {

            # Initialize $ParsedGuid to null
            [Guid]$ParsedGuid = [Guid]::Empty

            # Resolve based on type
            if ([Guid]::TryParse($GeneralGPO, [ref]$ParsedGuid)) {

                Write-Verbose -Message ('Input {0} is detected as GUID.' -f $GeneralGPO)

                # Get Custom "Domain Wide" GPO by using GUID
                $DomainGPO = Get-GPO -Guid $GeneralGPO -Domain $DomainDNSName -ErrorAction Stop

            } else {

                Write-Verbose -Message ('Input {0} is detected as Name.' -f $GeneralGPO)

                # Get Custom "Domain Wide" GPO by using its name
                $DomainGPO = Get-GPO -Name $GeneralGPO -Domain $DomainDNSName -ErrorAction Stop

            } #end If


            Write-Verbose -Message ('Resolved GPO: {0} to GUID: {1}' -f $DomainGPO.DisplayName, $DomainGPO.Id)

        } else {

            # Use "Default Domain Policy" GPO
            Write-Verbose -Message (
                'Using fallback "DefaultDomainPolicy" GPO GUID: {0}' -f $DefaultDomainPolicy
            )
            $DomainGPO = Get-GPO -Guid $DefaultDomainPolicy -Domain $DomainDNSName -ErrorAction Stop

        } #end If

        # Check if DomainControllers GPO was parsed
        If ($DomainControllerGPO) {

            # Initialize $ParsedGuid to null
            [Guid]$ParsedGuid = [Guid]::Empty

            # Resolve based on type
            if ([Guid]::TryParse($DomainControllerGPO, [ref]$ParsedGuid)) {

                Write-Verbose -Message ('Input {0} is detected as GUID.' -f $DomainControllerGPO)

                # Get Custom "Domain Controller" GPO by using GUID
                $DC_GPO = Get-GPO -Guid $DomainControllerGPO -Domain $DomainDNSName -ErrorAction Stop

            } else {

                Write-Verbose -Message ('Input {0} is detected as Name.' -f $DomainControllerGPO)

                # Get Custom "Domain Wide" GPO by using its name
                $DC_GPO = Get-GPO -Name $DomainControllerGPO -Domain $DomainDNSName -ErrorAction Stop

            }

            Write-Verbose -Message ('Resolved GPO: {0} to GUID: {1}' -f $DC_GPO.DisplayName, $DC_GPO.Id)
        } else {

            # Use "Default Domain Policy" GPO
            Write-Verbose -Message (
                'Using fallback "DefaultDomainControllersPolicy" GPO GUID: {0}' -f $DefaultDomainControllerPolicy
            )
            $DC_GPO = Get-GPO -Guid $DefaultDomainControllerPolicy -Domain $DomainDNSName -ErrorAction Stop

        } #end If

    } # End Begin

    Process {

        # Core Logic for processing each pipeline input
        Write-Verbose -Message ('Processing domain: {0}' -f $DomainDNSName)

        try {
            # Enable Claim Support on Domain Controllers
            $KDCEnableClaim = @{
                GUID      = $DC_GPO.ID
                Key       = 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
                ValueName = 'EnableCbacAndArmor'
                Value     = 1
                Type      = 'DWORD'
            }
            if ($PSCmdlet.ShouldProcess("$DomainDNSName", 'Enable KDC Claim Support')) {

                Set-GPRegistryValue @KDCEnableClaim -Domain $DomainDNSName
                Write-Verbose -Message ('KDC Support enabled in {0}' -f $DomainDNSName)

            } #end If

            # Enable client claim support for domain controllers
            $ClientClaimSupportDC = @{
                GUID      = $DC_GPO.ID
                Key       = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
                ValueName = 'EnableCbacAndArmor'
                Value     = 1
                Type      = 'DWORD'
            }
            if ($PSCmdlet.ShouldProcess("$DomainDNSName", 'Enable Client Claim Support for Domain Controllers')) {

                Set-GPRegistryValue @ClientClaimSupportDC -Domain $DomainDNSName
                Write-Verbose -Message ('Client claim support for domain controllers enabled in {0}' -f $DomainDNSName)

            } #end If
        } catch {
            Write-Error -Message ('Failed to update the Default Domain Controller Policy in {0}. {1}' -f $DomainDNSName, $_)
            Write-Error -Message 'Set Administrative Templates\KDC\Enable Combound authentication to supported'
            Write-Error -Message 'set Administrative Templates\Kerberos\Enabel client support to Enable'
        } #end Try-Catch

        # Enable client claim support on any clients
        try {
            $ClientClaimSupportClients = @{
                GUID      = $DomainGPO.ID
                Key       = 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
                ValueName = 'EnableCbacAndArmor'
                Value     = 1
                Type      = 'DWORD'
            }
            if ($PSCmdlet.ShouldProcess("$DomainDNSName", 'Enable Client Claim Support on Clients')) {

                Set-GPRegistryValue @ClientClaimSupportClients -Domain $DomainDNSName
                Write-Verbose -Message ('Client claim support enabled on every client in {0}' -f $DomainDNSName)

            } #end If
        } catch {
            Write-Error -Message ('Failed to update the Domain Wide Policy in {0}. {1}' -f $DomainDNSName, $_)
            Write-Error -Message 'Enable Administrative Templates\Kerberos\Enable Claim support to enable'
        } #end Try-Catch
    } # End Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'processing Enable-KerberosClaimSupport function.'
        )
        Write-Verbose -Message $txt
    } # End End
} #end Function
