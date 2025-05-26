function Test-RegistryValue {
    <#
        .SYNOPSIS
            Tests if a specific registry value exists.

        .DESCRIPTION
            This function tests whether a specified registry value exists in a given registry path.
            It provides a safe way to check registry values without throwing errors if the value
            doesn't exist. The function returns a boolean value indicating the existence of the
            specified registry value.

        .PARAMETER Path
            The registry path to check. Must be a valid registry path starting with one of the
            PowerShell registry drives (HKLM:, HKCU:, etc.).

        .PARAMETER Value
            The name of the registry value to test for existence. This is the specific value
            name within the specified registry key.

        .INPUTS
            System.String
            You can pipe registry paths and value names to this function.

        .OUTPUTS
            System.Boolean
            Returns $true if the registry value exists, $false otherwise.

        .EXAMPLE
            Test-RegistryValue -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value "AutoAdminLogon"

            Tests if the AutoAdminLogon value exists in the Windows NT Winlogon registry key.

        .EXAMPLE
            Test-RegistryValue "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"

            Shows using positional parameters to test the existence of the AutoAdminLogon value.

        .EXAMPLE
            "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Test-RegistryValue -Value "AutoAdminLogon"

            Shows how to pipe a registry path to the function.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ItemProperty                           ║ Microsoft.PowerShell.Management
                Get-CurrentErrorToDisplay                  ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Test-RegistryValue.ps1

        .COMPONENT
            Windows Registry Management

        .ROLE
            System Administration

        .FUNCTIONALITY
            Registry Value Validation
  #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([Bool])]

    Param (
        [parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Registry path to be tested',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Registry value to be tested',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Value
    )

    Begin {

        ##############################
        # Module imports

        ##############################
        # Variables Definition

    } #end Begin

    Process {
        try {
            Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
            return $true
        } catch {
            return $false
        }
    } #end Process

    End {

    } #end End

} #end Function
