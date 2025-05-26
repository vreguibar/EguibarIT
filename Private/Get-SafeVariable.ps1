function Get-SafeVariable {
    <#
        .SYNOPSIS
            Retrieves a variable from the current or global scope, creating it if it doesn't exist.

        .DESCRIPTION
            This function checks if a variable exists in the current or global scope.
            If it does, it returns its value.
            If it doesn't, it can create the variable using a provided script block.

        .PARAMETER Name
            The name of the variable to retrieve.

        .PARAMETER CreateIfNotExist
            A script block that defines how to create the variable if it doesn't exist.

        .INPUTS
            None
            This function does not accept pipeline input.

        .OUTPUTS
            [System.Object]
            Returns the value of the requested variable or the newly created value.

        .EXAMPLE
            $myVar = Get-SafeVariable -Name 'MyVariable' -CreateIfNotExist { 'DefaultValue' }

            This example retrieves the variable 'MyVariable'. If it doesn't exist, it creates it with the value 'DefaultValue'.

        .EXAMPLE
            $myVar = Get-SafeVariable -Name 'MyVariable'

            This example retrieves the variable 'MyVariable'. If it doesn't exist, it returns $null.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Write-Debug                            ║ Microsoft.PowerShell.Utility
                Get-Variable                           ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.0
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Private/Get-SafeVariable.ps1

        .COMPONENT
            Variable Management

        .ROLE
            Utility

        .FUNCTIONALITY
            Variable Safety
    #>

    [CmdletBinding()]
    [OutputType([object])]

    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $false)]
        [scriptblock]$CreateIfNotExist
    )

    # Check if variable exists in any scope
    $var = Get-Variable -Name $Name -Scope Global -ErrorAction SilentlyContinue
    if ($null -eq $var) {
        $var = Get-Variable -Name $Name -Scope Script -ErrorAction SilentlyContinue
    }

    if ($null -ne $var) {
        Write-Debug -Message ('Variable {0} already exists, using existing value' -f $Name)
        return $var.Value
    } elseif ($null -ne $CreateIfNotExist) {
        Write-Debug -Message ('Variable {0} does not exist, creating new value' -f $Name)
        $newValue = & $CreateIfNotExist
        return $newValue
    } else {
        Write-Debug -Message ('Variable {0} not found and no creation logic provided' -f $Name)
        return $null
    }
}
