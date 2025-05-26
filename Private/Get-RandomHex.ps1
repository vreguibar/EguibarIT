Function Get-RandomHex {
    <#
        .SYNOPSIS
            Generates a random hexadecimal string of specified length.

        .DESCRIPTION
            This function generates a cryptographically secure random hexadecimal string
            of the specified length using .NET methods for better performance.

        .PARAMETER Length
            The length of the hexadecimal string to generate.
            Must be a positive integer.
            Maximum value is 2147483647 (Int32.MaxValue).

        .INPUTS
            System.Int32
            You can pipe an integer representing the desired length to this function.

        .OUTPUTS
            System.String
            Returns a random hexadecimal string of specified length.

        .EXAMPLE
            Get-RandomHex -Length 8

            Generates an 8-character random hexadecimal string (e.g., "1A2B3C4D").

        .EXAMPLE
            Get-RandomHex -Length 16 -Verbose

            Generates a 16-character random hexadecimal string with verbose output.

        .EXAMPLE
            1..5 | ForEach-Object { Get-RandomHex -Length 4 }

            Generates five different 4-character random hexadecimal strings.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Debug                            ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility
                Get-Random                             ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                    ║ EguibarIT

        .NOTES
            Version:         2.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Private/Get-RandomHex.ps1

        .COMPONENT
            Security

        .ROLE
            Cryptography

        .FUNCTIONALITY
            Random Value Generation
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([string])]

    param (
        [parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the length of the hexadecimal string (1-2147483647).')]
        [ValidateRange(1, [int]::MaxValue)]
        [Alias('Size', 'Characters')]
        [int]
        $Length
    )

    Begin {
        Set-StrictMode -Version Latest

        # Output header information
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

        # Generating random hexadecimal string
        $Hex = '0123456789ABCDEF'
        [System.Text.StringBuilder]$StringBuilder = [System.Text.StringBuilder]::new($Length)

    } #end Begin

    Process {
        try {
            Write-Debug -Message ('Generating {0} character hex string' -f $Length)

            # Using StringBuilder for better performance with string concatenation
            for ($i = 1; $i -le $Length; $i++) {
                [void]$StringBuilder.Append($HexChars[(Get-Random -Minimum 0 -Maximum 16)])
            } #end For

            $Result = $StringBuilder.ToString()
            Write-Verbose -Message ('Generated random hexadecimal string: {0}' -f $Result)

        } catch {

            Write-Error -Message ('Failed to generate hex string: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {
            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'generating random hexadecimal string (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if

        # Returning the generated string
        $Return
    } #end End

} #end Function Get-RandomHex
