Function Get-RandomHex {
    <#
        .SYNOPSIS
            Generates a random hexadecimal string of specified length.

        .DESCRIPTION
            This function generates a random hexadecimal string of the specified length.

        .PARAMETER Length
            The length of the hexadecimal string to generate.

        .EXAMPLE
            Get-RandomHex -Length 8
            Generates a random hexadecimal string of length 8.

        .INPUTS
            None

        .OUTPUTS
            System.String
            A random hexadecimal string.

        .NOTES
        Version:         1.0
            DateModified:    22/Jun/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess=$False)]
    param (
        [parameter(Mandatory=$true,
                   HelpMessage="Specify the length of the hexadecimal string.")]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Length
    )

    try {
        # Generating random hexadecimal string
        $Hex = '0123456789ABCDEF'
        [string]$Return = $null

        for ($i=1; $i -le $Length; $i++) {
            $Return += $Hex.Substring((Get-Random -Minimum 0 -Maximum 16), 1)
        }

        # Displaying verbose output
        Write-Verbose "Generated random hexadecimal string: $Return"

        # Returning the generated string
        $Return
    } catch {
        # Handling exceptions
        Write-Error "An error occurred: $_"
    } #end Try
} #end Function
