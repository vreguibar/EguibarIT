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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([string])]

    param (
        [parameter(Mandatory = $true,
            HelpMessage = 'Specify the length of the hexadecimal string.')]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Length
    )

    Begin {
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

        # Generating random hexadecimal string
        $Hex = '0123456789ABCDEF'
        [string]$Return = $null

    } #end Begin

    Process {
        try {
            for ($i = 1; $i -le $Length; $i++) {
                $Return += $Hex.Substring((Get-Random -Minimum 0 -Maximum 16), 1)
            } #end For

            # Displaying verbose output
            Write-Verbose -Message ('Generated random hexadecimal string: {0}' -f $Return)

        } catch {
            # Handling exceptions
            ###Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } #end Try
    } #end Process

    End {
        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'generating random hexadecimal string.'
        )
        Write-Verbose -Message $txt

        # Returning the generated string
        $Return
    } #end End

} #end Function
