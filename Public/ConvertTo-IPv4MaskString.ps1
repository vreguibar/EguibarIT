function ConvertTo-IPv4MaskString {
    <#
        .SYNOPSIS
            Converts a number of bits (0-32) to an IPv4 network mask string (e.g., "255.255.255.0").
        .DESCRIPTION
            Converts a number of bits (0-32) to an IPv4 network mask string (e.g., "255.255.255.0").
        .PARAMETER MaskBits
            Specifies the number of bits in the mask.
        .EXAMPLE
            ConvertTo-IPv4MaskString -MaskBits "24"
        .EXAMPLE
            ConvertTo-IPv4MaskString "24"
        .NOTES
            Version:         1.0
            DateModified:    13/Apr/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([string])]

    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [ValidateRange(0, 32)]
        [System.Int32]
        $MaskBits
    )

    Begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

    } #end Begin

    Process {
        $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
        $bytes = [BitConverter]::GetBytes([UInt32] $mask)
        (($bytes.Count - 1)..0 | ForEach-Object { [String] $bytes[$_] }) -join '.'
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'converting bits to a networkmask string.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
