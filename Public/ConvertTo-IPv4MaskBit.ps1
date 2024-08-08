function ConvertTo-IPv4MaskBit {
    <#
        .SYNOPSIS
            Returns the number of bits (0-32) in a network mask string (e.g., "255.255.255.0").
        .DESCRIPTION
            Returns the number of bits (0-32) in a network mask string (e.g., "255.255.255.0").
        .PARAMETER MaskString
            Specifies the IPv4 network mask string (e.g., "255.255.255.0").
        .EXAMPLE
            ConvertTo-IPv4MaskBit -MaskString "255.255.255.0"
        .EXAMPLE
            ConvertTo-IPv4MaskBit "192.168.1.200"
        .NOTES
            Version:         1.0
            DateModified:    13/Apr/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([System.Int32])]

    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [ValidateScript({ Test-IPv4MaskString $_ })]
        [String]
        $MaskString
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
    } #end Begin

    Process {
        $mask = ([IPAddress] $MaskString).Address
        for ( $bitCount = 0; $mask -ne 0; $bitCount++ ) {
            $mask = $mask -band ($mask - 1)
        }
        $bitCount
    } #end Process

    End {
        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'returning the bits in a bitmask IPv4.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
