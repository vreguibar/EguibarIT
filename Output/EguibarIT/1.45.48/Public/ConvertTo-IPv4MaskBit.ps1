function ConvertTo-IPv4MaskBit {
    <#
        .SYNOPSIS
            Returns the number of bits (0-32) in a network mask string (e.g., "255.255.255.0").

        .DESCRIPTION
            Returns the number of bits (0-32) in a network mask string (e.g., "255.255.255.0").

        .PARAMETER MaskString
            Specifies the IPv4 network mask string (e.g., "255.255.255.0").
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([System.Int32])]
    Param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
        Position = 1)]
        [ValidateScript({Test-IPv4MaskString $_})]
        [String] $MaskString
    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"
    }
    Process {
        $mask = ([IPAddress] $MaskString).Address
        for ( $bitCount = 0; $mask -ne 0; $bitCount++ ) {
            $mask = $mask -band ($mask - 1)
        }
        $bitCount
    }
    End {
        Write-Verbose -Message ('Function {0} finished.' -f $MyInvocation.InvocationName)
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}