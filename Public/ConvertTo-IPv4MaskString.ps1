function ConvertTo-IPv4MaskString {
    <#
        .SYNOPSIS
            Converts a number of bits (0-32) to an IPv4 network mask string (e.g., "255.255.255.0").

        .DESCRIPTION
            Converts a number of bits (0-32) to an IPv4 network mask string (e.g., "255.255.255.0").

        .PARAMETER MaskBits
            Specifies the number of bits in the mask.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
        Position = 1)]
        [ValidateRange(0,32)]
        [System.Int32] $MaskBits
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
        $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
        $bytes = [BitConverter]::GetBytes([UInt32] $mask)
        (($bytes.Count - 1)..0 | ForEach-Object { [String] $bytes[$_] }) -join "."
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}