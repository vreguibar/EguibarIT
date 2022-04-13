function ConvertTo-IPv4Integer {
    <#
        .SYNOPSIS
            Returns the integer representing the given IP Address
        .DESCRIPTION
            Returns the integer representing the given IP Address
        .PARAMETER Ipv4Address
            Specifies the IPv4 Address as a string (e.g., "192.168.1.200")
        .EXAMPLE
            ConvertTo-IPv4Integer -Ipv4Address "192.168.1.200"
        .EXAMPLE
            ConvertTo-IPv4Integer "192.168.1.200"
        .NOTES
            Version:         1.0
            DateModified:    13/Apr/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    [OutputType([System.Int32])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
        Position = 0)]
        [String] $Ipv4Address
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
        Try{
            $ipAddress = [IPAddress]::Parse($IPv4Address)
        
            $bytes = $ipAddress.GetAddressBytes()

            [Array]::Reverse($bytes)
        
            [System.BitConverter]::ToUInt32($bytes,0)

          }Catch{
            Write-Error -Exception $_.Exception -Category $_.CategoryInfo.Category
          }
    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}