function ConvertTo-IntegerIPv4 {
    <#
        .SYNOPSIS
            Returns the IP Address from given integer
        .DESCRIPTION
            Returns the IP Address from given integer
        .PARAMETER Integer
            Specifies the integer representing the IP Address (e.g., 3232235776 will return "192.168.1.0")
        .EXAMPLE
            ConvertTo-IntegerIPv4 -Integer 24
        .EXAMPLE
            ConvertTo-IntegerIPv4 24
        .NOTES
            Version:         1.0
            DateModified:    13/Apr/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    [OutputType([System.Net.IpAddress])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
        Position = 0)]
        [uint32] $Integer
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
        Try {
            $bytes=[System.BitConverter]::GetBytes($Integer)

            [Array]::Reverse($bytes)

            ([IPAddress]($bytes)).ToString()

        } Catch {
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