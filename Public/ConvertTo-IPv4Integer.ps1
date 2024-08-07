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
    [OutputType([System.UInt32])]
    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [String]
        $Ipv4Address
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
    }

    Process {
        Try {
            $ipAddress = [IPAddress]::Parse($IPv4Address)

            $bytes = $ipAddress.GetAddressBytes()

            [Array]::Reverse($bytes)

            [System.BitConverter]::ToUInt32($bytes, 0)

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
