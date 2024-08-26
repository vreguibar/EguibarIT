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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([System.Net.IpAddress])]

    Param     (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [uint32]
        $Integer
    )

    Begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

    } #end Begin

    Process {
        Try {
            $bytes = [System.BitConverter]::GetBytes($Integer)

            [Array]::Reverse($bytes)

            ([IPAddress]($bytes)).ToString()

        } Catch {
            Write-Error -Message 'Error when converting Integer to IPv4'
            throw
        }
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'converting Integer to IPv4.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
