function ConvertTo-IntegerIPv4 {
    <#
        .SYNOPSIS
            Converts an integer value to its IPv4 address representation.

        .DESCRIPTION
            This function converts a 32-bit unsigned integer to a standard dotted-decimal
            IPv4 address format. This is the reverse operation of ConvertTo-IPv4Integer and
            is useful for IP address calculations, range conversions, and subnet operations.

        .PARAMETER Integer
            Specifies the 32-bit unsigned integer representing the IPv4 address.
            For example, 3232235776 will convert to "192.168.1.0".

        .INPUTS
            System.UInt32
            You can pipe a 32-bit unsigned integer value to this function.

        .OUTPUTS
            System.Net.IPAddress
            Returns an IPv4 address object in dotted-decimal notation.

        .EXAMPLE
            ConvertTo-IntegerIPv4 -Integer 3232235776

            Converts the integer 3232235776 to the IP address 192.168.1.0.

        .EXAMPLE
            ConvertTo-IntegerIPv4 167772160

            Converts the integer 167772160 to the IP address 10.0.0.0.

        .EXAMPLE
            3232235521 | ConvertTo-IntegerIPv4

            Converts the integer received from the pipeline to its IPv4 representation.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                    ║ EguibarIT
                BitConverter.GetBytes                  ║ System
                IPAddress                              ║ System.Net

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/ConvertTo-IntegerIPv4.ps1

        .COMPONENT
            Networking

        .ROLE
            Utility

        .FUNCTIONALITY
            IP Address Conversion
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
            (Get-Date).ToString('dd/MMM/yyyy'),
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
