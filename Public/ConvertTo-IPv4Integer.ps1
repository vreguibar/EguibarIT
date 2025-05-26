function ConvertTo-IPv4Integer {
    <#
        .SYNOPSIS
            Converts an IPv4 address to its integer representation.

        .DESCRIPTION
            This function converts a standard dotted-decimal IPv4 address (e.g., 192.168.1.200)
            to its 32-bit unsigned integer equivalent. This conversion is useful for IP address
            calculations, range comparisons, and subnet operations.

        .PARAMETER Ipv4Address
            Specifies the IPv4 Address as a string (e.g., "192.168.1.200").
            Must be a valid IPv4 address in dotted-decimal notation.

        .INPUTS
            System.String
            You can pipe a string value representing an IPv4 address to this function.

        .OUTPUTS
            System.UInt32
            Returns a 32-bit unsigned integer representation of the IPv4 address.

        .EXAMPLE
            ConvertTo-IPv4Integer -Ipv4Address "192.168.1.200"

            Converts the IP address 192.168.1.200 to its integer representation.

        .EXAMPLE
            ConvertTo-IPv4Integer "192.168.1.200"

            Converts the IP address using positional parameter.

        .EXAMPLE
            "10.0.0.1" | ConvertTo-IPv4Integer

            Converts the IP address received from the pipeline.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                    ║ EguibarIT
                IPAddress.Parse                        ║ System.Net
                BitConverter.ToUInt32                  ║ System

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/ConvertTo-IPv4Integer.ps1

        .COMPONENT
            Networking

        .ROLE
            Utility

        .FUNCTIONALITY
            IP Address Conversion
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
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
            $ipAddress = [IPAddress]::Parse($IPv4Address)

            $bytes = $ipAddress.GetAddressBytes()

            [Array]::Reverse($bytes)

            [System.BitConverter]::ToUInt32($bytes, 0)

        } Catch {
            Write-Error -Exception $_.Exception -Category $_.CategoryInfo.Category
        } #end Try-Catch

    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'converting IPv4 to Integer.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
