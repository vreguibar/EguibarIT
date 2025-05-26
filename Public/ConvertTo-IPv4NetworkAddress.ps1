Function ConvertTo-IPv4NetworkAddress {
    <#
        .SYNOPSIS
            Calculates the network address for a given IP address and subnet mask.

        .DESCRIPTION
            This function calculates the network address based on an IP address and either a subnet mask
            or prefix length (CIDR notation). For example, 192.168.1.0 is the network address of
            192.168.1.200/24 or 192.168.1.200 with subnet mask 255.255.255.0.

        .PARAMETER IPv4Address
            Specifies the IPv4 Address as string (e.g., "192.168.1.200").
            Must be a valid IPv4 address in dotted-decimal notation.

        .PARAMETER SubnetMask
            Specifies the IPv4 network mask as string (e.g., "255.255.255.0").
            Used in the SubnetMask parameter set.

        .PARAMETER PrefixLength
            Specifies the network prefix length, also known as CIDR notation (e.g., "24").
            Used in the PrefixLength parameter set.

        .INPUTS
            System.String
            You can pipe the IPv4 address as a string to this function.

        .OUTPUTS
            System.Net.IPAddress
            Returns an IPAddress object representing the network address.

        .EXAMPLE
            ConvertTo-IPv4NetworkAddress -IPv4Address "192.168.1.200" -SubnetMask "255.255.255.0"

            Returns 192.168.1.0 as the network address for the given IP and subnet mask.

        .EXAMPLE
            ConvertTo-IPv4NetworkAddress -IPv4Address "192.168.1.200" -PrefixLength "24"

            Returns 192.168.1.0 as the network address for the given IP and CIDR prefix.

        .EXAMPLE
            ConvertTo-IPv4NetworkAddress "192.168.1.200" "255.255.255.0"

            Uses positional parameters to calculate the network address.

        .EXAMPLE
            ConvertTo-IPv4NetworkAddress "192.168.1.200" "24"

            Uses positional parameters with a CIDR prefix length.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                ConvertTo-IPv4Integer                  ║ EguibarIT
                ConvertTo-IntegerIPv4                  ║ EguibarIT
                ConvertTo-IPv4MaskString               ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                    ║ EguibarIT

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/ConvertTo-IPv4NetworkAddress.ps1

        .COMPONENT
            Networking

        .ROLE
            Utility

        .FUNCTIONALITY
            IP Address Calculation
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([System.Net.IpAddress])]

    Param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Specifies the IPv4 Address as string (e.g., 192.168.1.200)',
            Position = 0)]
        [String]
        $IPv4Address,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Specifies the IPv4 network mask as string (e.g., 255.255.255.0)',
            ParameterSetName = 'SubnetMask',
            Position = 1)]
        [String]
        $SubnetMask,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Specifies the network prefix length, also known as CIDR  (e.g., 24)',
            ParameterSetName = 'PrefixLength',
            Position = 1)]
        [String]
        $PrefixLength
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

        $IntegerIPv4Address = 0
        $IntegerIPv4SubnetMask = 0
        $IntegerNetworkAddress = 0
        [IpAddress]$NetworkAddress
    } #end Begin

    Process {
        # Get IPv4 address as an Integer
        $IntegerIPv4Address = ConvertTo-IPv4Integer -Ipv4Address $IPv4Address
        Write-Verbose -Message ('IP Address {0} to Integer: {1}' -f $IPv4Address, $IntegerIPv4Address)

        # Get IPv4 subnet mask as an Integer
        If ($PSCmdlet.ParameterSetName -eq 'PrefixLength') {
            $SubnetMask = (ConvertTo-IPv4MaskString -MaskBits $PrefixLength).ToString()
            Write-Verbose -Message ('PrefixLength of {0} to Integer: {1}' -f $SubnetMask, $IntegerIPv4SubnetMask)
        }

        $IntegerIPv4SubnetMask = ConvertTo-IPv4Integer -Ipv4Address $SubnetMask
        Write-Verbose -Message ('SubnetMask {0} to Integer: {1}' -f $SubnetMask, $IntegerIPv4SubnetMask)

        # BitwiseAnd IpAddress and Subnet mask
        $IntegerNetworkAddress = $IntegerIPv4Address -band $IntegerIPv4SubnetMask

        # Convert Integer to Network Address
        $NetworkAddress = ConvertTo-IntegerIPv4 -Integer $IntegerNetworkAddress
        Write-Verbose -Message ('Network Address {0} to Integer: {1}' -f $NetworkAddress, $IntegerNetworkAddress)
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'finding network address based on IP Address and Subnet Mask.'
        )
        Write-Verbose -Message $txt

        return $NetworkAddress
    } #end End
} #end Function
