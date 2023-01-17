Function ConvertTo-IPv4NetworkAddress {
    <#
        .SYNOPSIS
            Find network address based on IP Address and Subnet Mask (e. g. 192.168.1.0 is the Network Address of 192.168.1.200/24)
        .DESCRIPTION
            Find network address based on IP Address and Subnet Mask (e. g. 192.168.1.0 is the Network Address of 192.168.1.200/24)
        .PARAMETER IPv4Address
            Specifies the IPv4 Address as string (e.g., 192.168.1.200)
        .PARAMETER SubnetMask
            Specifies the IPv4 network mask as string (e.g., 255.255.255.0)
        .PARAMETER PrefixLength
            Specifies the network prefix length, also known as CIDR  (e.g., 24)
        .EXAMPLE
            ConvertTo-IPv4NetworkAddress -IPv4Address "192.168.1.200" -SubnetMask "255.255.255.0"
        .EXAMPLE
            ConvertTo-IPv4NetworkAddress -IPv4Address "192.168.1.200" -PrefixLength "24"
        .EXAMPLE
            ConvertTo-IPv4NetworkAddress "192.168.1.200" "255.255.255.0"
        .EXAMPLE
            ConvertTo-IPv4NetworkAddress "192.168.1.200" "24"
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                ConvertTo-IPv4Integer                  | EguibarIT
                ConvertTo-IntegerIPv4                  | EguibarIT
                ConvertTo-IPv4MaskString               | EguibarIT

        .NOTES
            Version:         1.0
            DateModified:    12/Apr/2022
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
            HelpMessage = "Specifies the IPv4 Address as string (e.g., 192.168.1.200)",
        Position = 0)]
        [String] $IPv4Address,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = "Specifies the IPv4 network mask as string (e.g., 255.255.255.0)",
            ParameterSetName='SubnetMask',
        Position = 1)]
        [String] $SubnetMask,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = "Specifies the network prefix length, also known as CIDR  (e.g., 24)",
            ParameterSetName='PrefixLength',
        Position = 1)]
        [String] $PrefixLength
    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        #####
        # Variables
        $IntegerIPv4Address    = 0
        $IntegerIPv4SubnetMask = 0
        $IntegerNetworkAddress = 0
        [IpAddress]$NetworkAddress
    }
    Process {
        # Get IPv4 address as an Integer
        $IntegerIPv4Address = ConvertTo-IPv4Integer -Ipv4Address $IPv4Address
        Write-Verbose -Message ('IP Address {0} to Integer: {1}' -f $IPv4Address, $IntegerIPv4Address)

        # Get IPv4 subnet mask as an Integer
        If($PSCmdlet.ParameterSetName -eq 'PrefixLength') {
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
    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        return $NetworkAddress
    }
}
