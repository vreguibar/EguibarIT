function ConvertTo-IPv4MaskBit {
    <#
        .SYNOPSIS
            Converts a subnet mask string to its CIDR bit count (0-32).

        .DESCRIPTION
            This function converts a subnet mask in dotted-decimal format (e.g., "255.255.255.0")
            to its equivalent CIDR notation bit count (e.g., 24). This is useful for network
            calculations and subnet operations where CIDR notation is required.

        .PARAMETER MaskString
            Specifies the IPv4 subnet mask in dotted-decimal format (e.g., "255.255.255.0").
            Must be a valid subnet mask that passes the Test-IPv4MaskString validation.

        .INPUTS
            System.String
            You can pipe a string value representing a subnet mask to this function.

        .OUTPUTS
            System.Int32
            Returns an integer between 0 and 32 representing the CIDR bit count.

        .EXAMPLE
            ConvertTo-IPv4MaskBit -MaskString "255.255.255.0"

            Returns 24, which is the CIDR bit count for the subnet mask 255.255.255.0.

        .EXAMPLE
            ConvertTo-IPv4MaskBit "255.255.0.0"

            Returns 16, which is the CIDR bit count for the subnet mask 255.255.0.0.

        .EXAMPLE
            "255.255.255.252" | ConvertTo-IPv4MaskBit

            Returns 30, which is the CIDR bit count for the subnet mask 255.255.255.252.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Test-IPv4MaskString                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                    ║ EguibarIT
                IPAddress                              ║ System.Net

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/ConvertTo-IPv4MaskBit.ps1

        .COMPONENT
            Networking

        .ROLE
            Utility

        .FUNCTIONALITY
            Subnet Mask Conversion
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([System.Int32])]

    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [ValidateScript({ Test-IPv4MaskString $_ })]
        [String]
        $MaskString
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
        $mask = ([IPAddress] $MaskString).Address
        for ( $bitCount = 0; $mask -ne 0; $bitCount++ ) {
            $mask = $mask -band ($mask - 1)
        }
        $bitCount
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'returning the bits in a bitmask IPv4.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
