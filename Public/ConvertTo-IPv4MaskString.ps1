function ConvertTo-IPv4MaskString {
    <#
        .SYNOPSIS
            Converts a CIDR bit count (0-32) to its equivalent subnet mask in dotted-decimal format.

        .DESCRIPTION
            This function converts a CIDR bit count (e.g., 24) to its equivalent subnet mask
            in dotted-decimal format (e.g., "255.255.255.0"). This is useful for network
            configurations that require subnet masks in the traditional format rather than CIDR notation.

        .PARAMETER MaskBits
            Specifies the number of bits in the subnet mask (0-32).
            Must be an integer between 0 and 32.

        .INPUTS
            System.Int32
            You can pipe an integer value representing CIDR bit count to this function.

        .OUTPUTS
            System.String
            Returns a string representing the subnet mask in dotted-decimal notation.

        .EXAMPLE
            ConvertTo-IPv4MaskString -MaskBits 24

            Returns "255.255.255.0", which is the subnet mask for a CIDR /24 network.

        .EXAMPLE
            ConvertTo-IPv4MaskString 16

            Returns "255.255.0.0", which is the subnet mask for a CIDR /16 network.

        .EXAMPLE
            30 | ConvertTo-IPv4MaskString

            Returns "255.255.255.252", which is the subnet mask for a CIDR /30 network.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                    ║ EguibarIT
                Math.Pow                               ║ System
                BitConverter.GetBytes                  ║ System

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/ConvertTo-IPv4MaskString.ps1

        .COMPONENT
            Networking

        .ROLE
            Utility

        .FUNCTIONALITY
            Subnet Mask Conversion
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([string])]

    Param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [ValidateRange(0, 32)]
        [System.Int32]
        $MaskBits
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
        $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
        $bytes = [BitConverter]::GetBytes([UInt32] $mask)
        (($bytes.Count - 1)..0 | ForEach-Object { [String] $bytes[$_] }) -join '.'
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'converting bits to a networkmask string.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
