function Test-IPv4MaskString {
    <#
        .SYNOPSIS
            Tests whether an IPv4 network mask string is valid.

        .DESCRIPTION
            Validates an IPv4 subnet mask string (e.g., '255.255.255.0') by checking that
            each octet is a valid mask byte. Valid mask octets are: 0, 128, 192, 224, 240,
            248, 252, 254, 255 — and the mask must be contiguous.

        .PARAMETER MaskString
            [String] The IPv4 network mask string to validate.
            Example: '255.255.255.0', '255.255.0.0'

        .EXAMPLE
            Test-IPv4MaskString -MaskString '255.255.255.0'

            Returns $true because 255.255.255.0 is a valid IPv4 subnet mask.

        .EXAMPLE
            Test-IPv4MaskString -MaskString '255.255.255.1'

            Returns $false because 255.255.255.1 is not a valid subnet mask.

        .EXAMPLE
            '255.255.0.0', '255.0.0.0', '0.0.0.0' | Test-IPv4MaskString

            Tests multiple mask strings via pipeline input.

        .INPUTS
            [System.String]
            You can pipe mask strings to this function.

        .OUTPUTS
            [System.Boolean]
            Returns $true if the mask string is valid, $false otherwise.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    21/Sep/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Test-IPv4MaskString.ps1

        .COMPONENT
            Networking

        .ROLE
            Infrastructure Administration

        .FUNCTIONALITY
            IPv4 Mask Validation
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([bool])]

    param (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Specifies the IPv4 network mask string (e.g., 255.255.255.0)',
            Position = 1)]
        [String]
        $MaskString
    )

    begin {
        Set-StrictMode -Version Latest

        # Initialize logging
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Module imports

    } #end begin

    process {
        $validBytes = '0|128|192|224|240|248|252|254|255'
        $maskPattern = ('^((({0})\.0\.0\.0)|' -f $validBytes) +
        ('(255\.({0})\.0\.0)|' -f $validBytes) +
        ('(255\.255\.({0})\.0)|' -f $validBytes) +
        ('(255\.255\.255\.({0})))$' -f $validBytes)
        $MaskString -match $maskPattern
    } #end process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'testing whether an IPv4 network mask string.'
        )
        Write-Verbose -Message $txt
    } #end end

} #end Function
