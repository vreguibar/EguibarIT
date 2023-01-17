function Test-IPv4MaskString {
    <#
        .SYNOPSIS
            Tests whether an IPv4 network mask string (e.g., "255.255.255.0") is valid.
        .DESCRIPTION
            Tests whether an IPv4 network mask string (e.g., "255.255.255.0") is valid.
        .PARAMETER MaskString
            Specifies the IPv4 network mask string (e.g., "255.255.255.0").
        .EXAMPLE
            Test-IPv4MaskString -MaskString "255.255.255.0"
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = "Specifies the IPv4 network mask string (e.g., 255.255.255.0)",
        Position = 1)]
        [String] $MaskString
    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

    }
    Process {
        $validBytes = '0|128|192|224|240|248|252|254|255'
        $maskPattern = ('^((({0})\.0\.0\.0)|'      -f $validBytes) +
             ('(255\.({0})\.0\.0)|'      -f $validBytes) +
             ('(255\.255\.({0})\.0)|'    -f $validBytes) +
             ('(255\.255\.255\.({0})))$' -f $validBytes)
        $MaskString -match $maskPattern
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
