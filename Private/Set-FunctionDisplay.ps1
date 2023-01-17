Function Set-FunctionDisplay {
    <#
        .Synopsis
            Nice display PsBoundParameters
        .DESCRIPTION

        .EXAMPLE
            Set-FunctionDisplay $PsBoundParameters
        .EXAMPLE
            Set-FunctionDisplay -HashTable $PsBoundParameters
        .PARAMETER HashTable
            Hashtable variable from calling function containing PsBoundParameters to format accordingly
        .PARAMETER TabCount
            Amount of Tabs to be used on the formatting.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
        .NOTES
            Version:         1.0
            DateModified:    20/Oct/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([Hashtable])]

    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Hashtable variable from calling function containing PsBoundParameters to format accordingly',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $HashTable,

        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Amount of Tabs to be used on the formatting.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [int]
        $TabCount
    )

    Begin {
        If(($null -eq $PsBoundParameters['TabCount']) -or
            ($PsBoundParameters['TabCount'] -lt 1)
        ) {
            $TabCount = 4
        }
    } # end Begin

    Process {

        # Display PSBoundparameters formatted nicely for Verbose output
        # Get hashtable formated properly
        [string]$pb = ($HashTable | Format-Table -AutoSize | Out-String).TrimEnd()

        # Add a new line
        $Display = $Constants.NL

        # Add corresponding tab's and new lines to each table member
        $Display += $($pb.split($($Constants.NL)).Foreach({"$($Constants.HTab*$TabCount)$_"}) | Out-String)

        # Add a new line
        $Display += $Constants.NL

    } # end Process

    End {
        Return $Display
    } #end END
} #end Function
