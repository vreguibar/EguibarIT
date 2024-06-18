Function Get-FunctionDisplay {
    <#
        .Synopsis
            Nice display PsBoundParameters
        .DESCRIPTION
            This function formats and displays the PsBoundParameters hashtable in a visually appealing way for Verbose output.
        .EXAMPLE
            Get-FunctionDisplay $PsBoundParameters
        .EXAMPLE
            Get-FunctionDisplay -HashTable $PsBoundParameters
        .PARAMETER HashTable
            Hashtable variable from calling function containing PsBoundParameters to format accordingly
        .PARAMETER TabCount
            Amount of Tabs to be used on the formatting.
        .NOTES
            Version:         1.0
            DateModified:    20/Oct/2022
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([String])]

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
        [PSDefaultValue(Help = 'Default Value is "2"')]
        [int]
        $TabCount = 2
    )

    Begin {

    } # end Begin

    Process {

        # Display PSBoundparameters formatted nicely for Verbose output

        $display = $Constants.NL

        # Validate if HashTable is not empty
        if ($HashTable.Count -gt 0) {
            # Get hashtable formatted properly
            $pb = $HashTable | Format-Table -AutoSize | Out-String

            # Add corresponding tabs and new lines to each table member
            $display += $pb -split $Constants.NL | ForEach-Object { "$($Constants.HTab * $TabCount)$_" } | Out-String
        } else {
            $display = 'No PsBoundParameters to display.'
        } #end If
        $display += $Constants.NL
        $display += $Constants.NL

    } # end Process

    End {
        Return $display
    } #end END
} #end Function
