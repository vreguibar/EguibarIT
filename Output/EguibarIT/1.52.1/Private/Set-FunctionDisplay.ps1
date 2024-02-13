Function Set-FunctionDisplay {
    <#
        .SYNOPSIS
            Formats and displays the PsBoundParameters in a visually appealing way.

        .DESCRIPTION
            This advanced function formats and displays the contents of a hashtable, typically PsBoundParameters,
            making it easier to read and understand in verbose output. It supports customization of indentation.

        .EXAMPLE
            Set-FunctionDisplay $PsBoundParameters

        .EXAMPLE
            Set-FunctionDisplay -HashTable $PsBoundParameters

        .PARAMETER HashTable
            The hashtable to format and display. This is usually the $PsBoundParameters variable.

        .PARAMETER TabCount
            The number of tabs to prepend to each line of output for indentation.
            Defaults to 2 if not specified or less than 2.

        .NOTES
            Version:         1.1
            DateModified:    13/Feb/2024
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
        [ValidateRange(2, [int]::MaxValue)]
        [int]
        $TabCount
    )

    Begin {

        # Validate TabCount and set default if needed
        if ($TabCount -lt 2) {
            $TabCount = 2
        }

        $NewLine = [System.Environment]::NewLine
        $HorizontalTab = "`t"

        $tab = $HorizontalTab * $TabCount

        $objectList = [System.Collections.ArrayList]::New()

    } # end Begin

    Process {

        # Validate if HashTable is not empty
        if ($HashTable.Count -gt 0) {

            # New empty line at the begining
            [void]$objectList.Add($NewLine)

            # Convert each hashtable entry to a custom object and add to the list
            foreach ($entry in $HashTable.GetEnumerator()) {
                $obj = New-Object PSObject -Property @{
                    Key   = $entry.Key
                    Value = $entry.Value
                }
                [void]$objectList.Add($obj)
            } #end Foreach

            # New empty line at the end
            [void]$objectList.Add($NewLine)

        } else {

            # No parameters to display
            [void]$objectList.Add('No PsBoundParameters to display.')

        } #end If-Else

    } # end Process

    End {

        # Convert the list of custom objects to a table and then to a string
        $tableString = $objectList | Format-Table -Property Key, Value -AutoSize | Out-String

        $indentedTableString = $tableString -split $NewLine | ForEach-Object { $Tab + $_ } | Out-String

        Return $indentedTableString
    } #end END
} #end Function
