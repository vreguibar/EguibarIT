Function Get-FunctionDisplay {
    <#
        .SYNOPSIS
            Formats and displays the PsBoundParameters hashtable in a visually appealing way.

        .DESCRIPTION
            Get-FunctionDisplay formats a hashtable (typically $PsBoundParameters) into a readable
            table format suitable for verbose output or logging. It provides customizable indentation
            through the TabCount parameter and handles empty hashtables gracefully.

            This function is particularly useful for debugging or providing verbose output in complex
            PowerShell functions to show what parameters were passed to the function.

            The function uses StringBuilder for efficient string building operations.

        .EXAMPLE
            Get-FunctionDisplay -HashTable $PsBoundParameters

            Formats the $PsBoundParameters from the calling function with default indentation (2 tabs).

        .EXAMPLE
            Get-FunctionDisplay -HashTable $PsBoundParameters -TabCount 4

            Formats the $PsBoundParameters with 4 tabs of indentation for deeper nesting.

        .EXAMPLE
            $MyParams = @{
                Server = 'DC01'
                Credential = $Credential
                Force = $true
            }
            Get-FunctionDisplay -HashTable $MyParams

            Formats a custom hashtable with the default indentation.

        .PARAMETER HashTable
            Hashtable variable from calling function containing parameters to format accordingly.
            Typically this will be $PsBoundParameters from the calling function.

        .PARAMETER TabCount
            Number of tab characters to use for indentation in the formatted output.
            Default value is 2.

        .OUTPUTS
            [System.String]
            Returns a formatted string representation of the provided hashtable.

        .NOTES
            Version:         2.0
            DateModified:    19/Mar/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Format-Table                               ║ Microsoft.PowerShell.Utility
                Out-String                                 ║ Microsoft.PowerShell.Utility
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                StringBuilder                              ║ [System.Text.StringBuilder]

            Required Modules:
                None - Uses built-in PowerShell cmdlets and .NET classes

        .LINK
            https://github.com/vreguibar/EguibarIT.DelegationPS/blob/main/Private/Get-FunctionDisplay.ps1
            https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/format-table
            https://learn.microsoft.com/en-us/dotnet/api/system.text.stringbuilder
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low',
        DefaultParameterSetName = 'Default',
        PositionalBinding = $true
    )]
    [OutputType([String])]

    Param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Hashtable containing parameters to format (typically $PsBoundParameters).',
            Position = 0,
            ParameterSetName = 'Default'
        )]
        [ValidateNotNull()]
        [Alias('Parameters', 'Params', 'BoundParameters')]
        [Hashtable]
        $HashTable,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Number of tab characters to use for indentation in the formatted output.',
            Position = 1,
            ParameterSetName = 'Default'
        )]
        [ValidateNotNull()]
        [ValidateRange(0, 10)]
        [PSDefaultValue(Help = 'Default Value is "2"')]
        [Alias('Tabs', 'Indentation')]
        [int]
        $TabCount = 2
    )

    Begin {
        # Set strict mode
        Set-StrictMode -Version Latest

        # Variables Definition
        [System.Text.StringBuilder]$sb = [System.Text.StringBuilder]::New(1024)
        [string]$IndentString = $Constants.HTab * $TabCount

    } # end Begin

    Process {
        try {
            # Start with a new line
            [void]$sb.AppendLine()

            # Validate if HashTable is not empty
            if ($HashTable.Count -gt 0) {
                # Get hashtable formatted as a table
                $FormattedTable = $HashTable | Format-Table -AutoSize | Out-String

                # Process each line of the table output
                $TableLines = $FormattedTable -split $Constants.NL

                foreach ($Line in $TableLines) {

                    # Add indentation to each line and append to StringBuilder
                    if (-not [string]::IsNullOrWhiteSpace($Line)) {

                        [void]$sb.Append($IndentString).AppendLine($Line)

                    } # end if

                } # end foreach

            } else {

                # Handle empty hashtable case
                [void]$sb.AppendLine('Empty hashtable received, no parameters to display.')

            } # end If

            # Add extra newlines for readability
            [void]$sb.AppendLine()

        } catch {
            # Handle any errors during processing
            Write-Warning -Message ('Error formatting hashtable: {0}' -f $_.Exception.Message)

            [void]$sb.Clear()
            [void]$sb.AppendLine('Error formatting parameters: {0}' -f $_.Exception.Message)

        } # end try-catch
    } # end Process

    End {

        # Return the final formatted output as string
        return $sb.ToString()

    } # end End

} # end Function Get-FunctionDisplay
