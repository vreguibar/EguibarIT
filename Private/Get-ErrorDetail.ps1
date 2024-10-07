function Get-ErrorDetail {

    <#
        .SYNOPSIS
            Processes and displays detailed information from an error record.

        .DESCRIPTION
            This function takes an error record (typically from $Error[0]) and returns a detailed string
            containing various aspects of the error, including the error message, category, exception details,
            and invocation information.

        .PARAMETER ErrorRecord
            The error record to process. If not provided, it defaults to $Error[0].

        .EXAMPLE
            Get-ErrorDetail
            # This will process and display details for the most recent error ($Error[0])

        .EXAMPLE
            Get-ErrorDetail -ErrorRecord $Error[1]
            # This will process and display details for the second most recent error

        .INPUTS
            [System.Management.Automation.ErrorRecord]

        .OUTPUTS
            [System.String]

        .NOTES
            Version:        1.1
            Author:         [Your Name]
            Last Modified:  [Current Date]
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([System.String])]

    param (

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Current error (usually from $Error variable) which is going to be processed. If no error is provided then $error[0] will be used instead.',
            Position = 0)]
        [PSDefaultValue(Help = 'Default Value is "$Error[0]"')]
        [System.Management.Automation.ErrorRecord]
        $ErrorRecord = $Error[0]

    )

    begin {

        $output = [System.Text.StringBuilder]::new()
        [void]$output.AppendLine('   ■■■■■■■■■■▌    Error  Details    ▐■■■■■■■■■■')
        [void]$output.AppendLine('═' * 50)
        [void]$output.AppendLine($Constants.NL)

        $separator = '━' * 50

    } #end Begin

    process {
        if ($null -eq $ErrorRecord) {
            return 'No error record provided or found.'
        }

        $errorProperties = @(
            @{Name = 'Error Message'; Value = $ErrorRecord.Exception.Message },
            @{Name = 'Category'; Value = $ErrorRecord.CategoryInfo.Category },
            @{Name = 'Target Object'; Value = $ErrorRecord.TargetObject },
            @{Name = 'Fully Qualified Error ID'; Value = $ErrorRecord.FullyQualifiedErrorId },
            @{Name = 'Error Details'; Value = if ($null -ne $ErrorRecord.ErrorDetails) { $ErrorRecord.ErrorDetails.Message } else { 'Not Available' } },
            @{Name = 'Script Stack Trace'; Value = $ErrorRecord.ScriptStackTrace }
        )

        foreach ($prop in $errorProperties) {
            [void]$output.AppendLine("     $($prop.Name):")
            [void]$output.AppendLine($separator)
            [void]$output.AppendLine("$($prop.Value)")
            [void]$output.AppendLine($Constants.NL)
        }

        # Add invocation information if available
        if ($ErrorRecord.InvocationInfo) {
            [void]$output.AppendLine('Invocation Information:')
            $invocationInfo = @(
                @{Name = 'Command'; Value = if ($null -ne $ErrorRecord.InvocationInfo.MyCommand.Name) {
                        $ErrorRecord.InvocationInfo.MyCommand.Name
                    } else {
                        'Unknown Command'
                    }
                },
                @{Name = 'Script'; Value = if ($null -ne $ErrorRecord.InvocationInfo.ScriptName) {
                        $ErrorRecord.InvocationInfo.ScriptName
                    } else {
                        'Not Available'
                    }
                },
                @{Name = 'Line Number'; Value = $ErrorRecord.InvocationInfo.ScriptLineNumber },
                @{Name = 'Position'; Value = $ErrorRecord.InvocationInfo.PositionMessage },
                @{Name = 'Line'; Value = $ErrorRecord.InvocationInfo.Line },
                @{Name = 'PSMessageDetails'; Value = if ($null -ne $ErrorRecord.PSMessageDetails) {
                        $ErrorRecord.PSMessageDetails
                    } else {
                        'None'
                    }
                }
            )

            foreach ($info in $invocationInfo) {
                [void]$output.AppendLine("$($info.Name): $($info.Value)")
                [void]$output.AppendLine($separator)
                [void]$output.AppendLine($Constants.NL)
            } #end Foreach

        } else {
            [void]$output.AppendLine('Invocation Information: Not Available')
        } #end If-Else
    } #end Process

    end {
        return $output.ToString()
    } #end End
}
