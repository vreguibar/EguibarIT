function Write-ErrorEventLog {
    <#
        .SYNOPSIS
            Writes an error event to the log.

        .DESCRIPTION
            This function writes an error event to the Windows Event Log.

        .PARAMETER Message
            The error message to be written to the event log.

        .PARAMETER EventId
            The ID of the event. Default is 1.

        .PARAMETER Source
            The source of the event. Default is 'MyApplication'.

        .EXAMPLE
            Write-ErrorEventLog -Message 'An error occurred in the application'

        .EXAMPLE
            Write-ErrorEventLog -Message 'Database connection failed' -EventId 100 -Source 'DatabaseModule'
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([System.Void])]

    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Enter the error message to be logged',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Message,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Enter the ID of the event',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [int]
        $EventId,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Enter the source of the event',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Source
    )

    Begin {
        # No specific begin actions for this function
    } #end Begin

    Process {
        Write-CustomEventLog -Message $Message -EventType 'Error' -EventId $EventId -Source $Source
    } #end Process

    End {
        # No specific end actions for this function
    } #end End
} #end function Write-ErrorEventLog
