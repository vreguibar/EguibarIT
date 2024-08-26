function Write-CustomEventLog {
    <#
        .SYNOPSIS
            Writes a custom event log entry.

        .DESCRIPTION
            This function writes a custom event log entry to the Windows Event Log.

        .PARAMETER Message
            The message to be written to the event log.

        .PARAMETER EventType
            The type of event (Error, Warning, Information, or Debug).

        .PARAMETER Source
            The source of the event. Default is 'MyApplication'.

        .PARAMETER EventId
            The ID of the event. Default is 1.

        .EXAMPLE
            Write-CustomEventLog -Message 'Application started' -EventType 'Information'

        .EXAMPLE
            Write-CustomEventLog -Message 'An error occurred' -EventType 'Error' -EventId 100
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([System.Void])]

    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Enter the message to be logged',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Message,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Enter the event type (Error, Warning, Information, or Debug)',
            Position = 1)]
        [ValidateSet('Error', 'Warning', 'Information', 'Debug')]
        [ValidateNotNullOrEmpty()]
        [string]
        $EventType,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Enter the source of the event',
            Position = 2)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Source,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Enter the ID of the event',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [int]
        $EventId
    )

    Begin {
        $eventType = switch ($EventType) {
            'Error' {
                [System.Diagnostics.EventLogEntryType]::Error
            }
            'Warning' {
                [System.Diagnostics.EventLogEntryType]::Warning
            }
            'Information' {
                [System.Diagnostics.EventLogEntryType]::Information
            }
            'Debug' {
                $Message = '[DEBUG] {0}' -f $Message
                [System.Diagnostics.EventLogEntryType]::Information
            }
        } #end switch
    } #end Begin

    Process {
        $params = @(
            $Source,
            $Message,
            $eventType,
            $EventId
        )

        try {
            # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlog.writeentry?view=net-8.0
            <# [System.Diagnostics.EventLog]::WriteEntry (string source,
                                                          string message,
                                                          System.Diagnostics.EventLogEntryType type,
                                                          int eventID,
                                                          short category,
                                                          byte[] rawData)
            #>

            [System.Diagnostics.EventLog]::WriteEntry($params)
        } catch {
            Write-Error -Message ('Failed to write to event log: {0}' -f $_)
        } #end try-catch
    } #end Process

    End {
        # No specific end actions for this function
    } #end End
} #end function Write-CustomEventLog
