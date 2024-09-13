function Write-CustomLog {
    <#
        .SYNOPSIS
            Logs custom events to the Windows Event Log and optionally outputs to a JSON file.

        .DESCRIPTION
            This function writes events to the Windows Event Log using predefined or custom event details.
            It also supports logging to a JSON file. The function supports custom logging categories, severities,
            and allows sensitive information to be masked. File logging can be customized for size and retention.

        .PARAMETER EventInfo
            Predefined event details, such as EventID, EventName, and Category, provided as a structured object.

        .PARAMETER CustomEventId
            The custom event ID for custom event logs.

        .PARAMETER EventName
            The name of the custom event being logged.

        .PARAMETER EventCategory
            Specifies the category of the event.

        .PARAMETER Message
            The log message that will be written. Sensitive information will be masked if necessary.

        .PARAMETER CustomSeverity
            The severity level of the event (e.g., Information, Warning, Error, etc.).

        .PARAMETER LogAsJson
            Switch to indicate if the log should be written to a JSON file.

        .PARAMETER MaximumKilobytes
            The maximum size in kilobytes for the event log. Default is 16 MB.

        .PARAMETER RetentionDays
            The number of days the logs should be retained. Default is 30 days.

        .PARAMETER LogPath
            The directory path where the JSON log files should be saved.

        .EXAMPLE
            Write-CustomLog -EventInfo ([EventIDs]::SlowPerformance) -Message 'Old hardware.' -Verbose

            Use the pre-defined events ([EventIDs]) and corresponding Message string.
            Where "EventInfo" is defined as [EventIDs] Class with pre-defined values as:
                EventID       = ID of the event as enum [EventID]
                Name          = Name of the event
                Description   = Description of the event
                EventCategory = Category of the event as enum [EventCategory]. This is only working if a compiled DLL exist.
                EventSeverity = Severity of the event as enum [EventSeverity]

        .EXAMPLE
            Write-CustomLog -CustomEventId ([EventID]::LowDiskSpace) `
            -EventName "LowDiskSpace" `
            -EventCategory SystemHealth `
            -Message "Low disk space detected on C: drive. Free space below 10%." `
            -CustomSeverity Warning -Verbose

            We create the event to log by providing the required parameters.

        .NOTES
            Ensure necessary event types (EventIDs, EventCategory, etc.) are defined on Class.Events.ps1 file
            located under Classes folder.
            This file is written in C# (CSharp) language and compiled in runtime when module is imported. This is
            due visibility and compatibility issues on modules when using just PowerShell code.

        .NOTES
            Used Functions:
                Name                          | Module
                ------------------------------|--------------------------
                Remove-SensitiveData          | EguibarIT
                Initialize-EventLogging       | EguibarIT
                Write-EventLog                | Microsoft.PowerShell.Management
                Write-Error                   | Microsoft.PowerShell.Utility.Activities
                Write-Verbose                 | Microsoft.PowerShell.Utility.Activities
                Write-Warning                 | Microsoft.PowerShell.Utility.Activities

    #>

    [CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Predefined')]
    [OutputType([void])]

    param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Default Event Information to be used.',
            Position = 0,
            ParameterSetName = 'Predefined')]
        [ValidateNotNullOrEmpty()]
        [EventIDInfo]
        $EventInfo,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Integer representing the Event ID.',
            Position = 1,
            ParameterSetName = 'Custom')]
        [ValidateRange(1000, 65535)] # assuming a valid custom event ID range
        [int]
        $CustomEventId,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Name of the event.',
            Position = 2,
            ParameterSetName = 'Custom')]
        [string]
        $EventName,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Category assigned to the event.',
            Position = 3,
            ParameterSetName = 'Custom')]
        [ValidateScript({
                [Enum]::IsDefined([EventCategory], $_)
            })]
        [EventCategory]
        $EventCategory,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Message of the event.',
            Position = 4)]
        [ValidateLength(1, 2048)]
        [string]
        $Message,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Severity assigned to the event.',
            Position = 5,
            ParameterSetName = 'Custom')]
        #[ValidateSet('Information', 'Warning', 'Error', 'SuccessAudit', 'FailureAudit')]
        [ValidateScript({
                [Enum]::IsDefined([EventSeverity], $_)
            })]
        [EventSeverity]
        $CustomSeverity,

        [Parameter(ParameterSetName = 'JsonLogging')]
        [switch]
        $LogAsJson,

        [Parameter(ParameterSetName = 'EventLogging')]
        [int]
        $MaximumKilobytes = 16384, # default 16 MB

        [Parameter(ParameterSetName = 'EventLogging')]
        [int]
        $RetentionDays = 30, # default 30 days

        [Parameter(ParameterSetName = 'JsonLogging')]
        [ValidateScript({ Test-Path $_ -PathType 'Container' })] # Validate directory
        [string]
        $LogPath = 'C:\Logs',

        [Parameter(ParameterSetName = 'JsonLogging')]
        [string]
        $JsonLogName = 'CustomLog',

        [Parameter(ParameterSetName = 'JsonLogging')]
        [int]
        $JsonMaxFileSizeMB = 10

    )

    Begin {
        $ErrorActionPreference = 'Stop'

        # Mask sensitive data
        $maskedMessage = Remove-SensitiveData -Message $Message

        # Initialize event logging
        Initialize-EventLogging -MaximumKilobytes $MaximumKilobytes -RetentionDays $RetentionDays

        if ($PSCmdlet.ParameterSetName -eq 'Custom') {
            $eventId = $CustomEventId
            $eventName = $EventName
            $eventCategory = $EventCategory
            $severity = $CustomSeverity
        } else {
            $eventId = $EventInfo.ID
            $eventName = $EventInfo.Name
            $eventCategory = $EventInfo.Category
            $severity = $EventInfo.DefaultSeverity
        } #end If-Else

        $entryType = switch ($severity) {
            'Information' {
                [System.Diagnostics.EventLogEntryType]::Information
            }
            'Warning' {
                [System.Diagnostics.EventLogEntryType]::Warning
            }
            'Error' {
                [System.Diagnostics.EventLogEntryType]::Error
            }
            'SuccessAudit' {
                [System.Diagnostics.EventLogEntryType]::SuccessAudit
            }
            'FailureAudit' {
                [System.Diagnostics.EventLogEntryType]::FailureAudit
            }
        }


        $sb = [System.Text.StringBuilder]::new()
        $sb.AppendLine("Event          : $eventName") | Out-Null
        $sb.AppendLine("Event Category : $eventCategory") | Out-Null
        $sb.AppendLine("Details        : $maskedMessage") | Out-Null

    } #end Begin

    Process {
        if ($PSCmdlet.ShouldProcess("Logging event: $eventName with severity $severity")) {
            try {

                # Write to Windows Event Log
                # LogName and Source are defined on $Variables which is initialized when module is imported.
                $Splat = @{
                    LogName   = $Variables.LogConfig.LogName
                    Source    = $Variables.LogConfig.Source
                    EntryType = $entryType
                    EventId   = $eventId
                    Category  = [int]([Enum]::Parse([EventCategory], $eventCategory))  # Convert EventCategory to int
                    Message   = $sb.ToString()
                }
                Write-EventLog @Splat

                # https://learn.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlog.writeentry?view=net-8.0
                <# [System.Diagnostics.EventLog]::WriteEntry (string source,
                                                          string message,
                                                          System.Diagnostics.EventLogEntryType type,
                                                          int eventID,
                                                          short category,
                                                          byte[] rawData)

                $params = @(
                    $Source,
                    $Message,
                    $eventType,
                    $EventId
                )

                [System.Diagnostics.EventLog]::WriteEntry($params)
                #>



                # Log to JSON
                if ($LogAsJson) {
                    $logObject = [PSCustomObject]@{
                        EventID        = $eventId
                        Name           = $eventName
                        Category       = $eventCategory
                        Severity       = $severity
                        Message        = $maskedMessage
                        Timestamp      = (Get-Date).ToString('o')
                        AdditionalData = @{
                            # Add any additional structured data here
                            MachineName = $env:COMPUTERNAME
                            UserName    = $env:USERNAME
                        }
                    }

                    $jsonFile = Join-Path $LogPath "$JsonLogName.json"

                    # Ensure directory exists
                    if (-not (Test-Path -Path $LogPath)) {
                        New-Item -ItemType Directory -Force -Path $LogPath | Out-Null
                    }

                    # Check file size and rotate if necessary
                    if (Test-Path $jsonFile) {
                        $fileInfo = Get-Item $jsonFile
                        if ($fileInfo.Length / 1MB -ge $JsonMaxFileSizeMB) {
                            $backupFile = Join-Path $LogPath "$JsonLogName-$(Get-Date -Format 'yyyyMMddHHmmss').json"
                            Move-Item $jsonFile $backupFile
                        }
                    }

                    $logObject | ConvertTo-Json | Out-File -FilePath $jsonFile -Append

                    Write-Verbose -Message ('Event {0} was logged successfully to JSON.' -f $eventName)
                } #end If

                Write-Verbose -Message ('
                    Event {0} with ID {1}
                    was logged successfully to the event log.' -f
                    $eventName, $eventId
                )
            } catch {
                Write-Error -Message ('
                    An error occurred while logging the event.
                    Exception: {0}
                    Full details: {1}' -f
                    $_.Exception.Message, $_
                )
                throw
            } #end Try-Catch
        } #end If
    } #end Process

    End {
        Write-Verbose -Message 'Logging process completed.'
    } #end End
} #end Function
