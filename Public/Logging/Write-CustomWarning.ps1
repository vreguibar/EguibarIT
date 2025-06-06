﻿function Write-CustomWarning {

    <#
        .SYNOPSIS
            Mimics Write-Warning but with optional logging to the Windows Event Log.

        .DESCRIPTION
            This function writes warning messages to the console and, if instructed, to the specified Windows Event Log.
            It supports both predefined and custom event logging, allowing flexibility in logging approaches.

            The function acts as a wrapper around Write-Warning, enhancing it with event logging capabilities.
            This helps maintain a centralized logging system while preserving the familiar PowerShell warning output.

        .PARAMETER CreateWindowsEvent
            Switch to indicate if a Windows Event Log entry should be created in addition to outputting a warning message.

        .PARAMETER Message
            The message to be written, either to the console (as warning) or the Windows Event Log.

        .PARAMETER EventInfo
            Predefined event information of type [EventIDs], if using predefined events.

        .PARAMETER EventId
            Custom event ID if logging a custom event.

        .PARAMETER EventName
            Name of the custom event being logged.

        .PARAMETER EventCategory
            Custom event category for the event.

        .EXAMPLE
            # Write a simple warning message
            Write-CustomWarning -Message "Starting process" -Verbose

        .EXAMPLE
            # Log a warning message and also create a Windows Event Log entry with predefined event info
            Write-CustomWarning -CreateWindowsEvent -EventInfo ([EventIDs]::SlowPerformance) -Message "Old hardware detected."

        .EXAMPLE
            # Log a warning message and also create a Windows Event Log entry with predefined event info
            $Splat = @{
                CreateWindowsEvent = $true
                EventInfo          = ([EventIDs]::GetGroupMembership)
                Message            = 'Fetched all members of the group.'
            }
            Write-CustomWarning @Splat

        .EXAMPLE
            # Log a custom event with specific event details
            Write-CustomWarning -CreateWindowsEvent -EventId 5001 -EventName "CustomEvent" -EventCategory SystemHealth
            -Message "Custom verbose message." -Verbose

        .EXAMPLE
            Write-CustomWarning -CustomEventId ([EventID]::LowDiskSpace) -EventName "LowDiskSpace" -EventCategory SystemHealth
            -Message "Low disk space detected on C: drive. Free space below 10%." -Verbose

        .NOTES
            Ensure necessary event types (EventIDs, EventCategory, etc.) are defined on Class.Events.ps1 file
            located under Classes folder.
            This file is written in C# (CSharp) language and compiled in runtime when module is imported. This is
            due visibility and compatibility issues on modules when using just PowerShell code.

        .NOTES
            Used Functions:
                Name                          ║ Module/Namespace
                ══════════════════════════════╬════════════════════════════════
                Write-CustomLog               ║ EguibarIT
                Write-Warning                 ║ Microsoft.PowerShell.Utility
                Write-Verbose                 ║ Microsoft.PowerShell.Utility
                Write-Error                   ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    01/Apr/2025
            LastModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Logging/Write-CustomWarning.ps1
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low',
        DefaultParameterSetName = 'Default'
    )]
    [OutputType([void])]

    param(

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'If present a new event will be created in the corresponding Windows Event among Write-Verbose.',
            Position = 0)]
        [Alias('LogEvent', 'WriteEvent')]
        [switch]
        $CreateWindowsEvent,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Message body of the event and/or Verbose message.',
            Position = 1,
            ParameterSetName = 'Default')]
        [Parameter(ParameterSetName = 'Custom')]
        [ValidateNotNullOrEmpty()]
        [Alias('Text', 'WarningMessage')]
        [string]
        $Message,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Default built-in Event Information to be used of type [EventIDs].',
            Position = 2,
            ParameterSetName = 'Default')]
        [EventIDInfo]
        $EventInfo,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Custom Event ID to be used of type [EventID].',
            Position = 2,
            ParameterSetName = 'Custom')]
        [ValidateScript({
                [Enum]::IsDefined([EventID], $_)
            })]
        [EventID]
        $EventId,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Custom Event Name to be used.',
            Position = 3,
            ParameterSetName = 'Custom')]
        [ValidateNotNullOrEmpty()]
        [string]
        $EventName,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Custom Category to be used of type [EventCategory].',
            Position = 4,
            ParameterSetName = 'Custom')]
        [ValidateScript({
                [Enum]::IsDefined([EventCategory], $_)
            })]
        [EventCategory]
        $EventCategory

    )

    Begin {

        $ErrorActionPreference = 'Stop'

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {
        if ($PSCmdlet.ShouldProcess("Writing verbose log: $Message")) {

            # Handle logging to Windows Event Log if requested
            If ($PSBoundParameters.ContainsKey('CreateWindowsEvent')) {

                # Use predefined event info if available, otherwise, use custom event details
                If ($PSBoundParameters.ContainsKey('EventInfo')) {

                    # Predefined (Built-In) event to be used.
                    # Those are defined on the Class.Events.ps1 file under Classes folder.
                    Write-CustomLog -EventInfo $PSBoundParameters['EventInfo'] -Message $PSBoundParameters['Message']

                } else {

                    # Custom event logging
                    $Splat = @{
                        CustomEventId  = $PSBoundParameters['EventID']
                        EventName      = $PSBoundParameters['EventName']
                        EventCategory  = $PSBoundParameters['EventCategory']
                        Message        = $PSBoundParameters['Message']
                        CustomSeverity = [EventSeverity]::Warning
                        Verbose        = $PSBoundParameters['Verbose']
                    }
                    Write-CustomLog @Splat

                } #end Else-If

            } #end If CreateWindowsEvent

            # Call Write-Verbose with parsed message.
            Write-Warning -Message $Message -Verbose:$PSBoundParameters['Verbose']
        }
    } #end Process

    End {

    } #end End
} #end Function
