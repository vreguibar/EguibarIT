function Initialize-EventLogging {

    <#
        .SYNOPSIS
            Initializes event logging by creating and configuring a new event log.

        .DESCRIPTION
            This function checks if an event log exists and creates it if it doesn't.
            It also configures the log with a maximum size, retention policy, and error-handling retry logic.
            The function supports verbose output, what-if, and confirmation prompts.

        .PARAMETER MaximumKilobytes
            Specifies the maximum size of the event log in kilobytes. Default is 16384 KB (16 MB).

        .PARAMETER RetentionDays
            Specifies the number of days to retain event log entries. Default is 30 days.

        .PARAMETER LogName
            The name of the Windows Event Log to create or configure.
            Default is the value from $Variables.LogConfig.LogName or "EguibarIT-Events" if not set.

        .PARAMETER Source
            The source identifier for the event log entries.
            Default is the value from $Variables.LogConfig.Source or "EguibarIT-PowerShellModule" if not set.

        .EXAMPLE
            Initialize-EventLogging -MaximumKilobytes 8192 -RetentionDays 15 -Verbose

            Initializes event logging with a log size of 8192 KB and retention period of 15 days, with verbose output enabled.

        .EXAMPLE
            Initialize-EventLogging -LogName "MyCustomLog" -Source "MyApp" -WhatIf

            Shows what would happen if a custom event log were initialized, without making any changes.

        .INPUTS
            [int] - MaximumKilobytes
            [int] - RetentionDays
            [string] - LogName
            [string] - Source

        .OUTPUTS
            [bool] - Returns $true if initialization was successful, $false otherwise.

        .NOTES
            Used Functions:
                Name                                    ║ Module/Namespace
                ════════════════════════════════════════╬══════════════════════════════
                Get-FunctionDisplay                     ║ EguibarIT
                Get-Date                                ║ Microsoft.PowerShell.Utility
                New-EventLog                            ║ Microsoft.PowerShell.Management
                Limit-EventLog                          ║ Microsoft.PowerShell.Management
                Write-EventLog                          ║ Microsoft.PowerShell.Management
                Write-Error                             ║ Microsoft.PowerShell.Utility
                Write-Verbose                           ║ Microsoft.PowerShell.Utility
                Write-Warning                           ║ Microsoft.PowerShell.Utility
                Start-Sleep                             ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:    24/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Event Management

        .ROLE
            System Administration

        .FUNCTIONALITY
            Event Logging, System Configuration
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([bool])]

    param (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Maximum size of the Event file.',
            Position = 0)]
        [ValidateRange(64, 1048576)]  # Minimum of 64 KB, max of 1 GB
        [PSDefaultValue(
            Help = 'Default Value is "16384"',
            value = 16384
        )]
        [int]
        $MaximumKilobytes, # default to 16 MB

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Maximum day to retain events.',
            Position = 1)]
        [ValidateRange(1, 365)]  # Minimum of 1 day, max of 1 year
        [PSDefaultValue(
            Help = 'Default Value is "30"',
            Value = 30
        )]
        [int]
        $RetentionDays, # default to 30 days

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the Windows Event Log.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $LogName,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Source identifier for the event log entries.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Source
    )

    Begin {
        Set-StrictMode -Version Latest

        # Show ONLY if not Initialized.
        If (-not $Variables.EventLogInitialized) {
            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Retry logic in case of failure
        [int]$RetryCount = 0

        # Check for administrative privileges
        [bool]$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')

        if (-not $IsAdmin) {
            Write-Warning -Message 'This function requires administrative privileges to create event logs.'
        } #end If


        # Ensure LogConfig exists in $Variables
        if (-not $Variables.ContainsKey('LogConfig')) {
            $Variables['LogConfig'] = @{
                LogName = 'EguibarIT-Events'
                Source  = 'EguibarIT-PowerShellModule'
            }
        } #end If

        # Set default values for LogName and Source if not provided
        if (-not $PSBoundParameters.ContainsKey('LogName')) {
            $LogName = $Variables.LogConfig.LogName
        } else {
            # Update the global variable with the new value
            $Variables.LogConfig.LogName = $LogName
        } #end If-Else

        if (-not $PSBoundParameters.ContainsKey('Source')) {
            $Source = $Variables.LogConfig.Source
        } else {
            # Update the global variable with the new value
            $Variables.LogConfig.Source = $Source
        } #end If-Else

        # Update maximum size and retention days
        $Variables.LogConfig.MaximumKilobytes = $MaximumKilobytes
        $Variables.LogConfig.RetentionDays = $RetentionDays

    } #end Begin

    Process {
        # Retry logic with up to 3 attempts
        while (-not $Variables.EventLogInitialized -and $RetryCount -lt 3) {

            try {
                # Check if the event source exists, and if not, create it
                if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {

                    if ($PSCmdlet.ShouldProcess("Event log source '$Source'", 'Create')) {

                        Write-Verbose -Message ('Creating event log source {0} for log {1}' -f $Source, $LogName)

                        $Splat = @{
                            LogName = $LogName
                            Source  = $Source
                        }

                        # Add Verbose if specified
                        if ($PSBoundParameters['Verbose']) {
                            $Splat['Verbose'] = $true
                        } #end If

                        New-EventLog @Splat

                        Write-Verbose -Message ('Log source {0} created in log {1}.' -f $Source, $LogName)

                        $Splat = @{
                            LogName        = $LogName
                            MaximumSize    = $MaximumKilobytes * 1KB  # Convert to bytes
                            OverflowAction = 'OverwriteOlder'
                            RetentionDays  = $RetentionDays
                        }

                        # Add Verbose if specified
                        if ($PSBoundParameters['Verbose']) {
                            $Splat['Verbose'] = $true
                        } #end If

                        Limit-EventLog @Splat

                        Write-Verbose -Message (
                            'Log {0} was configured with {1} KB size and {2} days retention.' -f
                            $LogName,
                            $MaximumKilobytes,
                            $RetentionDays
                        )
                    } #end If ShouldProcess

                } else {
                    Write-Verbose -Message ('Event log source {0} already exists.' -f $Source)

                    # Update the log configuration even if source exists
                    if ($PSCmdlet.ShouldProcess("Event log '$LogName'", 'Update configuration')) {

                        $Splat = @{
                            LogName        = $LogName
                            MaximumSize    = $MaximumKilobytes * 1KB  # Convert to bytes
                            OverflowAction = 'OverwriteOlder'
                            RetentionDays  = $RetentionDays
                        }

                        # Add Verbose if specified
                        if ($PSBoundParameters['Verbose']) {
                            $Splat['Verbose'] = $true
                        } #end If

                        Limit-EventLog @Splat

                        Write-Verbose -Message (
                            'Updated log {0} configuration: {1} KB size, {2} days retention.' -f
                            $LogName,
                            $MaximumKilobytes,
                            $RetentionDays
                        )
                    } #end If ShouldProcess
                } #end If-Else SourceExists

                # Set Global Variable
                $Variables.EventLogInitialized = $true
                Write-Verbose -Message 'Event logging initialized successfully.'

                # Write a test entry to verify everything is working
                if ($PSCmdlet.ShouldProcess('Test event log entry', 'Write to Event Log')) {

                    $Splat = @{
                        LogName   = $LogName
                        Source    = $Source
                        EventId   = 1000  # Information event ID
                        EntryType = 'Information'
                        Message   = 'Event logging initialized successfully by EguibarIT module.'
                    }
                    Write-EventLog @Splat

                } #end If ShouldProcess

            } catch [System.Security.SecurityException] {
                $RetryCount++

                Write-Warning -Message (
                    'Security exception encountered. Administrative privileges may be required. Retrying... ({0}/3)' -f
                    $RetryCount
                )
                Start-Sleep -Seconds 2

            } catch [System.InvalidOperationException] {
                $RetryCount++

                Write-Warning -Message ('Invalid operation when initializing event log. Retrying... ({0}/3)' -f $RetryCount)
                Start-Sleep -Seconds 2

            } catch {
                $retryCount++

                Write-Warning -Message (
                    'Failed to initialize event logging: {0}. Retrying... ({1}/3)' -f
                    $_.Exception.Message,
                    $RetryCount
                )

                Start-Sleep -Seconds 2
            } #end Try-Catch

        } #end While

        if (-not $Variables.EventLogInitialized) {
            throw 'Failed to initialize event log after 3 attempts.'
            return $false
        } #end If

        return $true

    } #end Process

    End {
        # Show ONLY if not Initialized.
        If (-not $Variables.EventLogInitialized) {
            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'initializing Event Logging.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function Initialize-EventLogging
