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

        .EXAMPLE
            Initialize-EventLogging -MaximumKilobytes 8192 -RetentionDays 15 -Verbose

            Initializes event logging with a log size of 8192 KB and retention period of 15 days, with verbose output enabled.

        .EXAMPLE
            Initialize-EventLogging -WhatIf

            Shows what would happen if the event logging were initialized, without making any changes.

        .INPUTS
            [int] - MaximumKilobytes
            [int] - RetentionDays

        .OUTPUTS
            None. Writes to the verbose stream or throws an error if initialization fails.

        .NOTES
            Used Functions:
                Name                          | Module
                ------------------------------|--------------------------
                Get-FunctionDisplay           | EguibarIT
                Get-Date                      | Microsoft.PowerShell.Utility
                Limit-EventLog                | Microsoft.PowerShell.Management
                Write-EventLog                | Microsoft.PowerShell.Management
                Write-Error                   | Microsoft.PowerShell.Utility.Activities
                Write-Verbose                 | Microsoft.PowerShell.Utility.Activities
                Write-Warning                 | Microsoft.PowerShell.Utility.Activities
    #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([void])]

    param (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Maximum size of the Event file.',
            Position = 0)]
        [ValidateRange(64, 1048576)]  # Minimum of 64 KB, max of 1 GB
        [PSDefaultValue(Help = 'Default Value is "16384"')]
        [int]
        $MaximumKilobytes = 16384, # default to 16 MB

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Maximum day to retain events.',
            Position = 0)]
        [ValidateRange(1, 365)]  # Minimum of 1 day, max of 1 year
        [PSDefaultValue(Help = 'Default Value is "30"')]
        [int]
        $RetentionDays = 30         # default to 30 days
    )

    Begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Retry logic in case of failure
        $retryCount = 0

    } #end Begin

    Process {
        # Retry logic with up to 3 attempts
        while (-not $Variables.EventLogInitialized -and $retryCount -lt 3) {
            try {
                # Check if the event source exists, and if not, create it
                if (-not [System.Diagnostics.EventLog]::SourceExists($Variables.LogConfig.Source)) {

                    if ($PSCmdlet.ShouldProcess("Event log source $($Variables.LogConfig.Source)", 'Create event log')) {
                        $Splat = @{
                            LogName = $Variables.LogConfig.LogName
                            Source  = $Variables.LogConfig.Source
                            Verbose = ($PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -eq $true)
                        }
                        New-EventLog @Splat

                        Write-Verbose -Message ('Log {0} did not exist. It got created.' -f $Variables.LogConfig.LogName)

                        $Splat = @{
                            LogName        = $Variables.LogConfig.LogName
                            MaximumSize    = $MaximumKilobytes
                            OverflowAction = 'OverwriteOlder'
                            RetentionDays  = $RetentionDays
                            Verbose        = ($PSCmdlet.MyInvocation.BoundParameters['Verbose'].IsPresent -eq $true)
                        }
                        Limit-EventLog @Splat

                        Write-Verbose -Message ('Log {0} was configured correctly.' -f $Variables.LogConfig.LogName)
                    } #end If ShouldProcess

                } #end If SourceExist

                # Set Global Variable
                $Variables.EventLogInitialized = $true

            } catch {
                $retryCount++

                Write-Warning -Message ('Failed to initialize event logging. Retrying... ({0}/3)' -f $retryCount)

                Start-Sleep -Seconds 2
            } #end Try-Catch

        } #end While

        if (-not $Variables.EventLogInitialized) {
            throw 'Failed to initialize event log after 3 attempts.'
        } #end If

    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'initializing Event Logging.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
