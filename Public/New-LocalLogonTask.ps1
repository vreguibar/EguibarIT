function New-LocalLogonTask {
    <#
        .SYNOPSIS
            Creates a new scheduled task that runs on user logon.

        .DESCRIPTION
            Creates a new Windows Scheduled Task that executes when users log on:
            - Configures task with specified name and description
            - Sets up logon trigger for execution
            - Supports hidden tasks
            - Allows command arguments
            - Implements security best practices
            - Provides detailed logging

            The task is created using the Schedule.Service COM object and configured
            to run with standard user privileges.

        .PARAMETER Name
            [String] Name of the scheduled task.
            Must be unique within the Task Scheduler.
            Used to identify the task in Task Scheduler.

        .PARAMETER Description
            [String] Detailed description of the task's purpose.
            Appears in Task Scheduler properties.

        .PARAMETER Author
            [String] Name of the task creator.
            Used for administrative tracking.

        .PARAMETER Command
            [String] Full path to the executable or script to run.
            Must be accessible to the executing user.

        .PARAMETER CommandArguments
            [String] Optional arguments passed to the command.
            Default: None

        .PARAMETER Hidden
            [Switch] If specified, hides the task from Task Scheduler UI.
            Default: Task is visible

        .EXAMPLE
            New-LocalLogonTask -Name "UpdateProfile" `
                            -Description "Updates user profile at logon" `
                            -Author "IT Department" `
                            -Command "C:\Scripts\Update-Profile.ps1"

            Creates a visible logon task that runs a PowerShell script.

        .EXAMPLE
            $params = @{
                Name = "SecurityScan"
                Description = "Runs security scan at logon"
                Author = "Security Team"
                Command = "C:\Program Files\Scanner\scan.exe"
                CommandArguments = "/quiet /full"
                Hidden = $true
            }
            New-LocalLogonTask @params

            Creates a hidden logon task with command arguments.

        .OUTPUTS
            [void]

        .NOTES
            Used Functions:
                Name                                  ║ Module/Namespace
                ══════════════════════════════════════╬════════════════════════
                Get-FunctionDisplay                   ║ EguibarIT
                Write-Verbose                         ║ Microsoft.PowerShell.Utility
                Write-Error                           ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    31/Mar/2024
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT
        .LINK
            https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-objects
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([void])]

    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
            HelpMessage = 'Name of the scheduled task',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $name,

        # Param2 help description
        [Parameter(Mandatory = $true,
            HelpMessage = 'Description of the task',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Description,

        # Param3 help description
        [Parameter(Mandatory = $true,
            HelpMessage = 'Author of the task',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Author,

        # Param4 help description
        [Parameter(Mandatory = $true,
            HelpMessage = 'Command to execute',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Command,

        # Param5 help description
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Optional command arguments',
            Position = 4)]
        [string]
        $CommandArguments,

        # Param6 help description
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Hide task from Task Scheduler UI',
            Position = 5)]
        [switch]
        $Hidden
    )

    Begin {
        Set-StrictMode -Version Latest

        # Initialize logging
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToShortDateString(),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Module imports

        ##############################
        # Variables Definition

    } #end Begin

    Process {
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa383607(v=vs.85).aspx
        try {

            if ($PSCmdlet.ShouldProcess($Name, 'Create logon task')) {
                Write-Debug -Message ('Creating task service object for {0}' -f $Env:COMPUTERNAME)

                # Create the TaskService object
                $service = [Type]::GetTypeFromProgID('Schedule.Service')
                $taskService = [Activator]::CreateInstance($service)
                $taskService.Connect($Env:COMPUTERNAME)
                $rootFolder = $taskService.GetFolder('\')

                $taskDefinition = $service.NewTask(0)

                # Set registration info using direct property access
                Write-Debug -Message 'Configuring task registration info'
                $taskDefinition.RegistrationInfo.Description = $Description
                $taskDefinition.RegistrationInfo.Author = $Author

                # Configure settings using direct property access
                Write-Debug -Message 'Configuring task settings'
                $taskDefinition.Settings.Enabled = $true
                $taskDefinition.Settings.StartWhenAvailable = $true
                $taskDefinition.Settings.Hidden = $Hidden.IsPresent

                # Create logon trigger using method calls
                Write-Debug -Message 'Creating logon trigger'
                $trigger = $taskDefinition.Triggers.Create(9) # TriggerTypeLogon
                $trigger.Id = 'LogonTriggerId'
                $trigger.Enabled = $true

                # Trigger variables that define when the trigger is active
                $trigger.StartBoundary = '2014-10-0T22:00:00'
                #$trigger.DaysInterval = 1
                $trigger.Id = 'LogonTriggerId'
                $trigger.Enabled = $true

                # Create action using method calls
                Write-Debug -Message ('Creating task action: {0}' -f $Command)
                $action = $taskDefinition.Actions.Create(0)
                $action.Path = $Command
                if ($PSBoundParameters.ContainsKey('CommandArguments')) {
                    $action.Arguments = $CommandArguments
                } #end If

                # Register task
                Write-Debug -Message ('Registering task: {0}' -f $Name)
                $rootFolder.RegisterTaskDefinition(
                    $Name,
                    $taskDefinition,
                    6, # Create or update
                    $null, # No user
                    $null, # No password
                    0         # Run only when user is logged on
                )

                Write-Verbose -Message ('Successfully created task: {0}' -f $Name)

            } #end If
        } catch {
            Write-Error -Message ('Failed to create logon task {0}: {1}' -f $Name, $_.Exception.Message)
            throw
        }
    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating new task.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End

} #end Process New-LocalLogonTask
