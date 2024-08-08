function New-LocalLogonTask {
    <#
    .SYNOPSIS
        Generates a New Local Logon task
    .DESCRIPTION
        Generates a New Local Logon task
    .EXAMPLE
        New-LocalLogonTask -Name -Description -Author -Command -CommandArguments -Hiden
    .NOTES
        Version:         1.0
        DateModified:    31/Mar/2015
        LasModifiedBy:   Vicente Rodriguez Eguibar
            vicente@eguibar.com
            Eguibar Information Technology S.L.
            http://www.eguibarit.com
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param
    (
        # Param1 help description
        [Parameter(Mandatory = $true,
            HelpMessage = 'Add help message for user',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $name,

        # Param2 help description
        [Parameter(Mandatory = $true,
            HelpMessage = 'Add help message for user',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Description,

        # Param3 help description
        [Parameter(Mandatory = $true,
            HelpMessage = 'Add help message for user',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Author,

        # Param4 help description
        [Parameter(Mandatory = $true,
            HelpMessage = 'Add help message for user',
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
            Position = 4)]
        [string]
        $CommandArguments,

        # Param6 help description
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 5)]
        [switch]
        $Hidden
    )

    Begin {
        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

    } #end Begin

    Process {
        # https://msdn.microsoft.com/en-us/library/windows/desktop/aa383607(v=vs.85).aspx
        try {
            # Create the TaskService object
            $service = New-Object -ComObject('Schedule.Service')
            # Connect to the server's Task Service Scheduler
            $service.Connect($Env:computername)

            $rootFolder = $service.GetFolder('\')

            $taskDefinition = $service.NewTask(0)

            # Define information about the task.
            # Set the registration info for the task by creating the RegistrationInfo object.
            $regInfo = $taskDefinition.RegistrationInfo
            $regInfo.Description = $Description
            $regInfo.Author = $Author

            # Set the task setting info for the Task Scheduler by creating a TaskSettings object.
            $settings = $taskDefinition.Settings
            $settings.Enabled = $true
            $settings.StartWhenAvailable = $true
            $settings.Hidden = $Hidden

            # Create a logon trigger
            $triggers = $taskDefinition.Triggers
            # TriggerTypeLogon is 9
            $trigger = $triggers.Create(9)

            # Trigger variables that define when the trigger is active
            $trigger.StartBoundary = '2014-10-0T22:00:00'
            #$trigger.DaysInterval = 1
            $trigger.Id = 'LogonTriggerId'
            $trigger.Enabled = $true

            # Create the action for the task to execute. Add an action to the task
            $Action = $taskDefinition.Actions.Create(0)
            $Action.Path = $Command
            $Action.Arguments = $CommandArguments

            # Register (create -> 6 ) the task
            $rootFolder.RegisterTaskDefinition( $name, $taskDefinition, 6, $null , $null , 0)
        } catch {
            Write-Error -Message 'Error when creating new logon task'
            throw
        }
    } #end Process

    End {
        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'creating new task.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Process
