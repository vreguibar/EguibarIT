function Initialize-CustomEventLog {
    <#
        .SYNOPSIS
            Initializes a custom event log source.

        .DESCRIPTION
            This function checks if a specified event log source exists and creates it if it doesn't.

        .PARAMETER LogName
            The name of the event log. Default is 'MyApplicationLog'.

        .PARAMETER Source
            The name of the event source. Default is 'MyApplication'.

        .EXAMPLE
            Initialize-CustomEventLog

        .EXAMPLE
            Initialize-CustomEventLog -LogName 'CustomLog' -Source 'CustomApp'
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([System.Void])]

    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Enter the name of the event log',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $LogName,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Enter the name of the event source',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Source
    )

    Begin {
    } #end Begin

    Process {
        if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
            try {
                [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
                Write-Verbose -Message ('Event log source {0} created successfully.' -f $Source)
            } catch {
                Write-Error -Message ('Failed to create event log source: {0}' -f $_)
            } #end try-catch
        } else {
            Write-Verbose -Message ('Event log source {0} already exists.' -f $Source)
        } #end if-else
    } #end Process

    End {
    } #end End

} #end function Initialize-CustomEventLog
