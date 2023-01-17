Function Import-MyModule
{
    <#
        .Synopsis
            Function to Import Modules with error handling
        .DESCRIPTION
            Function to Import Modules as with Import-Module Cmdlet but
            with error handling on it.
        .INPUTS
            Param1 name:........String representing Module Name
        .EXAMPLE
            Import-MyModule ActiveDirectory
        .NOTES
            Version:         1.0
            DateModified:    19/Feb/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        # Param1 STRING for the Module Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the module to be imported',
        Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $name
    )
    Begin{
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
    }
    Process
    {
        if(-not(Get-Module -Name $PSBoundParameters['name']))
        {
            if(Get-Module -ListAvailable -Name $PSBoundParameters['name'])
            {
                Import-Module -Name $PSBoundParameters['name'] -Force

                Write-Verbose -Message ('Imported module {0}' -f $PSBoundParameters['name'])
            }
            else
            {
                Throw ('Module {0} is not installed. Exiting...' -f $PSBoundParameters['name'])
                Write-Verbose -Message ('The module {0} is not installed.' -f $PSBoundParameters['name'])
            }
        }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished importing module."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
