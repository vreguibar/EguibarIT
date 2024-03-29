Function Import-MyModule {
    <#
        .SYNOPSIS
            Imports a PowerShell module with enhanced error handling.

        .DESCRIPTION
            This function imports a specified PowerShell module with additional
            error handling and verbose output. It checks if the module is available
            and not already imported before attempting to import it.

        .PARAMETER Name
            The name of the module to import.

        .EXAMPLE
            Import-MyModule -Name ActiveDirectory

            Tries to import the ActiveDirectory module, providing verbose output
            and handling errors if the module is not available.

        .NOTES
            Version:         1.1
            DateModified:    27/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Medium')]

    Param (

        # Param1 STRING for the Module Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the module to be imported',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $name,

        # Indicates whether to force the import of the module
        [switch]
        $Force
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        Import-MyModule -name ActiveDirectory

        ##############################
        # Variables Definition

        [Hashtable]$Splat = [hashtable]::New()

    } #end Begin

    Process {

        try {
            $module = Get-Module -Name $PSBoundParameters['name'] -ErrorAction Stop

            if (-not $module) {
                $availableModule = Get-Module -ListAvailable -Name $PSBoundParameters['name'] -ErrorAction Stop

                if ($availableModule) {

                    $Splat = @{
                        Name        = $PSBoundParameters['name']
                        ErrorAction = 'Stop'
                    }

                    If ($Force) {
                        $Splat.Add('Force', $True)
                    }

                    Import-Module @Splat

                    Write-Verbose -Message ('Successfully imported module {0}' -f $PSBoundParameters['name'])

                } else {
                    Write-Error "Module '$Name' is not installed. Please install the module before importing."
                } #end If-Else

            } else {
                Write-Verbose ('Module {0} is already imported.' -f $PSBoundParameters['name'])
            } #end If-Else
        } catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch

    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished importing module."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
}
