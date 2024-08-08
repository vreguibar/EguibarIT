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
    [OutputType([void])]

    Param (

        # Param1 STRING for the Module Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the module to be imported',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $name,

        # Indicates whether to force the import of the module
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 1)]
        [switch]
        $Force
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

        [Hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {

        try {
            $module = Get-Module -Name $PSBoundParameters['name'] -ListAvailable -ErrorAction SilentlyContinue

            if ($null -eq $module) {
                Write-Error -Message ('Module {0} is not installed. Please install the module before importing.' -f $PSBoundParameters['name'])
            } else {
                # Import the module if it's not already imported
                if (-not (Get-Module -Name $PSBoundParameters['name'] -ErrorAction SilentlyContinue)) {
                    $Splat = @{
                        ModuleInfo  = $module
                        ErrorAction = 'Stop'
                        Verbose     = $Verbose
                    }

                    if ($Force) {
                        $Splat.Add('Force', $true)
                    }

                    Import-Module @Splat
                    Write-Verbose -Message ('Successfully imported module {0}' -f $PSBoundParameters['name'])
                } else {
                    Write-Verbose -Message ('Module {0} is already imported.' -f $PSBoundParameters['name'])
                }
            }
        } catch {
            Write-Error -Message 'Error when importing module'
            throw
        } #end Try-Catch

    } #end Process

    End {
        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'importing module.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
