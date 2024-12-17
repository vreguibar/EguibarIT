Function Import-MyModule {
    <#
        .SYNOPSIS
        Imports a PowerShell module with enhanced error handling and functionality.

        .DESCRIPTION
            This function imports a specified PowerShell module with additional
            error handling, verbose output, and advanced features. It checks if the module
            is available, handles different versions, and provides options for forced imports
            and minimum version requirements. It also accepts additional arguments for maximum flexibility.

        .PARAMETER Name
            The name of the module to import.

        .PARAMETER MinimumVersion
            The minimum version of the module to import. If specified, the function will
            import the newest version that meets this criteria.

        .PARAMETER RequiredVersion
            The exact version of the module to import. If specified, only this version
            will be imported.

        .PARAMETER Force
            Forces a module to be imported even if it's already imported.

        .PARAMETER Global
            Imports the module into the global session state.

        .PARAMETER PassThru
            Returns the imported module object.

        .PARAMETER Prefix
            Adds a prefix to the imported module's cmdlets and other items.

        .PARAMETER DisableNameChecking
            Suppresses the message that warns you when you import a cmdlet or function
            whose name includes an unapproved verb or a prohibited character.

        .PARAMETER NoClobber
            Prevents importing commands that would hide or overwrite existing commands.

        .PARAMETER Scope
            Defines the scope of the import, either 'Global' or 'Local'.

        .PARAMETER SkipEditionCheck
            Skips the edition check if importing modules designed for Windows PowerShell in PowerShell Core.

        .PARAMETER UseWindowsPowerShell
            Forces the module to be imported using Windows PowerShell instead of PowerShell Core.


        .EXAMPLE
            Import-MyModule -Name ActiveDirectory
            Tries to import the ActiveDirectory module, providing verbose output
            and handling errors if the module is not available.

        .EXAMPLE
            Import-MyModule -Name AzureAD -MinimumVersion 2.0.0 -Force -Verbose
            Imports the AzureAD module with a minimum version of 2.0.0, forcing the import
            even if it's already loaded, and provides verbose output.

        .NOTES
            Version:        2.1
            DateModified:   27/Aug/2024
            LastModifiedBy: Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([System.Management.Automation.PSModuleInfo])]

    Param (

        # Param1 STRING for the Module Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'Name of the module to be imported',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('Module', 'ModuleName')]
        [string]
        $Name,

        [Parameter(Mandatory = $false)]
        [switch]
        $Force,

        [Parameter(Mandatory = $false)]
        [switch]
        $Global,

        [Parameter(Mandatory = $false)]
        [System.Version]
        $MinimumVersion,

        [Parameter(Mandatory = $false)]
        [System.Version]
        $RequiredVersion,

        [Parameter(Mandatory = $false)]
        [switch]
        $PassThru,

        [Parameter(Mandatory = $false)]
        [string]
        $Prefix,

        [Parameter(Mandatory = $false)]
        [switch]
        $DisableNameChecking,

        [Parameter(Mandatory = $false)]
        [switch]
        $NoClobber,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Global', 'Local')]
        [string]
        $Scope,

        [Parameter(Mandatory = $false)]
        [switch]
        $SkipEditionCheck,

        [Parameter(Mandatory = $false)]
        [switch]
        $UseWindowsPowerShell
    )

    Begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $Preference = $VerbosePreference
        $VerbosePreference = 'SilentlyContinue'

        $functionName = $MyInvocation.MyCommand.Name

        # Get Hashtable with corresponding parameters to import module
        $importParams = @{
            Name        = $name
            ErrorAction = 'Stop'
        }


        if ($Force) {
            $importParams['Force'] = $true
        } #end If

        if ($Global) {
            $importParams['Global'] = $true
        } #end If

        # Add optional parameters if specified
        if ($PSBoundParameters.ContainsKey('MinimumVersion')) {
            $importParams['MinimumVersion'] = $MinimumVersion
        } #end If

        if ($PSBoundParameters.ContainsKey('RequiredVersion')) {
            $importParams['RequiredVersion'] = $RequiredVersion
        } #end If

        if ($PassThru) {
            $importParams['PassThru'] = $true
        } #end If

        if ($PSBoundParameters.ContainsKey('Prefix')) {
            $importParams['Prefix'] = $Prefix
        } #end If

        if ($DisableNameChecking) {
            $importParams['DisableNameChecking'] = $true
        } #end If

        if ($NoClobber) {
            $importParams['NoClobber'] = $true
        } #end If

        if ($Scope) {
            $importParams['Scope'] = $PSBoundParameters['Scope']
        } #end If

        if ($SkipEditionCheck) {
            $importParams['SkipEditionCheck'] = $true
        } #end If

        if ($UseWindowsPowerShell) {
            $importParams['UseWindowsPowerShell'] = $true
        } #end If


        # Handle Verbose parameter correctly
        if ($PSBoundParameters['Verbose'] -eq $true) {
            $importParams['Verbose'] = $true
        } elseIf (($PSBoundParameters['Verbose'] -eq $false) -or (-Not $PSBoundParameters.ContainsKey('Verbose'))) {
            $importParams['Verbose'] = $false
        }

    } #end Begin

    Process {

        try {

            If ($Name -eq 'GroupPolicy') {
                $importParams['Name'] = 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\GroupPolicy\GroupPolicy.psd1'
                Import-Module @importParams
            }

            If ($Name -eq 'ServerManager') {
                $importParams['Name'] = 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\ServerManager\ServerManager.psd1'
                Import-Module @importParams
            }

            # Change this part to correctly check for module availability
            $availableModule = Get-Module -Name $Name -ErrorAction SilentlyContinue -Verbose:$PSBoundParameters['Verbose']

            if (-not $availableModule) {
                Write-Error -Message ('Module "{0}" is not installed. Please install the module before importing.' -f $Name)
            } #end If


            # Check if the module is already imported
            $importedModule = Get-Module -Name $Name -ErrorAction SilentlyContinue -Verbose:$PSBoundParameters['Verbose']

            if ($null -ne $importedModule -and -not $Force) {
                Write-Verbose -Message ('[{0}] Module {1} is already imported.' -f $functionName, $Name)

                if ($PassThru) {
                    return $Module
                } #end If
                return

            } #end If

            # Perform the import
            if ($PSCmdlet.ShouldProcess($Name, 'Import Module')) {

                $importedModule = Import-Module @importParams -Verbose:$PSBoundParameters['Verbose']

                Write-Verbose -Message ('[{0}] Successfully imported module {1}' -f $functionName, $Name)


                if ($PassThru) {
                    return $importedModule
                } #end If

                Write-Verbose -Message ('Module {0} has been successfully imported.' -f $ModuleName)
            } #end else



        } catch {
            Write-Error -Message ('[{0}] Error importing module {1}: {2}' -f $functionName, $Name, $_)
            #throw
        } #end Try-Catch

    } #end Process

    End {
        $VerbosePreference = $Preference

        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'importing module.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
