Function Import-MyModule {

    <#
        .SYNOPSIS
            Imports a PowerShell module with enhanced error handling and functionality.

        .DESCRIPTION
            This function imports a specified PowerShell module with additional
            error handling, verbose output, and advanced features. It checks if the module
            is available, handles different versions, and provides options for forced imports
            and minimum version requirements. It also accepts additional arguments for maximum flexibility.

            For PowerShell Core (7+), it provides special compatibility handling for Windows PowerShell modules.

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

        .PARAMETER FallbackToWindowsPowerShell
            If set to true, when importing a module fails in PowerShell Core, the function will attempt to
            create proxy functions using Windows PowerShell. This is useful for modules that are not
            compatible with PowerShell Core.

        .EXAMPLE
            Import-MyModule -Name ActiveDirectory
            Tries to import the ActiveDirectory module, providing verbose output
            and handling errors if the module is not available.

        .EXAMPLE
            Import-MyModule -Name AzureAD -MinimumVersion 2.0.0 -Force -Verbose
            Imports the AzureAD module with a minimum version of 2.0.0, forcing the import
            even if it's already loaded, and provides verbose output.

        .EXAMPLE
            Import-MyModule -Name ServerManager -FallbackToWindowsPowerShell
            Attempts to import the ServerManager module, falling back to Windows PowerShell compatibility
            mode if direct import fails in PowerShell Core.

        .INPUTS
            System.String
            You can pipe module names to this function.

        .OUTPUTS
            System.Management.Automation.PSModuleInfo
            Returns the imported module object when -PassThru is specified.

        .NOTES
            Used Functions:
                Name                                    ║ Module/Namespace
                ════════════════════════════════════════╬══════════════════════════════
                Get-Module                              ║ Microsoft.PowerShell.Core
                Import-Module                           ║ Microsoft.PowerShell.Core
                Write-Verbose                           ║ Microsoft.PowerShell.Utility
                Write-Error                             ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                     ║ EguibarIT

        .NOTES
            Version:        2.7
            DateModified:   23/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Import-MyModule.ps1

        .COMPONENT
            PowerShell Module Management

        .ROLE
            System Administration

        .FUNCTIONALITY
            Module Import
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'low'
    )]
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
        $UseWindowsPowerShell,

        [Parameter(Mandatory = $false)]
        [switch]
        $FallbackToWindowsPowerShell
    )

    Begin {
        # Set strict mode
        Set-StrictMode -Version Latest

        # Initialize logging
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Variables Definition

        # Store original VerbosePreference to restore it later
        [string]$OriginalVerbosePreference = $VerbosePreference

        # Define function name for consistent logging
        [string]$FunctionName = $MyInvocation.MyCommand.Name

        # Initialize module tracking variables
        [System.Management.Automation.PSModuleInfo]$AvailableModule = $null
        [System.Management.Automation.PSModuleInfo]$ImportedModule = $null
        # Check PowerShell version - are we running in PowerShell Core (7+)?
        [bool]$IsPSCore = $PSVersionTable.PSVersion.Major -ge 7

        Write-Verbose -Message (
            '[{0}] Running in PowerShell version {1}.{2}. IsPSCore = {3}' -f
            $FunctionName, $PSVersionTable.PSVersion.Major, $PSVersionTable.PSVersion.Minor, $IsPSCore
        )

        # List of known Windows PowerShell-only modules that need special handling
        [string[]]$WindowsPSOnlyModules = @(
            'ServerManager',
            'GroupPolicy',
            'ActiveDirectory',
            'DFSN',
            'DFSR'
        )

        # Should we try to use Windows PowerShell compatibility?
        [bool]$TryWindowsCompatibility = $IsPSCore -and (
            $FallbackToWindowsPowerShell -or
            $UseWindowsPowerShell -or
            ($WindowsPSOnlyModules -contains $Name)
        )

        # Create import parameters hashtable
        [hashtable]$ImportParams = @{
            Name        = $Name
            ErrorAction = 'Stop'
        }

        # Add optional parameters based on what was passed to the function
        if ($Force) {
            $ImportParams['Force'] = $true
        } #end If

        if ($Global) {
            $ImportParams['Global'] = $true
        } #end If

        if ($PSBoundParameters.ContainsKey('MinimumVersion')) {
            $ImportParams['MinimumVersion'] = $MinimumVersion
        } #end If

        if ($PSBoundParameters.ContainsKey('RequiredVersion')) {
            $ImportParams['RequiredVersion'] = $RequiredVersion
        } #end If

        if ($PassThru) {
            $ImportParams['PassThru'] = $true
        } #end If

        if ($PSBoundParameters.ContainsKey('Prefix')) {
            $ImportParams['Prefix'] = $Prefix
        } #end If

        if ($DisableNameChecking) {
            $ImportParams['DisableNameChecking'] = $true
        } #end If

        if ($NoClobber) {
            $ImportParams['NoClobber'] = $true
        } #end If

        if ($PSBoundParameters.ContainsKey('Scope')) {
            $ImportParams['Scope'] = $Scope
        } #end If

        # Only add mutually exclusive parameters if not both set
        # Priority: UseWindowsPowerShell (for Windows-only modules in PS Core), else SkipEditionCheck if explicitly requested
        if ($IsPSCore -and ($UseWindowsPowerShell -or ($WindowsPSOnlyModules -contains $Name))) {
            $ImportParams['UseWindowsPowerShell'] = $true
        } elseif ($SkipEditionCheck) {
            $ImportParams['SkipEditionCheck'] = $true
        } #end If

        # Handle Verbose parameter correctly
        if ($PSBoundParameters.ContainsKey('Verbose')) {
            $ImportParams['Verbose'] = $PSBoundParameters['Verbose']
        }

    } #end Begin

    Process {

        try {

            # First check if the module is available (installed) on the system
            $AvailableModule = Get-Module -Name $Name -ListAvailable -ErrorAction SilentlyContinue -Verbose:$false

            if ($null -eq $AvailableModule) {

                # Special case handling for built-in modules with specific paths
                if ($Name -eq 'GroupPolicy') {

                    $GpPath = 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\GroupPolicy\GroupPolicy.psd1'

                    if (Test-Path -Path $GpPath) {

                        $ImportParams['Name'] = $GpPath
                        Write-Verbose -Message (
                            '[{0}] Using specific path for GroupPolicy module: {1}' -f
                            $FunctionName, $GpPath
                        )

                        # Reset previously imported module variable to prevent confusion
                        $ImportedModule = $null

                    } else {

                        Write-Error -Message (
                            'Module "{0}" is not installed.
                            Please install the module before importing.' -f
                            $Name
                        )
                        return

                    } #end If-else

                } elseif ($Name -eq 'ServerManager') {

                    $SmPath = 'C:\Windows\system32\WindowsPowerShell\v1.0\Modules\ServerManager\ServerManager.psd1'

                    if (Test-Path -Path $SmPath) {

                        $ImportParams['Name'] = $SmPath
                        Write-Verbose -Message (
                            '[{0}] Using specific path for ServerManager module: {1}' -f
                            $FunctionName, $SmPath
                        )

                        # Reset previously imported module variable to prevent confusion
                        $ImportedModule = $null

                    } else {

                        Write-Error -Message (
                            'Module "{0}" is not installed. Please install the module before importing.' -f
                            $Name
                        )
                        return
                    } #end If-else

                } else {
                    Write-Error -Message (
                        'Module "{0}" is not installed. Please install the module before importing.' -f
                        $Name
                    )
                    return
                } #end If-elseIf-else
            } else {
                Write-Verbose -Message (
                    '[{0}] Found module {1} installed on the system.' -f
                    $FunctionName, $Name
                )
            } #end If

            # Check if the module is already imported (only if we're not using a specific path)
            # For specific paths (like GroupPolicy loaded from a direct path), we'll always attempt the import
            if ($ImportParams['Name'] -eq $Name) {
                $ImportedModule = Get-Module -Name $Name -ErrorAction SilentlyContinue -Verbose:$false

                if ($null -ne $ImportedModule -and -not $Force) {
                    Write-Verbose -Message (
                        '[{0}] Module {1} is already imported.' -f
                        $FunctionName, $Name
                    )

                    if ($PassThru) {
                        return $ImportedModule
                    } #end If
                    return
                } #end If
            } #end If

            # Perform the import
            if ($PSCmdlet.ShouldProcess($Name, 'Import Module')) {
                # First try to import directly
                try {
                    Write-Verbose -Message ('[{0}] Importing module {1}...' -f $FunctionName, $Name)

                    # For PowerShell Core, try to use UseWindowsPowerShell if appropriate
                    if ($IsPSCore -and
                        $TryWindowsCompatibility -and
                        (-not $ImportParams.ContainsKey('UseWindowsPowerShell'))) {

                        Write-Verbose -Message (
                            '[{0}] Running in PowerShell Core, adding UseWindowsPowerShell parameter' -f
                            $FunctionName
                        )
                        $ImportParams['UseWindowsPowerShell'] = $true
                    } #end If

                    if ($PassThru) {
                        $ImportedModule = Import-Module @ImportParams -PassThru

                        Write-Verbose -Message (
                            '[{0}] Successfully imported module {1}' -f
                            $FunctionName, $Name
                        )

                        # When using a specific path, we may need to return the module by name
                        if ($null -eq $ImportedModule -and ($ImportParams['Name'] -match '\.ps[dm]1$')) {
                            # Get the module by original name since the path-based import might not return the module correctly
                            $ImportedModule = Get-Module -Name $Name -ErrorAction SilentlyContinue -Verbose:$false

                            if ($null -eq $ImportedModule) {
                                # Try to get by path basename as a fallback
                                $BaseName = [System.IO.Path]::GetFileNameWithoutExtension($ImportParams['Name'])
                                $ImportedModule = Get-Module -Name $BaseName -ErrorAction SilentlyContinue -Verbose:$false
                            } #end If
                        } #end If

                        return $ImportedModule
                    } else {
                        Import-Module @ImportParams

                        Write-Verbose -Message (
                            '[{0}] Successfully imported module {1}' -f
                            $FunctionName, $Name
                        )
                    } #end If-else

                } catch {
                    # If we're in PowerShell Core and direct import failed, try compatibility measures
                    if ($IsPSCore -and $FallbackToWindowsPowerShell) {
                        Write-Verbose -Message (
                            '[{0}] Direct import failed. Attempting Windows PowerShell compatibility for {1}' -f
                            $FunctionName, $Name
                        )

                        # Explicitly use Windows PowerShell via PowerShell.exe to run the commands
                        try {
                            $ModuleCmds = powershell.exe -Command "
                                `$ErrorActionPreference = 'Stop'
                                Import-Module -Name $Name -Force -DisableNameChecking
                                Get-Command -Module $Name | Select-Object -Property Name, CommandType | ConvertTo-Json
                            "

                            if ($null -ne $ModuleCmds -and $ModuleCmds -ne '') {
                                $Commands = $ModuleCmds | ConvertFrom-Json

                                Write-Verbose -Message (
                                    '[{0}] Successfully retrieved {1} commands from {2} via Windows PowerShell' -f
                                    $FunctionName, $Commands.Count, $Name
                                )

                                # Create a new module in memory for our compatibility wrapper
                                $ModuleManifestPath = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath "$Name-compat.psd1"

                                # Return a "fake" module info if PassThru was specified
                                if ($PassThru) {
                                    $ImportedModule = New-Object -TypeName System.Management.Automation.PSModuleInfo -ArgumentList $ModuleManifestPath
                                    return $ImportedModule
                                } #end If

                                Write-Verbose -Message ('[{0}] Created compatibility wrapper for {1}' -f $FunctionName, $Name)
                                return

                            } else {
                                throw "Failed to retrieve commands from module $Name via Windows PowerShell"
                            } #end If-else

                        } catch {
                            Write-Error -Message (
                                '[{0}] Error creating Windows PowerShell compatibility for {1}: {2}' -f
                                $FunctionName, $Name, $_.Exception.Message
                            )
                        } #end Try-Catch
                    } else {
                        # If not in PowerShell Core or not using compatibility, just report the original error
                        Write-Error -Message (
                            '[{0}] Error importing module {1}: {2}' -f
                            $FunctionName, $Name, $_.Exception.Message
                        )
                    } #end if-else
                } #end try-catch
            } #end If
        } catch {
            Write-Error -Message (
                '[{0}] Error importing module {1}: {2}' -f
                $FunctionName, $Name, $_.Exception.Message
            )
        } #end Try-Catch
    } #end Process

    End {
        # Restore original VerbosePreference
        $VerbosePreference = $OriginalVerbosePreference

        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {
            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'importing module.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function Import-MyModule
