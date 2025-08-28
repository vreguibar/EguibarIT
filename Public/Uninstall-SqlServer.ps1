function Uninstall-SqlServer {

    <#
        .SYNOPSIS
            Uninstalls SQL Server completely from the system.

        .DESCRIPTION
            The Uninstall-SqlServer function removes SQL Server installation completely,
            including all instances, shared components, and registry entries.
            This is useful when SQL Server installation failed and left the system
            in a corrupted state that prevents new installations.

        .PARAMETER InstanceName
            Name of the SQL Server instance to uninstall. Default is MSSQLSERVER.

        .PARAMETER RemoveAllComponents
            Remove all SQL Server components including shared components.

        .PARAMETER Force
            Force removal even if some components cannot be uninstalled gracefully.

        .EXAMPLE
            Uninstall-SqlServer

            Uninstalls the default SQL Server instance (MSSQLSERVER).

        .EXAMPLE
            Uninstall-SqlServer -InstanceName "MYINSTANCE" -RemoveAllComponents

            Uninstalls the named instance and all shared components.

        .INPUTS
            None. You cannot pipe objects to Uninstall-SqlServer.

        .OUTPUTS
            [System.Boolean]
            Returns True if uninstallation was successful, otherwise False.

        .NOTES
            Used Functions:
                Name                             ║ Module/Namespace
                ═════════════════════════════════╬══════════════════════════════
                Get-WmiObject                    ║ Microsoft.PowerShell.Management
                Start-Process                    ║ Microsoft.PowerShell.Management
                Write-Verbose                    ║ Microsoft.PowerShell.Utility
                Write-Warning                    ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay              ║ EguibarIT

        .NOTES
            Version:         1.0
            DateModified:    13/Aug/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Functions/Uninstall-SqlServer.ps1

        .COMPONENT
            SQL Server Management

        .ROLE
            Administrator

        .FUNCTIONALITY
            Removes SQL Server installations and components.
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.Boolean])]

    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 0,
            HelpMessage = 'SQL Server instance name to uninstall'
        )]
        [PSDefaultValue(
            Help = 'Default Value is "MSSQLSERVER"',
            Value = 'MSSQLSERVER'
        )]
        [String]
        $InstanceName = 'MSSQLSERVER',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Remove all SQL Server components including shared components'
        )]
        [Switch]
        $RemoveAllComponents,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Force removal even if some components fail to uninstall'
        )]
        [Switch]
        $Force
    )

    Begin {
        Set-StrictMode -Version Latest

        # Display function header if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Variables Definition

        [Boolean]$UninstallResult = $false
        [String]$StartTime = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')

    } #end Begin

    Process {

        try {
            Write-Verbose -Message ('Starting SQL Server uninstallation at {0}' -f $StartTime)

            # Check if SQL Server is installed
            Write-Verbose -Message 'Checking for SQL Server installations...'

            $SqlProducts = Get-WmiObject -Class Win32_Product | 
                Where-Object { $_.Name -like '*SQL Server*' }

            if (-not $SqlProducts) {
                Write-Warning -Message 'No SQL Server products found to uninstall.'
                return $true
            } #end if

            Write-Verbose -Message ('Found {0} SQL Server product(s) to uninstall' -f $SqlProducts.Count)

            foreach ($Product in $SqlProducts) {
                Write-Verbose -Message ('Found SQL Server product: {0} (Version: {1})' -f $Product.Name, $Product.Version)
            } #end foreach

            if ($PSCmdlet.ShouldProcess("SQL Server ($InstanceName)", 'Uninstall SQL Server')) {

                # Method 1: Try using SQL Server setup.exe for clean uninstall
                Write-Verbose -Message 'Attempting clean uninstall using SQL Server setup...'

                $SetupPath = $null
                $PossiblePaths = @(
                    'C:\Program Files\Microsoft SQL Server\*\Setup Bootstrap\SQLServer*\setup.exe',
                    'D:\setup.exe'
                )

                foreach ($Path in $PossiblePaths) {
                    $FoundSetup = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($FoundSetup) {
                        $SetupPath = $FoundSetup.FullName
                        Write-Verbose -Message ('Found SQL Server setup at: {0}' -f $SetupPath)
                        break
                    } #end if
                } #end foreach

                if ($SetupPath) {
                    Write-Verbose -Message 'Using SQL Server setup for uninstallation...'

                    $UninstallArgs = @(
                        '/Q',                                    # Silent uninstall
                        '/ACTION=Uninstall',                    # Uninstall action
                        '/FEATURES=SQL,AS,IS,MDS,Tools',        # Remove core features
                        '/INSTANCENAME={0}' -f $InstanceName    # Instance to remove
                    )

                    Write-Verbose -Message ('Uninstall arguments: {0}' -f ($UninstallArgs -join ' '))

                    $UninstallProcess = Start-Process -FilePath $SetupPath -ArgumentList $UninstallArgs -Wait -PassThru

                    if ($UninstallProcess.ExitCode -eq 0) {
                        Write-Verbose -Message 'SQL Server uninstalled successfully using setup.exe'
                        $UninstallResult = $true
                    } else {
                        Write-Warning -Message ('SQL Server setup uninstall failed with exit code: {0}' -f $UninstallProcess.ExitCode)
                        if (-not $Force) {
                            throw ('Setup uninstall failed with exit code: {0}' -f $UninstallProcess.ExitCode)
                        } #end if
                    } #end if-else
                } else {
                    Write-Warning -Message 'SQL Server setup.exe not found, trying alternative methods...'
                } #end if-else

                # Method 2: Use Windows Installer (MSI) to remove products
                if (-not $UninstallResult -or $RemoveAllComponents) {
                    Write-Verbose -Message 'Using Windows Installer to remove SQL Server products...'

                    foreach ($Product in $SqlProducts) {
                        Write-Verbose -Message ('Uninstalling {0}...' -f $Product.Name)

                        try {
                            $Result = $Product.Uninstall()
                            if ($Result.ReturnValue -eq 0) {
                                Write-Verbose -Message ('Successfully uninstalled {0}' -f $Product.Name)
                                $UninstallResult = $true
                            } else {
                                Write-Warning -Message ('Failed to uninstall {0}. Return code: {1}' -f $Product.Name, $Result.ReturnValue)
                                if (-not $Force) {
                                    throw ('Failed to uninstall {0}' -f $Product.Name)
                                } #end if
                            } #end if-else
                        } catch {
                            Write-Warning -Message ('Error uninstalling {0}: {1}' -f $Product.Name, $_.Exception.Message)
                            if (-not $Force) {
                                throw
                            } #end if
                        } #end try-catch
                    } #end foreach
                } #end if

                # Method 3: Manual cleanup (registry and files)
                if ($Force -or $RemoveAllComponents) {
                    Write-Verbose -Message 'Performing manual cleanup of SQL Server remnants...'

                    # Stop SQL Server services
                    Write-Verbose -Message 'Stopping SQL Server services...'
                    $SqlServices = Get-Service | Where-Object { $_.Name -like '*SQL*' -and $_.Status -eq 'Running' }
                    foreach ($Service in $SqlServices) {
                        try {
                            Write-Verbose -Message ('Stopping service: {0}' -f $Service.Name)
                            Stop-Service -Name $Service.Name -Force -ErrorAction Stop
                        } catch {
                            Write-Warning -Message ('Failed to stop service {0}: {1}' -f $Service.Name, $_.Exception.Message)
                        } #end try-catch
                    } #end foreach

                    # Remove SQL Server directories
                    $SqlDirectories = @(
                        'C:\Program Files\Microsoft SQL Server',
                        'C:\Program Files (x86)\Microsoft SQL Server'
                    )

                    foreach ($Directory in $SqlDirectories) {
                        if (Test-Path -Path $Directory) {
                            Write-Verbose -Message ('Removing directory: {0}' -f $Directory)
                            try {
                                Remove-Item -Path $Directory -Recurse -Force -ErrorAction Stop
                                Write-Verbose -Message ('Successfully removed directory: {0}' -f $Directory)
                            } catch {
                                Write-Warning -Message ('Failed to remove directory {0}: {1}' -f $Directory, $_.Exception.Message)
                            } #end try-catch
                        } #end if
                    } #end foreach

                    Write-Verbose -Message 'Manual cleanup completed'
                    $UninstallResult = $true
                } #end if

            } #end if ShouldProcess

        } catch {
            Write-Error -Message ('Error during SQL Server uninstallation: {0}' -f $_.Exception.Message)
            $UninstallResult = $false
        } #end try-catch

    } #end Process

    End {
        Write-Verbose -Message ('SQL Server uninstallation completed. Result: {0}' -f $UninstallResult)

        if ($UninstallResult) {
            Write-Host '✓ SQL Server uninstallation completed successfully!' -ForegroundColor Green
            Write-Host 'You can now proceed with a fresh SQL Server installation.' -ForegroundColor Yellow
        } else {
            Write-Warning -Message 'SQL Server uninstallation may not have completed successfully.'
            Write-Warning -Message 'Manual cleanup may be required before attempting reinstallation.'
        } #end if-else

        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'uninstalling SQL Server components.'
            )
            Write-Verbose -Message $txt
        } #end If

        return $UninstallResult
    } #end End
} #end function Uninstall-SqlServer
