function Set-SqlServerFirewall {

    <#
        .SYNOPSIS
            Configures Windows Firewall rules for SQL Server connectivity.

        .DESCRIPTION
            The Set-SqlServerFirewall function creates Windows Firewall rules to allow
            SQL Server traffic including Database Engine, SQL Server Browser, and
            administrative connections. This is essential for SQL Server connectivity
            especially on Windows Server Core installations.

        .PARAMETER InstanceName
            SQL Server instance name. Default is MSSQLSERVER (default instance).

        .PARAMETER TcpPort
            TCP port for SQL Server Database Engine. Default is 1433.

        .PARAMETER EnableBrowserService
            Enable firewall rule for SQL Server Browser service (UDP 1434).

        .PARAMETER EnableDac
            Enable Dedicated Administrator Connection (DAC) on TCP port 1434.

        .PARAMETER EnableSsisService
            Enable firewall rule for SQL Server Integration Services (port 135).

        .PARAMETER EnableSsasService
            Enable firewall rule for SQL Server Analysis Services (port 2383).

        .PARAMETER EnableSsrsService
            Enable firewall rule for SQL Server Reporting Services (ports 80, 443).

        .PARAMETER RemoveRules
            Remove existing SQL Server firewall rules instead of creating them.

        .EXAMPLE
            Set-SqlServerFirewall

            Creates standard firewall rules for default SQL Server instance.

        .EXAMPLE
            Set-SqlServerFirewall -InstanceName "MYINSTANCE" -TcpPort 1435 -EnableBrowserService

            Creates firewall rules for named instance with custom port and browser service.

        .EXAMPLE
            Set-SqlServerFirewall -RemoveRules

            Removes all SQL Server firewall rules.

        .INPUTS
            None. You cannot pipe objects to Set-SqlServerFirewall.

        .OUTPUTS
            [System.Boolean]
            Returns True if firewall configuration was successful, otherwise False.

        .NOTES
            Used Functions:
                Name                             ║ Module/Namespace
                ═════════════════════════════════╬══════════════════════════════
                New-NetFirewallRule              ║ NetSecurity
                Remove-NetFirewallRule           ║ NetSecurity
                Get-NetFirewallRule              ║ NetSecurity
                Write-Verbose                    ║ Microsoft.PowerShell.Utility
                Write-Warning                    ║ Microsoft.PowerShell.Utility
                Write-Error                      ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay              ║ EguibarIT

        .NOTES
            Version:         1.0
            DateModified:    13/Aug/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Functions/Set-SqlServerFirewall.ps1

        .COMPONENT
            SQL Server Management

        .ROLE
            Administrator

        .FUNCTIONALITY
            Configures Windows Firewall for SQL Server connectivity.
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([System.Boolean])]

    param(
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 0,
            HelpMessage = 'SQL Server instance name'
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
            HelpMessage = 'TCP port for SQL Server Database Engine'
        )]
        [PSDefaultValue(
            Help = 'Default Value is 1433',
            Value = 1433
        )]
        [ValidateRange(1024, 65535)]
        [Int]
        $TcpPort = 1433,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable firewall rule for SQL Server Browser service'
        )]
        [Switch]
        $EnableBrowserService,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable Dedicated Administrator Connection (DAC)'
        )]
        [Switch]
        $EnableDac,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable firewall rule for SQL Server Integration Services'
        )]
        [Switch]
        $EnableSsisService,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable firewall rule for SQL Server Analysis Services'
        )]
        [Switch]
        $EnableSsasService,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable firewall rule for SQL Server Reporting Services'
        )]
        [Switch]
        $EnableSsrsService,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Remove existing SQL Server firewall rules'
        )]
        [Switch]
        $RemoveRules
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
        # Module imports

        Import-Module -Name NetSecurity -Force -ErrorAction SilentlyContinue

        ##############################
        # Variables Definition

        [Boolean]$ConfigurationResult = $false
        [String]$RulePrefix = 'SQL Server'

        # Define firewall rules to create/remove
        $FirewallRules = @()

    } #end Begin

    Process {

        try {
            if ($RemoveRules) {
                Write-Verbose -Message 'Removing existing SQL Server firewall rules...'

                if ($PSCmdlet.ShouldProcess('SQL Server Firewall Rules', 'Remove firewall rules')) {

                    # Get existing SQL Server rules
                    $ExistingRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "$RulePrefix*" }

                    if ($ExistingRules) {
                        Write-Verbose -Message ('Found {0} existing SQL Server firewall rules to remove' -f $ExistingRules.Count)

                        foreach ($Rule in $ExistingRules) {
                            try {
                                Write-Verbose -Message ('Removing firewall rule: {0}' -f $Rule.DisplayName)
                                Remove-NetFirewallRule -Name $Rule.Name -ErrorAction Stop
                            } catch {
                                Write-Warning -Message ('Failed to remove rule {0}: {1}' -f $Rule.DisplayName, $_.Exception.Message)
                            } #end try-catch
                        } #end foreach

                        Write-Verbose -Message 'SQL Server firewall rules removed successfully'
                        $ConfigurationResult = $true
                    } else {
                        Write-Verbose -Message 'No existing SQL Server firewall rules found to remove'
                        $ConfigurationResult = $true
                    } #end if-else

                } #end if ShouldProcess

            } else {
                # Create firewall rules
                Write-Verbose -Message 'Configuring Windows Firewall rules for SQL Server...'

                # Core Database Engine rule (always created)
                $FirewallRules += @{
                    DisplayName = "$RulePrefix - Database Engine (TCP-In)"
                    Direction   = 'Inbound'
                    Protocol    = 'TCP'
                    LocalPort   = $TcpPort
                    Action      = 'Allow'
                    Description = "Allow inbound TCP traffic to SQL Server Database Engine on port $TcpPort"
                }

                # SQL Server Browser Service (for named instances)
                if ($EnableBrowserService -or $InstanceName -ne 'MSSQLSERVER') {
                    $FirewallRules += @{
                        DisplayName = "$RulePrefix - Browser Service (UDP-In)"
                        Direction   = 'Inbound'
                        Protocol    = 'UDP'
                        LocalPort   = 1434
                        Action      = 'Allow'
                        Description = 'Allow inbound UDP traffic to SQL Server Browser Service on port 1434'
                    }
                } #end if

                # Dedicated Administrator Connection (DAC)
                if ($EnableDac) {
                    $FirewallRules += @{
                        DisplayName = "$RulePrefix - DAC (TCP-In)"
                        Direction   = 'Inbound'
                        Protocol    = 'TCP'
                        LocalPort   = 1434
                        Action      = 'Allow'
                        Description = 'Allow inbound TCP traffic for Dedicated Administrator Connection on port 1434'
                    }
                } #end if

                # SQL Server Integration Services
                if ($EnableSsisService) {
                    $FirewallRules += @{
                        DisplayName = "$RulePrefix - Integration Services (TCP-In)"
                        Direction   = 'Inbound'
                        Protocol    = 'TCP'
                        LocalPort   = 135
                        Action      = 'Allow'
                        Description = 'Allow inbound TCP traffic to SQL Server Integration Services on port 135'
                    }
                } #end if

                # SQL Server Analysis Services
                if ($EnableSsasService) {
                    $FirewallRules += @{
                        DisplayName = "$RulePrefix - Analysis Services (TCP-In)"
                        Direction   = 'Inbound'
                        Protocol    = 'TCP'
                        LocalPort   = 2383
                        Action      = 'Allow'
                        Description = 'Allow inbound TCP traffic to SQL Server Analysis Services on port 2383'
                    }
                } #end if

                # SQL Server Reporting Services
                if ($EnableSsrsService) {
                    $FirewallRules += @{
                        DisplayName = "$RulePrefix - Reporting Services HTTP (TCP-In)"
                        Direction   = 'Inbound'
                        Protocol    = 'TCP'
                        LocalPort   = 80
                        Action      = 'Allow'
                        Description = 'Allow inbound HTTP traffic to SQL Server Reporting Services on port 80'
                    }

                    $FirewallRules += @{
                        DisplayName = "$RulePrefix - Reporting Services HTTPS (TCP-In)"
                        Direction   = 'Inbound'
                        Protocol    = 'TCP'
                        LocalPort   = 443
                        Action      = 'Allow'
                        Description = 'Allow inbound HTTPS traffic to SQL Server Reporting Services on port 443'
                    }
                } #end if

                if ($PSCmdlet.ShouldProcess('Windows Firewall', 'Create SQL Server firewall rules')) {

                    Write-Verbose -Message ('Creating {0} firewall rules for SQL Server...' -f $FirewallRules.Count)

                    foreach ($Rule in $FirewallRules) {
                        try {
                            # Check if rule already exists
                            $ExistingRule = Get-NetFirewallRule -DisplayName $Rule.DisplayName -ErrorAction SilentlyContinue

                            if ($ExistingRule) {
                                Write-Verbose -Message ('Firewall rule already exists: {0}' -f $Rule.DisplayName)
                            } else {
                                Write-Verbose -Message ('Creating firewall rule: {0}' -f $Rule.DisplayName)

                                $SplatFirewall = @{
                                    DisplayName = $Rule.DisplayName
                                    Direction   = $Rule.Direction
                                    Protocol    = $Rule.Protocol
                                    LocalPort   = $Rule.LocalPort
                                    Action      = $Rule.Action
                                    Description = $Rule.Description
                                    Enabled     = 'True'
                                    Profile     = 'Any'
                                    ErrorAction = 'Stop'
                                }

                                New-NetFirewallRule @SplatFirewall | Out-Null
                                Write-Verbose -Message ('Successfully created firewall rule: {0}' -f $Rule.DisplayName)
                            } #end if-else

                        } catch {
                            Write-Error -Message ('Failed to create firewall rule {0}: {1}' -f $Rule.DisplayName, $_.Exception.Message)
                            throw
                        } #end try-catch
                    } #end foreach

                    Write-Host '✓ Windows Firewall configured for SQL Server connectivity!' -ForegroundColor Green
                    Write-Host ('  - Database Engine: TCP port {0}' -f $TcpPort) -ForegroundColor Yellow

                    if ($EnableBrowserService -or $InstanceName -ne 'MSSQLSERVER') {
                        Write-Host '  - Browser Service: UDP port 1434' -ForegroundColor Yellow
                    } #end if

                    if ($EnableDac) {
                        Write-Host '  - Dedicated Admin Connection: TCP port 1434' -ForegroundColor Yellow
                    } #end if

                    $ConfigurationResult = $true

                } #end if ShouldProcess

            } #end if-else RemoveRules

        } catch {
            Write-Error -Message ('Error configuring SQL Server firewall: {0}' -f $_.Exception.Message)
            $ConfigurationResult = $false
        } #end try-catch

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'configuring Windows Firewall for SQL Server.'
            )
            Write-Verbose -Message $txt
        } #end If

        return $ConfigurationResult
    } #end End
} #end function Set-SqlServerFirewall
