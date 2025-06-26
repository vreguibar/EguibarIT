function Install-SqlServer {

    <#
        .SYNOPSIS
            Installs SQL Server with comprehensive configuration options including gMSA support and production settings.

        .DESCRIPTION
            The Install-SqlServer function provides automated SQL Server installation with advanced configuration
            capabilities. It supports both traditional service accounts and group Managed Service Accounts (gMSA),
            auto-detects installation media from DVD drives or downloads SQL Server 2019 Developer Edition,
            and includes production-ready performance optimizations.

        .PARAMETER IsoPath
            Path to SQL Server ISO file. If not specified, the function will:
            1. Check for mounted DVD drives with SQL Server installation media
            2. Use the SQLSERVER_ISOPATH environment variable if available
            3. Download SQL Server 2019 Developer Edition from Microsoft

        .PARAMETER Features
            SQL Server features to install. Default is SQLEngine.

        .PARAMETER InstallDir
            Non-default installation directory for SQL Server.

        .PARAMETER DataDir
            Data directory for SQL Server system databases.

        .PARAMETER InstanceName
            SQL Server instance name. Default is MSSQLSERVER (default instance).

        .PARAMETER SaPassword
            SA user password for mixed mode authentication.

        .PARAMETER ServiceAccountName
            Username for SQL Server service account. Can be:
            - Traditional domain account (DOMAIN\ServiceAccount)
            - Group Managed Service Account (DOMAIN\ServiceAccount$)
            The function auto-detects gMSA accounts based on the $ suffix.

        .PARAMETER ServiceAccountPassword
            Password for traditional service account. Not required for gMSA accounts.

        .PARAMETER SystemAdminAccounts
            List of system administrative accounts. Default is current user.

        .PARAMETER ProductKey
            SQL Server product key for licensed editions.

        .PARAMETER UseBitsTransfer
            Use BITS transfer for downloads when available.

        .PARAMETER EnableProtocols
            Enable SQL Server network protocols (TCP/IP, Named Pipes) after installation.

        .PARAMETER SqlCollation
            SQL Server collation settings. Default is SQL_Latin1_General_CP1_CI_AS.

        .PARAMETER DataPath
            Data directory path for SQL Server data files.

        .PARAMETER LogPath
            Log directory path for SQL Server log files.

        .PARAMETER TempPath
            Temporary database directory path.

        .PARAMETER BackupPath
            Backup directory path for SQL Server backups.

        .PARAMETER SqlTempDbFileSize
            TempDB data file size in MB. Default is 1024 MB.

        .PARAMETER SqlTempDbFileGrowth
            TempDB data file growth in MB. Default is 512 MB.

        .PARAMETER SqlTempDbLogFileSize
            TempDB log file size in MB. Default is 64 MB.

        .PARAMETER SqlTempDbLogFileGrowth
            TempDB log file growth in MB. Default is 64 MB.

        .PARAMETER SqlTempDbFileCount
            Number of TempDB data files. Default is number of logical processors (up to 8).

        .PARAMETER AuthenticationMode
            SQL Server authentication mode: Windows or Mixed. Default is Windows.

        .PARAMETER PerformVolumeMaintenanceTasks
            Enable instant file initialization for SQL Server. Default is True for performance.

        .PARAMETER MaxDegreeOfParallelism
            Maximum degree of parallelism (MAXDOP) setting.

        .PARAMETER MaxServerMemory
            Maximum server memory in MB.

        .PARAMETER MinServerMemory
            Minimum server memory in MB.

        .PARAMETER EnableTcpIp
            Enable TCP/IP protocol. Default is True.

        .PARAMETER TcpPort
            TCP port for SQL Server. Default is 1433.

        .EXAMPLE
            Install-SqlServer

            Installs SQL Server with default settings using auto-detected media or downloads Developer Edition.

        .EXAMPLE
            Install-SqlServer -ServiceAccountName "CONTOSO\sql-service$" -Features @('SQLEngine', 'FullText')

            Installs SQL Server using a group Managed Service Account with SQL Engine and Full-Text features.        .EXAMPLE
            Install-SqlServer -IsoPath "C:\ISO\SQLServer2019.iso" -InstanceName "PROD01" `
                -ServiceAccountName "CONTOSO\sqlsvc" -ServiceAccountPassword (Read-Host -AsSecureString)

            Installs SQL Server from specific ISO with custom instance name and traditional account.

        .INPUTS
            None. You cannot pipe objects to Install-SqlServer.

        .OUTPUTS
            [System.Boolean]
            Returns True if installation was successful, otherwise False.

        .NOTES
            Used Functions:
                Name                             ║ Module/Namespace
                ═════════════════════════════════╬══════════════════════════════
                Import-MyModule                  ║ EguibarIT
                Get-FunctionDisplay              ║ EguibarIT
                Mount-DiskImage                  ║ Storage
                Dismount-DiskImage               ║ Storage
                Start-BitsTransfer               ║ BitsTransfer
                Invoke-WebRequest                ║ Microsoft.PowerShell.Utility
                Get-CimInstance                  ║ CimCmdlets
                Start-Process                    ║ Microsoft.PowerShell.Management
                Get-Service                      ║ Microsoft.PowerShell.Management
                Restart-Service                  ║ Microsoft.PowerShell.Management
                Write-Verbose                    ║ Microsoft.PowerShell.Utility
                Write-Warning                    ║ Microsoft.PowerShell.Utility
                Write-Error                      ║ Microsoft.PowerShell.Utility
                Get-Date                         ║ Microsoft.PowerShell.Utility
                Test-Path                        ║ Microsoft.PowerShell.Management
                Join-Path                        ║ Microsoft.PowerShell.Management
                New-Item                         ║ Microsoft.PowerShell.Management
                Get-FileHash                     ║ Microsoft.PowerShell.Utility
                Get-Content                      ║ Microsoft.PowerShell.Management
                Out-File                         ║ Microsoft.PowerShell.Utility
                Start-Transcript                 ║ Microsoft.PowerShell.Host
                Stop-Transcript                  ║ Microsoft.PowerShell.Host

        .NOTES
            Version:         1.3
            DateModified:    11/Jun/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Install-SqlServer.ps1

        .COMPONENT
            SQL Server Installation

        .ROLE
            Administrator

        .FUNCTIONALITY
            Automated SQL Server installation with advanced configuration options.
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'Default'
    )]
    [OutputType([System.Boolean])]

    param(

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 0,
            HelpMessage = 'Path to SQL Server ISO file or auto-detect DVD drives'
        )]        [PSDefaultValue(
            Help = 'Auto-detects DVD drives, uses SQLSERVER_ISOPATH, or downloads SQL Server 2019',
            value = { $ENV:SQLSERVER_ISOPATH }
        )]
        [String]
        $IsoPath = $ENV:SQLSERVER_ISOPATH,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 1,
            HelpMessage = 'SQL features'
        )]
        [ValidateSet(
            'SQL',
            'SQLEngine',
            'Replication',
            'FullText',
            'DQ',
            'PolyBase',
            'AdvancedAnalytics',
            'AS',
            'RS',
            'DQC',
            'IS',
            'MDS',
            'SQL_SHARED_MR',
            'Tools',
            'BC',
            'BOL',
            'Conn',
            'DREPLAY_CLT',
            'SNAC_SDK',
            'SDK',
            'LocalDB'
        )]
        [PSDefaultValue(
            Help = 'Default Value is SQLEngine',
            value = { @('SQLEngine') }
        )]
        [String[]]
        $Features = @('SQLEngine'),

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Non-default installation directory'
        )]        [String]
        $InstallDir,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Data directory for SQL Server'
        )]
        [String]
        $DataDir, [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'SQL Server instance name'
        )]
        [ValidateNotNullOrEmpty()]
        [PSDefaultValue(Help = 'Default Value is MSSQLSERVER')]
        [String]
        $InstanceName = 'MSSQLSERVER',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'SA user password for mixed mode authentication'
        )]
        [SecureString]
        $SaPassword,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Username for SQL Server service account (use DOMAIN\ServiceAccount$ for gMSA)',
            ParameterSetName = 'Default'
        )]
        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Username for SQL Server service account',
            ParameterSetName = 'TraditionalAccount'
        )]
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'gMSA account name in format DOMAIN\ServiceAccount$',
            ParameterSetName = 'gMSAAccount'
        )]
        [String]
        $ServiceAccountName,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Password for service account (not required for gMSA)',
            ParameterSetName = 'Default'
        )]
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Password for traditional service account',
            ParameterSetName = 'TraditionalAccount'
        )]
        [SecureString]
        $ServiceAccountPassword,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'List of system administrative accounts'
        )]
        [PSDefaultValue(
            Help = 'Default Value is current user',
            value = { @("$Env:USERDOMAIN\$Env:USERNAME") }
        )]
        [String[]]
        $SystemAdminAccounts = @("$Env:USERDOMAIN\$Env:USERNAME"),

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'SQL Server product key'
        )]
        [String]
        $ProductKey,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Use BITS transfer for downloads'
        )]
        [Switch]
        $UseBitsTransfer,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable SQL Server network protocols after installation'
        )]
        [Switch]
        $EnableProtocols,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'SQL Server collation settings'
        )]
        [PSDefaultValue(
            Help = 'Default Value is SQL_Latin1_General_CP1_CI_AS',
            Value = 'SQL_Latin1_General_CP1_CI_AS'
        )]
        [String]
        $SqlCollation = 'SQL_Latin1_General_CP1_CI_AS',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Data directory path for SQL Server data files'
        )]
        [String]
        $DataPath,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Log directory path for SQL Server log files'
        )]
        [String]
        $LogPath,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Temporary database directory path'
        )]
        [String]
        $TempPath,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Backup directory path for SQL Server backups'
        )]
        [String]
        $BackupPath,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'TempDB data file size in MB'
        )]
        [PSDefaultValue(
            Help = 'Default Value is 1024 MB',
            Value = 1024
        )]
        [ValidateRange(8, 102400)]
        [Int32]
        $SqlTempDbFileSize = 1024,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'TempDB data file growth in MB'
        )]
        [PSDefaultValue(
            Help = 'Default Value is 512 MB',
            Value = 512
        )]
        [ValidateRange(1, 10240)]
        [Int32]
        $SqlTempDbFileGrowth = 512,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'TempDB log file size in MB'
        )]
        [PSDefaultValue(
            Help = 'Default Value is 64 MB',
            Value = 64
        )]
        [ValidateRange(4, 10240)]
        [Int32]
        $SqlTempDbLogFileSize = 64,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'TempDB log file growth in MB'
        )]
        [PSDefaultValue(
            Help = 'Default Value is 64 MB',
            Value = 64
        )]
        [ValidateRange(1, 1024)]
        [Int32]
        $SqlTempDbLogFileGrowth = 64,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Number of TempDB data files'
        )]
        [PSDefaultValue(
            Help = 'Default Value is number of logical processors (up to 8)',
            Value = { [Math]::Min(8, $env:NUMBER_OF_PROCESSORS) }
        )]
        [ValidateRange(1, 8)]
        [Int32]
        $SqlTempDbFileCount = [Math]::Min(8, $env:NUMBER_OF_PROCESSORS),

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'SQL Server authentication mode'
        )]
        [ValidateSet('Windows', 'Mixed')]
        [PSDefaultValue(
            Help = 'Default Value is Windows',
            Value = 'Windows'
        )]
        [String]
        $AuthenticationMode = 'Windows',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable instant file initialization for SQL Server'
        )]
        [PSDefaultValue(
            Help = 'Default Value is $true for performance optimization',
            Value = $true
        )]
        [Boolean]
        $PerformVolumeMaintenanceTasks = $true,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Maximum degree of parallelism (MAXDOP)'
        )]
        [ValidateRange(0, 64)]
        [Int32]
        $MaxDegreeOfParallelism,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Maximum server memory in MB'
        )]
        [ValidateRange(128, 2147483647)]
        [Int32]
        $MaxServerMemory,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Minimum server memory in MB'
        )]
        [ValidateRange(0, 2147483647)]
        [Int32]
        $MinServerMemory,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Enable TCP/IP protocol'
        )]
        [PSDefaultValue(
            Help = 'Default Value is $true',
            Value = $true
        )]
        [Boolean]
        $EnableTcpIp = $true,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'TCP port for SQL Server'
        )]
        [PSDefaultValue(
            Help = 'Default Value is 1433',
            Value = 1433
        )]
        [ValidateRange(1, 65535)]
        [Int32]
        $TcpPort = 1433
    )

    Begin {
        Set-StrictMode -Version Latest

        # Display function header if variables exist
        try {
            if ($null -ne $Variables -and
                $null -ne $Variables.Header) {

                $txt = ($Variables.Header -f
                    (Get-Date).ToString('dd/MMM/yyyy'),
                    $MyInvocation.Mycommand,
                    (Get-FunctionDisplay -Hashtable $PsBoundParameters -Verbose:$False)
                )
                Write-Verbose -Message $txt
            } #end If
        } catch {
            # Module variables not available, continue without header
            Write-Verbose -Message 'EguibarIT module variables not available'
        } #end try-catch

        ##############################
        # Module imports

        try {
            Import-MyModule -Name Storage -Force -Verbose:$false
            Import-MyModule -Name BitsTransfer -Force -Verbose:$false
        } catch {
            # Fallback to standard Import-Module if Import-MyModule is not available
            Import-Module -Name Storage -Force -ErrorAction SilentlyContinue
            Import-Module -Name BitsTransfer -Force -ErrorAction SilentlyContinue
        } #end try-catch

        ##############################
        # Variables Definition

        [String]$ScriptName = $MyInvocation.MyCommand.Name.Replace('.ps1', '')
        [DateTime]$StartTime = Get-Date
        [String]$LogFileName = '{0}-{1}.log' -f $ScriptName, $StartTime.ToString('s').Replace(':', '-')
        [String]$LogPath = Join-Path -Path $PSScriptRoot -ChildPath $LogFileName
        [String]$DefaultIsoUrl = 'https://download.microsoft.com/download/7/c/1/' +
        '7c14e92e-bdcb-4f89-b7cf-93543e7112d1/SQLServer2019-x64-ENU-Dev.iso'
        [Boolean]$InstallationResult = $false

        ##############################
        # Parameter Set Validation and gMSA Detection

        # Determine the actual parameter set being used
        $CurrentParameterSetName = $PSCmdlet.ParameterSetName
        Write-Verbose -Message ('Using parameter set: {0}' -f $CurrentParameterSetName)

        # Auto-detect gMSA accounts when using Default parameter set
        if ($CurrentParameterSetName -eq 'Default' -and $ServiceAccountName) {
            $IsGMSAAccount = $ServiceAccountName.EndsWith('$')
            if ($IsGMSAAccount) {
                Write-Verbose -Message ('Auto-detected gMSA account: {0}' -f $ServiceAccountName)
                # Warn if password was provided for gMSA
                if ($ServiceAccountPassword) {
                    Write-Warning -Message (
                        'Password provided for gMSA account {0}. ' +
                        'Passwords are not used with gMSAs and will be ignored.' -f $ServiceAccountName
                    )
                } #end if
            } else {
                # Traditional domain account without password
                if (-not $ServiceAccountPassword) {
                    Write-Warning -Message (
                        'Domain service account {0} specified without password. ' +
                        'This may cause installation to fail. ' +
                        'Consider using -ServiceAccountPassword parameter.' -f $ServiceAccountName
                    )
                } #end if
            } #end if-else
        } elseif ($CurrentParameterSetName -eq 'gMSAAccount') {
            # Validate gMSA format
            if (-not $ServiceAccountName.EndsWith('$')) {
                throw (
                    'gMSA account name must end with $ symbol. ' +
                    'Provided: {0}. Expected format: DOMAIN\ServiceAccount$' -f $ServiceAccountName
                )
            } #end if
            Write-Verbose -Message ('Using explicit gMSA parameter set with account: {0}' -f $ServiceAccountName)
        } elseif ($CurrentParameterSetName -eq 'TraditionalAccount') {
            # Validate traditional account format
            if ($ServiceAccountName.EndsWith('$')) {
                throw (
                    'Traditional service account should not end with $ symbol. ' +
                    'Use gMSA parameter set for group Managed Service Accounts. ' +
                    'Provided: {0}' -f $ServiceAccountName
                )
            } #end if
            Write-Verbose -Message (
                'Using traditional service account parameter set with account: {0}' -f $ServiceAccountName
            )
        } #end if-elseif

        ##############################
        # Password Conversion

        # Convert SecureString passwords to plain text for SQL Server setup
        [String]$SaPasswordPlain = $null
        [String]$ServiceAccountPasswordPlain = $null

        if ($SaPassword) {
            $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SaPassword)
            $SaPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Bstr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
        } #end if

        if ($ServiceAccountPassword) {
            $Bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ServiceAccountPassword)
            $ServiceAccountPasswordPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Bstr)
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Bstr)
        } #end if

        Write-Verbose -Message ('Starting SQL Server installation at {0}' -f $StartTime)
    } #end Begin

    Process {
        try {
            # Start transcript logging
            Start-Transcript -Path $LogPath -Force

            # Handle ISO path resolution and DVD drive detection
            [Boolean]$UseIsoFile = $true
            [String]$SqlServerDrive = $null

            if (-not $IsoPath) {
                Write-Verbose -Message 'ISO path not specified, checking for mounted DVD drives...'

                # Check for DVD drives with SQL Server installation media                $DvdDrives = Get-CimInstance -ClassName Win32_LogicalDisk |
                Where-Object { $_.DriveType -eq 5 -and $_.Size -gt 0 }

                Write-Verbose -Message ('Found {0} DVD drive(s) with media' -f @($DvdDrives).Count)

                foreach ($Drive in $DvdDrives) {
                    # Ensure DeviceID is properly cast as string
                    $DriveId = [string]$Drive.DeviceID
                    Write-Verbose -Message ('Checking drive {0} for SQL Server installation media...' -f $DriveId)
                    $SetupPath = Join-Path -Path $DriveId -ChildPath 'setup.exe'

                    if (Test-Path -Path $SetupPath) {
                        Write-Verbose -Message ('Found setup.exe on drive: {0}' -f $DriveId)

                        # Verify it's a SQL Server setup by checking for required files
                        $SqlSetupIndicators = @(
                            Join-Path -Path $DriveId -ChildPath 'DefaultSetup.ini',
                            Join-Path -Path $DriveId -ChildPath 'x64\setup.exe',
                            Join-Path -Path $DriveId -ChildPath 'autorun.inf'
                        )

                        # Test each file and provide detailed diagnostics
                        $SqlSetupFound = @()
                        foreach ($Indicator in $SqlSetupIndicators) {
                            if (Test-Path -Path $Indicator) {
                                Write-Verbose -Message ('Found SQL Server indicator: {0}' -f $Indicator)
                                $SqlSetupFound += $Indicator
                            } else {
                                Write-Verbose -Message ('Missing SQL Server indicator: {0}' -f $Indicator)
                            } #end if-else
                        } #end foreach

                        if ($SqlSetupFound.Count -ge 2) {
                            # Double-check drive accessibility
                            try {
                                Get-ChildItem -Path $DriveId -ErrorAction Stop | Out-Null
                                Write-Verbose -Message ('SQL Server installation media verified on drive: {0}' -f $DriveId)
                                $SqlServerDrive = $DriveId
                                $UseIsoFile = $false
                                break
                            } catch {
                                Write-Warning -Message (
                                    'Drive {0} became inaccessible: {1}' -f $DriveId, $_.Exception.Message
                                )
                                continue
                            } #end try-catch
                        } else {
                            Write-Verbose -Message (
                                'Drive {0} does not contain sufficient SQL Server indicators ({1}/3 found)' -f
                                $DriveId, $SqlSetupFound.Count
                            )
                        } #end if-else
                    } else {
                        Write-Verbose -Message ('No setup.exe found on drive: {0}' -f $Drive.DeviceID)
                    } #end if-else
                } #end foreach

                if ($UseIsoFile) {
                    Write-Verbose -Message 'No SQL Server DVD found, checking environment variables and defaults'
                    $IsoPath = $DefaultIsoUrl
                    $SaveDir = Join-Path -Path $Env:TEMP -ChildPath $ScriptName

                    if (-not (Test-Path -Path $SaveDir)) {
                        New-Item -Path $SaveDir -ItemType Directory -Force | Out-Null
                    } #end if

                    $IsoName = $IsoPath -split '/' | Select-Object -Last 1
                    $SavePath = Join-Path -Path $SaveDir -ChildPath $IsoName

                    # Initialize hash variables
                    $Hash = $null
                    $OldHash = $null

                    if (Test-Path -Path $SavePath) {
                        Write-Verbose -Message 'ISO already downloaded, checking hash...'
                        $Hash = Get-FileHash -Algorithm SHA256 -Path $SavePath | Select-Object -ExpandProperty Hash
                        $OldHash = Get-Content -Path "$SavePath.sha256" -ErrorAction SilentlyContinue
                    } #end if

                    if ($Hash -and $Hash -eq $OldHash) {
                        Write-Verbose -Message 'Hash verification successful'
                    } else {
                        if ($Hash) {
                            Write-Warning -Message 'Hash verification failed, re-downloading ISO'
                        } #end if

                        Write-Verbose -Message ('Downloading: {0}' -f $IsoPath)

                        if ($UseBitsTransfer) {
                            Write-Verbose -Message 'Using BITS transfer'
                            $ProxySplat = @{}
                            if ($ENV:HTTP_PROXY) {
                                $ProxySplat = @{
                                    ProxyList  = $ENV:HTTP_PROXY -replace 'http?://'
                                    ProxyUsage = 'Override'
                                }
                            } #end if
                            Start-BitsTransfer -Source $IsoPath -Destination $SaveDir @ProxySplat
                        } else {
                            # Enhanced web proxy handling with multiple fallback strategies
                            $DownloadSuccess = $false
                            $DownloadAttempts = @()

                            # Strategy 1: Try with system proxy if configured
                            if ($ENV:HTTP_PROXY -and $ENV:HTTP_PROXY -ne '') {
                                $DownloadAttempts += @{
                                    Name  = 'System Proxy'
                                    Splat = @{
                                        Uri             = $IsoPath
                                        OutFile         = $SavePath
                                        UseBasicParsing = $true
                                        Proxy           = $ENV:HTTP_PROXY
                                    }
                                }
                            } #end if

                            # Strategy 2: Try with default proxy (system default)
                            $DownloadAttempts += @{
                                Name  = 'Default Proxy'
                                Splat = @{
                                    Uri                   = $IsoPath
                                    OutFile               = $SavePath
                                    UseBasicParsing       = $true
                                    UseDefaultCredentials = $true
                                }
                            }

                            # Strategy 3: Try without proxy
                            $DownloadAttempts += @{
                                Name  = 'Direct Connection'
                                Splat = @{
                                    Uri             = $IsoPath
                                    OutFile         = $SavePath
                                    UseBasicParsing = $true
                                    Proxy           = ''
                                }
                            }

                            # Attempt each download strategy
                            foreach ($Attempt in $DownloadAttempts) {
                                try {
                                    Write-Verbose -Message ('Attempting download using: {0}' -f $Attempt.Name)
                                    Invoke-WebRequest @($Attempt.Splat)
                                    $DownloadSuccess = $true
                                    Write-Verbose -Message ('Download successful using: {0}' -f $Attempt.Name)
                                    break
                                } catch [System.Net.WebException] {
                                    Write-Warning -Message (
                                        'Download attempt failed using {0}: {1}' -f
                                        $Attempt.Name, $_.Exception.Message
                                    )
                                    # Clean up partial file if it exists
                                    if (Test-Path -Path $SavePath) {
                                        Remove-Item -Path $SavePath -Force -ErrorAction SilentlyContinue
                                    } #end if
                                } catch {
                                    Write-Warning -Message (
                                        'Unexpected error using {0}: {1}' -f
                                        $Attempt.Name, $_.Exception.Message
                                    )
                                    # Clean up partial file if it exists
                                    if (Test-Path -Path $SavePath) {
                                        Remove-Item -Path $SavePath -Force -ErrorAction SilentlyContinue
                                    } #end if
                                } #end try-catch
                            } #end foreach

                            if (-not $DownloadSuccess) {
                                throw 'All download strategies failed. Please check network connectivity and proxy settings.'
                            } #end if
                        } #end if-else

                        $NewHash = Get-FileHash -Algorithm SHA256 -Path $SavePath | Select-Object -ExpandProperty Hash
                        $NewHash | Out-File -FilePath "$SavePath.sha256" -Force
                    } #end if-else

                    $IsoPath = $SavePath
                } else {
                    Write-Verbose -Message ('Using SQL Server installation media from DVD drive: {0}' -f $SqlServerDrive)
                } #end if-else
            } else {
                Write-Verbose -Message ('Using specified ISO path: {0}' -f $IsoPath)
            } #end if

            # Display installation source information
            if ($UseIsoFile) {
                Write-Verbose -Message ('ISO Path: {0}' -f $IsoPath)
            } else {
                Write-Verbose -Message ('DVD Drive: {0}' -f $SqlServerDrive)
            } #end if-else

            if ($PSCmdlet.ShouldProcess(
                    $(if ($UseIsoFile) {
                            $IsoPath
                        } else {
                            $SqlServerDrive
                        }),
                    $(if ($UseIsoFile) {
                            'Mount ISO and install SQL Server'
                        } else {
                            'Install SQL Server from DVD'
                        })
                )) {

                [String]$InstallationDrive = $null

                if ($UseIsoFile) {
                    Write-Verbose -Message ('Mounting ISO file: {0}' -f $IsoPath)
                    # Mount the ISO
                    $Volume = Mount-DiskImage -ImagePath $IsoPath -StorageType ISO -PassThru | Get-Volume
                    $InstallationDrive = if ($Volume) {
                        $Volume.DriveLetter + ':'
                    } else {
                        # Fallback for Windows Sandbox where Get-Volume might not work
                        Get-PSDrive | Where-Object Description -Like 'sql*' | Select-Object -ExpandProperty Root
                    } #end if-else

                    if (-not $InstallationDrive) {
                        throw "Cannot find mounted ISO drive for path: $IsoPath"
                    } #end if

                    Write-Verbose -Message ('ISO mounted on drive: {0}' -f $InstallationDrive)
                } else {
                    # Use DVD drive directly
                    $InstallationDrive = $SqlServerDrive
                    Write-Verbose -Message ('Using DVD drive: {0}' -f $InstallationDrive)
                } #end if-else

                # Display installation media contents
                Get-ChildItem -Path $InstallationDrive | Format-Table -AutoSize | Out-String | Write-Verbose

                # Check for running SQL Server setup processes
                $RunningSetupFilter = {
                    $_.CommandLine -like '*setup.exe*/ACTION=install*'
                }
                $RunningSetup = Get-CimInstance -ClassName Win32_Process |
                    Where-Object $RunningSetupFilter

                if ($RunningSetup) {
                    $ProcessMessage = 'Found running SQL Server installer, terminating process ID: {0}' -f
                    $RunningSetup.ProcessId
                    Write-Warning -Message $ProcessMessage
                    Stop-Process -Id $RunningSetup.ProcessId -Force
                } #end if

                # Build setup command arguments
                $SetupArgs = [System.Collections.Generic.List[String]]::new()
                $SetupArgs.Add('/Q')                                    # Silent install
                $SetupArgs.Add('/INDICATEPROGRESS')                     # Verbose logging to console
                $SetupArgs.Add('/IACCEPTSQLSERVERLICENSETERMS')         # Accept license terms
                $SetupArgs.Add('/ACTION=install')                       # Installation action
                $SetupArgs.Add('/UPDATEENABLED=false')                  # Disable product updates

                # Optional directories
                if ($InstallDir) {
                    $SetupArgs.Add('/INSTANCEDIR="{0}"' -f $InstallDir)
                } #end if

                if ($DataDir) {
                    $SetupArgs.Add('/INSTALLSQLDATADIR="{0}"' -f $DataDir)
                } #end if

                # Features
                $SetupArgs.Add('/FEATURES=' + ($Features -join ','))

                # Security configuration
                $AdminAccountsString = $SystemAdminAccounts -join '","'
                $SetupArgs.Add('/SQLSYSADMINACCOUNTS="{0}"' -f $AdminAccountsString)

                if ($SaPasswordPlain) {
                    $SetupArgs.Add('/SECURITYMODE=SQL')
                    $SetupArgs.Add('/SAPWD="{0}"' -f $SaPasswordPlain)
                } #end if

                # Instance configuration
                $SetupArgs.Add('/INSTANCENAME={0}' -f $InstanceName)

                # Service account configuration
                if ($ServiceAccountName) {
                    $SetupArgs.Add('/SQLSVCACCOUNT="{0}"' -f $ServiceAccountName)

                    # Determine service account type based on parameter set and account format
                    $IsGMSA = ($CurrentParameterSetName -eq 'gMSAAccount') -or
                    ($CurrentParameterSetName -eq 'Default' -and $ServiceAccountName.EndsWith('$'))

                    if (-not $IsGMSA -and $ServiceAccountPasswordPlain) {
                        # Traditional domain account with password
                        $SetupArgs.Add('/SQLSVCPASSWORD="{0}"' -f $ServiceAccountPasswordPlain)
                        Write-Verbose -Message ('Using traditional domain service account: {0}' -f $ServiceAccountName)
                    } elseif (-not $IsGMSA -and -not $ServiceAccountPasswordPlain) {
                        Write-Warning -Message (
                            'Domain service account specified but no password provided. This may cause installation to fail.'
                        )
                    } elseif ($IsGMSA) {
                        Write-Verbose -Message ('Using group Managed Service Account (gMSA): {0}' -f $ServiceAccountName)
                        # gMSA accounts don't use passwords
                        if ($ServiceAccountPasswordPlain) {
                            Write-Warning -Message (
                                'Password provided for gMSA account. Passwords are not used with gMSAs and will be ignored.'
                            )
                        } #end if
                    } #end if-elseif
                } else {
                    Write-Verbose -Message 'No service account specified, using default NT Service accounts'
                } #end if

                # Service startup types
                $SetupArgs.Add('/SQLSVCSTARTUPTYPE=automatic')
                $SetupArgs.Add('/AGTSVCSTARTUPTYPE=automatic')
                $SetupArgs.Add('/ASSVCSTARTUPTYPE=manual')

                # SQL Server Configuration Parameters
                # Collation
                $SetupArgs.Add('/SQLCOLLATION={0}' -f $SqlCollation)

                # Authentication mode
                if ($AuthenticationMode -eq 'Mixed') {
                    $SetupArgs.Add('/SECURITYMODE=SQL')
                } #end if

                # File paths
                if ($DataPath) {
                    $SetupArgs.Add('/SQLUSERDBDIR="{0}"' -f $DataPath)
                } #end if

                if ($LogPath) {
                    $SetupArgs.Add('/SQLUSERDBLOGDIR="{0}"' -f $LogPath)
                } #end if

                if ($TempPath) {
                    $SetupArgs.Add('/SQLTEMPDBDIR="{0}"' -f $TempPath)
                } #end if

                if ($BackupPath) {
                    $SetupArgs.Add('/SQLBACKUPDIR="{0}"' -f $BackupPath)
                } #end if

                # TempDB Configuration
                $SetupArgs.Add('/SQLTEMPDBFILECOUNT={0}' -f $SqlTempDbFileCount)
                $SetupArgs.Add('/SQLTEMPDBFILESIZE={0}' -f $SqlTempDbFileSize)
                $SetupArgs.Add('/SQLTEMPDBFILEGROWTH={0}' -f $SqlTempDbFileGrowth)
                $SetupArgs.Add('/SQLTEMPDBLOGFILESIZE={0}' -f $SqlTempDbLogFileSize)
                $SetupArgs.Add('/SQLTEMPDBLOGFILEGROWTH={0}' -f $SqlTempDbLogFileGrowth)

                # TCP/IP Configuration
                if ($EnableTcpIp) {
                    $SetupArgs.Add('/TCPENABLED=1')
                    $SetupArgs.Add('/SQLSVCPORT={0}' -f $TcpPort)
                } else {
                    $SetupArgs.Add('/TCPENABLED=0')
                } #end if-else

                # Performance optimization
                if ($PerformVolumeMaintenanceTasks) {
                    $SetupArgs.Add('/SQLSVCINSTANTFILEINIT=true')
                } #end if

                # Product key
                if ($ProductKey) {
                    $SetupArgs.Add('/PID={0}' -f $ProductKey)
                } #end if

                # Remove empty arguments
                $CleanedArgs = $SetupArgs | Where-Object { $_ -notmatch '/.+?=("")?$' }

                # Create sanitized output for logging (hide passwords)
                $LoggingArgs = $CleanedArgs -replace '(SAPWD|SQLSVCPASSWORD)=.+', '$1="****"'

                Write-Verbose -Message 'SQL Server setup parameters:'
                foreach ($Arg in $LoggingArgs) {
                    $Parts = $Arg -split '=', 2
                    if ($Parts.Count -eq 2) {
                        Write-Verbose -Message ('   {0} = {1}' -f $Parts[0].PadRight(40), $Parts[1])
                    } else {
                        Write-Verbose -Message ('   {0}' -f $Parts[0])
                    } #end if-else
                } #end foreach

                # Execute SQL Server setup
                $SetupPath = Join-Path -Path $InstallationDrive -ChildPath 'setup.exe'
                $SetupProcess = Start-Process -FilePath $SetupPath -ArgumentList $CleanedArgs -Wait -PassThru

                if ($SetupProcess.ExitCode -eq 0) {
                    Write-Verbose -Message 'SQL Server installation completed successfully'
                    $InstallationResult = $true
                } elseif ($SetupProcess.ExitCode -eq 3010) {
                    Write-Warning -Message 'SQL Server installation completed but requires system reboot'
                    $InstallationResult = $true
                } else {
                    $ErrorMessage = 'SQL Server installation failed with exit code: {0}' -f $SetupProcess.ExitCode
                    throw $ErrorMessage
                } #end if-elseif-else

                # Enable protocols if requested
                if ($EnableProtocols -and $InstallationResult) {

                    Write-Verbose -Message 'Enabling SQL Server network protocols: TCP/IP, Named Pipes'

                    try {

                        $NamespaceFilter = { $_.Name -Match 'ComputerManagement' }

                        $SqlCM = Get-CimInstance -Namespace 'root\Microsoft\SqlServer' -ClassName '__NAMESPACE' |
                            Where-Object $NamespaceFilter |
                                Select-Object -ExpandProperty Name

                        $NetworkProtocolNamespace = "root\Microsoft\SqlServer\$SqlCM"
                        $SqlNetworkProtocols = Get-CimInstance -Namespace $NetworkProtocolNamespace `
                            -ClassName ServerNetworkProtocol

                        # Enable TCP/IP
                        $TcpProtocol = $SqlNetworkProtocols | Where-Object ProtocolDisplayName -EQ 'TCP/IP'

                        if ($TcpProtocol) {

                            $TcpProtocol | Invoke-CimMethod -MethodName SetEnable | Out-Null
                            Write-Verbose -Message 'TCP/IP protocol enabled'
                        } #end if

                        # Enable Named Pipes
                        $NamedPipesProtocol = $SqlNetworkProtocols | Where-Object ProtocolDisplayName -EQ 'Named Pipes'

                        if ($NamedPipesProtocol) {
                            $NamedPipesProtocol | Invoke-CimMethod -MethodName SetEnable | Out-Null
                            Write-Verbose -Message 'Named Pipes protocol enabled'
                        } #end if

                        # Restart SQL Server service
                        Get-Service -Name $InstanceName | Restart-Service -Force
                        Write-Verbose -Message ('SQL Server service {0} restarted' -f $InstanceName)
                    } catch {
                        Write-Warning -Message ('Failed to enable protocols: {0}' -f $_.Exception.Message)
                    } #end try-catch
                } #end if

                # Configure SQL Server settings that require post-installation configuration
                if ($InstallationResult -and ($MaxDegreeOfParallelism -or $MaxServerMemory -or $MinServerMemory)) {

                    Write-Verbose -Message 'Configuring SQL Server advanced settings'

                    try {

                        # Build T-SQL configuration commands
                        $ConfigCommands = [System.Collections.Generic.List[String]]::new()

                        if ($MaxDegreeOfParallelism) {
                            $ConfigCommands.Add("EXEC sp_configure 'max degree of parallelism', $MaxDegreeOfParallelism")
                            Write-Verbose -Message ('Setting MAXDOP to {0}' -f $MaxDegreeOfParallelism)
                        } #end if

                        if ($MaxServerMemory) {
                            $ConfigCommands.Add("EXEC sp_configure 'max server memory (MB)', $MaxServerMemory")
                            Write-Verbose -Message ('Setting max server memory to {0} MB' -f $MaxServerMemory)
                        } #end if

                        if ($MinServerMemory) {
                            $ConfigCommands.Add("EXEC sp_configure 'min server memory (MB)', $MinServerMemory")
                            Write-Verbose -Message ('Setting min server memory to {0} MB' -f $MinServerMemory)
                        } #end if

                        if ($ConfigCommands.Count -gt 0) {
                            # Add RECONFIGURE to apply changes
                            $ConfigCommands.Add('RECONFIGURE WITH OVERRIDE')

                            # Execute configuration using sqlcmd
                            $SqlCommand = $ConfigCommands -join '; '
                            $SqlCmdArgs = @(
                                '-S', 'localhost'
                                '-E'  # Use Windows Authentication
                                '-Q', $SqlCommand
                            )

                            Write-Verbose -Message 'Executing SQL Server configuration commands'
                            $ConfigResult = & sqlcmd @SqlCmdArgs 2>&1

                            if ($LASTEXITCODE -eq 0) {
                                Write-Verbose -Message 'SQL Server configuration completed successfully'
                            } else {
                                $WarningMessage = 'SQL Server configuration completed with warnings: {0}' -f
                                ($ConfigResult -join '; ')
                                Write-Warning -Message $WarningMessage
                            } #end if-else
                        } #end if
                    } catch {
                        Write-Warning -Message ('Failed to configure SQL Server settings: {0}' -f $_.Exception.Message)
                    } #end try-catch
                } #end if

                # Dismount ISO only if we mounted one
                if ($UseIsoFile -and $IsoPath) {
                    Write-Verbose -Message ('Dismounting ISO: {0}' -f $IsoPath)
                    Dismount-DiskImage -ImagePath $IsoPath -ErrorAction SilentlyContinue
                } #end if
            } #end if ShouldProcess
        } catch {
            Write-Error -Message ('SQL Server installation failed: {0}' -f $_.Exception.Message)
            $InstallationResult = $false

            # Ensure ISO is dismounted on error only if we mounted one
            if ($UseIsoFile -and $IsoPath) {
                Write-Verbose -Message ('Dismounting ISO after error: {0}' -f $IsoPath)
                Dismount-DiskImage -ImagePath $IsoPath -ErrorAction SilentlyContinue
            } #end if
        } finally {
            # Always stop transcript
            Stop-Transcript -ErrorAction SilentlyContinue
        } #end try-catch-finally
    } #end Process

    End {
        $EndTime = Get-Date
        $Duration = $EndTime - $StartTime
        Write-Verbose -Message ('Installation completed in {0:F1} minutes' -f $Duration.TotalMinutes)

        # Display function footer if variables exist
        try {
            if ($null -ne $Variables -and $null -ne $Variables.Footer) {
                $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                    'installing SQL Server with specified configuration.'
                )
                Write-Verbose -Message $txt
            } #end If
        } catch {
            # Module variables not available, continue without footer
            Write-Verbose -Message 'Function Install-SqlServer finished installing SQL Server with specified configuration.'
        } #end try-catch

        return $InstallationResult
    } #end End
} #end function Install-SqlServer
