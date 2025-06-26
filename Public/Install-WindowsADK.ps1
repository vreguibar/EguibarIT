function Install-WindowsADK {

    <#
        .SYNOPSIS
            Downloads and installs Windows Assessment and Deployment Kit (ADK).

        .DESCRIPTION
            The Install-WindowsADK function provides functionality to download and install
            multiple versions of Windows ADK tool. It supports downloading ADK setup files
            and installing specific features to a target directory.

        .PARAMETER Action
            Specifies the action to perform. Valid values are 'Download', 'Install', or 'Help'.

        .PARAMETER Version
            Specifies the Windows ADK version to download or install. If not specified,
            the function will attempt to detect the OS version and use the appropriate ADK version.

        .PARAMETER InstallPath
            Specifies the installation path for Windows ADK. Defaults to 'C:\Tools\ADK'.

        .PARAMETER Features
            Specifies which ADK features to install. Defaults to Deployment Tools.

        .EXAMPLE
            Install-WindowsADK -Action Download -Version '1709'

            Downloads Windows ADK version 1709 setup files.

        .EXAMPLE
            Install-WindowsADK -Action Install -Version '1607' -InstallPath 'C:\MyTools\ADK'

            Installs Windows ADK version 1607 to the specified path with default features.

        .EXAMPLE
            Install-WindowsADK -Action Install -Version '1809' -Features 'Deployment Tools', 'Windows Performance Toolkit (WPT)'

            Installs Windows ADK version 1809 with Deployment Tools and Windows Performance Toolkit.

        .EXAMPLE
            Install-WindowsADK -Action Install -WhatIf

            Shows what would be installed without actually performing the installation.

        .INPUTS
            None. You cannot pipe objects to Install-WindowsADK.

        .OUTPUTS
            [System.Boolean]
            Returns True if the operation was successful, otherwise False.

        .NOTES
            Used Functions:
                Name                             ║ Module/Namespace
                ═════════════════════════════════╬══════════════════════════════
                Write-Verbose                    ║ Microsoft.PowerShell.Utility
                Write-Error                      ║ Microsoft.PowerShell.Utility
                Write-Warning                    ║ Microsoft.PowerShell.Utility
                Get-Date                         ║ Microsoft.PowerShell.Utility
                Start-Process                    ║ Microsoft.PowerShell.Management
                Test-Path                        ║ Microsoft.PowerShell.Management
                New-Item                         ║ Microsoft.PowerShell.Management
                Invoke-WebRequest                ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay              ║ EguibarIT

        .NOTES
            Version:         1.0
            DateModified:    27/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Install-WindowsADK.ps1

        .COMPONENT
            Windows Deployment Tools

        .ROLE
            Administrator

        .FUNCTIONALITY
            Downloads and installs Windows Assessment and Deployment Kit (ADK).
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.Boolean])]

    param(
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 0,
            HelpMessage = 'Action to perform: Download, Install, or Help'
        )]
        [ValidateSet('Download', 'Install', 'Help')]
        [String]
        $Action,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            Position = 1,
            HelpMessage = 'Windows ADK version to download or install'
        )]
        [ValidateSet(
            '1507',
            '1511',
            '1607',
            '1703',
            '1709',
            '1803',
            '1809',
            '1903',
            '1909',
            '2004',
            '20H2',
            '21H1',
            '21H2',
            '22H2'
        )]
        [String]
        $Version,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'Installation path for Windows ADK'
        )]
        [ValidateNotNullOrEmpty()]
        [PSDefaultValue(
            Help = 'Path where Windows ADK will be installed',
            value = { 'C:\Program Files\ADK' }
        )]
        [String]
        $InstallPath = 'C:\Program Files\ADK',

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            HelpMessage = 'ADK features to install'
        )]
        [ValidateSet(
            'Application Compatibility Toolkit (ACT)',
            'Deployment Tools',
            'Windows Preinstallation Environment (Windows PE)',
            'User State Migration Tool',
            'Volume Activation Management Tool (VAMT)',
            'Windows Performance Toolkit (WPT)',
            'Windows Assessment Toolkit',
            'Windows Assessment Services — Client',
            'Windows Assessment Services',
            'Microsoft SQL Server 2012 Express',
            '.NET Framework'
        )]
        [PSDefaultValue(
            Help = 'Default is "Deployment Tools"',
            value = { @('Deployment Tools') }
        )]
        [String[]]
        $Features = @('Deployment Tools')
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

        # ADK version to download URL mapping
        [hashtable]$AdkUrls = @{}
        $AdkUrls.Add('1507', 'https://go.microsoft.com/fwlink/p/?LinkId=526740')
        $AdkUrls.Add('1511', 'https://go.microsoft.com/fwlink/p/?LinkId=526740')
        $AdkUrls.Add('1607', 'https://go.microsoft.com/fwlink/p/?LinkId=845542')
        $AdkUrls.Add('1703', 'https://go.microsoft.com/fwlink/p/?LinkId=845542')
        $AdkUrls.Add('1709', 'https://go.microsoft.com/fwlink/p/?linkid=859206')
        $AdkUrls.Add('1803', 'https://go.microsoft.com/fwlink/?linkid=873065')
        $AdkUrls.Add('1809', 'https://go.microsoft.com/fwlink/?linkid=2026036')
        $AdkUrls.Add('1903', 'https://go.microsoft.com/fwlink/?linkid=2086042')
        $AdkUrls.Add('1909', 'https://go.microsoft.com/fwlink/?linkid=2120254')
        $AdkUrls.Add('2004', 'https://go.microsoft.com/fwlink/?linkid=2120254')
        $AdkUrls.Add('20H2', 'https://go.microsoft.com/fwlink/?linkid=2120254')
        $AdkUrls.Add('21H1', 'https://go.microsoft.com/fwlink/?linkid=2165884')
        $AdkUrls.Add('21H2', 'https://go.microsoft.com/fwlink/?linkid=2165884')
        $AdkUrls.Add('22H2', 'https://go.microsoft.com/fwlink/?linkid=2196127')

        # Windows version to ADK mapping based on build numbers
        [hashtable]$WindowsToAdkMapping = @{}
        $WindowsToAdkMapping.Add('10240', '1507')    # Windows 10 1507
        $WindowsToAdkMapping.Add('10586', '1511')    # Windows 10 1511
        $WindowsToAdkMapping.Add('14393', '1607')    # Windows 10 1607 / Server 2016
        $WindowsToAdkMapping.Add('15063', '1703')    # Windows 10 1703
        $WindowsToAdkMapping.Add('16299', '1709')    # Windows 10 1709
        $WindowsToAdkMapping.Add('17134', '1803')    # Windows 10 1803
        $WindowsToAdkMapping.Add('17763', '1809')    # Windows 10 1809 / Server 2019
        $WindowsToAdkMapping.Add('18362', '1903')    # Windows 10 1903
        $WindowsToAdkMapping.Add('18363', '1909')    # Windows 10 1909
        $WindowsToAdkMapping.Add('19041', '2004')    # Windows 10 2004
        $WindowsToAdkMapping.Add('19042', '20H2')    # Windows 10 20H2
        $WindowsToAdkMapping.Add('19043', '21H1')    # Windows 10 21H1
        $WindowsToAdkMapping.Add('19044', '21H2')    # Windows 10 21H2
        $WindowsToAdkMapping.Add('19045', '22H2')    # Windows 10 22H2
        $WindowsToAdkMapping.Add('20348', '21H2')    # Server 2022
        $WindowsToAdkMapping.Add('22000', '21H2')    # Windows 11 21H2
        $WindowsToAdkMapping.Add('22621', '22H2')    # Windows 11 22H2
        $WindowsToAdkMapping.Add('22631', '22H2')    # Windows 11 23H2
        $WindowsToAdkMapping.Add('26100', '22H2')    # Windows 11 24H2

        # Features to install
        [hashtable]$FeaturesToInstall = @{}
        $FeaturesToInstall.Add('Application Compatibility Toolkit (ACT)', 'OptionId.ApplicationCompatibilityToolkit')
        $FeaturesToInstall.Add('Deployment Tools', 'OptionId.DeploymentTools')
        $FeaturesToInstall.Add('Windows Preinstallation Environment (Windows PE)', 'OptionId.WindowsPreinstallationEnvironment')
        $FeaturesToInstall.Add('User State Migration Tool', 'OptionId.UserStateMigrationTool')
        $FeaturesToInstall.Add('Volume Activation Management Tool (VAMT)', 'OptionId.VolumeActivationManagementTool')
        $FeaturesToInstall.Add('Windows Performance Toolkit (WPT)', 'OptionId.WindowsPerformanceToolkit')
        $FeaturesToInstall.Add('Windows Assessment Toolkit', 'OptionId.WindowsAssessmentToolkit')
        $FeaturesToInstall.Add('Windows Assessment Services — Client', 'OptionId.WindowsAssessmentServicesClient')
        $FeaturesToInstall.Add('Windows Assessment Services', 'OptionId.WindowsAssessmentServices')
        $FeaturesToInstall.Add('Microsoft SQL Server 2012 Express', 'OptionId.SqlExpress2012')
        $FeaturesToInstall.Add('.NET Framework', 'OptionId.Netfx')


        # Result variable
        [boolean]$Result = $false

    } #end Begin

    Process {

        try {

            # If no version specified, try to detect from OS
            if (-not $Version) {

                $OsBuild = [System.Environment]::OSVersion.Version.Build.ToString()
                Write-Verbose -Message ('Detected OS build: {0}' -f $OsBuild)

                if ($WindowsToAdkMapping.ContainsKey($OsBuild)) {

                    $Version = $WindowsToAdkMapping[$OsBuild]
                    Write-Verbose -Message ('Mapped OS build {0} to ADK version {1}' -f $OsBuild, $Version)

                } else {

                    Write-Warning -Message ('Unknown OS build {0}, defaulting to latest ADK version (22H2)' -f $OsBuild)
                    $Version = '22H2'

                } #end if-else

            } #end if

            switch ($Action) {
                'Help' {

                    Write-Output 'Install-WindowsADK - Downloads and installs Windows Assessment and Deployment Kit'
                    Write-Output ''
                    Write-Output 'Available ADK versions:'
                    foreach ($Ver in $AdkUrls.Keys | Sort-Object) {

                        Write-Output ('  {0} - {1}' -f $Ver, $AdkUrls[$Ver])

                    } #end foreach
                    Write-Output ''
                    Write-Output 'Available ADK features:'
                    foreach ($FeatureName in $FeaturesToInstall.Keys | Sort-Object) {

                        Write-Output ('  {0}' -f $FeatureName)

                    } #end foreach
                    Write-Output ''
                    Write-Output 'Usage examples:'
                    Write-Output '  Install-WindowsADK -Action Download -Version 1809'
                    Write-Output '  Install-WindowsADK -Action Install -Version 1809 -InstallPath "C:\ADK"'
                    Write-Output '  Install-WindowsADK -Action Install -Features "Deployment Tools", "Windows Performance Toolkit (WPT)"'
                    $Result = $true

                } #end Help

                'Download' {

                    if (-not $AdkUrls.ContainsKey($Version)) {

                        throw ('Unsupported ADK version: {0}' -f $Version)

                    } #end if

                    $DownloadUrl = $AdkUrls[$Version]
                    $SetupFileName = 'adksetup.exe'
                    $DownloadPath = Join-Path -Path $env:TEMP -ChildPath $SetupFileName

                    Write-Verbose -Message ('Downloading ADK {0} from {1}' -f $Version, $DownloadUrl)

                    if ($PSCmdlet.ShouldProcess($DownloadUrl, 'Download ADK setup')) {

                        try {

                            $SplatWebRequest = @{
                                Uri         = $DownloadUrl
                                OutFile     = $DownloadPath
                                ErrorAction = 'Stop'
                            }
                            Invoke-WebRequest @SplatWebRequest

                            if (Test-Path -Path $DownloadPath) {

                                Write-Verbose -Message ('Successfully downloaded ADK setup to: {0}' -f $DownloadPath)
                                $Result = $true

                            } else {

                                Write-Error -Message 'Download completed but file not found'

                            } #end if-else

                        } catch {

                            Write-Error -Message ('Failed to download ADK: {0}' -f $_.Exception.Message)

                        } #end try-catch

                    } #end if

                } #end Download

                'Install' {

                    if (-not $AdkUrls.ContainsKey($Version)) {

                        throw ('Unsupported ADK version: {0}' -f $Version)

                    } #end if

                    # Ensure installation directory exists
                    if (-not (Test-Path -Path $InstallPath)) {

                        Write-Verbose -Message ('Creating installation directory: {0}' -f $InstallPath)

                        if ($PSCmdlet.ShouldProcess($InstallPath, 'Create installation directory')) {

                            try {

                                New-Item -Path $InstallPath -ItemType Directory -Force -ErrorAction Stop | Out-Null

                            } catch {

                                Write-Error -Message ('Failed to create installation directory: {0}' -f $_.Exception.Message)
                                return $false

                            } #end try-catch

                        } #end if

                    } #end if

                    $DownloadUrl = $AdkUrls[$Version]
                    $SetupFileName = 'adksetup.exe'
                    $SetupPath = Join-Path -Path $env:TEMP -ChildPath $SetupFileName

                    # Download ADK if not already present
                    if (-not (Test-Path -Path $SetupPath)) {

                        Write-Verbose -Message ('Downloading ADK {0} setup' -f $Version)

                        try {

                            $SplatWebRequest = @{
                                Uri         = $DownloadUrl
                                OutFile     = $SetupPath
                                ErrorAction = 'Stop'
                            }
                            Invoke-WebRequest @SplatWebRequest

                        } catch {

                            Write-Error -Message ('Failed to download ADK setup: {0}' -f $_.Exception.Message)
                            return $false

                        } #end try-catch

                    } #end if

                    # Install ADK
                    Write-Verbose -Message ('Installing ADK {0} to {1}' -f $Version, $InstallPath)

                    $InstallArgs = @('/quiet', '/installpath', $InstallPath)

                    # Add features to install
                    foreach ($Feature in $Features) {

                        # Map user-friendly names to option IDs
                        if ($FeaturesToInstall.ContainsKey($Feature)) {

                            $OptionId = $FeaturesToInstall[$Feature]
                            Write-Verbose -Message ('Adding feature: {0} ({1})' -f $Feature, $OptionId)

                        } else {

                            # Assume it's already an option ID
                            $OptionId = $Feature
                            Write-Verbose -Message ('Adding feature option ID: {0}' -f $OptionId)

                        } #end if-else

                        $InstallArgs += '/features'
                        $InstallArgs += $OptionId

                    } #end foreach

                    if ($PSCmdlet.ShouldProcess($InstallPath, ('Install Windows ADK {0}' -f $Version))) {

                        try {

                            $SplatProcess = @{
                                FilePath     = $SetupPath
                                ArgumentList = $InstallArgs
                                Wait         = $true
                                NoNewWindow  = $true
                                PassThru     = $true
                                ErrorAction  = 'Stop'
                            }
                            $InstallProcess = Start-Process @SplatProcess

                            if ($InstallProcess.ExitCode -eq 0) {

                                Write-Verbose -Message ('Successfully installed Windows ADK {0}' -f $Version)
                                $Result = $true

                            } else {

                                Write-Error -Message ('ADK installation failed with exit code: {0}' -f $InstallProcess.ExitCode)

                            } #end if-else

                        } catch {

                            Write-Error -Message ('Failed to start ADK installation: {0}' -f $_.Exception.Message)

                        } #end try-catch

                    } #end if

                } #end Install

            } #end switch

        } catch {

            Write-Error -Message ('Error in Install-WindowsADK: {0}' -f $_.Exception.Message)
            $Result = $false

        } #end try-catch

    } #end Process

    End {

        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'processing Windows ADK installation.'
            )
            Write-Verbose -Message $txt
        } #end If

        return $Result

    } #end End

} #end function Install-WindowsADK
