Function New-WsusObjects
{
    <#
        .Synopsis
            Create WSUS Objects and Delegations
        .DESCRIPTION
            Create the WSUS Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-WsusObjects
        .INPUTS
        .NOTES
            Version:         1.1
            DateModified:    22/Apr/2021
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param ( )

    Begin {

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        ################################################################################
        # Initialisations
        Import-Module ActiveDirectory      -Verbose:$false

        #Get the OS Instalation Type
        $OsInstalationType = Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' | Select-Object -ExpandProperty InstallationType

    } # End Bigin

    Process {

        # Check if AD module is installed
        If(-not((Get-WindowsFeature -Name RSAT-AD-PowerShell).Installed)) {
            Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature
        }

        # Check if feature is installed, if not then proceed to install it.
        If(-not((Get-WindowsFeature -Name UpdateServices-Services).Installed)) {
  
            Install-WindowsFeature -Name UpdateServices, UpdateServices-Services, UpdateServices-WidDB -Restart

        }

        If($OsInstalationType -ne 'Server Core') {
            Install-WindowsFeature -Name UpdateServices-RSAT -IncludeAllSubFeature
        }

        # Configure Download Location

        #Create WSUS folder
        # Create Folder where to store all Delegation Model scripts & files
        $WsusFolder = ('{0}\WSUS\' -f $env:SystemDrive)

        if(-not(Test-Path $WsusFolder)) {
            New-Item -ItemType Directory -Force -Path $WsusFolder
        }

        # Create a new Windows Script Shell
        $sh = New-Object -comobject 'Wscript.Shell'

        [String]$cmd = '"C:\Program Files\Update Services\Tools\WsusUtil.exe" PostInstall CONTENT_DIR=C:\WSUS'
        $sh.Run($cmd,1,'true')

        # Download Microsoft System CLR Types for SQL Server 2014
        #$URL = 'https://download.microsoft.com/download/1/3/0/13089488-91FC-4E22-AD68-5BE58BD5C014/ENU/x64/SQLSysClrTypes.msi'

        # Download Microsoft System CLR Types for SQL Server 2012
        $URL = 'http://download.microsoft.com/download/F/E/D/FEDB200F-DE2A-46D8-B661-D019DFE9D470/ENU/x64/SQLSysClrTypes.msi'
        Start-BitsTransfer -Source $URL -Destination $env:TEMP -Priority High -TransferType Download -RetryInterval 60 -RetryTimeout 180 -ErrorVariable err
        if ($err) {
            write-Error -Message 'Microsoft Microsoft System CLR Types for SQL Server 2014 could not be downloaded!. Please download and install it manually to use WSUS Reports.'
        }

        # Download MICROSOFT� REPORT VIEWER 2015 RUNTIME
        #$URL = 'https://download.microsoft.com/download/A/1/2/A129F694-233C-4C7C-860F-F73139CF2E01/ENU/x86/ReportViewer.msi'

        # Download MICROSOFT� REPORT VIEWER 2012 RUNTIME
        $URL = 'https://download.microsoft.com/download/F/B/7/FB728406-A1EE-4AB5-9C56-74EB8BDDF2FF/ReportViewer.msi'
        Start-BitsTransfer -Source $URL -Destination $env:TEMP -Priority High -TransferType Download -RetryInterval 60 -RetryTimeout 180 -ErrorVariable err
        if ($err) {
            write-Error -Message 'Microsoft REPORT VIEWER 2015 RUNTIME could not be downloaded!. Please download and install it manually to use WSUS Reports.'
        }



        # Install Microsoft System CLR Types for SQL Server 2014
        $Arguments = '/i "{0}\SQLSysClrTypes.msi" /qn /quiet /norestart' -f $env:TEMP
        $setup = Start-Process -FilePath 'msiexec.exe' -Verb RunAs -ArgumentList $Arguments -Wait -PassThru -Verbose
        $setup.WaitForExit()
        if ($setup.exitcode -eq 0) {
            write-verbose -Message 'Microsoft System CLR Types for SQL Server 2017 Successfully installed'
        }  else {
            write-error -Message 'Microsoft System CLR Types for SQL Server 2017 did not install correctly. Please download and install it manually to use WSUS Reports.'
        }


        # Install REPORT VIEWER 2015 RUNTIME
        $Arguments = '/i "{0}\ReportViewer.msi" /qn /quiet /norestart' -f $env:TEMP
        $setup = Start-Process -FilePath 'msiexec.exe' -Verb RunAs -ArgumentList $Arguments -Wait -PassThru -Verbose
        $setup.WaitForExit()
        if ($setup.exitcode -eq 0) {
            write-verbose -Message 'Microsoft REPORT VIEWER 2015 RUNTIME Successfully installed'
        } else {
            write-error -Message 'Microsoft REPORT VIEWER 2015 RUNTIME did not install correctly. Please download and install it manually to use WSUS Reports.'
        }




        # Cannot be imported in the bigin section due features installation
        Import-Module -Name WebAdministration -Force -Verbose:$false





        # Set Application Pool Maximum Private memory
        #Clear-ItemProperty IIS:\AppPools\WsusPool -Name Recycling.periodicRestart.privatememory
        #[int32] $PrivMemMax = 4GB
        #[int32] $PrivMemMax = 8GB
        [int32] $PrivMemMax = 0
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name Recycling.periodicRestart.privateMemory -Value $PrivMemMax

		# ( C:\Program Files\Update Services\WebServices\ClientWebService\web.config ) for WSUS: Replace <httpRuntime maxRequestLength="4096" /> with <httpRuntime maxRequestLength="204800" executionTimeout="7200"/>

        <#
        This one are failing
        Set-WebConfiguration -Filter "/system.applicationHost/applicationPools/add[@name='WsusPool']/recycling/periodicRestart/@privateMemory" -Value 0
        Set-WebConfiguration -Filter "/system.applicationHost/applicationPools/add[@name='WsusPool']/processModel/@maxProcesses" -Value 0
        #>

        # Other "Unexpected error" hacks
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name queueLength -Value 25000
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name cpu.resetInterval -Value "00.00:15:00"
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name failure.loadBalancerCapabilities -Value "TcpLevel"
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name failure.rapidFailProtectionInterval -Value "00.00:30:00"
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name failure.rapidFailProtectionMaxCrashes -Value 60
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name ProcessModel.MaxProcesses -Value 0


        # Get WSUS Server Object
        $wsus = Get-WSUSServer

        # Connect to WSUS server configuration
        $wsusConfig = $wsus.GetConfiguration()

        ### Remove WSUS configuration pop-up when opening WSUS Management Console
        $wsusConfig.OobeInitialized = $true
        $wsusConfig.Save()


        #Check WSUS services. Mark those as automatic
        Set-Service WSusCertServer -StartupType Automatic
        Set-Service WsusService -StartupType Automatic
        Set-Service wuauserv -StartupType Automatic

        #Start Services
        Start-Service WSusCertServer, WsusService, wuauserv -Verbose


        # Get a new certificate from CA1 using WebServerV2 template
        $Splat = @{
            Template          = 'WebServerV2'
            DnsName           = ('{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN).ToLower()
            Url               = 'ldap:'
            CertStoreLocation = 'cert:\LocalMachine\My'
            SubjectName       = ('CN={0}' -f $env:COMPUTERNAME).ToLower()
        }
        $WsusCert = Get-Certificate @Splat

        # Get the binding as object
        $bind = Get-WebBinding -Name 'WSUS Administration' -Protocol https

        # Merge the 2 objects
        $bind.AddSslCertificate($WsusCert.Certificate.Thumbprint, "My")

        # Set all corresponding virtual directories to use SSL
        $Splat = @{
            PSPath = 'MACHINE/WEBROOT/APPHOST'
            Filter = "system.webServer/Security/access"
            Name   = "sslFlags"
            Value  ="Ssl"
        }
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/ApiRemoting30'
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/ClientWebService'
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/DSSAuthWebService'
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/ServerSyncWebService'
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/SimpleAuthWebService'

        # Final SSL configuration
        [String]$cmd = '"C:\Program Files\Update Services\Tools\WsusUtil.exe" configuressl {0}' -f ('{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN).ToLower()
        $sh.Run($cmd,1,'true')



        # Get WSUS Server Object
        $wsus = Get-WSUSServer
        # Refresh WSUS server configuration
        $wsusConfig = $wsus.GetConfiguration()

        # Set to download updates from Microsoft Updates
        Set-WsusServerSynchronization -SyncFromMU

        # Set Update Languages to English and save configuration settings
        $wsusConfig.AllUpdateLanguagesEnabled = $false
        $wsusConfig.SetEnabledUpdateLanguages('en')
        $wsusConfig.GetContentFromMU = $True
        $wsusConfig.AutoApproveWsusInfrastructureUpdates = $True
        $wsusConfig.AutoRefreshUpdateApprovals = $True
        $wsusConfig.AutoRefreshUpdateApprovalsDeclineExpired = $True
        $wsusConfig.HostBinariesOnMicrosoftUpdate = $True
        $wsusConfig.Save()

        # Get WSUS Subscription and perform initial synchronization to get latest categories
        $subscription = $wsus.GetSubscription()
        $subscription.StartSynchronizationForCategoryOnly()

        while ($subscription.GetSynchronizationProgress().ProcessedItems -ne $subscription.GetSynchronizationProgress().TotalItems) {
            Write-Progress -PercentComplete ( $subscription.GetSynchronizationProgress().ProcessedItems*100/($subscription.GetSynchronizationProgress().TotalItems) ) -Activity "WSUS Sync Progress"
        }


        # Disable all previously selected products
        Get-WsusProduct | Set-WsusProduct -Disable

        # Configure the Platforms that we want WSUS to receive updates
        Get-WsusProduct | where-Object {
            $_.Product.Title -in (
            'Active Directory',
            'Developer Tools, Runtimes, and Redistributables',
            'Forefront Client Security',
            'Forefront Identity Manager 2010 R2',
            'Forefront Identity Manager 2010',
            'Forefront Protection Category',
            'Forefront Server Security Category',
            'Forefront Threat Management Gateway, Definition Updates for HTTP Malware Inspection',
            'Forefront TMG MBE',
            'Forefront TMG',
            'Forefront',
            'Microsoft Advanced Threat Analytics',
            'Microsoft BitLocker Administration and Monitoring v1',
            'Microsoft BitLocker Administration and Monitoring',
            'Microsoft Edge',
            'Microsoft Security Essentials',
            'MS Security Essentials',
            'Report Viewer 2005',
            'Report Viewer 2008',
            'Report Viewer 2010',
            'Security Essentials',
            'Visual Studio 2015',
            'Visual Studio 2017',
            'Windows 10, version 1809 and later, Upgrade & Servicing Drivers',
            'Windows 10',
            'Windows Admin Center',
            'Windows Defender',
            'Windows Dictionary Updates',
            'Windows Server 2016 and Later Servicing Drivers',
            'Windows Server 2016',
            'Windows Server 2019 and later, Servicing Drivers',
            'Windows Server 2019 and later, Upgrade & Servicing Drivers',
            'Windows Server 2019',
            'Windows Server Drivers',
            'Windows Server Solutions Best Practices Analyzer 1.0',
            'Windows Server, version 1903 and later'
            )
        } | Set-WsusProduct



        # Configure the Classifications
        write-Output 'Setting WSUS Classifications'
        Get-WsusClassification | Where-Object {
            $_.Classification.Title -in (
            'Critical Updates',
            'Definition Updates',
            'Feature Packs',
            'Security Updates',
            'Service Packs',
            'Update Rollups',
            'Updates')
        } | Set-WsusClassification



        # Configure Default Approval Rule
        [void][reflection.assembly]::LoadWithPartialName('Microsoft.UpdateServices.Administration')

        $rule = $wsus.GetInstallApprovalRules() | Where-Object { $_.Name -eq 'Default Automatic Approval Rule' }

        $class = $wsus.GetUpdateClassifications() | Where-Object {$_.Title -In (
            'Critical Updates',
            'Definition Updates',
            'Security Updates',
            'Service Packs',
            'Update Rollups',
            'Updates')
        }

        $class_coll = New-Object Microsoft.UpdateServices.Administration.UpdateClassificationCollection

        $class_coll.AddRange($class)
        $rule.SetUpdateClassifications($class_coll)
        $rule.Enabled = $True
        $rule.Save()


        # Configure Synchronizations
        write-Output 'Enabling WSUS Automatic Synchronisation'
        $subscription.SynchronizeAutomatically=$true

        # Set synchronization scheduled for midnight each night
        $subscription.SynchronizeAutomaticallyTimeOfDay= (New-TimeSpan -Hours 0)
        $subscription.NumberOfSynchronizationsPerDay=1
        $subscription.Save()

        # Kick off a synchronization
        $subscription.StartSynchronization()


        ### Create computer target group
        $wsus.CreateComputerTargetGroup("DCs")
        $wsus.CreateComputerTargetGroup("PAWs")
        $wsus.CreateComputerTargetGroup("Infrastructure Servers")
        $wsus.CreateComputerTargetGroup("Tier1")
        $wsus.CreateComputerTargetGroup("Tier2")

    } # End Process

    End {

        Write-Verbose -Message ('Function {0} created Wsus objects and Delegations successfully.' -f $MyInvocation.InvocationName)
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

    } # End end
} # end function New-WsusObjects