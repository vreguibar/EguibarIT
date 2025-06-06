function New-Tier0Gpo {

    <#
        .SYNOPSIS
            Creates and configures Group Policy Objects (GPOs) for a Tier 0 environment in Active Directory.

        .DESCRIPTION
            The New-Tier0Gpo function creates and configures Group Policy Objects (GPOs) for a Tier 0 environment
            in Active Directory. It implements a secure baseline configuration for various security tiers and
            organizational units (OUs), including:

            - Domain-level baseline GPOs
            - Domain Controller baseline GPOs
            - Admin area baseline GPOs
            - Service Account baseline GPOs
            - PAW (Privileged Access Workstation) baseline GPOs
            - Infrastructure Server baseline GPOs
            - Housekeeping and redirected container GPOs

            The function uses GPO backups from a specified location and links them to the appropriate OUs.
            It also delegates GPO administration rights to the specified security group.

        .PARAMETER ConfigXMLFile
            Full path to the XML configuration file that contains all naming conventions, OU structure, and
            security settings. Must be a valid XML file with required schema elements.

            The XML must include the following sections:
            - Admin section with GPOs subsection
            - Naming conventions (NC) section

            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            Path to all the scripts and files needed by this function. This directory must contain a 'SecTmpl'
            subfolder with the GPO backup files.

            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0Gpo -ConfigXMLFile 'C:\PsScripts\Config.xml' -DMScripts 'C:\PsScripts'

            Creates and configures all Tier 0 GPOs using the specified configuration file and scripts directory.

        .EXAMPLE
            New-Tier0Gpo -ConfigXMLFile 'C:\Custom\Configuration.xml' -DMScripts 'D:\Scripts' -Verbose

            Creates and configures all Tier 0 GPOs using a custom configuration file and scripts directory,
            with verbose output to track progress.

        .INPUTS
            System.IO.FileInfo
            System.String

        .OUTPUTS
            System.String
            Returns a success message upon completion.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Import-MyModule                            ║ EguibarIT
                Get-AdObjectType                           ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT
                New-DelegateAdGpo                          ║ EguibarIT.DelegationPS
                Import-GPO                                 ║ GroupPolicy
                Get-Content                                ║ Microsoft.PowerShell.Management
                Test-Path                                  ║ Microsoft.PowerShell.Management
                Join-Path                                  ║ Microsoft.PowerShell.Management
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.0
            DateModified:    30/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Active Directory
            Group Policy

        .ROLE
            Administrator

        .FUNCTIONALITY
            Group Policy Object Management, Security Baseline Configuration
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]

    param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0)]
        [ValidateScript({
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw ('File not found: {0}' -f $_)
                }
                if ($_.Extension -ne '.xml') {
                    throw ('File must be XML: {0}' -f $_)
                }
                try {
                    [xml]$xml = Get-Content -Path $_ -ErrorAction Stop
                    # Verify required XML elements are present
                    if ($null -eq $xml.n.Admin -or
                        $null -eq $xml.n.Admin.GPOs) {
                        throw 'XML file is missing required elements (Admin or GPOs section)'
                    }
                    return $true
                } catch {
                    throw ('Invalid XML file: {0}' -f $_.Exception.Message)
                }
            })]
        [PSDefaultValue(Help = 'Default Value is "C:\PsScripts\Config.xml"',
            Value = 'C:\PsScripts\Config.xml'
        )]
        [Alias('Config', 'XML', 'ConfigXml')]
        [System.IO.FileInfo]
        $ConfigXMLFile,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
            Position = 1)]
        [PSDefaultValue(
            Help = 'Default Value is "C:\PsScripts\"',
            Value = 'C:\PsScripts\'
        )]
        [Alias('ScriptPath')]
        [string]
        $DMScripts = 'C:\PsScripts\',

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Start transcript logging to DMScripts path with function name',
            Position = 2)]
        [Alias('Transcript', 'Log')]
        [switch]
        $EnableTranscript

    )

    Begin {
        Set-StrictMode -Version Latest

        If (-not $PSBoundParameters.ContainsKey('ConfigXMLFile')) {
            $PSBoundParameters['ConfigXMLFile'] = 'C:\PsScripts\Config.xml'
        } #end If

        If (-not $PSBoundParameters.ContainsKey('DMScripts')) {
            $PSBoundParameters['DMScripts'] = 'C:\PsScripts\'
        } #end If

        # If EnableTranscript is specified, start a transcript
        if ($EnableTranscript) {
            # Ensure DMScripts directory exists
            if (-not (Test-Path -Path $DMScripts -PathType Container)) {
                try {
                    New-Item -Path $DMScripts -ItemType Directory -Force | Out-Null
                    Write-Verbose -Message ('Created transcript directory: {0}' -f $DMScripts)
                } catch {
                    Write-Warning -Message ('Failed to create transcript directory: {0}' -f $_.Exception.Message)
                } #end try-catch
            } #end if

            # Create transcript filename using function name and current date/time
            $TranscriptFile = Join-Path -Path $DMScripts -ChildPath ('New-Tier0Gpo_{0}.LOG' -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

            try {
                Start-Transcript -Path $TranscriptFile -Force -ErrorAction Stop
                Write-Verbose -Message ('Transcript started: {0}' -f $TranscriptFile)
            } catch {
                Write-Warning -Message ('Failed to start transcript: {0}' -f $_.Exception.Message)
            } #end try-catch
        } #end if

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
        # Module imports

        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Resolve script path - parameter value has precedence over default value
        [string]$ScriptPath = $DMScripts

        # Validate script path exists and is not empty
        if ([string]::IsNullOrWhiteSpace($ScriptPath)) {
            Write-Warning -Message 'DMScripts path is empty. Using default path: C:\PsScripts\'
            $ScriptPath = 'C:\PsScripts\'
        }

        # Normalize the script path
        if (-not [System.IO.Path]::IsPathRooted($ScriptPath)) {
            $ScriptPath = Join-Path -Path (Get-Location).Path -ChildPath $ScriptPath
        }

        # Ensure script path ends with trailing slash for consistency
        if (-not $ScriptPath.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
            $ScriptPath = $ScriptPath + [System.IO.Path]::DirectorySeparatorChar
        }

        Write-Debug -Message ('Using DMScripts path: {0}' -f $ScriptPath)

        # Load the XML configuration file
        try {
            $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message "Error reading XML file: $($_.Exception.Message)"
            throw
        } #end Try-Catch

        # Load naming conventions from XML
        [hashtable]$NC = @{
            'sl'    = $confXML.n.NC.LocalDomainGroupPreffix
            'sg'    = $confXML.n.NC.GlobalGroupPreffix
            'su'    = $confXML.n.NC.UniversalGroupPreffix
            'Delim' = $confXML.n.NC.Delimiter
            'T0'    = $confXML.n.NC.AdminAccSufix0
            'T1'    = $confXML.n.NC.AdminAccSufix1
            'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        $SL_GpoAdminRight = Get-SafeVariable -Name 'SL_GpoAdminRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        # Build OU paths using string format for consistency
        [string]$ItAdminOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminOU.name, $Variables.AdDn)
        [string]$ItAdminAccountsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminAccountsOU.name, $ItAdminOuDn)
        [string]$ItServiceAccountsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name, $ItAdminOuDn)
        [string]$ItPawOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)
        [string]$ItInfraOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)
        [string]$ItHousekeepingOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItHousekeepingOU.name, $ItAdminOuDn)

        # Verify and construct SecTmpl path
        [string]$SecTmplPath = Join-Path -Path $ScriptPath -ChildPath 'SecTmpl'

        Write-Debug -Message ('Checking if SecTmpl directory exists at: {0}' -f $SecTmplPath)

        if (-not (Test-Path -Path $SecTmplPath -PathType Container)) {
            Write-Error -Message "SecTmpl directory not found at path: $SecTmplPath. Please ensure it exists."
            throw "SecTmpl directory not found at path: $SecTmplPath"
        }

        # Define progress tracking variables
        [int]$TotalSteps = 25  # Total number of GPO creation operations
        [int]$CurrentStep = 0
        [string]$ProgressActivity = 'Creating Tier 0 GPO Structure'

        # Hashtable for Write-Progress splatting
        [hashtable]$ProgressSplat = @{
            Activity        = $ProgressActivity
            Status          = ''
            PercentComplete = 0
        }

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Group Policy Objects', 'Create Baseline GPOs')) {

            # Domain
            $Splat = @{
                gpoDescription = 'Baseline'
                gpoLinkPath    = $Variables.AdDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupPath  = $SecTmplPath
            }


            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Domain Controllers Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat -gpoScope 'C' -gpoBackupID $confXML.n.Admin.GPOs.PCbaseline.backupID


            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Domain User Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat -gpoScope 'U' -gpoBackupID $confXML.n.Admin.GPOs.Userbaseline.backupID


            # Domain Controllers
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Name
                gpoScope       = $confXML.n.Admin.GPOs.DCBaseline.Scope
                gpoLinkPath    = 'OU=Domain Controllers,{0}' -f $Variables.AdDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupId    = $confXML.n.Admin.GPOs.DCBaseline.backupID
                gpoBackupPath  = $SecTmplPath
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Domain Controllers Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat


            # Admin Area
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.GPOs.Adminbaseline.Name
                gpoLinkPath    = $ItAdminOuDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupPath  = $SecTmplPath
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Admin Computer Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo -gpoScope 'C' @Splat


            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Admin User Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo -gpoScope 'U' @Splat


            # Users
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.OUs.ItAdminAccountsOU.Name
                gpoScope       = 'U'
                gpoLinkPath    = $ItAdminAccountsOuDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupPath  = $SecTmplPath
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Admin Accounts Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat


            # Service Accounts
            $Splat = @{
                gpoScope = 'U'
                GpoAdmin = $sl_GpoAdminRight
            }
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItServiceAccountsOU.Name)
                gpoLinkPath    = $ItServiceAccountsOuDn
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Service Accounts Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT0OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.Name, $ItServiceAccountsOuDn)
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating T0 Service Accounts Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT1OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT1OU.Name, $ItServiceAccountsOuDn)
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating T1 Service Accounts Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT2OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT2OU.Name, $ItServiceAccountsOuDn)
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating T2 Service Accounts Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1


            # PAWs
            $Splat = @{
                gpoScope = 'C'
                GpoAdmin = $sl_GpoAdminRight
            }
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawOU.Name)
                gpoLinkPath    = $ItPawOuDn
                gpoBackupID    = $confXML.n.Admin.GPOs.PAWbaseline.backupID
                gpoBackupPath  = $SecTmplPath
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating PAW Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT0OU.Name, $ItPawOuDn)
                gpoBackupID    = $confXML.n.Admin.GPOs.PawT0baseline.backupID
                gpoBackupPath  = $SecTmplPath
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating T0 PAW Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT1OU.Name, $ItPawOuDn)
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating T1 PAW Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT2OU.Name, $ItPawOuDn)
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating T2 PAW Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name, $ItPawOuDn)
                gpoBackupID    = $confXML.n.Admin.GPOs.PawStagingbaseline.backupID
                gpoBackupPath  = $SecTmplPath
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating PAW Staging Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            # Infrastructure Servers
            $Splat = @{
                gpoScope = 'C'
                GpoAdmin = $sl_GpoAdminRight
            }
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraOU.Name)
                gpoLinkPath    = $ItInfraOuDn
                gpoBackupID    = $confXML.n.Admin.GPOs.INFRAbaseline.backupID
                gpoBackupPath  = $SecTmplPath
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Infrastructure Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0Ou.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT0Ou.Name, $ItInfraOuDn)
                gpoBackupID    = $confXML.n.Admin.GPOs.INFRAT0baseline.backupID
                gpoBackupPath  = $SecTmplPath
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating T0 Infrastructure Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1Ou.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT1Ou.Name, $ItInfraOuDn)
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating T1 Infrastructure Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2Ou.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT2Ou.Name, $ItInfraOuDn)
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating T2 Infrastructure Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name, $ItInfraOuDn)
                gpoBackupID    = $confXML.n.Admin.GPOs.INFRAStagingBaseline.backupID
                gpoBackupPath  = $SecTmplPath
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Infrastructure Staging Baseline' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat @Splat1

            # redirected containers (X-Computers & X-Users)
            $Splat = @{
                gpoDescription = ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItNewComputersOU.Name)
                gpoScope       = 'C'
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItNewComputersOU.Name, $Variables.AdDn)
                GpoAdmin       = $sl_GpoAdminRight
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating New Computers Lockdown' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat

            $Splat = @{
                gpoDescription = ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItNewUsersOU.Name)
                gpoScope       = 'U'
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItNewUsersOU.Name, $Variables.AdDn)
                GpoAdmin       = $sl_GpoAdminRight
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating New Users Lockdown' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo @Splat

            # Housekeeping
            $Splat = @{
                gpoDescription = ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItHousekeepingOU.Name)
                gpoLinkPath    = $ItHousekeepingOuDn
                GpoAdmin       = $sl_GpoAdminRight
            }
            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Housekeeping User Lockdown' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo -gpoScope 'U' @Splat

            $CurrentStep++
            $ProgressSplat.Status = 'Step {0} of {1}: Creating Housekeeping Computer Lockdown' -f $CurrentStep, $TotalSteps
            $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            Write-Progress @ProgressSplat
            New-DelegateAdGpo -gpoScope 'C' @Splat


            ###############################################################################
            # Import GPO from Archive

            #Import the Default Domain Policy
            If ($confXML.n.Admin.GPOs.DefaultDomain.backupID) {
                $splat = @{
                    BackupId   = $confXML.n.Admin.GPOs.DefaultDomain.backupID
                    TargetName = $confXML.n.Admin.GPOs.DefaultDomain.Name
                    path       = $SecTmplPath
                }
                $CurrentStep++
                $ProgressSplat.Status = 'Step {0} of {1}: Importing Default Domain Policy' -f $CurrentStep, $TotalSteps
                $ProgressSplat.PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                Write-Progress @ProgressSplat
                Import-GPO @splat
            }

            # Complete the progress bar
            $ProgressSplat.Status = 'Completed'
            Write-Progress @ProgressSplat -Completed

        } #end If ShouldProcess

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Create Baseline GPOs.'
            )
            Write-Verbose -Message $txt
        } #end If

        # Stop transcript if it was started
        if ($EnableTranscript) {
            try {
                Stop-Transcript -ErrorAction Stop
                Write-Verbose -Message 'Transcript stopped successfully'
            } catch {
                Write-Warning -Message ('Failed to stop transcript: {0}' -f $_.Exception.Message)
            } #end Try-Catch
        } #end If

    } #end End
} #end Function New-Tier0Gpo
