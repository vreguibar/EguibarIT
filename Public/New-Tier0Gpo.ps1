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

        .PARAMETER DMscripts
            Path to all the scripts and files needed by this function. This directory must contain a 'SecTmpl'
            subfolder with the GPO backup files.

            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0Gpo -ConfigXMLFile 'C:\PsScripts\Config.xml' -DMscripts 'C:\PsScripts'

            Creates and configures all Tier 0 GPOs using the specified configuration file and scripts directory.

        .EXAMPLE
            New-Tier0Gpo -ConfigXMLFile 'C:\Custom\Configuration.xml' -DMscripts 'D:\Scripts' -Verbose

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
        [ValidateScript({
                if (-not (Test-Path -Path $_ -PathType Container)) {
                    throw ('Directory not found: {0}' -f $_)
                }
                if (-not (Test-Path -Path (Join-Path -Path $_ -ChildPath 'SecTmpl'))) {
                    throw ('SecTmpl subfolder not found in: {0}' -f $_)
                }
                return $true
            })]
        [PSDefaultValue(
            Help = 'Default Value is "C:\PsScripts\"',
            value = 'C:\PsScripts\'
        )]
        [Alias('ScriptPath')]
        [System.IO.DirectoryInfo]
        $DMscripts

    )

    Begin {
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
        # Module imports

        Import-MyModule -Name 'ServerManager' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

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

        $GpoAdminRight = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.name

        if ($null -ne $sl_GpoAdminRight) {
            $sl_GpoAdminRight = Get-AdObjectType -Identity $GpoAdminRight
        } #end If

        # Build OU paths using string format for consistency
        [string]$ItAdminOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminOU.name, $Variables.AdDn)
        [string]$ItAdminAccountsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminAccountsOU.name, $ItAdminOuDn)
        [string]$ItServiceAccountsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name, $ItAdminOuDn)
        [string]$ItPawOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)
        [string]$ItInfraOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)
        [string]$ItHousekeepingOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItHousekeepingOU.name, $ItAdminOuDn)

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Group Policy Objects', 'Create Baseline GPOs')) {

            # Domain
            $Splat = @{
                gpoDescription = 'Baseline'
                gpoLinkPath    = $Variables.AdDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat -gpoScope 'C' -gpoBackupID $confXML.n.Admin.GPOs.PCbaseline.backupID
            New-DelegateAdGpo @Splat -gpoScope 'U' -gpoBackupID $confXML.n.Admin.GPOs.Userbaseline.backupID

            # Domain Controllers
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Name
                gpoScope       = $confXML.n.Admin.GPOs.DCBaseline.Scope
                gpoLinkPath    = 'OU=Domain Controllers,{0}' -f $Variables.AdDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupId    = $confXML.n.Admin.GPOs.DCBaseline.backupID
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat

            # Admin Area
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.GPOs.Adminbaseline.Name
                gpoLinkPath    = $ItAdminOuDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo -gpoScope 'C' @Splat
            New-DelegateAdGpo -gpoScope 'U' @Splat

            # Users
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.OUs.ItAdminAccountsOU.Name
                gpoScope       = 'U'
                gpoLinkPath    = $ItAdminAccountsOuDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupId    = $confXML.n.Admin.GPOs.AdminUserbaseline.backupID
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
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
            New-DelegateAdGpo @Splat @Splat1
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT0OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.Name, $ItServiceAccountsOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT1OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT1OU.Name, $ItServiceAccountsOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT2OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT2OU.Name, $ItServiceAccountsOuDn)
            }
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
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT0OU.Name, $ItPawOuDn)
                gpoBackupID    = $confXML.n.Admin.GPOs.PawT0baseline.backupID
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT1OU.Name, $ItPawOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT2OU.Name, $ItPawOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name, $ItPawOuDn)
                gpoBackupID    = $confXML.n.Admin.GPOs.PawStagingbaseline.backupID
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
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
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0Ou.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT0Ou.Name, $ItInfraOuDn)
                gpoBackupID    = $confXML.n.Admin.GPOs.INFRAT0baseline.backupID
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1Ou.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT1Ou.Name, $ItInfraOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2Ou.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT2Ou.Name, $ItInfraOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name, $ItInfraOuDn)
                gpoBackupID    = $confXML.n.Admin.GPOs.INFRAStagingBaseline.backupID
                gpoBackupPath  = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat @Splat1

            # redirected containers (X-Computers & X-Users)
            $Splat = @{
                gpoDescription = ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItNewComputersOU.Name)
                gpoScope       = 'C'
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItNewComputersOU.Name, $Variables.AdDn)
                GpoAdmin       = $sl_GpoAdminRight
            }
            New-DelegateAdGpo @Splat
            $Splat = @{
                gpoDescription = ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItNewUsersOU.Name)
                gpoScope       = 'U'
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItNewUsersOU.Name, $Variables.AdDn)
                GpoAdmin       = $sl_GpoAdminRight
            }
            New-DelegateAdGpo @Splat

            # Housekeeping
            $Splat = @{
                gpoDescription = ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItHousekeepingOU.Name)
                gpoLinkPath    = $ItHousekeepingOuDn
                GpoAdmin       = $sl_GpoAdminRight
            }
            New-DelegateAdGpo -gpoScope 'U' @Splat
            New-DelegateAdGpo -gpoScope 'C' @Splat


            ###############################################################################
            # Import GPO from Archive

            #Import the Default Domain Policy
            If ($confXML.n.Admin.GPOs.DefaultDomain.backupID) {
                $splat = @{
                    BackupId   = $confXML.n.Admin.GPOs.DefaultDomain.backupID
                    TargetName = $confXML.n.Admin.GPOs.DefaultDomain.Name
                    path       = Join-Path -Path $PSBoundParameters['DMscripts'] -ChildPath 'SecTmpl' -Resolve
                }
                Import-GPO @splat
            }

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
    } #end End
} #end Function New-Tier0Gpo
