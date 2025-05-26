function New-Tier0Delegation {

    <#
        .SYNOPSIS
            Delegates rights and permissions to the Tier0 Admin area.

        .DESCRIPTION
            This function applies delegation permissions for administrative groups within the Tier0
            administrative area, following a tiered administration model and principle of least privilege.
            It configures access control lists (ACLs) for various security functions including:
            - User Management (UM - Semi-Privileged User Management)
            - Group Management (GM - Semi-Privileged Group Management)
            - Privileged User Management (PUM)
            - Privileged Group Management (PGM)
            - Server Admin Groups Management (SAGM)
            - Privileged Infrastructure Services Management (PISM)
            - Privileged Access Workstation Management (PAWM)
            - Domain Controller Management (DCManagement)
            - Privileged Service Account Management (PSAM)
            - GPO Administration
            - Directory Replication
            - Infrastructure Administration
            - FSMO Role Transfer
            - AD Administration

            This function is critical for implementing proper security boundaries in a tiered
            administrative model.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            [String] Path to all the scripts and files needed by this function.
            Should contain a SecTmpl subfolder.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0Delegation -ConfigXMLFile C:\PsScripts\Config.xml

            Delegates rights and permissions to the Tier0 Admin area using the default configuration file.

        .EXAMPLE
            $Splat = @{
                ConfigXMLFile = 'C:\CustomPath\Config.xml'
                DMScripts = 'D:\Scripts\'
                Verbose = $true
            }
            New-Tier0Delegation @Splat

            Delegates rights and permissions to the Tier0 Admin area with custom paths and verbose output.

        .INPUTS
            [System.IO.FileInfo]
            You can pipe the path to the XML configuration file to this function.

        .OUTPUTS
            [System.String]
            Returns completion status message.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Set-StrictMode                             ║ Microsoft.PowerShell.Core
                Import-MyModule                            ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT
                Get-Content                                ║ Microsoft.PowerShell.Management
                Get-AdObjectType                           ║ EguibarIT
                Set-AdAclDelegateUserAdmin                 ║ EguibarIT.DelegationPS
                Set-AdAclDelegateGalAdmin                  ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGroup                 ║ EguibarIT.DelegationPS
                Set-AdAclChangeGroup                       ║ EguibarIT.DelegationPS
                Set-AdAclDelegateComputerAdmin             ║ EguibarIT.DelegationPS
                Add-GroupToSCManager                       ║ EguibarIT.DelegationPS
                Add-ServiceAcl                             ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGMSA                  ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteMSA                   ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteUser                  ║ EguibarIT.DelegationPS
                Set-AdAclResetUserPassword                 ║ EguibarIT.DelegationPS
                Set-AdAclChangeUserPassword                ║ EguibarIT.DelegationPS
                Set-AdAclUserGroupMembership               ║ EguibarIT.DelegationPS
                Set-AdAclUserAccountRestriction            ║ EguibarIT.DelegationPS
                Set-AdAclUserLogonInfo                     ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGPO                   ║ EguibarIT.DelegationPS
                Set-AdAclLinkGPO                           ║ EguibarIT.DelegationPS
                Set-AdAclGPoption                          ║ EguibarIT.DelegationPS
                Set-AdDirectoryReplication                 ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteOU                    ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteSubnet                ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteSite                  ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteSiteLink              ║ EguibarIT.DelegationPS
                Set-AdAclFMSOtransfer                      ║ EguibarIT.DelegationPS
                Set-DeleteOnlyComputer                     ║ EguibarIT.DelegationPS
                Set-AdAclChangeSubnet                      ║ EguibarIT.DelegationPS
                Set-AdAclChangeSite                        ║ EguibarIT.DelegationPS
                Set-AdAclChangeSiteLink                    ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Get-Service                                ║ Microsoft.PowerShell.Management

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

        .ROLE
            Security

        .FUNCTIONALITY
            Tier 0 Delegation
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
                        $null -eq $xml.n.Admin.OUs) {
                        throw 'XML file is missing required elements (Admin or OUs section)'
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
            $TranscriptFile = Join-Path -Path $DMScripts -ChildPath ('{0}_{1}.LOG' -f $MyInvocation.MyCommand.Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))

            try {
                Start-Transcript -Path $TranscriptFile -Force -ErrorAction Stop
                Write-Verbose -Message ('Transcript started: {0}' -f $TranscriptFile)
            } catch {
                Write-Warning -Message ('Failed to start transcript: {0}' -f $_.Exception.Message)
            } #end try-catch
        } #end if

        # Display function header if variables exist
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

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        #[System.Collections.ArrayList]$ArrayList = [System.Collections.ArrayList]::new()
        [System.Collections.Generic.List[object]]$ArrayList = [System.Collections.Generic.List[object]]::New()

        # Load the XML configuration file
        try {
            [xml]$confXML = [xml](Get-Content -Path $PSBoundParameters['ConfigXMLFile'] -ErrorAction Stop)
            Write-Verbose -Message ('Successfully loaded configuration from {0}' -f $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        # Naming conventions hashtable
        $NC = @{'sl' = $confXML.n.NC.LocalDomainGroupPreffix
            'sg'     = $confXML.n.NC.GlobalGroupPreffix
            'su'     = $confXML.n.NC.UniversalGroupPreffix
            'Delim'  = $confXML.n.NC.Delimiter
            'T0'     = $confXML.n.NC.AdminAccSufix0
            'T1'     = $confXML.n.NC.AdminAccSufix1
            'T2'     = $confXML.n.NC.AdminAccSufix2
        }
        # For example :
        # ('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM.name, $NC['T0'])
        # Returns: SG_PAWM_T0

        #region Local groups Variables
        $SL_UM = Get-SafeVariable -Name 'SL_UM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.UM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GM = Get-SafeVariable -Name 'SL_GM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PUM = Get-SafeVariable -Name 'SL_PUM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PUM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PGM = Get-SafeVariable -Name 'SL_PGM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PGM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_SAGM = Get-SafeVariable -Name 'SL_SAGM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.SAGM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PISM = Get-SafeVariable -Name 'SL_PISM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PISM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PAWM = Get-SafeVariable -Name 'SL_PAWM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PAWM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_DcManagement = Get-SafeVariable -Name 'SL_DcManagement' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.DcManagement.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PSAM = Get-SafeVariable -Name 'SL_PSAM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PSAM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GpoAdminRight = Get-SafeVariable -Name 'SL_GpoAdminRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_DirReplRight = Get-SafeVariable -Name 'SL_DirReplRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.DirReplRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_InfraRight = Get-SafeVariable -Name 'SL_InfraRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_TransferFSMOright = Get-SafeVariable -Name 'SL_TransferFSMOright' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.TransferFSMOright.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_AdRight = Get-SafeVariable -Name 'SL_AdRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.AdRight.Name)
            Get-AdObjectType -Identity $groupName
        }
        #endregion Local groups Variables

        $AllLocalGroupVariables = @(
            $SL_UM,
            $SL_GM,
            $SL_PUM,
            $SL_PGM,
            $SL_SAGM,
            $SL_PISM,
            $SL_PAWM,
            $SL_DcManagement,
            $SL_PSAM,
            $SL_GpoAdminRight,
            $SL_DirReplRight,
            $SL_InfraRight,
            $SL_TransferFSMOright,
            $SL_AdRight
        )
        foreach ($Item in $AllLocalGroupVariables) {
            if ($null -ne $Item) {
                [void]$ArrayList.Add($Item)
            } else {
                Write-Error -Message ('Group not found: {0}' -f $Item)
            } #end If GroupName
        } #end ForEach

        # Build OU paths using string format for consistency
        [string]$ItAdminOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminOU.name, $Variables.AdDn)
        [string]$ItAdminAccountsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminAccountsOU.name, $ItAdminOuDn)
        [string]$ItAdminGroupsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminGroupsOU.name, $ItAdminOuDn)
        [string]$ItPrivGroupsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItPrivGroupsOU.name, $ItAdminOuDn)
        [string]$ItRightsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItRightsOU.name, $ItAdminOuDn)
        [string]$ItAdminSrvGroupsOUDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminSrvGroupsOU.name, $ItAdminOuDn)

        [string]$ItInfraT0OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItInfraT0OU.name, $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)
        [string]$ItInfraT1OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItInfraT1OU.name, $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)
        [string]$ItInfraT2OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItInfraT2OU.name, $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)
        [string]$ItInfraStagingOuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItInfraStagingOU.name, $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)

        [string]$ItPawT0OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItPawT0OU.name, $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)
        [string]$ItPawT1OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItPawT1OU.name, $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)
        [string]$ItPawT2OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItPawT2OU.name, $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)
        [string]$ItPawStagingOuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItPawStagingOU.name, $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)

        [string]$DCsOuDn = ('OU=Domain Controllers,{0}' -f $Variables.AdDn)
        [string]$ItQuarantinePcOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItNewComputersOU.name, $Variables.AdDn)

        [string]$ItSAT0OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItSAT0OU.name, $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name, $ItAdminOuDn)
        [string]$ItSAT1OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItSAT1OU.name, $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name, $ItAdminOuDn)
        [string]$ItSAT2OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItSAT2OU.name, $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name, $ItAdminOuDn)

        Write-Verbose -Message 'Starting the Tier0 delegation process...'
    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Active Directory Security', 'Delegate Rights and Permissions to Tier0 Admin area')) {

            # Define progress variables
            [int]$CurrentStep = 0
            [int]$TotalSteps = 15 # Total number of major delegation tasks
            [string]$ProgressActivity = 'Delegating permissions to Tier0 Admin area'
            [string]$CurrentOperation = ''

            # Computer objects within this area MUST have read access, otherwise GPO will not apply

            # UM - Semi-Privileged User Management
            $CurrentStep++
            $CurrentOperation = 'Configuring User Management (UM) permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            Set-AdAclDelegateUserAdmin -Group $SL_UM -LDAPpath $ItAdminAccountsOuDn
            Set-AdAclDelegateGalAdmin -Group $SL_UM -LDAPpath $ItAdminAccountsOuDn



            # GM - Semi-Privileged Group Management
            $CurrentStep++
            $CurrentOperation = 'Configuring Group Management (GM) permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            Set-AdAclCreateDeleteGroup -Group $SL_GM -LDAPpath $ItAdminGroupsOuDn
            Set-AdAclChangeGroup -Group $SL_GM -LDAPpath $ItAdminGroupsOuDn



            # PUM - Privileged User Management
            $CurrentStep++
            $CurrentOperation = 'Configuring Privileged User Management (PUM) permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            Set-AdAclDelegateUserAdmin -Group $SL_PUM -LDAPpath $ItAdminAccountsOuDn
            Set-AdAclDelegateGalAdmin -Group $SL_PUM -LDAPpath $ItAdminAccountsOuDn



            # PGM - Privileged Group Management
            $CurrentStep++
            $CurrentOperation = 'Configuring Privileged Group Management (PGM) permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            # Create/Delete Groups
            Set-AdAclCreateDeleteGroup -Group $SL_PGM -LDAPpath $ItPrivGroupsOUDn
            Set-AdAclCreateDeleteGroup -Group $SL_PGM -LDAPpath $ItRightsOuDn
            # Change Group Properties
            Set-AdAclChangeGroup -Group $SL_PGM -LDAPpath $ItPrivGroupsOUDn
            Set-AdAclChangeGroup -Group $SL_PGM -LDAPpath $ItRightsOuDn




            # Local Admin groups management
            $CurrentStep++
            $CurrentOperation = 'Configuring Server Admin Groups Management (SAGM) permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            # Create/Delete Groups
            Set-AdAclCreateDeleteGroup -Group $SL_SAGM -LDAPpath $ItAdminSrvGroupsOUDn
            # Change Group Properties
            Set-AdAclChangeGroup -Group $SL_SAGM -LDAPpath $ItAdminSrvGroupsOUDn



            # PISM - Privileged Infrastructure Services Management
            $CurrentStep++
            $CurrentOperation = 'Configuring Privileged Infrastructure Services Management (PISM) permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            # Create/Delete Computers
            Set-AdAclDelegateComputerAdmin -Group $SL_PISM -LDAPpath $ItInfraT0OuDn
            Set-AdAclDelegateComputerAdmin -Group $SL_PISM -LDAPpath $ItInfraT1OuDn
            Set-AdAclDelegateComputerAdmin -Group $SL_PISM -LDAPpath $ItInfraT2OuDn
            Set-AdAclDelegateComputerAdmin -Group $SL_PISM -LDAPpath $ItInfraStagingOuDn



            # PAWM - Privileged Access Workstation Management
            $CurrentStep++
            $CurrentOperation = 'Configuring Privileged Access Workstation Management (PAWM) permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            Set-AdAclDelegateComputerAdmin -Group $SL_PAWM -LDAPpath $ItPawT0OuDn
            Set-AdAclDelegateComputerAdmin -Group $SL_PAWM -LDAPpath $ItPawT1OuDn
            Set-AdAclDelegateComputerAdmin -Group $SL_PAWM -LDAPpath $ItPawT2OuDn
            Set-AdAclDelegateComputerAdmin -Group $SL_PAWM -LDAPpath $ItPawStagingOuDn



            # DC_Management - Domain Controllers Management
            $CurrentStep++
            $CurrentOperation = 'Configuring Domain Controller Management (DCM) permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat
            Set-AdAclDelegateComputerAdmin -Group $SL_DcManagement -LDAPpath $DCsOuDn

            # DC_Management - Service Control Management (Permission to services)
            Add-GroupToSCManager -Group $SL_DcManagement -verbose

            # DC_Management - Service permissions
            $CurrentStep++
            $CurrentOperation = 'Configuring service permissions for DC Management'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            # Get all services
            $AllServices = Get-Service -ErrorAction SilentlyContinue
            $ServiceCount = $AllServices.Count
            $ServiceIndex = 0

            Foreach ($item in $AllServices) {
                $ServiceIndex++
                # Update nested progress for service permissions
                $NestedProgressSplat = @{
                    Id              = 1
                    Activity        = 'Configuring service permissions'
                    Status          = ('Service {0}/{1}: {2}' -f $ServiceIndex, $ServiceCount, $item.Name)
                    PercentComplete = (($ServiceIndex / $ServiceCount) * 100)
                }
                Write-Progress @NestedProgressSplat

                # ToDo: Error due Access Denied.
                #Add-ServiceAcl -Group $SL_DcManagement -Service $Item.Name -verbose

            } #end Foreach service

            # Complete the nested progress bar
            Write-Progress -Id 1 -Activity 'Configuring service permissions' -Completed


            # PSAM - Privileged Service Account Management
            $CurrentStep++
            $CurrentOperation = 'Configuring Privileged Service Account Management (PSAM) permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            # Managed Service Accounts "Default Container"
            $Splat = @{
                Group    = $SL_PSAM
                LDAPPath = ('CN=Managed Service Accounts,{0}' -f $Variables.AdDn)
            }
            Set-AdAclCreateDeleteGMSA @Splat
            Set-AdAclCreateDeleteMSA @Splat

            # TIER 0
            $Splat = @{
                Group    = $SL_PSAM
                LDAPPath = $ItSAT0OuDn
            }
            Set-AdAclCreateDeleteGMSA @Splat
            Set-AdAclCreateDeleteMSA @Splat
            Set-AdAclCreateDeleteUser @Splat
            Set-AdAclResetUserPassword @Splat
            Set-AdAclChangeUserPassword @Splat
            Set-AdAclUserGroupMembership @Splat
            Set-AdAclUserAccountRestriction @Splat
            Set-AdAclUserLogonInfo @Splat

            # TIER 1
            $Splat = @{
                Group    = $SL_PSAM
                LDAPPath = $ItSAT1OuDn
            }
            Set-AdAclCreateDeleteGMSA @Splat
            Set-AdAclCreateDeleteMSA @Splat
            Set-AdAclCreateDeleteUser @Splat
            Set-AdAclResetUserPassword @Splat
            Set-AdAclChangeUserPassword @Splat
            Set-AdAclUserGroupMembership @Splat
            Set-AdAclUserAccountRestriction @Splat
            Set-AdAclUserLogonInfo @Splat

            # TIER 2
            $Splat = @{
                Group    = $SL_PSAM
                LDAPPath = $ItSAT2OuDn
            }
            Set-AdAclCreateDeleteGMSA @Splat
            Set-AdAclCreateDeleteMSA @Splat
            Set-AdAclCreateDeleteUser @Splat
            Set-AdAclResetUserPassword @Splat
            Set-AdAclChangeUserPassword @Splat
            Set-AdAclUserGroupMembership @Splat
            Set-AdAclUserAccountRestriction @Splat
            Set-AdAclUserLogonInfo @Splat




            # GPO Admins
            $CurrentStep++
            $CurrentOperation = 'Configuring GPO Admin permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            # Create/Delete GPOs
            Set-AdAclCreateDeleteGPO -Group $SL_GpoAdminRight -Confirm:$false
            # Link existing GPOs to OUs
            Set-AdAclLinkGPO -Group $SL_GpoAdminRight
            # Change GPO options
            Set-AdAclGPoption -Group $SL_GpoAdminRight


            # Directory Replication Rights
            $CurrentStep++
            $CurrentOperation = 'Configuring Directory Replication Rights'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            # Delegate Directory Replication Rights
            # ToDo: 'Error while trying to change Directory Replication Rights. Access denied.'
            #Set-AdDirectoryReplication -Group $SL_DirReplRight -Confirm:$false




            # Infrastructure Admins
            $CurrentStep++
            $CurrentOperation = 'Configuring Infrastructure Admin permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            # Organizational Units at domain level
            Set-AdAclCreateDeleteOU -Group $SL_InfraRight -LDAPpath $Variables.AdDn
            # Organizational Units at Admin area
            Set-AdAclCreateDeleteOU -Group $SL_InfraRight -LDAPpath $ItAdminOuDn
            # Subnet Configuration Container
            # Create/Delete Subnet
            Set-AdAclCreateDeleteSubnet -Group $SL_InfraRight
            # Site Configuration Container
            # Create/Delete Sites
            Set-AdAclCreateDeleteSite -Group $SL_InfraRight
            # Site-Link Configuration Container
            # Create/Delete Site-Link
            Set-AdAclCreateDeleteSiteLink -Group $SL_InfraRight

            # Transfer FSMO roles
            $CurrentStep++
            $CurrentOperation = 'Configuring FSMO Role Transfer permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            $Splat = @{
                Group     = $SL_TransferFSMOright
                FSMOroles = 'Schema', 'Infrastructure', 'DomainNaming', 'RID', 'PDC'
                Confirm   = $false
            }
            Set-AdAclFMSOtransfer @Splat




            # AD Admins
            $CurrentStep++
            $CurrentOperation = 'Configuring AD Admin permissions'
            $ProgressSplat = @{
                Activity        = $ProgressActivity
                Status          = ('{0}/{1} - {2}' -f $CurrentStep, $TotalSteps, $CurrentOperation)
                PercentComplete = (($CurrentStep / $TotalSteps) * 100)
            }
            Write-Progress @ProgressSplat

            # Domain Controllers management
            Set-AdAclDelegateComputerAdmin -Group $SL_AdRight -LDAPpath $DCsOuDn
            # Delete computers from default container
            Set-DeleteOnlyComputer -Group $SL_AdRight -LDAPpath $ItQuarantinePcOuDn
            # Subnet Configuration Container|
            # Change Subnet
            Set-AdAclChangeSubnet -Group $SL_AdRight
            # Site Configuration Container
            # Change Site
            Set-AdAclChangeSite -Group $SL_AdRight
            # Site-Link Configuration Container
            # Change SiteLink
            Set-AdAclChangeSiteLink -Group $SL_AdRight

            # Complete the progress bar
            Write-Progress -Activity $ProgressActivity -Completed

        } #end If ShouldProcess

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Delegate Rights and Permissions to Tier0 Admin area.'
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
} #end Function New-Tier0Delegation
