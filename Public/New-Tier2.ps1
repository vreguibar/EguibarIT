function New-Tier2 {

    <#
        .SYNOPSIS
            Creates Tier2 infrastructure including OUs, GPOs and delegations

        .DESCRIPTION
            Creates the Tier2 infrastructure, including all necessary Organizational Units (OUs),
            Group Policy Objects (GPOs), and delegations based on the configuration XML file.
            This function follows the tiered administrative model for Active Directory security.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            Path to all the scripts and files needed by this function.
            Default: C:\PsScripts\

        .PARAMETER EnableTranscript
            Start transcript logging to DMScripts path with function name

        .EXAMPLE
            New-Tier2 -ConfigXMLFile C:\PsScripts\Config.xml
            Creates the Tier2 infrastructure using the specified configuration file

        .EXAMPLE
            New-Tier2 -ConfigXMLFile C:\PsScripts\Config.xml -EnableTranscript
            Creates the Tier2 infrastructure with transcript logging enabled

        .INPUTS
            System.IO.FileInfo, System.String, System.Switch

        .OUTPUTS
            System.String

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ADUser                                 ║ ActiveDirectory
                Get-ADGroup                                ║ ActiveDirectory
                Get-AdObjectType                           ║ EguibarIT
                Get-SafeVariable                           ║ EguibarIT
                Import-MyModule                            ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT
                New-DelegateAdOU                           ║ EguibarIT.DelegationPS
                New-DelegateAdGpo                          ║ EguibarIT.DelegationPS
                Set-GpoPrivilegeRight                      ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteOU                    ║ EguibarIT.DelegationPS
                Set-AdAclChangeOU                          ║ EguibarIT.DelegationPS
                Set-AdAclDelegateUserAdmin                 ║ EguibarIT.DelegationPS
                Set-AdAclDelegateGalAdmin                  ║ EguibarIT.DelegationPS
                Add-AdGroupNesting                         ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGroup                 ║ EguibarIT.DelegationPS
                Set-AdAclChangeGroup                       ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Progress                             ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.0
            DateModified:    9/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                        vicente@eguibar.com
                        Eguibar IT
                        http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Active Directory

        .ROLE
            Infrastructure, Security

        .FUNCTIONALITY
            Tier Model, AD Delegation, Security
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
                    if ($null -eq $xml.n.Admin -or
                        $null -eq $xml.n.Sites -or
                        $null -eq $xml.n.NC) {
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
        [System.Collections.Generic.List[object]]$ArrayList = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$DenyLogon = [System.Collections.Generic.List[object]]::New()

        # Progress bar variables
        [hashtable]$ProgressParams = @{
            Activity         = 'Creating Tier2 Infrastructure'
            Status           = 'Initializing'
            PercentComplete  = 0
            CurrentOperation = 'Loading configuration'
        }
        Write-Progress @ProgressParams

        # Phases to track progress
        [string[]]$ProgressPhases = @(
            'Loading Configuration',
            'Creating Tier2 Organizational Units',
            'Creating Tier2 Baseline GPOs',
            'Creating Tier2 GPO Restrictions',
            'Creating Tier2 Delegations'
        )
        [int]$PhaseCount = $ProgressPhases.Count
        [int]$CurrentPhase = 0



        # Update progress to show we're loading configuration
        $CurrentPhase++
        $ProgressParams['Status'] = $ProgressPhases[$CurrentPhase - 1]
        $ProgressParams['PercentComplete'] = [math]::Min([int](($CurrentPhase / $PhaseCount) * 100), 100)
        Write-Progress @ProgressParams

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

        #region Users Variables
        $AdminName = Get-SafeVariable -Name 'AdminName' -CreateIfNotExist {
            try {
                Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Administrator: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $NewAdminExists = Get-SafeVariable -Name 'NewAdminExists' -CreateIfNotExist {
            $newAdminName = $confXML.n.Admin.users.NEWAdmin.Name
            if (-not [string]::IsNullOrEmpty($newAdminName)) {
                Get-AdObjectType -Identity $newAdminName
            } else {
                $null
            }
        }
        #endregion Users Variables

        #region Well-Known groups Variables
        $Administrators = Get-SafeVariable -Name 'Administrators' -CreateIfNotExist {
            try {
                Get-ADGroup -Identity 'S-1-5-32-544'
            } catch {
                Write-Debug -Message ('Failed to retrieve Administrators group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $DomainAdmins = Get-SafeVariable -Name 'DomainAdmins' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-512' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Domain Admins group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $EnterpriseAdmins = Get-SafeVariable -Name 'EnterpriseAdmins' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-519' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Enterprise Admins group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $SchemaAdmins = Get-SafeVariable -Name 'SchemaAdmins' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-518' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Schema Admins group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $AccountOperators = Get-SafeVariable -Name 'AccountOperators' -CreateIfNotExist {
            try {
                Get-ADGroup -Identity 'S-1-5-32-548'
            } catch {
                Write-Debug -Message ('Failed to retrieve Account Operators group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $BackupOperators = Get-SafeVariable -Name 'BackupOperators' -CreateIfNotExist {
            try {
                Get-ADGroup -Identity 'S-1-5-32-551'
            } catch {
                Write-Debug -Message ('Failed to retrieve Backup Operators group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $PrintOperators = Get-SafeVariable -Name 'PrintOperators' -CreateIfNotExist {
            try {
                Get-ADGroup -Identity 'S-1-5-32-550'
            } catch {
                Write-Debug -Message ('Failed to retrieve Print Operators group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $ServerOperators = Get-SafeVariable -Name 'ServerOperators' -CreateIfNotExist {
            try {
                Get-ADGroup -Identity 'S-1-5-32-549'
            } catch {
                Write-Debug -Message ('Failed to retrieve Server Operators group: {0}' -f $_.Exception.Message)
                $null
            }
        }
        #endregion Well-Known groups Variables

        #region Global groups Variables
        # ToDo: the GetSafeVariable is finding the variable, but variable has old DN. Interim fix filling the variable again
        $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name)
        $SG_Tier0ServiceAccount = Get-AdObjectType -Identity $groupName


        # ToDo: the GetSafeVariable is finding the variable, but variable has old DN. Interim fix filling the variable again
        $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name)
        $SG_Tier1ServiceAccount = Get-AdObjectType -Identity $groupName

        # ToDo: the GetSafeVariable is finding the variable, but variable has old DN. Interim fix filling the variable again
        $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name)
        $SG_Tier2ServiceAccount = Get-AdObjectType -Identity $groupName

        $SG_Tier0Admins = Get-SafeVariable -Name 'SG_Tier0Admins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_Tier1Admins = Get-SafeVariable -Name 'SG_Tier1Admins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_Tier2Admins = Get-SafeVariable -Name 'SG_Tier2Admins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_GlobalGroupAdmins = Get-SafeVariable -Name 'SG_GlobalGroupAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalGroupAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }
        #endregion Global groups Variables

        #region Local groups Variables
        $SL_GpoAdminRight = Get-SafeVariable -Name 'SL_GpoAdminRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_AdRight = Get-SafeVariable -Name 'SL_AdRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.AdRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_InfraRight = Get-SafeVariable -Name 'SL_InfraRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GlobalAppAccUserRight = Get-SafeVariable -Name 'SL_GlobalAppAccUserRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GlobalAppAccUserRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GlobalGroupRight = Get-SafeVariable -Name 'SL_GlobalGroupRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GlobalGroupRight.Name)
            Get-AdObjectType -Identity $groupName
        }
        #endregion Local groups Variables

        [String]$SitesOu = $confXML.n.Sites.OUs.SitesOU.Name
        [string]$SitesGlobalOu = $confXML.n.Sites.OUs.OuSiteGlobal.Name
        [string]$SitesGlobalGroupOu = $confXML.n.Sites.OUs.OuSiteGlobalGroups.Name
        [string]$SitesGlobalAppAccUserOu = $confXML.n.Sites.OUs.OuSiteGlobalAppAccessUsers.Name

        [String]$SitesOuDn = ('OU={0},{1}' -f $SitesOu, $Variables.AdDn)
        [string]$SitesGlobalOuDn = ('OU={0},{1}' -f $SitesGlobalOu, $SitesOuDn)
        [string]$SitesGlobalAppAccUserOuDn = ('OU={0},{1}' -f $SitesGlobalAppAccUserOu, $SitesGlobalOuDn)
        [string]$SitesGlobalGroupOuDn = ('OU={0},{1}' -f $SitesGlobalGroupOu, $SitesGlobalOuDn)

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Create Tier2 Organizational Units')) {

            # Update progress to show we're creating OUs
            $CurrentPhase++
            $ProgressParams['Status'] = $ProgressPhases[$CurrentPhase - 1]
            $ProgressParams['PercentComplete'] = [math]::Min([int](($CurrentPhase / $PhaseCount) * 100), 100)
            $ProgressParams['CurrentOperation'] = 'Creating base OUs'
            Write-Progress @ProgressParams

            New-DelegateAdOU -ouName $SitesOu -ouPath $Variables.AdDn -ouDescription $confXML.n.Sites.OUs.SitesOU.Description

            # Create Global OU within SITES area
            $Splat = @{
                ouName        = $SitesGlobalOu
                ouPath        = $SitesOuDn
                ouDescription = $confXML.n.Sites.OUs.OuSiteGlobal.Description
            }
            New-DelegateAdOU @Splat

            $ProgressParams['CurrentOperation'] = 'Creating sub-OUs'
            Write-Progress @ProgressParams

            $Splat = @{
                ouName        = $SitesGlobalGroupOu
                ouPath        = $SitesGlobalOuDn
                ouDescription = $confXML.n.Sites.OUs.OuSiteGlobalGroups.Description
            }
            New-DelegateAdOU @Splat

            $Splat = @{
                ouName        = $SitesGlobalAppAccUserOu
                ouPath        = $SitesGlobalOuDn
                ouDescription = $confXML.n.Sites.OUs.OuSiteGlobalAppAccessUsers.Description
            }
            New-DelegateAdOU @Splat

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier2 Baseline GPOs')) {

            # Update progress to show we're creating GPOs
            $CurrentPhase++
            $ProgressParams['Status'] = $ProgressPhases[$CurrentPhase - 1]
            $ProgressParams['PercentComplete'] = [math]::Min([int](($CurrentPhase / $PhaseCount) * 100), 100)
            $ProgressParams['CurrentOperation'] = 'Creating baseline GPOs for computer and user objects'
            Write-Progress @ProgressParams

            # Create basic GPO for Users and Computers
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $SitesOu
                gpoLinkPath    = $SitesOuDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupPath  = Join-Path -Path $DMScripts -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat -gpoScope 'C' -gpoBackupID $confXML.n.Sites.OUs.OuSiteComputer.backupID
            New-DelegateAdGpo @Splat -gpoScope 'U' -gpoBackupID $confXML.n.Sites.OUs.OuSiteUser.backupID

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier2 GPO Restrictions')) {

            # Update progress to show we're configuring GPO restrictions
            $CurrentPhase++
            $ProgressParams['Status'] = $ProgressPhases[$CurrentPhase - 1]
            $ProgressParams['PercentComplete'] = [math]::Min([int](($CurrentPhase / $PhaseCount) * 100), 100)
            $ProgressParams['CurrentOperation'] = 'Configuring logon restrictions'
            Write-Progress @ProgressParams

            $DenyLogon.Clear()
            [void]$DenyLogon.Add($SchemaAdmins)
            [void]$DenyLogon.Add($EnterpriseAdmins)
            [void]$DenyLogon.Add($DomainAdmins)
            [void]$DenyLogon.Add($Administrators)
            [void]$DenyLogon.Add($AccountOperators)
            [void]$DenyLogon.Add($BackupOperators)
            [void]$DenyLogon.Add($PrintOperators)
            [void]$DenyLogon.Add($ServerOperators)
            if ($null -ne $AdminName) {
                [void]$DenyLogon.Add($AdminName)
            }
            if ($null -ne $NewAdminExists) {
                [void]$DenyLogon.Add($NewAdminExists)
            }
            if ($null -ne $SG_Tier0Admins) {
                [void]$DenyLogon.Add($SG_Tier0Admins)
            }
            if ($null -ne $SG_Tier1Admins) {
                [void]$DenyLogon.Add($SG_Tier1Admins)
            }

            $ProgressParams['CurrentOperation'] = 'Setting up privilege rights'
            Write-Progress @ProgressParams

            # Back up files and directories / Bypass traverse checking / Create Global Objects / Create symbolic links
            # Change System Time / Change Time Zone / Force shutdown from a remote system
            # Create Page File / Enable computer and user accounts to be trusted for delegation
            # Impersonate a client after authentication / Load and unload device drivers
            # Increase scheduling priority / Manage auditing and security log
            # Modify firmware environment values / Perform volume maintenance tasks
            # Profile single process / Profile system performance / Restore files and directories
            # Shut down the system / Take ownership of files or other objects
            $ArrayList.Clear()
            [void]$ArrayList.Add($Administrators)
            if ($null -ne $SG_Tier2Admins) {
                [void]$ArrayList.Add($SG_Tier2Admins)
            }
            $Splat = @{
                GpoToModify                = 'C-{0}-Baseline' -f $SitesOu
                DenyInteractiveLogon       = $DenyLogon
                DenyRemoteInteractiveLogon = $DenyLogon
                DenyBatchLogon             = @($SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount)
                DenyServiceLogon           = @($SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount)
                BatchLogon                 = $SG_Tier2ServiceAccount
                ServiceLogon               = $SG_Tier2ServiceAccount
                InteractiveLogon           = $SG_Tier2Admins
                RemoteInteractiveLogon     = $SG_Tier2Admins
                Backup                     = $ArrayList
                MachineAccount             = $ArrayList
                CreateGlobal               = @($ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE')
                Systemtime                 = @($ArrayList, 'LOCAL SERVICE')
                TimeZone                   = $ArrayList
                CreatePagefile             = $ArrayList
                CreateSymbolicLink         = $ArrayList
                RemoteShutDown             = $ArrayList
                Impersonate                = @($ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE')
                IncreaseBasePriority       = $ArrayList
                LoadDriver                 = $ArrayList
                AuditSecurity              = $ArrayList
                SystemEnvironment          = $ArrayList
                ManageVolume               = $ArrayList
                ProfileSingleProcess       = $ArrayList
                SystemProfile              = $ArrayList
                Restore                    = $ArrayList
                Shutdown                   = $ArrayList
                TakeOwnership              = $ArrayList
            }
            Set-GpoPrivilegeRight @Splat

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier2 Delegations')) {

            # Update progress to show we're setting up delegations
            $CurrentPhase++
            $ProgressParams['Status'] = $ProgressPhases[$CurrentPhase - 1]
            $ProgressParams['PercentComplete'] = [math]::Min([int](($CurrentPhase / $PhaseCount) * 100), 100)
            $ProgressParams['CurrentOperation'] = 'Setting up OU delegations'
            Write-Progress @ProgressParams

            # Sites OU
            # Create/Delete OUs within Sites
            Set-AdAclCreateDeleteOU -Group $SL_InfraRight -LDAPpath $SitesOuDn

            # Sites OU
            # Change OUs
            Set-AdAclChangeOU -Group $SL_AdRight -LDAPpath $SitesOuDn

            $ProgressParams['CurrentOperation'] = 'Setting up application access user delegation'
            Write-Progress @ProgressParams

            Write-Verbose -Message 'START APPLICATION ACCESS USER Global Delegation'

            # USER Site Administrator Delegation
            $Splat = @{
                Group    = $SL_GlobalAppAccUserRight
                LDAPPath = $SitesGlobalAppAccUserOuDn
            }
            Set-AdAclDelegateUserAdmin @Splat

            #### GAL
            Set-AdAclDelegateGalAdmin @Splat

            Add-AdGroupNesting -Identity $SL_GlobalAppAccUserRight -Members $SG_GlobalUserAdmins

            $ProgressParams['CurrentOperation'] = 'Setting up group delegation'
            Write-Progress @ProgressParams

            Write-Verbose -Message 'START GROUP Global Delegation'

            # Create/Delete Groups
            Set-AdAclCreateDeleteGroup -Group $SL_GlobalGroupRight -LDAPpath $SitesGlobalGroupOuDn

            # Nest groups
            Add-AdGroupNesting -Identity $SL_GlobalGroupRight -Members $SG_GlobalGroupAdmins

            #### GAL

            # Change Group Properties
            Set-AdAclChangeGroup -Group $SL_GlobalGroupRight -LDAPpath $SitesGlobalGroupOuDn

        } #end If ShouldProcess

    } #end Process

    End {
        # Complete the progress bar
        $ProgressParams['Status'] = 'Completed'
        $ProgressParams['PercentComplete'] = 100
        $ProgressParams['CurrentOperation'] = 'Tier2 infrastructure setup complete'
        Write-Progress @ProgressParams

        # Clear the progress bar after completion
        Write-Progress -Activity $ProgressParams['Activity'] -Completed

        # Stop transcript if it was started
        if ($EnableTranscript) {
            try {
                Stop-Transcript -ErrorAction Stop
                Write-Verbose -Message 'Transcript stopped successfully'
            } catch {
                Write-Warning -Message ('Failed to stop transcript: {0}' -f $_.Exception.Message)
            } #end Try-Catch
        } #end If

        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating Tier2 objects.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function New-Tier2
