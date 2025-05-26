function New-Tier1 {

    <#
        .SYNOPSIS


        .DESCRIPTION


        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml
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
                        $null -eq $xml.n.Servers -or
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
        } #end If        ##############################
        # Initialize progress tracking variables

        # Progress counter and total for percentage calculation
        [int]$script:CurrentStep = 0
        [int]$script:TotalSteps = 4 # OUs creation, GPOs creation, GPO restrictions, delegations

        # Base progress parameters for reuse
        [hashtable]$script:ProgressParams = @{
            Activity        = 'Creating Tier 1 Infrastructure'
            Status          = 'Starting...'
            PercentComplete = 0
            Id              = 1
        }

        ##############################
        # Module imports
        Import-MyModule -Name 'ServerManager' -UseWindowsPowerShell -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'GroupPolicy' -UseWindowsPowerShell -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -UseWindowsPowerShell -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        #$ArrayList = [System.Collections.ArrayList]::New()
        [System.Collections.Generic.List[object]]$ArrayList = [System.Collections.Generic.List[object]]::New()

        $DenyLogon = [System.Collections.Generic.List[object]]::New()

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
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-548' }
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
        # Tier Service Account Groups
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
        #endregion Global groups Variables

        #region Local groups Variables
        $SL_AdRight = Get-SafeVariable -Name 'SL_AdRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.AdRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_InfraRight = Get-SafeVariable -Name 'SL_InfraRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_SvrAdmRight = Get-SafeVariable -Name 'SL_SvrAdmRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_SvrOpsRight = Get-SafeVariable -Name 'SL_SvrOpsRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GpoAdminRight = Get-SafeVariable -Name 'SL_GpoAdminRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
            Get-AdObjectType -Identity $groupName
        }
        #endregion Local groups Variables

        [String]$ServersOu = $confXML.n.Servers.OUs.ServersOU.Name
        [string]$ServersOuDn = ('OU={0},{1}' -f $ServersOu, $Variables.AdDn)

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Create Tier1 Organizational Units')) {

            # Update progress
            $script:CurrentStep++
            $script:ProgressParams.Status = ('Step {0}/{1}: Creating Tier 1 Organizational Units' -f
                $script:CurrentStep, $script:TotalSteps)
            $script:ProgressParams.PercentComplete = [math]::Min(100,
                [math]::Round(($script:CurrentStep / $script:TotalSteps) * 100))
            Write-Progress @script:ProgressParams

            # Create Servers and Sub OUs
            $Splat = @{
                ouName        = $ServersOu
                ouPath        = $Variables.AdDn
                ouDescription = $confXML.n.Servers.OUs.ServersOU.Description
            }
            New-DelegateAdOU @Splat

            # Create Sub-OUs for Servers
            $Splat = @{
                ouPath = $ServersOuDn
            }

            # Count of sub-OUs for progress reporting
            $totalSubOUs = 7  # Update this if more OUs are added
            $currentSubOU = 0

            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.ApplicationOU.Name
                ouDescription = $confXML.n.Servers.OUs.ApplicationOU.Description
            }
            $currentSubOU++
            New-DelegateAdOU @Splat @Splat1

            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.FileOU.Name
                ouDescription = $confXML.n.Servers.OUs.FileOU.Description
            }
            $currentSubOU++
            New-DelegateAdOU @Splat @Splat1

            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.HypervOU.Name
                ouDescription = $confXML.n.Servers.OUs.HypervOU.Description
            }
            $currentSubOU++
            New-DelegateAdOU @Splat @Splat1

            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.LinuxOU.Name
                ouDescription = $confXML.n.Servers.OUs.LinuxOU.Description
            }
            $currentSubOU++
            New-DelegateAdOU @Splat @Splat1

            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.RemoteDesktopOU.Name
                ouDescription = $confXML.n.Servers.OUs.RemoteDesktopOU.Description
            }
            $currentSubOU++
            New-DelegateAdOU @Splat @Splat1

            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.SqlOU.Name
                ouDescription = $confXML.n.Servers.OUs.SqlOU.Description
            }
            $currentSubOU++
            New-DelegateAdOU @Splat @Splat1

            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.WebOU.Name
                ouDescription = $confXML.n.Servers.OUs.WebOU.Description
            }
            $currentSubOU++
            New-DelegateAdOU @Splat @Splat1

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier1 Baseline GPOs')) {

            # Update progress
            $script:CurrentStep++
            $script:ProgressParams.Status = ('Step {0}/{1}: Creating Baseline GPOs' -f
                $script:CurrentStep, $script:TotalSteps)
            $script:ProgressParams.PercentComplete = [math]::Min(100,
                [math]::Round(($script:CurrentStep / $script:TotalSteps) * 100))
            Write-Progress @script:ProgressParams

            # Create basic GPO for Servers
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $ServersOu
                gpoScope       = $confXML.n.Admin.GPOs.ServersBaseline.Scope
                gpoLinkPath    = $ServersOuDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupId    = $confXML.n.Admin.GPOs.ServersBaseline.backupID
                gpoBackupPath  = Join-Path -Path $DMScripts -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat

            # Create basic GPOs for different types under Servers
            $Splat = @{
                gpoScope      = 'C'
                GpoAdmin      = $sl_GpoAdminRight
                gpoBackupPath = Join-Path -Path $DMScripts -ChildPath 'SecTmpl' -Resolve
            }

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.ApplicationOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.ApplicationOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.FileOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.FileOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.HypervOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.HypervOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.RemoteDesktopOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.RemoteDesktopOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.SqlOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.SqlOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.WebOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.WebOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier1 GPO Restrictions')) {

            # Update progress
            $script:CurrentStep++
            $script:ProgressParams.Status = ('Step {0}/{1}: Creating GPO Restrictions' -f
                $script:CurrentStep, $script:TotalSteps)
            $script:ProgressParams.PercentComplete = [math]::Min(100,
                [math]::Round(($script:CurrentStep / $script:TotalSteps) * 100))
            Write-Progress @script:ProgressParams

            # Access this computer from the network / Deny Access this computer from the network
            # Not Defined

            # Allow Logon Locally / Allow Logon throug RDP/TerminalServices
            # Logon as a Batch job / Logon as a Service
            # Deny Allow Logon Locally / Deny Allow Logon throug RDP/TerminalServices
            # Deny Logon as a Batch job / Deny Logon as a Service
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
            if ($null -ne $SG_Tier2Admins) {
                [void]$DenyLogon.Add($SG_Tier2Admins)
            }


            # Back up files and directories / Bypass traverse checking / Create Global Objects
            # Create symbolic links / Change System Time / Change Time Zone
            # Force shutdown from a remote system / Create Page File
            # Enable computer and user accounts to be trusted for delegation
            # Impersonate a client after authentication / Load and unload device drivers
            # Increase scheduling priority / Manage auditing and security log
            # Modify firmware environment values / Perform volume maintenance tasks
            # Profile single process / Profile system performance / Restore files and directories
            # Shut down the system / Take ownership of files or other objects
            $ArrayList.Clear()
            [void]$ArrayList.Add($Administrators)
            if ($null -ne $SG_Tier1Admins) {
                [void]$ArrayList.Add($SG_Tier1Admins)
            }
            $Splat = @{
                GpoToModify                = 'C-{0}-Baseline' -f $ServersOu
                BatchLogon                 = $SG_Tier1ServiceAccount
                ServiceLogon               = $SG_Tier1ServiceAccount
                InteractiveLogon           = $SG_Tier1Admins
                RemoteInteractiveLogon     = $SG_Tier1Admins
                DenyInteractiveLogon       = $DenyLogon
                DenyRemoteInteractiveLogon = $DenyLogon
                DenyBatchLogon             = @($SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount)
                DenyServiceLogon           = @($SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount)
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

        if ($PSCmdlet.ShouldProcess('Create Tier1 Delegations')) {

            # Update progress for final phase
            $script:CurrentStep++
            $script:ProgressParams.Status = ('Step {0}/{1}: Creating Delegations' -f
                $script:CurrentStep, $script:TotalSteps)
            $script:ProgressParams.PercentComplete = [math]::Min(100,
                [math]::Round(($script:CurrentStep / $script:TotalSteps) * 100))
            Write-Progress @script:ProgressParams

            # Delegation to SL_SvrAdmRight and SL_SvrOpsRight groups to SERVERS area

            # Get the DN of 1st level OU underneath SERVERS area
            $Splat = @{
                Filter      = '*'
                SearchBase  = $ServersOuDn
                SearchScope = 'OneLevel'
            }
            $AllSubOu = Get-ADOrganizationalUnit @Splat | Select-Object -ExpandProperty DistinguishedName

            # Count of sub-OUs for progress reporting
            $totalSubOUs = $AllSubOu.Count
            $currentSubOU = 0

            # Iterate through each sub OU and invoke delegation
            Foreach ($Item in $AllSubOu) {
                $currentSubOU++

                # Update progress for sub-OU processing
                $script:ProgressParams.Status = ('Step {0}/{1}: Delegating permissions for sub-OU {2}/{3}' -f
                    $script:CurrentStep, $script:TotalSteps, $currentSubOU, $totalSubOUs)
                $subProgress = ($currentSubOU / $totalSubOUs)
                $script:ProgressParams.PercentComplete = [math]::Min(100,
                    [math]::Round((($script:CurrentStep - 1 + $subProgress) / $script:TotalSteps) * 100))
                Write-Progress @script:ProgressParams

                ###############################################################################
                # Delegation to SL_SvrAdmRight group to SERVERS area

                Set-AdAclDelegateComputerAdmin -Group $SL_SvrAdmRight -LDAPpath $Item

                ###############################################################################
                # Delegation to SL_SvrOpsRight group on SERVERS area

                # Change Public Info
                Set-AdAclComputerPublicInfo -Group $SL_SvrOpsRight -LDAPpath $Item

                # Change Personal Info
                Set-AdAclComputerPersonalInfo -Group $SL_SvrOpsRight -LDAPpath $Item
            } #end foreach

            # Complete the delegations
            $script:ProgressParams.Status = ('Step {0}/{1}: Completing Delegations' -f
                $script:CurrentStep, $script:TotalSteps)
            $script:ProgressParams.PercentComplete = 100
            Write-Progress @script:ProgressParams

            # Create/Delete OUs within Servers
            Set-AdAclCreateDeleteOU -Group $SL_InfraRight -LDAPpath $ServersOuDn

            # Change OUs within Servers
            Set-AdAclChangeOU -Group $SL_AdRight -LDAPpath $ServersOuDn

        } #end If ShouldProcess

    } #end Process

    End {

        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating Tier1 objects.'
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

        # Complete progress tracking
        $script:ProgressParams.Status = 'Completed'
        $script:ProgressParams.PercentComplete = 100
        Write-Progress @script:ProgressParams -Completed
    } #end End
} #end Function New-Tier1
