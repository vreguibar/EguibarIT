function New-Tier0NestingGroup {

    <#
        .SYNOPSIS
            Creates and applies nesting for Tier0 administration groups.

        .DESCRIPTION
            This function establishes and configures the nested group structure required for Tier0 security model.
            It configures which accounts/groups are denied from being replicated to Read-Only Domain Controllers (RODC).
            It configures group nesting for built-in groups with the correct delegated rights groups.
            It extends rights through the delegation model by nesting security groups appropriately.

            The function relies on pre-existing group variables that must be defined before calling this function.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            [System.String] Path to all the scripts and files needed by this function.
            The path must exist and contain a 'SecTmpl' subfolder.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0NestingGroup

            Creates the nesting structure for Tier0 administration groups using existing group variables.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            None. This function does not generate any output.

        .NOTES
            Used Functions:
                Name                              ║ Module/Namespace
                ══════════════════════════════════╬══════════════════════════════
                Import-MyModule                   ║ EguibarIT
                Get-FunctionDisplay               ║ EguibarIT
                Add-AdGroupNesting                ║ EguibarIT
                Get-ADGroup                       ║ ActiveDirectory
                New-ADGroup                       ║ ActiveDirectory
                Write-Verbose                     ║ Microsoft.PowerShell.Utility
                Write-Error                       ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    29/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                           vicente@eguibar.com
                           Eguibar IT
                           http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Active Directory

        .ROLE
            Security Administration

        .FUNCTIONALITY
            Tier 0 Security Group Management
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.Void])]

    param (

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0
        )]
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
                        $null -eq $xml.n.Admin.GG -or
                        $null -eq $xml.n.Admin.gMSA -or
                        $null -eq $xml.n.Admin.OUs -or
                        $null -eq $xml.n.NC) {
                        throw 'XML file is missing required elements (Admin, GG, gMSA, OUs or NC section)'
                    }
                    return $true
                } catch {
                    throw ('Invalid XML file: {0}' -f $_.Exception.Message)
                }
            })]
        [PSDefaultValue(
            Help = 'Default Value is "C:\PsScripts\Config.xml"',
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
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        #$ArrayList = [System.Collections.ArrayList]::new()
        [System.Collections.Generic.List[object]]$ArrayList = [System.Collections.Generic.List[object]]::New()

        # Load the XML configuration file
        try {
            [xml]$confXML = [xml](Get-Content -Path $PSBoundParameters['ConfigXMLFile'] -ErrorAction Stop)
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
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
                Write-Debug -Message ('Failed to retrieve Administrator name: {0}' -f $_.Exception.Message)
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

        $CryptoOperators = Get-SafeVariable -Name 'CryptoOperators' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-569' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Cryptographic Operators group: {0}' -f $_.Exception.Message)
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

        $RemoteMngtUsers = Get-SafeVariable -Name 'RemoteMngtUsers' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-580' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Remote Management Users group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $RemoteDesktopUsers = Get-SafeVariable -Name 'RemoteDesktopUsers' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-555' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Remote Desktop Users group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $EvtLogReaders = Get-SafeVariable -Name 'EvtLogReaders' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-573' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Event Log Readers group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $NetConfOperators = Get-SafeVariable -Name 'NetConfOperators' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-556' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Network Configuration Operators group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $PerfLogUsers = Get-SafeVariable -Name 'PerfLogUsers' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-559' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Performance Log Users group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $PerfMonitorUsers = Get-SafeVariable -Name 'PerfMonitorUsers' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-558' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Performance Monitor Users group: {0}' -f $_.Exception.Message)
                $null
            }
        }
        #endregion Well-Known groups Variables

        #region Global groups Variables
        $SG_InfraAdmins = Get-SafeVariable -Name 'SG_InfraAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.InfraAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_AdAdmins = Get-SafeVariable -Name 'SG_AdAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AdAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_GpoAdmins = Get-SafeVariable -Name 'SG_GpoAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GpoAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

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

        $SG_Operations = Get-SafeVariable -Name 'SG_Operations' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.Operations.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_ServerAdmins = Get-SafeVariable -Name 'SG_ServerAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_AllSiteAdmins = Get-SafeVariable -Name 'SG_AllSiteAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllSiteAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_AllGALAdmins = Get-SafeVariable -Name 'SG_AllGALAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllGalAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_GlobalUserAdmins = Get-SafeVariable -Name 'SG_GlobalUserAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalUserAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_GlobalPcAdmins = Get-SafeVariable -Name 'SG_GlobalPcAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalPCAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_GlobalGroupAdmins = Get-SafeVariable -Name 'SG_GlobalGroupAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalGroupAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_ServiceDesk = Get-SafeVariable -Name 'SG_ServiceDesk' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.ServiceDesk.Name)
            Get-AdObjectType -Identity $groupName
        }

        $DnsAdmins = Get-SafeVariable -Name 'DnsAdmins' -CreateIfNotExist {
            Get-AdObjectType -Identity 'DnsAdmins'
        }

        $ProtectedUsers = Get-SafeVariable -Name 'ProtectedUsers' -CreateIfNotExist {
            Get-AdObjectType -Identity 'Protected Users'
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

        $SL_DnsAdminRight = Get-SafeVariable -Name 'SL_DnsAdminRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.DnsAdminRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GpoAdminRight = Get-SafeVariable -Name 'SL_GpoAdminRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PGM = Get-SafeVariable -Name 'SL_PGM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PGM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PUM = Get-SafeVariable -Name 'SL_PUM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PUM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GM = Get-SafeVariable -Name 'SL_GM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_UM = Get-SafeVariable -Name 'SL_UM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.UM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PSAM = Get-SafeVariable -Name 'SL_PSAM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PSAM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PAWM = Get-SafeVariable -Name 'SL_PAWM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PAWM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PISM = Get-SafeVariable -Name 'SL_PISM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PISM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_SAGM = Get-SafeVariable -Name 'SL_SAGM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.SAGM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_DcManagement = Get-SafeVariable -Name 'SL_DcManagement' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.DcManagement.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_TransferFSMOright = Get-SafeVariable -Name 'SL_TransferFSMOright' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.TransferFSMOright.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PromoteDcRight = Get-SafeVariable -Name 'SL_PromoteDcRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PromoteDcRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_DirReplRight = Get-SafeVariable -Name 'SL_DirReplRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.DirReplRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_SvrOpsRight = Get-SafeVariable -Name 'SL_SvrOpsRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_SvrAdmRight = Get-SafeVariable -Name 'SL_SvrAdmRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GlobalGroupRight = Get-SafeVariable -Name 'SL_GlobalGroupRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.GlobalGroupRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GlobalAppAccUserRight = Get-SafeVariable -Name 'SL_GlobalAppAccUserRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.GlobalAppAccUserRight.Name)
            Get-AdObjectType -Identity $groupName
        }
        #endregion Local groups Variables

        $AllGlobalGroupVariables = @(
            $DomainAdmins,
            $SG_InfraAdmins,
            $SG_AdAdmins,
            $SG_GpoAdmins,
            $SG_Tier0Admins,
            $SG_Tier1Admins,
            $SG_Tier2Admins,
            $SG_Operations,
            $SG_ServerAdmins,
            $SG_AllSiteAdmins,
            $SG_AllGALAdmins,
            $SG_GlobalUserAdmins,
            $SG_GlobalPcAdmins,
            $SG_GlobalGroupAdmins,
            $SG_ServiceDesk
        )

        $AllLocalGroupVariables = @(
            $SL_AdRight,
            $SL_InfraRight,
            $SL_DnsAdminRight,
            $SL_GpoAdminRight,
            $SL_PGM,
            $SL_PUM,
            $SL_GM,
            $SL_UM,
            $SL_PSAM,
            $SL_PAWM,
            $SL_PISM,
            $SL_SAGM,
            $SL_DcManagement,
            $SL_TransferFSMOright,
            $SL_PromoteDcRight,
            $SL_DirReplRight,
            $SL_SvrOpsRight,
            $SL_SvrAdmRight,
            $SL_GlobalGroupRight,
            $SL_GlobalAppAccUserRight
        )

        $ItAdminOu = $ConfXML.n.Admin.OUs.ItAdminOU.name
        $ItRightsOu = $ConfXML.n.Admin.OUs.ItRightsOU.name
        $ItRightsOuDn = ('OU={0},OU={1},{2}' -f $ItRightsOu, $ItAdminOu, $Variables.AdDn)

    } #end Begin

    Process {

        # Progress parameters that will be reused
        [hashtable]$ProgressSplat = @{
            Activity        = 'Configuring Tier 0 Nesting Structure'
            Status          = 'Starting operation...'
            PercentComplete = 0
            Id              = 1
        }

        # Total number of operations for progress calculation
        $TotalOperations = 3
        $CurrentOperation = 0

        # Avoid having privileged or semi-privileged groups copy to RODC
        if ($PSCmdlet.ShouldProcess('Nesting Denied RODC groups')) {

            $CurrentOperation++
            $ProgressSplat['Status'] = ('Operation {0}/{1}: Configuring groups denied replication to RODC...' -f $CurrentOperation, $TotalOperations)
            $ProgressSplat['PercentComplete'] = ($CurrentOperation / $TotalOperations * 100)
            Write-Progress @ProgressSplat

            Write-Verbose -Message 'Configuring groups denied replication to RODC...'

            $ArrayList.Clear()

            foreach ($Item in $AllGlobalGroupVariables) {
                if ($null -ne $Item) {
                    [void]$ArrayList.Add($Item)
                } else {
                    Write-Error -Message ('Group not found: {0}' -f $Item)
                } #end If GroupName
            } #end ForEach
            # Include Enterprise Admins
            [void]$ArrayList.Add($EnterpriseAdmins)

            foreach ($Item in $AllLocalGroupVariables) {
                if ($null -ne $Item) {
                    [void]$ArrayList.Add($Item)
                } else {
                    Write-Error -Message ('Group not found: {0}' -f $Item)
                } #end If GroupName
            } #end ForEach
            # Add groups
            Add-AdGroupNesting -Identity $DeniedRODC -Members $ArrayList
            Write-Verbose -Message 'Successfully added groups to DeniedRODC'

            # Add Users
            $ArrayList.Clear()
            if ($null -ne $AdminName) {
                [void]$ArrayList.Add($AdminName)
            }
            if ($null -ne $NewAdminExists) {
                [void]$ArrayList.Add($NewAdminExists)
            }
            Add-AdGroupNesting -Identity $DeniedRODC -Members $ArrayList
            Write-Verbose -Message 'Successfully added admin users to DeniedRODC'

        } #end If ShouldProcess

        # Nest Groups - Delegate Rights through Builtin groups
        # https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups
        # http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/
        if ($PSCmdlet.ShouldProcess('Delegate rights through nesting Builtin groups')) {

            $CurrentOperation++
            $ProgressSplat['Status'] = ('Operation {0}/{1}: Configuring builtin group membership...' -f $CurrentOperation, $TotalOperations)
            $ProgressSplat['PercentComplete'] = ($CurrentOperation / $TotalOperations * 100)
            Write-Progress @ProgressSplat

            Write-Verbose -Message 'Configuring builtin group membership...'

            Add-AdGroupNesting -Identity $CryptoOperators -Members $SG_AdAdmins
            Add-AdGroupNesting -Identity $DnsAdmins -Members $SG_AdAdmins, $SG_Tier0Admins
            Add-AdGroupNesting -Identity $EvtLogReaders -Members $SG_AdAdmins, $SG_Operations
            Add-AdGroupNesting -Identity $NetConfOperators -Members $SG_AdAdmins, $SG_Tier0Admins
            Add-AdGroupNesting -Identity $PerfLogUsers -Members $SG_AdAdmins, $SG_Operations, $SG_Tier0Admins
            Add-AdGroupNesting -Identity $PerfMonitorUsers -Members $SG_AdAdmins, $SG_Operations, $SG_Tier0Admins
            Add-AdGroupNesting -Identity $RemoteDesktopUsers -Members $SG_AdAdmins
            Add-AdGroupNesting -Identity $ServerOperators -Members $SG_AdAdmins
            Add-AdGroupNesting -Identity $RemoteMngtUsers -Members $SG_AdAdmins, $SG_Tier0Admins

            # Create and configure WinRMRemoteWMIUsers group if it doesn't exist
            $RemoteWMI = Get-ADGroup -Filter { SamAccountName -like 'WinRMRemoteWMIUsers*' } -ErrorAction SilentlyContinue
            If (-not $RemoteWMI) {
                $Splat = @{
                    GroupScope    = 'DomainLocal'
                    GroupCategory = 'Security'
                    Name          = 'WinRMRemoteWMIUsers__'
                    Path          = $ItRightsOuDn
                }
                New-ADGroup @Splat
                $RemoteWMI = Get-ADGroup 'WinRMRemoteWMIUsers__'
                Write-Verbose -Message 'Created WinRMRemoteWMIUsers__ group'
            }
            Add-AdGroupNesting -Identity $RemoteWMI -Members $SG_AdAdmins, $SG_Tier0Admins

            # Configure Protected Users group membership
            # https://technet.microsoft.com/en-us/library/dn466518(v=ws.11).aspx
            $ArrayList.Clear()
            if ($null -ne $AdminName) {
                [void]$ArrayList.Add($AdminName)
            }
            if ($null -ne $NewAdminExists) {
                [void]$ArrayList.Add($NewAdminExists)
            }
            Add-AdGroupNesting -Identity $ProtectedUsers -Members $ArrayList

            $ArrayList.Clear()
            foreach ($Item in $AllGlobalGroupVariables) {
                if (($null -ne $Item) -and ($item -ne 'Enterprise Admins')) {
                    [void]$ArrayList.Add($Item)
                } else {
                    Write-Error -Message ('Group not found: {0}' -f $Item)
                } #end If GroupName
            } #end ForEach
            Add-AdGroupNesting -Identity $ProtectedUsers -Members $ArrayList

            Write-Verbose -Message 'Successfully configured builtin group membership'

        } #end If ShouldProcess

        # Nest Groups - Extend Rights through delegation model groups
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/
        if ($PSCmdlet.ShouldProcess('Extend Rights through delegation model group nesting')) {

            $CurrentOperation++
            $ProgressSplat['Status'] = ('Operation {0}/{1}: Configuring delegation model group nesting...' -f $CurrentOperation, $TotalOperations)
            $ProgressSplat['PercentComplete'] = ($CurrentOperation / $TotalOperations * 100)
            Write-Progress @ProgressSplat

            # InfraAdmins as member of InfraRight
            $Splat = @{
                Identity = $SL_InfraRight
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PUM
            $Splat = @{
                Identity = $SL_PUM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PGM
            $Splat = @{
                Identity = $SL_PGM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PISM
            $Splat = @{
                Identity = $SL_PISM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PAWM
            $Splat = @{
                Identity = $SL_PAWM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PSAM
            $Splat = @{
                Identity = $SL_PSAM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of Tier0Admins
            $Splat = @{
                Identity = $SG_Tier0Admins
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of DirReplRight
            $Splat = @{
                Identity = $SL_DirReplRight
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of AdAdmins
            $Splat = @{
                Identity = $SG_AdAdmins
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured InfraAdmins nesting'


            # AdAdmins as member of AdRight
            $Splat = @{
                Identity = $SL_AdRight
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of UM
            $Splat = @{
                Identity = $SL_UM
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of GM
            $Splat = @{
                Identity = $SL_GM
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of GpoAdmins
            $Splat = @{
                Identity = $SG_GpoAdmins
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of AllSiteAdmins
            $Splat = @{
                Identity = $SG_AllSiteAdmins
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of ServerAdmins
            $Splat = @{
                Identity = $SG_ServerAdmins
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of DcManagement
            $Splat = @{
                Identity = $SL_DcManagement
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of Tier0Admins
            $Splat = @{
                Identity = $SG_Tier0Admins
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat



            # Tier0Admins as member of DcManagement
            $Splat = @{
                Identity = $SL_DcManagement
                Members  = $SG_Tier0Admins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured Tier0Admins nesting'

            # GpoAdmins nesting
            $Splat = @{
                Identity = $SL_GpoAdminRight
                Members  = $SG_GpoAdmins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured GpoAdmins nesting'

            # AllSiteAdmins and AllGalAdmins nesting
            $Splat = @{
                Identity = $SG_AllGALAdmins
                Members  = $SG_AllSiteAdmins
            }
            Add-AdGroupNesting @Splat

            # AllGalAdmins as member of ServiceDesk
            $Splat = @{
                Identity = $SG_ServiceDesk
                Members  = $SG_AllGALAdmins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured AllSiteAdmins and AllGalAdmins nesting'


            # ServerAdmins as member of SvrAdmRight
            $Splat = @{
                Identity = $SL_SvrAdmRight
                Members  = $SG_ServerAdmins
            }
            Add-AdGroupNesting @Splat

            # Operations as member of SvrOpsRight
            $Splat = @{
                Identity = $SL_SvrOpsRight
                Members  = $SG_Operations
            }
            Add-AdGroupNesting @Splat

            # ServerAdmins as member of Operations
            $Splat = @{
                Identity = $SG_Operations
                Members  = $SG_ServerAdmins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured ServerAdmins and Operations nesting'

        } #end If ShouldProcess

        # Complete the progress bar
        $ProgressSplat['Status'] = 'Completed all operations'
        $ProgressSplat['PercentComplete'] = 100
        Write-Progress @ProgressSplat
        # Finally, clean up the progress bar
        Write-Progress -Id 1 -Activity 'Configuring Tier 0 Nesting Structure' -Completed

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Nesting Tier0 Groups.'
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
} #end Function New-Tier0NestingGroup
