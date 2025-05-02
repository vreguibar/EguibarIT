function New-Tier0GpoRestriction {

    <#
        .SYNOPSIS
            Creates and configures security baseline GPOs for tiered administration model.

        .DESCRIPTION
            This function creates and configures Group Policy Objects (GPOs) for implementing
            a tiered administrative model in Active Directory. It establishes security baselines
            for different administration tiers:
            - Domain baseline
            - Domain Controllers baseline
            - Admin/Tier0 baseline
            - Infrastructure (Tier 0, 1, 2) baselines
            - Privileged Access Workstation (PAW) baselines

            The function configures user rights assignments in these GPOs according to security
            best practices for a tiered administrative model, including logon restrictions,
            privilege assignments, and specific permissions for administrative accounts.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            [String] Path to all the scripts and files needed by this function.
            Must contain a subfolder named 'SecTmpl' with security templates.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0GpoRestriction -ConfigXMLFile C:\Scripts\Config.xml -DMScripts C:\Scripts

            Creates and configures all baseline GPOs using the specified configuration file and scripts path.

        .EXAMPLE
            New-Tier0GpoRestriction -ConfigXMLFile C:\Scripts\Config.xml -WhatIf

            Shows what would happen if the command runs without making any changes.

        .INPUTS
            System.IO.FileInfo, System.String

        .OUTPUTS
            System.String

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Import-MyModule                            ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT
                Get-AdObjectType                           ║ EguibarIT
                Set-GpoPrivilegeRight                      ║ EguibarIT
                Set-GpoFileSecurity                        ║ EguibarIT
                Set-GpoRegistryKey                         ║ EguibarIT
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Test-Path                                  ║ Microsoft.PowerShell.Management
                Get-Content                                ║ Microsoft.PowerShell.Management
                Get-ADUser                                 ║ ActiveDirectory
                Get-ADGroup                                ║ ActiveDirectory

        .NOTES
            Version:         1.1
            DateModified:    30/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            EguibarIT

        .ROLE
            Security

        .FUNCTIONALITY
            Group Policy, Tiered Administration, Security Baseline
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([void])]

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
                        $null -eq $xml.n.Admin.Users -or
                        $null -eq $xml.n.Admin.GPOs -or
                        $null -eq $xml.n.Admin.GG -or
                        $null -eq $xml.n.Admin.OUs -or
                        $null -eq $xml.n.NC) {
                        throw 'XML file is missing required elements (Admin, Users, OUs, GG, GPOs or NC section)'
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
            Value = 'C:\PsScripts\'
        )]
        [Alias('ScriptPath')]
        [System.IO.DirectoryInfo]
        $DMScripts

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

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # Parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Collection for groups that need logon rights
        [System.Collections.Generic.List[object]]$NetworkLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$DenyNetworkLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$InteractiveLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$DenyInteractiveLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$RemoteInteractiveLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$DenyRemoteInteractiveLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$BatchLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$DenyBatchLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$ServiceLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$DenyServiceLogon = [System.Collections.Generic.List[object]]::New()
        [System.Collections.Generic.List[object]]$Backup = [System.Collections.Generic.List[object]]::New()
        [System.Collections.ArrayList]$ArrayList = [System.Collections.ArrayList]::New()

        # Load the XML configuration file
        try {
            [xml]$ConfXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
            Write-Verbose -Message ('Successfully loaded configuration file: {0}' -f $PSBoundParameters['ConfigXMLFile'])
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


        # Check if variables contain the corresponding AD Group

        if ($null -ne $SG_AdAdmins) {
            $AdAdmins = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $ConfXML.n.Admin.GG.AdAdmins.Name
            $SG_AdAdmins = Get-AdObjectType -Identity $AdAdmins
        } #end If

        if ($null -ne $SG_Tier0Admins) {
            $Tier0Admins = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $ConfXML.n.Admin.GG.Tier0Admins.Name
            $SG_Tier0Admins = Get-AdObjectType -Identity $Tier0Admins
        } #end If

        if ($null -ne $SG_Tier1Admins) {
            $Tier1Admins = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $ConfXML.n.Admin.GG.Tier1Admins.Name
            $SG_Tier1Admins = Get-AdObjectType -Identity $Tier1Admins
        } #end If

        if ($null -ne $SG_Tier2Admins) {
            $Tier2Admins = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $ConfXML.n.Admin.GG.Tier2Admins.Name
            $SG_Tier2Admins = Get-AdObjectType -Identity $Tier2Admins
        } #end If

        if ($null -ne $SG_Tier0ServiceAccount) {
            $Tier0ServiceAccount = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $ConfXML.n.Admin.GG.Tier0ServiceAccount.Name
            $SG_Tier0ServiceAccount = Get-AdObjectType -Identity $Tier0ServiceAccount
        } #end If

        if ($null -ne $SG_Tier1ServiceAccount) {
            $Tier1ServiceAccount = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $ConfXML.n.Admin.GG.Tier1ServiceAccount.Name
            $SG_Tier1ServiceAccount = Get-AdObjectType -Identity $Tier1ServiceAccount
        } #end If

        if ($null -ne $SG_Tier2ServiceAccount) {
            $Tier2ServiceAccount = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $ConfXML.n.Admin.GG.Tier2ServiceAccount.Name
            $SG_Tier2ServiceAccount = Get-AdObjectType -Identity $Tier2ServiceAccount
        } #end If

        if ($null -ne $SL_PISM) {
            $SL_PISM = Get-AdObjectType -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $ConfXML.n.Admin.LG.PISM.Name)
        } #end If

        if ($null -ne $SL_PAWM) {
            $SL_PAWM = Get-AdObjectType -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $ConfXML.n.Admin.LG.PAWM.Name)
        } #end If

        if ($null -ne $SL_DcManagement) {
            $DcManagement = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $ConfXML.n.Admin.LG.DcManagement.Name
            $SL_DcManagement = Get-AdObjectType -Identity $DcManagement
        } #end If


        # Set admin names
        if ($null -ne $NewAdminName) {
            $NewAdminName = Get-ADUser -Identity $ConfXML.n.Admin.users.NEWAdmin.Name
        } #end If

        # Get the AD Objects by Well-Known SID
        try {
            # Administrator
            $AdminName = Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }

            $Administrators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-544' }

            $AuthUsers = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-11' }

            $EnterpriseDCs = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-9' }

            $LocalAccount = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-113' }

            $BackupOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-551' }

            $AccountOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-548' }

            $PrintOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-550' }

            $ServerOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-549' }

            # RODC
            $RODC = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-521' }
            # Cryptographic Operators
            $CryptoOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-569' }
            # Domain Admins
            $DomainAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-512' }
            # Enterprise Admins
            $EnterpriseAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-519' }
            # Group Policy Creators Owner
            $GPOCreatorsOwner = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-520' }

            # Schema Admins
            $SchemaAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-518' }
            # Account Operators
            $AccountOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-548' }
            # Backup Operators
            $BackupOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-551' }
            # Server Operators
            $ServerOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-549' }
            # Print Operators
            $PrintOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-550' }
            # Domain Controllers
            $DomainControllers = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-516' }

            # Crypto Operators
            $CryptoOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-569' }
            # Read-only Domain Controllers
            $RODC = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-521' }
            # Administrators
            $Administrators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-544' }

            Write-Verbose -Message 'Successfully loaded all security principals by SID'
        } catch {

            Write-Error -Message ('Error initializing security principals: {0}' -f $_.Exception.Message)
            throw

        } #end Try-Catch

        Write-Verbose -Message 'Begin block initialization completed successfully'
    } #end Begin

    Process {
        if ($PSCmdlet.ShouldProcess('Active Directory', 'Configure Domain Baseline GPO Restrictions')) {
            try {
                Write-Verbose -Message 'Configuring Domain Baseline GPO Restrictions'

                # Access this computer from the network
                $NetworkLogon.Clear()
                [void]$NetworkLogon.Add($Administrators)
                [void]$NetworkLogon.Add($AuthUsers)
                [void]$NetworkLogon.Add($EnterpriseDCs)

                # Deny access to this computer from the network
                $DenyNetworkLogon.Clear()
                [void]$DenyNetworkLogon.Add('ANONYMOUS LOGON')
                [void]$DenyNetworkLogon.Add($LocalAccount)
                [void]$DenyNetworkLogon.Add('Local Account and member of administrators group')

                # Deny Logon Locally
                $DenyInteractiveLogon.Clear()
                [void]$DenyInteractiveLogon.Add('Guests')
                if ($null -ne $SG_Tier0ServiceAccount) {
                    [void]$DenyInteractiveLogon.Add($SG_Tier0ServiceAccount)
                }
                if ($null -ne $SG_Tier1ServiceAccount) {
                    [void]$DenyInteractiveLogon.Add($SG_Tier1ServiceAccount)
                }
                if ($null -ne $SG_Tier2ServiceAccount) {
                    [void]$DenyInteractiveLogon.Add($SG_Tier2ServiceAccount)
                }

                # Deny logon through RDS/TerminalServices
                $DenyRemoteInteractiveLogon.Clear()
                [void]$DenyRemoteInteractiveLogon.Add($LocalAccount)
                [void]$DenyRemoteInteractiveLogon.Add('Guests')
                [void]$DenyRemoteInteractiveLogon.Add($AccountOperators)
                [void]$DenyRemoteInteractiveLogon.Add($BackupOperators)
                [void]$DenyRemoteInteractiveLogon.Add($PrintOperators)
                [void]$DenyRemoteInteractiveLogon.Add($ServerOperators)
                [void]$DenyRemoteInteractiveLogon.Add($DomainControllers)
                [void]$DenyRemoteInteractiveLogon.Add($RODC)
                if ($null -ne $SG_Tier0ServiceAccount) {
                    [void]$DenyRemoteInteractiveLogon.Add($SG_Tier0ServiceAccount)
                }
                if ($null -ne $SG_Tier1ServiceAccount) {
                    [void]$DenyRemoteInteractiveLogon.Add($SG_Tier1ServiceAccount)
                }
                if ($null -ne $SG_Tier2ServiceAccount) {
                    [void]$DenyRemoteInteractiveLogon.Add($SG_Tier2ServiceAccount)
                }
                # Logon as a Service
                # Deny Logon as a Batch job / Deny Logon as a Service
                $DenyBatchLogon.Clear()
                [void]$DenyBatchLogon.Add($SchemaAdmins)
                [void]$DenyBatchLogon.Add($EnterpriseAdmins)
                [void]$DenyBatchLogon.Add($DomainAdmins)
                [void]$DenyBatchLogon.Add($Administrators)
                [void]$DenyBatchLogon.Add($AccountOperators)
                [void]$DenyBatchLogon.Add($BackupOperators)
                [void]$DenyBatchLogon.Add($PrintOperators)
                [void]$DenyBatchLogon.Add($ServerOperators)
                [void]$DenyBatchLogon.Add($DomainControllers)
                [void]$DenyBatchLogon.Add($RODC)
                [void]$DenyBatchLogon.Add($GPOCreatorsOwner)
                [void]$DenyBatchLogon.Add($CryptoOperators)
                [void]$DenyBatchLogon.Add('Guests')
                if ($null -ne $SG_Tier0Admins) {
                    [void]$DenyBatchLogon.Add($SG_Tier0Admins)
                }
                if ($null -ne $SG_Tier1Admins) {
                    [void]$DenyBatchLogon.Add($SG_Tier1Admins)
                }
                if ($null -ne $SG_Tier2Admins) {
                    [void]$DenyBatchLogon.Add($SG_Tier2Admins)
                }
                if ($null -ne $AdminName) {
                    [void]$DenyBatchLogon.Add($AdminName)
                }
                if ($null -ne $NewAdminName) {
                    [void]$DenyBatchLogon.Add($NewAdminName)
                }

                # Logon as a Service
                $ServiceLogon.Clear()
                [void]$ServiceLogon.Add('Network Service')
                [void]$ServiceLogon.Add('All Services')

                <#
                # NOT Modified for this GPO

                $InteractiveLogon = [System.Collections.Generic.List[object]]::New()
                $RemoteInteractiveLogon = [System.Collections.Generic.List[object]]::New()
                $DenyBatchLogon = [System.Collections.Generic.List[object]]::New()
                $DenyServiceLogon = [System.Collections.Generic.List[object]]::New()
                $MachineAccount = [System.Collections.Generic.List[object]]::New()
                $IncreaseQuota = [System.Collections.Generic.List[object]]::New()
                $Backup = [System.Collections.Generic.List[object]]::New()
                $ChangeNotify = [System.Collections.Generic.List[object]]::New()
                $SystemTime = [System.Collections.Generic.List[object]]::New()
                $TimeZone = [System.Collections.Generic.List[object]]::New()
                $CreatePagefile = [System.Collections.Generic.List[object]]::New()
                $CreateGlobal = [System.Collections.Generic.List[object]]::New()
                $CreateSymbolicLink = [System.Collections.Generic.List[object]]::New()
                $EnableDelegation = [System.Collections.Generic.List[object]]::New()
                $RemoteShutdown = [System.Collections.Generic.List[object]]::New()
                $Audit = [System.Collections.Generic.List[object]]::New()
                $Impersonate = [System.Collections.Generic.List[object]]::New()
                $IncreaseWorkingSet = [System.Collections.Generic.List[object]]::New()
                $IncreaseBasePriority = [System.Collections.Generic.List[object]]::New()
                $LoadDriver = [System.Collections.Generic.List[object]]::New()
                $AuditSecurity = [System.Collections.Generic.List[object]]::New()
                $Relabel = [System.Collections.Generic.List[object]]::New()
                $SystemEnvironment = [System.Collections.Generic.List[object]]::New()
                $DelegateSessionUserImpersonate = [System.Collections.Generic.List[object]]::New()
                $ManageVolume = [System.Collections.Generic.List[object]]::New()
                $ProfileSingleProcess = [System.Collections.Generic.List[object]]::New()
                $SystemProfile = [System.Collections.Generic.List[object]]::New()
                $Undock = [System.Collections.Generic.List[object]]::New()
                $AssignPrimaryToken = [System.Collections.Generic.List[object]]::New()
                $Restore = [System.Collections.Generic.List[object]]::New()
                $Shutdown = [System.Collections.Generic.List[object]]::New()
                $SyncAgent = [System.Collections.Generic.List[object]]::New()
                $TakeOwnership = [System.Collections.Generic.List[object]]::New()
            #>

                # Modify all rights in one shot
                $Splat = @{
                    GpoToModify                = 'C-Baseline'
                    NetworkLogon               = $NetworkLogon
                    DenyNetworkLogon           = $DenyNetworkLogon
                    DenyInteractiveLogon       = $DenyInteractiveLogon
                    DenyRemoteInteractiveLogon = $DenyRemoteInteractiveLogon
                    DenyBatchLogon             = $DenyBatchLogon
                    ServiceLogon               = $ServiceLogon
                }
                Set-GpoPrivilegeRight @Splat
                Write-Verbose -Message 'Domain Baseline GPO configured successfully'

            } catch {

                Write-Error -Message ('Error configuring Domain Baseline GPO: {0}' -f $_.Exception.Message)

            } #end Try-Catch
        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Active Directory', 'Configure DomainControllers Baseline GPO Restrictions')) {
            try {
                Write-Verbose -Message 'Configuring Domain Controllers Baseline GPO restrictions'

                # Access this computer from the network
                $NetworkLogon.Clear()
                [void]$NetworkLogon.Add($Administrators)
                [void]$NetworkLogon.Add($AuthUsers)
                [void]$NetworkLogon.Add($EnterpriseDCs)

                # Allow Logon Locally / Allow Logon through RDP/TerminalServices
                $InteractiveLogon.Clear()
                [void]$InteractiveLogon.Add($SchemaAdmins)
                [void]$InteractiveLogon.Add($EnterpriseAdmins)
                [void]$InteractiveLogon.Add($DomainAdmins)
                [void]$InteractiveLogon.Add($Administrators)
                if ($null -ne $AdminName) {
                    [void]$InteractiveLogon.Add($AdminName)
                }
                if ($null -ne $NewAdminName) {
                    [void]$InteractiveLogon.Add($NewAdminName)
                }
                if ($null -ne $SG_Tier0Admins) {
                    [void]$InteractiveLogon.Add($SG_Tier0Admins)
                }
                $RemoteInteractiveLogon.Clear()
                $RemoteInteractiveLogon = $InteractiveLogon


                # Deny Logon Locally / Deny Logon through RDP/TerminalServices
                $DenyInteractiveLogon.Clear()
                [void]$DenyInteractiveLogon.Add($AccountOperators)
                [void]$DenyInteractiveLogon.Add($BackupOperators)
                [void]$DenyInteractiveLogon.Add($PrintOperators)
                [void]$DenyInteractiveLogon.Add('Guests')
                if ($null -ne $SG_Tier1Admins) {
                    [void]$DenyInteractiveLogon.Add($SG_Tier1Admins)
                }
                if ($null -ne $SG_Tier2Admins) {
                    [void]$DenyInteractiveLogon.Add($SG_Tier2Admins)
                }
                if ($null -ne $SG_Tier1ServiceAccount) {
                    [void]$DenyInteractiveLogon.Add($SG_Tier1ServiceAccount)
                }
                if ($null -ne $SG_Tier2ServiceAccount) {
                    [void]$DenyInteractiveLogon.Add($SG_Tier2ServiceAccount)
                }
                $DenyRemoteInteractiveLogon.Clear()
                $DenyRemoteInteractiveLogon = $DenyInteractiveLogon


                # Deny Logon as a Batch job / Deny Logon as a Service
                $DenyBatchLogon.Clear()
                [void]$DenyBatchLogon.Add($SchemaAdmins)
                [void]$DenyBatchLogon.Add($EnterpriseAdmins)
                [void]$DenyBatchLogon.Add($DomainAdmins)
                [void]$DenyBatchLogon.Add($Administrators)
                [void]$DenyBatchLogon.Add($AccountOperators)
                [void]$DenyBatchLogon.Add($BackupOperators)
                [void]$DenyBatchLogon.Add($PrintOperators)
                [void]$DenyBatchLogon.Add($ServerOperators)
                [void]$DenyBatchLogon.Add($GPOCreatorsOwner)
                [void]$DenyBatchLogon.Add($CryptoOperators)
                [void]$DenyBatchLogon.Add('Guests')
                if ($null -ne $AdminName) {
                    [void]$DenyBatchLogon.Add($AdminName)
                }
                if ($null -ne $NewAdminName) {
                    [void]$DenyBatchLogon.Add($NewAdminName)
                }
                if ($null -ne $SG_Tier0Admins) {
                    [void]$DenyBatchLogon.Add($SG_Tier0Admins)
                }
                if ($null -ne $SG_Tier1Admins) {
                    [void]$DenyBatchLogon.Add($SG_Tier1Admins)
                }
                if ($null -ne $SG_Tier2Admins) {
                    [void]$DenyBatchLogon.Add($SG_Tier2Admins)
                }
                if ($null -ne $SG_Tier1ServiceAccount) {
                    [void]$DenyBatchLogon.Add($SG_Tier1ServiceAccount)
                }
                if ($null -ne $SG_Tier2ServiceAccount) {
                    [void]$DenyBatchLogon.Add($SG_Tier2ServiceAccount)
                }
                $DenyServiceLogon.Clear()
                $DenyServiceLogon = $DenyBatchLogon


                # Back up files and directories / Bypass traverse checking / Create Global Objects / Create symbolic links
                # Change System Time / Change Time Zone / Force shutdown from a remote system
                # Create Page File / Enable computer and user accounts to be trusted for delegation
                # Impersonate a client after authentication / Load and unload device drivers
                # Increase scheduling priority / Manage auditing and security log
                # Modify firmware environment values / Perform volume maintenance tasks
                # Profile single process / Profile system performance / Restore files and directories
                # Shut down the system / Take ownership of files or other objects
                $Backup.Clear()
                [void]$Backup.Add($Administrators)
                if ($null -ne $SG_Tier0Admins) {
                    [void]$Backup.Add($SG_Tier0Admins)
                }
                if ($null -ne $SG_AdAdmins) {
                    [void]$Backup.Add($SG_AdAdmins)
                }

                # Modify all rights in one shot
                $Splat = @{
                    GpoToModify                = 'C-{0}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Name
                    NetworkLogon               = $NetworkLogon
                    InteractiveLogon           = $InteractiveLogon
                    RemoteInteractiveLogon     = $RemoteInteractiveLogon
                    DenyRemoteInteractiveLogon = $DenyRemoteInteractiveLogon
                    DenyInteractiveLogon       = $DenyInteractiveLogon
                    BatchLogon                 = @($SG_Tier0ServiceAccount, 'Performance Log Users')
                    ServiceLogon               = @($SG_Tier0ServiceAccount, 'Network Service')
                    DenyServiceLogon           = $DenyServiceLogon
                    DenyBatchLogon             = $DenyBatchLogon
                    Backup                     = $Backup
                    ChangeNotify               = @(
                        $Administrators,
                        $SG_Tier0Admins,
                        $SG_AdAdmins,
                        'LOCAL SERVICE',
                        'NETWORK SERVICE'
                    )
                    CreateGlobal               = @(
                        $Administrators,
                        $SG_Tier0Admins,
                        $SG_AdAdmins,
                        'LOCAL SERVICE',
                        'NETWORK SERVICE'
                    )
                    Systemtime                 = @($Administrators, $SG_Tier0Admins, $SG_AdAdmins, 'LOCAL SERVICE')
                    TimeZone                   = $Backup
                    CreatePagefile             = $Backup
                    CreateSymbolicLink         = $Backup
                    EnableDelegation           = $Backup
                    RemoteShutDown             = $Backup
                    Impersonate                = @(
                        $Administrators,
                        $SG_Tier0Admins,
                        $SG_AdAdmins,
                        'LOCAL SERVICE',
                        'NETWORK SERVICE',
                        'SERVICE'
                    )
                    IncreaseBasePriority       = $Backup
                    LoadDriver                 = $Backup
                    AuditSecurity              = $Backup
                    SystemEnvironment          = $Backup
                    ManageVolume               = $Backup
                    ProfileSingleProcess       = $Backup
                    SystemProfile              = $Backup
                    AssignPrimaryToken         = @('LOCAL SERVICE', 'NETWORK SERVICE')
                    Restore                    = $Backup
                    Shutdown                   = $Backup
                    TakeOwnership              = $Backup
                }
                Set-GpoPrivilegeRight @Splat


                # Additional configuration for File permissions and Registry permissions
                # these settings are intended to "delegate" software maintenance tasks to Dc_Management group
                Write-Verbose -Message 'Configuring additional File and Registry permissions'

                # File Security
                $Splat = @{
                    GpoToModify = 'C-{0}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Name
                    Group       = $SL_DcManagement
                }
                Set-GpoFileSecurity @Splat

                # Registry Keys
                $Splat = @{
                    GpoToModify = 'C-{0}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Name
                    Group       = $SL_DcManagement
                }
                Set-GpoRegistryKey @Splat

                Write-Verbose -Message 'Domain Controllers Baseline GPO configured successfully'

            } catch {

                Write-Error -Message ('Error configuring Domain Controllers Baseline GPO: {0}' -f $_.Exception.Message)

            } #end Try-Catch
        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Active Directory', 'Configure Admin/Tier0 Baseline GPO Restrictions')) {
            try {
                Write-Verbose -Message 'Configuring Admin/Tier0 Baseline GPO restrictions'

                #region Admin Area = Baseline

                # Logon as a Batch job / Logon as a Service
                $BatchLogon.Clear()
                [void]$BatchLogon.Add('Network Service')
                [void]$BatchLogon.Add('All Services')
                if ($null -ne $SG_Tier0ServiceAccount) {
                    [void]$BatchLogon.Add($SG_Tier0ServiceAccount)
                }
                $ServiceLogon.Clear()
                $ServiceLogon = $BatchLogon

                # Deny Logon as a Batch job / Deny Logon as a Service
                $DenyBatchLogon.Clear()
                [void]$DenyBatchLogon.Add($SchemaAdmins)
                [void]$DenyBatchLogon.Add($EnterpriseAdmins)
                [void]$DenyBatchLogon.Add($DomainAdmins)
                [void]$DenyBatchLogon.Add($Administrators)
                [void]$DenyBatchLogon.Add($AccountOperators)
                [void]$DenyBatchLogon.Add($BackupOperators)
                [void]$DenyBatchLogon.Add($PrintOperators)
                [void]$DenyBatchLogon.Add($ServerOperators)
                [void]$DenyBatchLogon.Add($RODC)
                [void]$DenyBatchLogon.Add($GPOCreatorsOwner)
                [void]$DenyBatchLogon.Add($CryptoOperators)
                [void]$DenyBatchLogon.Add('Guests')
                if ($null -ne $AdminName) {
                    [void]$DenyBatchLogon.Add($AdminName)
                }
                if ($null -ne $NewAdminName) {
                    [void]$DenyBatchLogon.Add($NewAdminName)
                }
                if ($null -ne $SG_Tier0Admins) {
                    [void]$DenyBatchLogon.Add($SG_Tier0Admins)
                }
                if ($null -ne $SG_Tier1Admins) {
                    [void]$DenyBatchLogon.Add($SG_Tier1Admins)
                }
                if ($null -ne $SG_Tier2Admins) {
                    [void]$DenyBatchLogon.Add($SG_Tier2Admins)
                }
                if ($null -ne $SG_Tier1ServiceAccount) {
                    [void]$DenyBatchLogon.Add($SG_Tier1ServiceAccount)
                }
                if ($null -ne $SG_Tier2ServiceAccount) {
                    [void]$DenyBatchLogon.Add($SG_Tier2ServiceAccount)
                }
                $DenyServiceLogon.Clear()
                $DenyServiceLogon = $DenyBatchLogon


                $ArrayList.Clear()
                [void]$ArrayList.Add($Administrators)
                if ($null -ne $SG_Tier0Admins) {
                    [void]$ArrayList.Add($SG_Tier0Admins)
                }
                if ($null -ne $SG_AdAdmins) {
                    [void]$ArrayList.Add($SG_AdAdmins)
                }

                # Modify all rights in one shot
                $Splat = @{
                    GpoToModify          = 'C-{0}-Baseline' -f $confXML.n.Admin.GPOs.Adminbaseline.Name
                    BatchLogon           = $BatchLogon
                    ServiceLogon         = $ServiceLogon
                    DenyBatchLogon       = $DenyBatchLogon
                    DenyServiceLogon     = $DenyServiceLogon
                    MachineAccount       = $ArrayList
                    Backup               = $ArrayList
                    SystemTime           = @($Administrators, $SG_Tier0Admins, $SG_AdAdmins, 'LOCAL SERVICE')
                    TimeZone             = $ArrayList
                    CreatePagefile       = $ArrayList
                    CreateSymbolicLink   = $ArrayList
                    RemoteShutdown       = $ArrayList
                    IncreaseBasePriority = $ArrayList
                    LoadDriver           = $ArrayList
                    AuditSecurity        = $ArrayList
                    SystemEnvironment    = $ArrayList
                    ManageVolume         = $ArrayList
                    ProfileSingleProcess = $ArrayList
                    SystemProfile        = $ArrayList
                    Restore              = $ArrayList
                    Shutdown             = $ArrayList
                    TakeOwnership        = $ArrayList
                }
                Write-Verbose -Message 'Applying Admin/Tier0 Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion Admin Area = Baseline



                #region HOUSEKEEPING

                # Access this computer from the network / Allow Logon Locally
                $NetworkLogon.Clear()
                [void]$NetworkLogon.Add($DomainAdmins)
                [void]$NetworkLogon.Add($Administrators)
                if ($null -ne $SG_Tier0Admins) {
                    [void]$NetworkLogon.Add($SG_Tier0Admins)
                }
                $InteractiveLogon.Clear()
                $InteractiveLogon = $NetworkLogon

                # Logon as a Batch job / Logon as a Service
                $BatchLogon.Clear()
                [void]$BatchLogon.Add('Network Service')
                [void]$BatchLogon.Add('All Services')
                if ($null -ne $SG_Tier0ServiceAccount) {
                    [void]$BatchLogon.Add($SG_Tier0ServiceAccount)
                }
                $ServiceLogon.Clear()
                $ServiceLogon = $BatchLogon

                # Modify all rights in one shot
                $Splat = @{
                    GpoToModify      = 'C-Housekeeping-LOCKDOWN'
                    NetworkLogon     = $NetworkLogon
                    InteractiveLogon = $InteractiveLogon
                    BatchLogon       = $BatchLogon
                    ServiceLogon     = $ServiceLogon
                }

                Write-Verbose -Message 'Applying Housekeeping Lockdown GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion HOUSEKEEPING



                #region Infrastructure

                # Allow Logon Locally / Allow Logon through RDP/TerminalServices
                $InteractiveLogon.Clear()
                [void]$InteractiveLogon.Add($DomainAdmins)
                [void]$InteractiveLogon.Add($Administrators)
                if ($null -ne $SL_PISM) {
                    [void]$InteractiveLogon.Add($SL_PISM)
                }
                if ($null -ne $SG_Tier0Admins) {
                    [void]$InteractiveLogon.Add($SG_Tier0Admins)
                }
                $RemoteInteractiveLogon.Clear()
                $RemoteInteractiveLogon = $InteractiveLogon


                $ArrayList.Clear()
                [void]$ArrayList.Add($Administrators)
                if ($null -ne $SG_Tier0Admins) {
                    [void]$ArrayList.Add($SG_Tier0Admins)
                }
                if ($null -ne $SL_PISM) {
                    [void]$ArrayList.Add($SG_AdAdmins)
                }


                # Modify all rights in one shot
                $Splat = @{
                    GpoToModify            = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0OU.Name
                    InteractiveLogon       = $InteractiveLogon
                    RemoteInteractiveLogon = $RemoteInteractiveLogon
                    MachineAccount         = $ArrayList
                    Backup                 = $ArrayList
                    CreateGlobal           = @($Administrators, $SG_Tier0Admins, $SG_AdAdmins, 'LOCAL SERVICE', 'NETWORK SERVICE')
                    SystemTime             = @($Administrators, $SG_Tier0Admins, $SG_AdAdmins, 'LOCAL SERVICE')
                    TimeZone               = $ArrayList
                    CreatePagefile         = $ArrayList
                    CreateSymbolicLink     = $ArrayList
                    RemoteShutdown         = $ArrayList
                    Impersonate            = @(
                        $Administrators,
                        $SG_Tier0Admins,
                        $SG_AdAdmins,
                        'LOCAL SERVICE',
                        'NETWORK SERVICE',
                        'SERVICE'
                    )
                    IncreaseBasePriority   = $ArrayList
                    LoadDriver             = $ArrayList
                    AuditSecurity          = $ArrayList
                    SystemEnvironment      = $ArrayList
                    ManageVolume           = $ArrayList
                    ProfileSingleProcess   = $ArrayList
                    SystemProfile          = $ArrayList
                    Restore                = $ArrayList
                    Shutdown               = $ArrayList
                    TakeOwnership          = $ArrayList
                }

                Write-Verbose -Message 'Applying Infrastructure Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion Infrastructure


                #Region Tier0 Infrastructure

                # Allow Logon Locally / Allow Logon throug RDP/TerminalServices
                $InteractiveLogon.Clear()
                [void]$InteractiveLogon.Add($DomainAdmins)
                [void]$InteractiveLogon.Add($Administrators)
                if ($null -ne $SL_PISM) {
                    [void]$InteractiveLogon.Add($SL_PISM)
                }
                if ($null -ne $SG_Tier0Admins) {
                    [void]$InteractiveLogon.Add($SG_Tier0Admins)
                }
                $RemoteInteractiveLogon.Clear()
                $RemoteInteractiveLogon = $InteractiveLogon


                # Logon as a Batch job / Logon as a Service
                $BatchLogon.Clear()
                [void]$BatchLogon.Add('Network Service')
                [void]$BatchLogon.Add('All Services')
                if ($null -ne $SG_Tier0ServiceAccount) {
                    [void]$BatchLogon.Add($SG_Tier0ServiceAccount)
                }
                $ServiceLogon.Clear()
                $ServiceLogon = $BatchLogon

                # Modify all rights in one shot
                $Splat = @{
                    GpoToModify            = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0OU.Name
                    InteractiveLogon       = $InteractiveLogon
                    RemoteInteractiveLogon = $RemoteInteractiveLogon
                    BatchLogon             = $BatchLogon
                    ServiceLogon           = $ServiceLogon
                    RemoteShutdown         = $InteractiveLogon
                    SystemTime             = $InteractiveLogon
                    ChangeNotify           = $InteractiveLogon
                    ManageVolume           = $InteractiveLogon
                    SystemProfile          = $InteractiveLogon
                    Shutdown               = $InteractiveLogon
                }

                Write-Verbose -Message 'Applying Tier0 Infrastructure Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion Tier0 Infrastructure



                #region Tier1 Infrastructure

                # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
                $Splat = @{
                    GpoToModify            = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1OU.Name
                    InteractiveLogon       = @($SG_Tier1Admins, $Administrators)
                    RemoteInteractiveLogon = $SG_Tier1Admins
                    BatchLogon             = $SG_Tier1ServiceAccount
                    ServiceLogon           = $SG_Tier1ServiceAccount
                    RemoteShutdown         = $SG_Tier1Admins
                    SystemTime             = $SG_Tier1Admins
                    ChangeNotify           = $SG_Tier1Admins
                    ManageVolume           = $SG_Tier1Admins
                    SystemProfile          = $SG_Tier1Admins
                    Shutdown               = $SG_Tier1Admins
                }

                Write-Verbose -Message 'Applying Tier1 Infrastructure Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion Tier1 Infrastructure



                #region Tier2 Infrastructure

                # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
                $Splat = @{
                    GpoToModify            = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2OU.Name
                    InteractiveLogon       = @($SG_Tier2Admins, $Administrators)
                    RemoteInteractiveLogon = $SG_Tier2Admins
                    BatchLogon             = $SG_Tier2ServiceAccount
                    ServiceLogon           = $SG_Tier2ServiceAccount
                    RemoteShutdown         = $SG_Tier2Admins
                    SystemTime             = $SG_Tier2Admins
                    ChangeNotify           = $SG_Tier2Admins
                    ManageVolume           = $SG_Tier2Admins
                    SystemProfile          = $SG_Tier2Admins
                    Shutdown               = $SG_Tier2Admins
                }

                Write-Verbose -Message 'Applying Tier2 Infrastructure Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion Tier2 Infrastructure




                #region Staging Infrastructure

                # Allow Logon Locally / Allow Logon through RDP/TerminalServices
                $ArrayList.Clear()
                [void]$ArrayList.Add($DomainAdmins)
                [void]$ArrayList.Add($Administrators)
                if ($null -ne $SL_PISM) {
                    [void]$ArrayList.Add($SL_PISM)
                }
                if ($null -ne $SG_Tier0Admins) {
                    [void]$ArrayList.Add($SG_Tier0Admins)
                }
                $Splat = @{
                    GpoToModify            = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.name
                    InteractiveLogon       = $ArrayList
                    RemoteInteractiveLogon = $ArrayList
                    RemoteShutdown         = $ArrayList
                    SystemTime             = $ArrayList
                    ChangeNotify           = $ArrayList
                    ManageVolume           = $ArrayList
                    SystemProfile          = $ArrayList
                    Shutdown               = $ArrayList
                }

                Write-Verbose -Message 'Applying Staging Infrastructure Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion Staging Infrastructure



                #region Staging PAWs

                # Allow Logon Locally / Allow Logon through RDP/TerminalServices
                $Splat = @{
                    GpoToModify            = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name
                    InteractiveLogon       = @($SL_PAWM, $Administrators)
                    RemoteInteractiveLogon = $SL_PAWM
                    RemoteShutdown         = $SL_PAWM
                    SystemTime             = $SL_PAWM
                    ChangeNotify           = $SL_PAWM
                    ManageVolume           = $SL_PAWM
                    SystemProfile          = $SL_PAWM
                    Shutdown               = $SL_PAWM
                }

                Write-Verbose -Message 'Applying Staging PAWs Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion Staging PAWs




                #region Tier0 PAWs

                # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
                # Deny Allow Logon Locally / Deny Allow Logon through RDP/TerminalServices
                # Deny Logon as a Batch job / Deny Logon as a Service

                $Splat = @{
                    GpoToModify                = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name
                    InteractiveLogon           = @($SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminName)
                    RemoteInteractiveLogon     = @($SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminName)
                    BatchLogon                 = $SG_Tier0ServiceAccount
                    ServiceLogon               = $SG_Tier0ServiceAccount
                    DenyInteractiveLogon       = @($SG_Tier1Admins, $SG_Tier2Admins)
                    DenyRemoteInteractiveLogon = @($SG_Tier1Admins, $SG_Tier2Admins)
                    DenyBatchLogon             = @($SG_Tier1ServiceAccount, $SG_Tier2ServiceAccount)
                    DenyServiceLogon           = @($SG_Tier1ServiceAccount, $SG_Tier2ServiceAccount)
                    RemoteShutdown             = @($SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminName)
                    SystemTime                 = @($SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminName)
                    ChangeNotify               = @($SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminName)
                    ManageVolume               = @($SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminName)
                    SystemProfile              = @($SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminName)
                    Shutdown                   = @($SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminName)
                }

                Write-Verbose -Message 'Applying Tier0 PAWs Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion Tier0 PAWs



                #region Tier1 PAWs

                # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
                # Deny Allow Logon Locally / Deny Allow Logon through RDP/TerminalServices
                # Deny Logon as a Batch job / Deny Logon as a Service
                $Splat = @{
                    GpoToModify                = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name
                    InteractiveLogon           = @($SG_Tier1Admins, $Administrators)
                    RemoteInteractiveLogon     = $SG_Tier1Admins
                    BatchLogon                 = $SG_Tier1ServiceAccount
                    ServiceLogon               = $SG_Tier1ServiceAccount
                    DenyInteractiveLogon       = @($SG_Tier0Admins, $SG_Tier2Admins)
                    DenyRemoteInteractiveLogon = @($SG_Tier0Admins, $SG_Tier2Admins)
                    DenyBatchLogon             = @($SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount)
                    DenyServiceLogon           = @($SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount)
                    RemoteShutdown             = $SG_Tier1Admins
                    SystemTime                 = $SG_Tier1Admins
                    ChangeNotify               = $SG_Tier1Admins
                    ManageVolume               = $SG_Tier1Admins
                    SystemProfile              = $SG_Tier1Admins
                    Shutdown                   = $SG_Tier1Admins
                }

                Write-Verbose -Message 'Applying Tier1 PAWs Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                #endregion Tier1 PAWs



                #region Tier2 PAWs

                # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
                # Deny Allow Logon Locally / Deny Allow Logon through RDP/TerminalServices
                # Deny Logon as a Batch job / Deny Logon as a Service
                $Splat = @{
                    GpoToModify                = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name
                    InteractiveLogon           = @($SG_Tier2Admins, $Administrators)
                    RemoteInteractiveLogon     = $SG_Tier2Admins
                    BatchLogon                 = $SG_Tier2ServiceAccount
                    ServiceLogon               = $SG_Tier2ServiceAccount
                    DenyInteractiveLogon       = @($SG_Tier0Admins, $SG_Tier1Admins)
                    DenyRemoteInteractiveLogon = @($SG_Tier0Admins, $SG_Tier1Admins)
                    DenyBatchLogon             = @($SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount)
                    DenyServiceLogon           = @($SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount)
                    RemoteShutdown             = $SG_Tier2Admins
                    SystemTime                 = $SG_Tier2Admins
                    ChangeNotify               = $SG_Tier2Admins
                    ManageVolume               = $SG_Tier2Admins
                    SystemProfile              = $SG_Tier2Admins
                    Shutdown                   = $SG_Tier2Admins
                }

                Write-Verbose -Message 'Applying Tier2 PAWs Baseline GPO settings'
                Set-GpoPrivilegeRight @Splat

                Write-Verbose -Message 'Admin/Tier0 Baseline GPO configurations completed successfully'

                #endregion Tier2 PAWs
            } catch {
                Write-Error -Message ('Error configuring Admin/Tier0 Baseline GPO: {0}' -f $_.Exception.Message)
            }
        } #end If ShouldProcess

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Configure Baseline GPO Restrictions.'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end End
} #end Function New-Tier0GpoRestriction
