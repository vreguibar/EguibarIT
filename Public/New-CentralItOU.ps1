function New-CentralItOu {
    <#
        .SYNOPSIS
            Creates and configures a complete Active Directory Tiered Administration model.

        .DESCRIPTION
            Creates and configures the complete Active Directory tiered administration model including:
            - Organizational Units structure following Microsoft's tier model
            - Security groups for delegated administration
            - Group Policy Objects (GPOs) with security baselines
            - Fine-grained password policies
            - Kerberos authentication policies and silos
            - Group Managed Service Accounts (gMSAs)
            - Rights delegation model across all tiers
            - Optional enterprise components (Exchange, DFS, PKI, AGPM, LAPS, DHCP)

            This function implements Microsoft's recommended three-tier administration model:
            - Tier 0: Domain Controllers and critical infrastructure
            - Tier 1: Servers and server administrators
            - Tier 2: User workstations and standard users

            The implementation provides:
            - Least-privilege security model
            - Isolated administration boundaries between tiers
            - Clear segregation of duties
            - Enhanced security for privileged accounts
            - Comprehensive auditing and monitoring

        .PARAMETER ConfigXMLFile
            Full path to the XML configuration file containing all naming conventions,
            OU structure, and security settings.
            The XML file must contain required elements: Admin, Servers, Sites, and NC sections.

        .PARAMETER CreateExchange
            If present, creates all Exchange-related objects, containers and delegations.
            Requires valid Exchange configuration in the XML file.

        .PARAMETER CreateDfs
            If present, creates all DFS-related objects, containers and delegations.
            Requires valid DFS configuration in the XML file.

        .PARAMETER CreateCa
            If present, creates Certificate Authority (PKI) objects and delegations.
            Requires valid PKI configuration in the XML file.

        .PARAMETER CreateAGPM
            If present, creates Advanced Group Policy Management objects and delegations.
            Requires valid AGPM configuration in the XML file.

        .PARAMETER CreateLAPS
            If present, creates Local Administrator Password Solution objects and delegations.
            Requires valid LAPS configuration in the XML file.

        .PARAMETER CreateDHCP
            If present, creates DHCP-related objects, containers and delegations.
            Requires valid DHCP configuration in the XML file.

        .PARAMETER DMscripts
            Path to all supporting scripts and files needed by this function.
            Must contain a SecTmpl subfolder with required templates.
            Default is C:\PsScripts\

        .EXAMPLE
            New-CentralItOu -ConfigXMLFile 'C:\PsScripts\Configuration.xml'

            Creates the basic tier model structure using the specified configuration file.

        .EXAMPLE
            New-CentralItOu -ConfigXMLFile 'C:\PsScripts\Configuration.xml' -CreateLAPS -CreateDHCP

            Creates the tier model structure including LAPS and DHCP components.

        .EXAMPLE
            # Create parameter hashtable
            $Params = @{
                ConfigXMLFile = 'C:\PsScripts\Config.xml'
                CreateExchange = $true
                CreateDfs = $true
                CreateCa = $true
                DMscripts = 'D:\AdminScripts\'
                Verbose = $true
            }

            # Create the complete AD structure
            New-CentralItOu @Params

            Creates a comprehensive tier model with Exchange, DFS and PKI components using
            a custom scripts directory and verbose output.

        .INPUTS
            [System.IO.FileInfo]
            You can pipe the path to the XML configuration file to this function.

        .OUTPUTS
            [String]
            Returns completion status message.

        .NOTES
            Used Functions:
                Name                                  ║ Module/Namespace
            ═══════════════════════════════════════╬════════════════════════
            Import-MyModule                        ║ EguibarIT
            New-Tier0CreateOU                      ║ EguibarIT
            New-Tier0MoveObject                    ║ EguibarIT
            New-Tier0AdminAccount                  ║ EguibarIT
            New-Tier0AdminGroup                    ║ EguibarIT
            New-Tier0gMSA                          ║ EguibarIT
            New-Tier0FineGrainPasswordPolicy       ║ EguibarIT
            New-Tier0NestingGroup                  ║ EguibarIT
            New-Tier0Redirection                   ║ EguibarIT
            New-Tier0Delegation                    ║ EguibarIT
            New-Tier0Gpo                           ║ EguibarIT
            New-Tier0AuthPolicyAndSilo             ║ EguibarIT
            New-Tier0GpoRestriction                ║ EguibarIT
            New-Tier1                              ║ EguibarIT
            New-Tier2                              ║ EguibarIT
            New-ExchangeObject                     ║ EguibarIT
            New-DfsObject                          ║ EguibarIT
            New-CaObject                           ║ EguibarIT
            New-AGPMObject                         ║ EguibarIT
            New-LAPSobject                         ║ EguibarIT
            New-DHCPobject                         ║ EguibarIT
            Set-AdAclMngPrivilegedAccount          ║ EguibarIT
            Set-AdAclMngPrivilegedGroup            ║ EguibarIT
            Get-FunctionDisplay                    ║ EguibarIT
            Get-ADUser                             ║ ActiveDirectory
            Get-ADGroup                            ║ ActiveDirectory

        .NOTES
            Version:         1.5
            DateModified:    25/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models

        .COMPONENT
            Active Directory

        .ROLE
            System Administrator

        .FUNCTIONALITY
            Active Directory, Security, Tier Model
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'Default'
    )]
    [OutputType([String])]

    Param (
        # PARAM1 full path to the configuration.xml file
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
                        $null -eq $xml.n.Sites -or
                        $null -eq $xml.n.NC) {
                        throw 'XML file is missing required elements (Admin, Servers, Sites or NC section)'
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

        # Param2 If present It will create all needed Exchange objects, containers and delegations
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects, containers and delegations.',
            Position = 1)]
        [Alias('Exchange')]
        [switch]
        $CreateExchange,

        # Param3 Create DFS Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed DFS objects, containers and delegations.',
            Position = 2)]
        [Alias('DFS', 'DistributedFileSystem')]
        [switch]
        $CreateDfs,

        # Param4 Create CA (PKI) Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Certificate Authority (PKI) objects, containers and delegations.',
            Position = 3)]
        [Alias('PKI', 'CA', 'CertificateAuthority')]
        [switch]
        $CreateCa,

        # Param5 Create AGPM Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed AGPM objects, containers and delegations.',
            Position = 4)]
        [Alias('GPM')]
        [switch]
        $CreateAGPM,

        # Param6 Create LAPS Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed LAPS objects, containers and delegations.',
            Position = 5)]
        [switch]
        $CreateLAPS,

        # Param7 Create DHCP Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed DHCP objects, containers and delegations.',
            Position = 6)]
        [switch]
        $CreateDHCP,

        # Param8 Location of all scripts & files
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
            Position = 7)]
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


        # Load the XML configuration file
        try {
            $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message "Error reading XML file: $($_.Exception.Message)"
            throw
        }


        # Naming conventions hashtable
        $NC = @{'sl' = $confXML.n.NC.LocalDomainGroupPreffix
            'sg'     = $confXML.n.NC.GlobalGroupPreffix
            'su'     = $confXML.n.NC.UniversalGroupPreffix
            'Delim'  = $confXML.n.NC.Delimiter
            'T0'     = $confXML.n.NC.AdminAccSufix0
            'T1'     = $confXML.n.NC.AdminAccSufix1
            'T2'     = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM.name, $NC['T0'])
        # SG_PAWM_T0




        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)


        $Splat = @{
            Name  = 'SG_Operations'
            Value = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.Operations.Name)
            Scope = 'Global'
            Force = $true
        }
        New-Variable @Splat
        $Splat = @{
            Name  = 'SG_ServerAdmins'
            Value = ('SG{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name)
            Scope = 'Global'
            Force = $true
        }
        New-Variable @Splat

        $Splat = @{
            Name  = 'SL_SvrAdmRight'
            Value = ('SL{0}{1}' -f $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name)
            Scope = 'Global'
            Force = $true
        }
        New-Variable @Splat
        $Splat = @{
            Name  = 'SL_SvrOpsRight'
            Value = ('SL{0}{1}' -f $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.Name)
            Scope = 'Global'
            Force = $true
        }
        New-Variable @Splat

        #endregion Files-Splatting


        #region Users
        $AdminName = $confXML.n.Admin.users.Admin.Name
        $newAdminName = $confXML.n.Admin.users.NEWAdmin.Name
        $GuestNewName = $confXML.n.Admin.users.Guest.Name


        # Get the AD Objects by Well-Known SID
        try {
            # Administrator
            $AdminName = Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
            # Administrators
            $Administrators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-544' }
            # Domain Admins
            $DomainAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-512' }
            # Enterprise Admins
            $EnterpriseAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-519' }
            # Schema Admins
            $SchemaAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-518' }
            # DomainControllers
            $DomainControllers = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-516' }
            # RODC
            $RODC = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-521' }
            # Group Policy Creators Owner
            $GPOCreatorsOwner = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-520' }
            # Denied RODC Password Replication Group
            $DeniedRODC = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-572' }
            # Cryptographic Operators
            $CryptoOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-569' }
            # Event Log Readers
            $EvtLogReaders = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-573' }
            # Performance Log Users
            $PerfLogUsers = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-559' }
            # Performance Monitor Users
            $PerfMonitorUsers = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-558' }
            # Remote Desktop Users
            $RemoteDesktopUsers = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-555' }
            # Server Operators
            $ServerOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-549' }
            # Remote Management Users
            $RemoteMngtUsers = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-580' }
            # Account Operators
            $AccountOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-548' }
            # Network Configuration Operators
            $NetConfOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-556' }

            # DNS Administrators
            $DnsAdmins = Get-ADGroup -Identity 'DnsAdmins'
            # Protected Users
            $ProtectedUsers = Get-ADGroup -Identity 'Protected Users'

        } catch {
            Write-Error -Message 'One or some of the User/Groups was not able to be retrieved. Please check'
        } #end Try-Catch
        #endregion Users



        # Organizational Units Names
        # Iterate all OUs within Admin
        Foreach ($node in $confXML.n.Admin.OUs.ChildNodes) {
            $Splat = @{
                Name        = "$($Node.LocalName)"
                Value       = $Node.Name
                Description = $Node.Description
                Option      = 'ReadOnly'
                Scope       = 'Global'
                Force       = $true
            }
            # Create variable for current OUs name, Using the XML LocalName of the node for the variable
            New-Variable @Splat
        }

        #region DistinguishedNames
        # Organizational Units Distinguished Names

        #region Tier0DistinguishedNames
        # Domain Controllers DistinguishedName
        $DCsOuDn = ('OU=Domain Controllers,{0}' -f $Variables.AdDn)

        # Admin Area

        # IT Admin OU Distinguished Name
        $Splat = @{
            Name   = 'ItAdminOuDn'
            Value  = 'OU={0},{1}' -f $ItAdminOu, $Variables.AdDn
            Option = 'ReadOnly'
            Scope  = 'Global'
            Force  = $true
        }
        New-Variable @Splat

        # It Admin Users OU Distinguished Name
        $ItAdminAccountsOuDn = 'OU={0},{1}' -f $ItAdminAccountsOu, $ItAdminOuDn

        # It Admin Groups OU Distinguished Name
        $ItAdminGroupsOuDn = 'OU={0},{1}' -f $ItAdminGroupsOu, $ItAdminOuDn

        # IT Administration purposes, containing groups used to grant local server Admin access.
        $ItAdminSrvGroupsOUDn = 'OU={0},{1}' -f $ItAdminSrvGroupsOU, $ItAdminOuDn

        # It Privileged Groups OU Distinguished Name
        $ItPrivGroupsOUDn = 'OU={0},{1}' -f $ItPrivGroupsOU, $ItAdminOuDn

        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

        # It Admin ServiceAccount OU Distinguished Name
        $ItServiceAccountsOuDn = 'OU={0},{1}' -f $ItServiceAccountsOu, $ItAdminOuDn

        # It Admin T0SA OU Distinguished Name
        $ItSAT0OuDn = 'OU={0},{1}' -f $ItSAT0Ou, $ItServiceAccountsOuDn

        # It Admin T0SA OU Distinguished Name
        $ItSAT1OuDn = 'OU={0},{1}' -f $ItSAT1Ou, $ItServiceAccountsOuDn

        # It Admin T0SA OU Distinguished Name
        $ItSAT2OuDn = 'OU={0},{1}' -f $ItSAT2Ou, $ItServiceAccountsOuDn

        # It PAW OU Distinguished Name
        $ItPawOuDn = 'OU={0},{1}' -f $ItPawOu, $ItAdminOuDn

        # It PAW T0 OU Distinguished Name
        $ItPawT0OuDn = 'OU={0},{1}' -f $ItPawT0Ou, $ItPawOuDn

        # It PAW T1 OU Distinguished Name
        $ItPawT1OuDn = 'OU={0},{1}' -f $ItPawT1Ou, $ItPawOuDn

        # It PAW T2 OU Distinguished Name
        $ItPawT2OuDn = 'OU={0},{1}' -f $ItPawT2Ou, $ItPawOuDn

        # It PAW Staging OU Distinguished Name
        $ItPawStagingOuDn = 'OU={0},{1}' -f $ItPawStagingOu, $ItPawOuDn

        # It Infrastructure Servers OU Distinguished Name
        $ItInfraOuDn = 'OU={0},{1}' -f $ItInfraOu, $ItAdminOuDn

        # It Infrastructure Servers T0 OU Distinguished Name
        $ItInfraT0OuDn = 'OU={0},{1}' -f $ItInfraT0Ou, $ItInfraOuDn

        # It Infrastructure Servers T1 OU Distinguished Name
        $ItInfraT1OuDn = 'OU={0},{1}' -f $ItInfraT1Ou, $ItInfraOuDn

        # It Infrastructure Servers T2 OU Distinguished Name
        $ItInfraT2OuDn = 'OU={0},{1}' -f $ItInfraT2Ou, $ItInfraOuDn

        # It Infrastructure Servers Staging OU Distinguished Name
        $ItInfraStagingOuDn = 'OU={0},{1}' -f $ItInfraStagingOu, $ItInfraOuDn

        # It HOUSEKEEPING OU Distinguished Name
        $ItHousekeepingOuDn = 'OU={0},{1}' -f $ItHousekeepingOu, $ItAdminOuDn

        #endregion Tier0DistinguishedNames


        # Servers Area

        # Servers OU
        New-Variable -Name 'ServersOu' -Value $confXML.n.Servers.OUs.ServersOU.Name -Option ReadOnly -Scope Global -Force
        # Servers OU Distinguished Name
        $ServersOuDn = 'OU={0},{1}' -f $ServersOu, $Variables.AdDn



        # Sites Area

        # Sites OU
        New-Variable -Name 'SitesOu' -Value $confXML.n.Sites.OUs.SitesOU.name -Option ReadOnly -Scope Global -Force
        # Sites OU Distinguished Name
        $SitesOuDn = 'OU={0},{1}' -f $SitesOu, $Variables.AdDn

        # Sites GLOBAL OU
        $SitesGlobalOu = $confXML.n.Sites.OUs.OuSiteGlobal.name
        # Sites GLOBAL OU Distinguished Name
        $SitesGlobalOuDn = 'OU={0},{1}' -f $SitesGlobalOu, $SitesOuDn

        # Sites GLOBAL GROUPS OU
        $SitesGlobalGroupOu = $confXML.n.Sites.OUs.OuSiteGlobalGroups.name
        # Sites GLOBAL GROUPS OU Distinguished Name
        $SitesGlobalGroupOuDn = 'OU={0},{1}' -f $SitesGlobalGroupOu, $SitesGlobalOuDn

        # Sites GLOBAL APPACCUSERS OU
        $SitesGlobalAppAccUserOu = $confXML.n.Sites.OUs.OuSiteGlobalAppAccessUsers.name
        # Sites GLOBAL APPACCUSERS OU Distinguished Name
        $SitesGlobalAppAccUserOuDn = 'OU={0},{1}' -f $SitesGlobalAppAccUserOu, $SitesGlobalOuDn

        #endregion DistinguishedNames



        # Quarantine OU for PCs
        $Splat = @{
            Name   = 'ItQuarantinePcOu'
            Value  = $confXML.n.Admin.OUs.ItNewComputersOU.name
            Option = 'ReadOnly'
            Scope  = 'Global'
            Force  = $true
        }
        New-Variable @Splat
        # PCs Quarantine OU Distinguished Name
        $ItQuarantinePcOuDn = 'OU={0},{1}' -f $ItQuarantinePcOu, $Variables.AdDn

        # Quarantine OU for Users
        $Splat = @{
            Name   = 'ItQuarantineUserOu'
            Value  = $confXML.n.Admin.OUs.ItNewUsersOU.name
            Option = 'ReadOnly'
            Scope  = 'Global'
            Force  = $true
        }
        New-Variable @Splat
        # Users Quarantine OU Distinguished Name
        $ItQuarantineUserOuDn = 'OU={0},{1}' -f $ItQuarantineUserOu, $Variables.AdDn

        #endregion Declarations
        ################################################################################
    } #end Begin

    Process {

        $Splat = @{
            ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
            DMscripts     = $PSBoundParameters['DMscripts']
        }

        if ($PSCmdlet.ShouldProcess('Active Directory', 'Create full tier model structure')) {

            ###############################################################################
            # Create IT Admin and Sub OUs
            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Create Admin Area and related structure...')

            # Create the IT Admin OU and sub OUs
            New-Tier0CreateOU @Splat



            ###############################################################################
            # Move Built-In Admin user & Groups (Builtin OU groups can't be moved)

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Moving objects to Admin (Tier 0)...')

            New-Tier0MoveObject @Splat



            ###############################################################################
            # Creating Secured Admin accounts

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating and securing Admin accounts...')

            New-Tier0AdminAccount @Splat


            ###############################################################################
            # Create Admin groups

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Admin groups...')

            New-Tier0AdminGroup @Splat



            ###############################################################################
            # Create Group Managed Service Account

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Create Group Managed Service Account')

            New-Tier0gMSA @Splat



            ###############################################################################
            # Create a New Fine Grained Password Policies

            Write-Verbose -Message ($Variables.NewRegionMessage -f
                'Create a New Fine Grained Password Policy for Admins Accounts...')

            New-Tier0FineGrainPasswordPolicy @Splat



            ###############################################################################
            # Nesting Groups


            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Nesting groups...')

            New-Tier0NestingGroup



            ###############################################################################
            # Enabling Management Accounts to Modify the Membership of Protected Groups

            Write-Verbose -Message ($Variables.NewRegionMessage -f
                'Enabling Management Accounts to Modify the Membership of Protected Groups...'
            )

            # Enable PUM to manage Privileged Accounts (Reset PWD, enable/disable Administrator built-in account)
            Set-AdAclMngPrivilegedAccount -Group $SL_PUM

            # Enable PGM to manage Privileged Groups (Administrators, Domain Admins...)
            Set-AdAclMngPrivilegedGroup -Group $SL_PGM





            ###############################################################################
            # redirect Users & Computers containers

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'redirect Users & Computers containers...')

            New-Tier0Redirection @Splat



            ###############################################################################
            # Delegation to ADMIN area (Tier 0)

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Delegate Admin Area (Tier 0)...')

            New-Tier0Delegation @Splat



            ###############################################################################
            # Create Baseline GPO

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Baseline GPOs and configure them accordingly...')

            New-Tier0Gpo @Splat

            # Configure Kerberos Claims and Authentication Policies/Silos

            New-Tier0AuthPolicyAndSilo @Splat




            ###############################################################################
            # Configure GPO Restrictions based on Tier Model

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Configure GPO Restrictions based on Tier Model...')

            New-Tier0GpoRestriction @Splat



            ###############################################################################
            # SERVERS OU (area)

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Servers Area (Tier 1)...')

            New-Tier1 @Splat



            ###############################################################################
            # Create Sites OUs (Area)

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Sites Area (Tier 2)...')

            New-Tier2 @Splat




            ###############################################################################
            # Check if Exchange objects have to be created. Process if TRUE
            if ($PSBoundParameters['CreateExchange']) {

                Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Exchange On-Prem objects and delegations')

                # Get the Config.xml file
                $param = @{
                    ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                    verbose       = $true
                }

                New-ExchangeObject @param
            }

            ###############################################################################
            # Check if DFS objects have to be created. Process if TRUE
            if ($PSBoundParameters['CreateDfs']) {

                Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating DFS objects and delegations')
                # Get the Config.xml file
                $param = @{
                    ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                    verbose       = $true
                }
                New-DfsObject @param
            }

            ###############################################################################
            # Check if Certificate Authority (PKI) objects have to be created. Process if TRUE
            if ($PSBoundParameters['CreateCa']) {

                Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating CA Services, objects and delegations')

                New-CaObject -ConfigXMLFile $PSBoundParameters['ConfigXMLFile']
            }

            ###############################################################################
            # Check if Advanced Group Policy Management (AGPM) objects have to be created. Process if TRUE
            if ($PSBoundParameters['CreateAGPM']) {

                try {
                    Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating AGPM objects and delegations')

                    # Create parameter hashtable for AGPM
                    [hashtable]$AgpmParams = @{
                        ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                        Verbose       = $VerbosePreference -eq 'Continue'
                    }

                    # Execute AGPM configuration
                    New-AGPMObject $AgpmParams

                } catch {

                    Write-Error -Message ('Failed to create AGPM objects: {0}' -f $_.Exception.Message)

                } #end Try-Catch

            } #end If

            ###############################################################################
            # Check if MS Local Administrator Password Service (LAPS) is to be used. Process if TRUE
            if ($PSBoundParameters['CreateLAPS']) {
                try {

                    Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating LAPS objects and delegations')

                    # Create parameter hashtable for LAPS
                    [hashtable]$LapsParams = @{
                        ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                        Verbose       = $VerbosePreference -eq 'Continue'
                    }

                    # Execute LAPS configuration
                    New-LAPSobject @LapsParams

                } catch {

                    Write-Error -Message ('Failed to create LAPS objects: {0}' -f $_.Exception.Message)

                } #end Try-Catch

            } #end If

            ###############################################################################
            # Check if DHCP is to be used. Process if TRUE
            if ($PSBoundParameters['CreateDHCP']) {

                try {
                    Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating DHCP objects and delegations')

                    # Create parameter hashtable for DHCP
                    [hashtable]$DhcpParams = @{
                        ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                        Verbose       = $VerbosePreference -eq 'Continue'
                    }

                    # Execute DHCP configuration
                    New-DHCPobject @DhcpParams

                } catch {

                    Write-Error -Message ('Failed to create DHCP objects: {0}' -f $_.Exception.Message)

                } #end Try-Catch

            } #end If

        } #end If ShouldProcess

    } #end Process

    End {

        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating Tier0 central IT OU structure and delegations.'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end End

} #end Function New-CentralItOu
