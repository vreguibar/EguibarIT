function New-CentralItOu {
    <#
        .Synopsis
            Create Central OU and additional Tier 0 infrastructure OUs
        .DESCRIPTION
            Create Central OU including sub-OUs, secure them accordingly, move built-in objects
            and secure them, create needed groups and secure them, make nesting and delegations
            and finally create PSO and delegate accordingly.
            This function is mainly a wrapper used to create Tier0 objects
        .EXAMPLE
            New-CentralItOu -ConfigXMLFile 'C:\PsScripts\Configuration.xml'
        .EXAMPLE
            # Get the Config.xml file
            $param = @{
                ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve
                verbose = $true
            }

            # Check if Exchange needs to be created
            if($confXML.N.Domains.Prod.CreateExContainers) {
                $param.add("CreateExchange", $true)
            }

            # Check if DFS needs to be created
            if($confXML.N.Domains.Prod.CreateDFS) {
                $param.add("CreateDFS", $true)
            }

            # Check if CA needs to be created
            if($confXML.N.Domains.Prod.CreateCa) {
                $param.add("CreateCa", $true)
            }

            # Check if LAPS needs to be created
            if($confXML.N.Domains.Prod.CreateLAPS) {
                $param.add("CreateLAPS", $true)
            }

            # Check if DHCP needs to be created
            if($confXML.N.Domains.Prod.CreateDHCP) {
                $param.add("CreateDHCP", $true)
            }

            #Create Central OU Structure
            New-CentralItOu @param

        .PARAMETER ConfigXMLFile
            [STRING] Full path to the configuration.xml file
        .PARAMETER CreateExchange
            [SWITCH] If present It will create all needed Exchange objects, containers and delegations
        .PARAMETER CreateDfs
            [SWITCH] If present It will create all needed DFS objects, containers and delegations
        .PARAMETER CreateCa
            [SWITCH] If present It will create all needed Certificate Authority (PKI) objects, containers and delegations
        .PARAMETER CreateAGPM
            [SWITCH] If present It will create all needed AGPM objects, containers and delegations
        .PARAMETER CreateLAPS
            [SWITCH] If present It will create all needed LAPS objects, containers and delegations
        .PARAMETER CreateDHCP
            [SWITCH] If present It will create all needed DHCP objects, containers and delegations
        .PARAMETER DMscripts
            [String] Full path to the Delegation Model Scripts Directory
        .NOTES
            This function relies on Config.xml file.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AdAclDelegateComputerAdmin         | EguibarIT
                Add-AdGroupNesting                     | EguibarIT
                Get-CurrentErrorToDisplay              | EguibarIT
                New-AdDelegatedGroup                   | EguibarIT
                New-DelegateAdGpo                      | EguibarIT
                New-DelegateAdOU                       | EguibarIT
                Set-AdAclDelegateUserAdmin             | EguibarIT
                Set-AdAclDelegateGalAdmin              | EguibarIT
                Remove-Everyone                        | EguibarIT.DelegationPS
                Remove-PreWin2000                      | EguibarIT.DelegationPS
                Set-AdAclChangeGroup                   | EguibarIT.DelegationPS
                Set-AdAclChangeOU                      | EguibarIT.DelegationPS
                Set-AdAclChangeSite                    | EguibarIT.DelegationPS
                Set-AdAclChangeSiteLink                | EguibarIT.DelegationPS
                Set-AdAclChangeSubnet                  | EguibarIT.DelegationPS
                Set-AdAclChangeUserPassword            | EguibarIT.DelegationPS
                Set-AdAclComputerPersonalInfo          | EguibarIT.DelegationPS
                Set-AdAclComputerPublicInfo            | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteComputer          | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteContact           | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGMSA              | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGPO               | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGroup             | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteMSA               | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteOU                | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteOU                | EguibarIT.DelegationPS
                Set-AdAclCreateDeletePrintQueue        | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteSite              | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteSiteLink          | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteSubnet            | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteUser              | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteUser              | EguibarIT.DelegationPS
                Set-AdAclGPoption                      | EguibarIT.DelegationPS
                Set-AdAclLinkGPO                       | EguibarIT.DelegationPS
                Set-AdAclMngPrivilegedAccounts         | EguibarIT.DelegationPS
                Set-AdAclMngPrivilegedGroups           | EguibarIT.DelegationPS
                Set-AdAclResetUserPassword             | EguibarIT.DelegationPS
                Set-AdAclUserAccountRestriction        | EguibarIT.DelegationPS
                Set-AdAclUserGroupMembership           | EguibarIT.DelegationPS
                Set-AdAclUserLogonInfo                 | EguibarIT.DelegationPS
                Set-AdDirectoryReplication             | EguibarIT.DelegationPS
                Set-AdInheritance                      | EguibarIT.DelegationPS
                Set-CreateDeleteInetOrgPerson          | EguibarIT.DelegationPS
                Set-DeleteOnlyComputer                 | EguibarIT.DelegationPS
                Set-GpoPrivilegeRight                 | EguibarIT.DelegationPS
                Add-ADFineGrainedPasswordPolicySubject | ActiveDirectory
                Get-ADFineGrainedPasswordPolicy        | ActiveDirectory
                Get-ADGroup                            | ActiveDirectory
                Get-ADServiceAccount                   | ActiveDirectory
                Get-AdUser                             | ActiveDirectory
                Move-ADObject                          | ActiveDirectory
                New-ADFineGrainedPasswordPolicy        | ActiveDirectory
                New-ADServiceAccount                   | ActiveDirectory
                New-AdUser                             | ActiveDirectory
                Set-ADObject                           | ActiveDirectory
                Set-AdUser                             | ActiveDirectory
                Import-GPO                             | GroupPolicy
                Add-KdsRootKey                         | Kds

        .NOTES
            Version:         1.3
            DateModified:    21/Oct/2021
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
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
                    throw 'The Path argument must be a file. Folder paths are not allowed.'
                }
                if ($_ -notmatch '(\.xml)') {
                    throw 'The file specified in the path argument must be of type XML'
                }
                return $true
            })]
        [PSDefaultValue(Help = 'Default Value is "C:\PsScripts\Config.xml"')]
        [System.IO.FileInfo]
        $ConfigXMLFile = 'C:\PsScripts\Config.xml',

        # Param2 If present It will create all needed Exchange objects, containers and delegations
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects, containers and delegations.',
            Position = 1)]
        [switch]
        $CreateExchange,

        # Param3 Create DFS Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed DFS objects, containers and delegations.',
            Position = 2)]
        [switch]
        $CreateDfs,

        # Param4 Create CA (PKI) Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Certificate Authority (PKI) objects, containers and delegations.',
            Position = 3)]
        [switch]
        $CreateCa,

        # Param5 Create AGPM Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed AGPM objects, containers and delegations.',
            Position = 4)]
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
        [PSDefaultValue(Help = 'Default Value is "C:\PsScripts\"')]
        [string]
        $DMscripts = 'C:\PsScripts\'
    )

    Begin {

        $error.clear()

        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports
        # These modules must be imported without checking and handling.
        Import-MyModule -Name 'ServerManager' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false


        ##############################
        # Variables Definition

        #region Files-Splatting
        try {
            # Check if Config.xml file is loaded. If not, proceed to load it.
            If (-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If (Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        } catch {
            Write-Error -Message 'Error when reading XML file'
            throw
        } # End Try

        # Read the value from parsed SWITCH parameters.
        try {
            # Check if CreateExchange parameter is parsed.
            If ($PSBoundParameters['CreateExchange']) {
                # If parameter is parsed, then make variable TRUE
                $CreateExchange = $True
            } else {
                # Otherwise variable is FALSE
                $CreateExchange = $False
            }

            # Check if CreateDfs parameter is parsed.
            If ($PSBoundParameters['CreateDfs']) {
                # If parameter is parsed, then make variable TRUE
                $CreateDfs = $True
            } else {
                # Otherwise variable is FALSE
                $CreateDfs = $False
            }

            # Check if CreateCa parameter is parsed.
            If ($PSBoundParameters['CreateCa']) {
                # If parameter is parsed, then make variable TRUE
                $CreateCa = $True
            } else {
                # Otherwise variable is FALSE
                $CreateCa = $False
            }

            # Check if CreateAGPM  parameter is parsed.
            If ($PSBoundParameters['CreateAGPM']) {
                # If parameter is parsed, then make variable TRUE
                $CreateAGPM = $True
            } else {
                # Otherwise variable is FALSE
                $CreateAGPM = $False
            }

            # Check if CreateLAPS  parameter is parsed.
            If ($PSBoundParameters['CreateLAPS']) {
                # If parameter is parsed, then make variable TRUE
                $CreateLAPS = $True
            } else {
                # Otherwise variable is FALSE
                $CreateLAPS = $False
            }
        } catch {
            Write-Error -Message 'Error when reading parameters'
            throw
        } # End Try



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




        [String]$CurrentDC = '{0}.{1}' -f (($env:LOGONSERVER).replace('\', '')), $env:USERDNSDOMAIN



        # parameters variable for splatting CMDlets
        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        $ArrayList = [System.Collections.ArrayList]::New()

        $AllGroups = [System.Collections.Generic.HashSet[object]]::New()


        $Splat = @{
            Name  = 'SG_Operations'
            Value = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.Operations.Name)
            Force = $true
        }
        New-Variable @Splat
        $Splat = @{
            Name  = 'SG_ServerAdmins'
            Value = ('SG{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name)
            Force = $true
        }
        New-Variable @Splat

        $Splat = @{
            Name  = 'SL_SvrAdmRight'
            Value = ('SL{0}{1}' -f $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name)
            Force = $true
        }
        New-Variable @Splat
        $Splat = @{
            Name  = 'SL_SvrOpsRight'
            Value = ('SL{0}{1}' -f $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.Name)
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
            Write-Error -Message 'One or some of the User/Groups was not able to be retrived. Please check'
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
        New-Variable -Name 'ItAdminOuDn' -Value ('OU={0},{1}' -f $ItAdminOu, $Variables.AdDn) -Option ReadOnly -Force

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
        New-Variable -Name 'ServersOu' -Value $confXML.n.Servers.OUs.ServersOU.Name -Option ReadOnly -Force
        # Servers OU Distinguished Name
        $ServersOuDn = 'OU={0},{1}' -f $ServersOu, $Variables.AdDn



        # Sites Area

        # Sites OU
        New-Variable -Name 'SitesOu' -Value $confXML.n.Sites.OUs.SitesOU.name -Option ReadOnly -Force
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
        New-Variable -Name 'ItQuarantinePcOu' -Value $confXML.n.Admin.OUs.ItNewComputersOU.name -Option ReadOnly -Force
        # Quarantine OU Distinguished Name
        $ItQuarantinePcOuDn = 'OU={0},{1}' -f $ItQuarantinePcOu, $Variables.AdDn

        # Quarantine OU for Users
        New-Variable -Name 'ItQuarantineUserOu' -Value $confXML.n.Admin.OUs.ItNewUsersOU.name -Option ReadOnly -Force

        #endregion Declarations
        ################################################################################
    } #end Begin

    Process {
        ###############################################################################
        # Create IT Admin and Sub OUs
        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Create Admin Area and related structure...')

        $Splat = @{
            ouName        = $ItAdminOu
            ouPath        = $Variables.AdDn
            ouDescription = $confXML.n.Admin.OUs.ItAdminOU.description
        }
        New-DelegateAdOU @Splat

        # Remove Inheritance and copy the ACE
        Set-AdInheritance -LDAPpath $ItAdminOuDn -RemoveInheritance $true -RemovePermissions $true
        <#
        # Remove AUTHENTICATED USERS group from OU
        #
        # CHECK... This one should not "LIST" but must be on ACL
        Remove-AuthUser -LDAPPath $ItAdminOuDn

        # Clean Ou
        Start-AdCleanOU -LDAPPath $ItAdminOuDn  -RemoveUnknownSIDs

        # Remove Pre-Windows 2000 Access group from OU
        Remove-PreWin2000FromOU -LDAPPath $ItAdminOuDn

        # Remove ACCOUNT OPERATORS 2000 Access group from OU
        Remove-AccountOperator -LDAPPath $ItAdminOuDn

        # Remove PRINT OPERATORS 2000 Access group from OU
        Remove-PrintOperator -LDAPPath $ItAdminOuDn
        #>

        <#

        Computer objects within this ares MUST have read access, otherwise GPO will not apply - TO BE DONE

        Manually change Authenticated Users from "This Object Only" to "This and descendant objects"

        then ACL will look like this:

        Get-AclAccessRule -LDAPpath 'OU=Admin,DC=EguibarIT,DC=local' -SearchBy 'Authenticated Users'
        VERBOSE:
                ACE (Access Control Entry)  Filtered By: Authenticated Users
        VERBOSE: ============================================================


        ACENumber              : 1
        DistinguishedName      : OU=Admin,DC=EguibarIT,DC=local
        IdentityReference      : Authenticated Users
        ActiveDirectoryRights : ReadProperty, GenericExecute
        AccessControlType      : Allow
        ObjectType             : GuidNULL
        InheritanceType        : All
        InheritedObjectType    : GuidNULL
        IsInherited            : False

        #>

        ###############################################################################
        #region Create Sub-OUs for admin

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Create Sub-OUs for Admin(Tier0)...')

        $Splat = @{
            ouPath   = $ItAdminOuDn
            CleanACL = $True
        }
        New-DelegateAdOU -ouName $ItAdminAccountsOu -ouDescription $confXML.n.Admin.OUs.ItAdminAccountsOU.description @Splat
        New-DelegateAdOU -ouName $ItAdminGroupsOU -ouDescription $confXML.n.Admin.OUs.ItAdminGroupsOU.description @Splat
        New-DelegateAdOU -ouName $ItPrivGroupsOU -ouDescription $confXML.n.Admin.OUs.ItPrivGroupsOU.description @Splat
        New-DelegateAdOU -ouName $ItPawOu -ouDescription $confXML.n.Admin.OUs.ItPawOU.description @Splat
        New-DelegateAdOU -ouName $ItRightsOu -ouDescription $confXML.n.Admin.OUs.ItRightsOU.description @Splat
        New-DelegateAdOU -ouName $ItServiceAccountsOu -ouDescription $confXML.n.Admin.OUs.ItServiceAccountsOU.description @Splat
        New-DelegateAdOU -ouName $ItHousekeepingOu -ouDescription $confXML.n.Admin.OUs.ItHousekeepingOU.description @Splat
        New-DelegateAdOU -ouName $ItInfraOu -ouDescription $confXML.n.Admin.OUs.ItInfraOU.description @Splat
        New-DelegateAdOU -ouName $ItAdminSrvGroupsOU -ouDescription $confXML.n.Admin.OUs.ItAdminSrvGroups.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPpath $ItAdminAccountsOuDn @Splat
        Set-AdInheritance -LDAPpath $ItAdminGroupsOUDn @Splat
        Set-AdInheritance -LDAPpath $ItPrivGroupsOUDn @Splat
        Set-AdInheritance -LDAPpath $ItPawOuDn @Splat
        Set-AdInheritance -LDAPpath $ItRightsOuDn @Splat
        Set-AdInheritance -LDAPpath $ItServiceAccountsOuDn @Splat
        Set-AdInheritance -LDAPpath $ItHousekeepingOuDn @Splat
        Set-AdInheritance -LDAPpath $ItInfraOuDn @Splat
        Set-AdInheritance -LDAPpath $ItAdminSrvGroupsOUDn @Splat

        # PAW Sub-OUs
        $Splat = @{
            ouPath   = $ItPawOuDn
            CleanACL = $True
        }
        New-DelegateAdOU -ouName $ItPawT0Ou -ouDescription $confXML.n.Admin.OUs.ItPawT0OU.description @Splat
        New-DelegateAdOU -ouName $ItPawT1Ou -ouDescription $confXML.n.Admin.OUs.ItPawT1OU.description @Splat
        New-DelegateAdOU -ouName $ItPawT2Ou -ouDescription $confXML.n.Admin.OUs.ItPawT2OU.description @Splat
        New-DelegateAdOU -ouName $ItPawStagingOu -ouDescription $confXML.n.Admin.OUs.ItPawStagingOU.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPpath $ItPawT0OuDn @Splat
        Set-AdInheritance -LDAPpath $ItPawT1OuDn @Splat
        Set-AdInheritance -LDAPpath $ItPawT2OuDn @Splat
        Set-AdInheritance -LDAPpath $ItPawStagingOuDn @Splat

        # Service Accounts Sub-OUs
        $Splat = @{
            ouPath   = $ItServiceAccountsOuDn
            CleanACL = $True
        }
        New-DelegateAdOU -ouName $ItSAT0OU -ouDescription $confXML.n.Admin.OUs.ItSAT0OU.description @Splat
        New-DelegateAdOU -ouName $ItSAT1OU -ouDescription $confXML.n.Admin.OUs.ItSAT1OU.description @Splat
        New-DelegateAdOU -ouName $ItSAT2OU -ouDescription $confXML.n.Admin.OUs.ItSAT2OU.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPpath $ItSAT0OuDn @Splat
        Set-AdInheritance -LDAPpath $ItSAT1OuDn @Splat
        Set-AdInheritance -LDAPpath $ItSAT2OuDn @Splat

        # Infrastructure Servers Sub-OUs
        $Splat = @{
            ouPath   = $ItInfraOuDn
            CleanACL = $True
        }
        New-DelegateAdOU -ouName $ItInfraT0Ou -ouDescription $confXML.n.Admin.OUs.ItInfraT0.description @Splat
        New-DelegateAdOU -ouName $ItInfraT1Ou -ouDescription $confXML.n.Admin.OUs.ItInfraT1.description @Splat
        New-DelegateAdOU -ouName $ItInfraT2Ou -ouDescription $confXML.n.Admin.OUs.ItInfraT2.description @Splat
        New-DelegateAdOU -ouName $ItInfraStagingOu -ouDescription $confXML.n.Admin.OUs.ItInfraStagingOU.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPpath $ItInfraT0OuDn @Splat
        Set-AdInheritance -LDAPpath $ItInfraT1OuDn @Splat
        Set-AdInheritance -LDAPpath $ItInfraT2OuDn @Splat
        Set-AdInheritance -LDAPpath $ItInfraStagingOuDn @Splat

        #endregion

        ###############################################################################
        #region  Move Built-In Admin user & Groups (Builtin OU groups can't be moved)

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Moving objects to Admin (Tier 0)...')

        # Move, and if needed, rename the Admin account
        If ($AdminName -ne $confXML.n.Admin.users.Admin.Name) {
            Rename-ADObject -Identity $AdminName.DistinguishedName -NewName $confXML.n.Admin.users.Admin.Name
            Set-ADUser $AdminName -SamAccountName $confXML.n.Admin.users.Admin.Name -DisplayName $confXML.n.Admin.users.Admin.Name
        }

        # Move the Guest Account
        Get-ADUser -Identity $GuestNewName | Move-ADObject -TargetPath $ItAdminAccountsOuDn -Server $CurrentDC

        $AdminName | Move-ADObject -TargetPath $ItAdminAccountsOuDn -Server $CurrentDC
        Get-ADUser -Identity krbtgt | Move-ADObject -TargetPath $ItAdminAccountsOuDn -Server $CurrentDC

        $DomainAdmins | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
        $EnterpriseAdmins | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
        Get-ADGroup -Identity $SchemaAdmins | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
        Get-ADGroup -Identity $DomainControllers | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
        Get-ADGroup -Identity $GPOCreatorsOwner | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
        Get-ADGroup -Identity $RODC | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
        Get-ADGroup -Identity 'Enterprise Read-only Domain Controllers' | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC

        Get-ADGroup -Identity 'DnsUpdateProxy' | Move-ADObject -TargetPath $ItAdminGroupsOuDn -Server $CurrentDC
        Get-ADGroup -Identity 'Domain Users' | Move-ADObject -TargetPath $ItAdminGroupsOuDn -Server $CurrentDC
        Get-ADGroup -Identity 'Domain Computers' | Move-ADObject -TargetPath $ItAdminGroupsOuDn -Server $CurrentDC
        Get-ADGroup -Identity 'Domain Guests' | Move-ADObject -TargetPath $ItAdminGroupsOuDn -Server $CurrentDC

        Get-ADGroup -Identity 'Allowed RODC Password Replication Group' | Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
        Get-ADGroup -Identity 'RAS and IAS Servers' | Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
        $DnsAdmins | Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
        Get-ADGroup -Identity 'Cert Publishers' | Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
        Get-ADGroup -Identity $DeniedRODC | Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
        $ProtectedUsers | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
        Get-ADGroup -Identity 'Cloneable Domain Controllers' | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
        Get-ADGroup -Identity 'Access-Denied Assistance Users' | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
        Get-ADGroup -Filter { SamAccountName -like 'WinRMRemoteWMIUsers*' } | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC


        # Following groups only exist on Win 2019
        If ([System.Environment]::OSVersion.Version.Build -ge 17763) {
            Get-ADGroup -Identity 'Enterprise Key Admins' | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
            Get-ADGroup -Identity 'Key Admins' | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
            Get-ADGroup -Identity 'Windows Admin Center CredSSP Administrators' | Move-ADObject -TargetPath $ItPrivGroupsOUDn
        }

        # Get-ADGroup $Administrators |                          Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Account Operators" |                       Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Backup Operators" |                        Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Certificate Service DCOM Access" |         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Cryptographic Operators" |                 Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Server Operators" |                        Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Remote Desktop Users" |                    Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Distributed COM Users" |                   Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Event Log Readers" |                       Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Guests" |                                  Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "IIS_IUSRS" |                               Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Incoming Forest Trust Builders" |          Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup $NetConfOperators |                         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Performance Log Users" |                   Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Performance Monitor Users" |               Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Pre-Windows 2000 Compatible Access" |      Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Print Operators" |                         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Replicator" |                              Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Terminal Server License Servers" |         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Users" |                                   Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Windows Authorization Access Group" |      Move-ADObject -TargetPath $ItRightsOuDn

        # REFRESH - Get the object after moving it.
        $AdminName = Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
        $DomainAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-512' }
        $EnterpriseAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-519' }
        $GPOCreatorsOwner = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-520' }
        $DeniedRODC = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-572' }
        $DnsAdmins = Get-ADGroup -Identity 'DnsAdmins'
        $ProtectedUsers = Get-ADGroup -Identity 'Protected Users'

        #endregion
        ###############################################################################

        ###############################################################################
        #region Creating Secured Admin accounts

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating and securing Admin accounts...')

        #try {

        # Try to get the new Admin
        $NewAdminExists = Get-ADUser -Filter { SamAccountName -eq $newAdminName } -ErrorAction SilentlyContinue

        # Get picture if exist. Use default if not.
        If (Test-Path -Path ('{0}\Pic\{1}.jpg' -f $DMscripts, $newAdminName)) {
            # Read the path and file name of JPG picture
            $PhotoFile = '{0}\Pic\{1}.jpg' -f $DMscripts, $newAdminName
            # Get the content of the JPG file
            #$photo = [byte[]](Get-Content -Path $PhotoFile -AsByteStream -Raw )
            [byte[]]$photo = [System.IO.File]::ReadAllBytes($PhotoFile)
        } else {
            If (Test-Path -Path ('{0}\Pic\Default.jpg' -f $DMscripts)) {
                # Read the path and file name of JPG picture
                $PhotoFile = '{0}\Pic\Default.jpg' -f $DMscripts
                # Get the content of the JPG file
                #$photo = [byte[]](Get-Content -Path $PhotoFile -Encoding byte) - NOT WORKING since PS 6
                # Alternative
                [byte[]]$photo = [System.IO.File]::ReadAllBytes($PhotoFile)
                #$photo = [byte[]](Get-Content -Path $PhotoFile -AsByteStream -Raw)
            } else {
                $photo = $null
            } #end If-Else
        } #end If-Else

        # Check if the new Admin account already exist. If not, then create it.
        If ($NewAdminExists) {
            #The user was found. Proceed to modify it accordingly.
            $Splat = @{
                Enabled              = $true
                UserPrincipalName    = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                SamAccountName       = $newAdminName
                DisplayName          = $newAdminName
                Description          = $confXML.n.Admin.users.NEWAdmin.description
                employeeId           = '0123456'
                TrustedForDelegation = $false
                AccountNotDelegated  = $true
                Company              = $confXML.n.RegisteredOrg
                Country              = 'MX'
                Department           = $confXML.n.Admin.users.NEWAdmin.department
                State                = 'Puebla'
                EmailAddress         = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                Replace              = @{
                    'employeeType'                  = $confXML.n.NC.AdminAccSufix0
                    'msNpAllowDialin'               = $false
                    'msDS-SupportedEncryptionTypes' = '24'
                }
            }

            # If photo exist, add it to parameters
            If ($photo) {
                # Only if photo exists, add it to splatting
                $Splat.Replace.Add('thumbnailPhoto', $photo)
            }

            Set-ADUser -Identity $newAdminName @Splat

        } Else {
            # User was not Found! create new.
            $Splat = @{
                Path                  = $ItAdminAccountsOuDn
                Name                  = $newAdminName
                AccountPassword       = (ConvertTo-SecureString -String $confXML.n.DefaultPassword -AsPlainText -Force)
                ChangePasswordAtLogon = $false
                Enabled               = $true
                UserPrincipalName     = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                SamAccountName        = $newAdminName
                DisplayName           = $newAdminName
                Description           = $confXML.n.Admin.users.NEWAdmin.description
                employeeId            = $confXML.n.Admin.users.NEWAdmin.employeeId
                TrustedForDelegation  = $false
                AccountNotDelegated   = $true
                Company               = $confXML.n.RegisteredOrg
                Country               = $confXML.n.Admin.users.NEWAdmin.Country
                Department            = $confXML.n.Admin.users.NEWAdmin.department
                State                 = $confXML.n.Admin.users.NEWAdmin.State
                EmailAddress          = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                OtherAttributes       = @{
                    'employeeType'                  = $confXML.n.NC.AdminAccSufix0
                    'msNpAllowDialin'               = $false
                    'msDS-SupportedEncryptionTypes' = '24'
                }
            }

            If ($photo) {
                # Only if photo exists, add it to splatting
                $Splat.OtherAttributes.Add('thumbnailPhoto', $photo)
            } #end If

            # Create the new Admin with special values
            Try {
                New-ADUser @Splat
            } Catch {
                Write-Error -Message 'Error when creating new Admin account'
                throw
            }

            #http://blogs.msdn.com/b/openspecification/archive/2011/05/31/windows-configurations-for-kerberos-supported-encryption-type.aspx
            # 'msDS-SupportedEncryptionTypes'= Kerberos DES Encryption = 2, Kerberos AES 128 = 8, Kerberos AES 256 = 16
        } #end else-if new user created
        #$newAdminName = Get-ADUser -Identity $confXML.n.Admin.users.NEWAdmin.name
        # Move AD object
        Get-ADUser -Identity $newAdminName | Move-ADObject -TargetPath $ItAdminAccountsOuDn -Server $CurrentDC
        #refresh object
        $NewAdminExists = Get-ADUser -Identity $newAdminName

        # Set the Protect against accidental deletions attribute
        # Identity ONLY accepts DistinguishedName or GUID -- DN fails I don't know why
        Set-ADObject -Identity $AdminName.ObjectGUID -ProtectedFromAccidentalDeletion $true
        Set-ADObject -Identity $NewAdminExists.ObjectGUID -ProtectedFromAccidentalDeletion $true

        # Make it member of administrative groups
        Add-AdGroupNesting -Identity $DomainAdmins -Members $NewAdminExists
        Add-AdGroupNesting -Identity $EnterpriseAdmins -Members $NewAdminExists
        Add-AdGroupNesting -Identity $GPOCreatorsOwner -Members $NewAdminExists
        Add-AdGroupNesting -Identity $DeniedRODC -Members $NewAdminExists

        # http://blogs.msdn.com/b/muaddib/archive/2013/12/30/how-to-modify-security-inheritance-on-active-directory-objects.aspx

        ####
        # Remove Everyone group from Admin-User & Administrator
        Remove-Everyone -LDAPpath $NewAdminExists.DistinguishedName
        Remove-Everyone -LDAPpath $AdminName.DistinguishedName

        ####
        # Remove AUTHENTICATED USERS group from Admin-User & Administrator
        #Remove-AuthUser -LDAPPath $NewAdminExists.DistinguishedName
        #Remove-AuthUser -LDAPPath ('CN={0},{1}' -f $AdminName, $ItAdminAccountsOuDn)

        ####
        # Remove Pre-Windows 2000 Compatible Access group from Admin-User & Administrator
        Remove-PreWin2000 -LDAPpath $NewAdminExists.DistinguishedName
        Remove-PreWin2000 -LDAPpath $AdminName.DistinguishedName

        ###
        # Configure TheGood account
        $params = @{
            'employeeType'                  = $confXML.n.NC.AdminAccSufix0
            'msNpAllowDialin'               = $false
            'msDS-SupportedEncryptionTypes' = 24
        }

        If ($photo) {
            # Only if photo exists, add it to splatting
            $params.Add('thumbnailPhoto', $photo)
        }

        $Splat = @{
            Identity             = $AdminName
            TrustedForDelegation = $false
            AccountNotDelegated  = $true
            Add                  = $params
            Server               = $CurrentDC
        }
        Set-ADUser @Splat

        Write-Verbose -Message 'Admin accounts created and secured.'

        #endregion Creating Secured Admin accounts
        ###############################################################################

        ###############################################################################
        #region Create Admin groups

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Admin groups...')

        # Iterate through all Admin-LocalGroups child nodes
        Foreach ($Node in $confXML.n.Admin.LG.ChildNodes) {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $Node.LocalName))
            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $Node.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = $Node.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = $Node.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $createdGroup = New-AdDelegatedGroup @Splat

            $varparam = @{
                Name  = "$('SL{0}{1}' -f  $NC['Delim'], $Node.LocalName)"
                Value = $createdGroup
                Force = $true
            }
            New-Variable @varparam

            #Clear variable for next use
            $createdGroup = $null
        } # End ForEach

        # Iterate through all Admin-GlobalGroups child nodes
        Foreach ($Node in $confXML.n.Admin.GG.ChildNodes) {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.localname))
            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = $Node.DisplayName
                Path                          = $ItAdminGroupsOuDn
                Description                   = $Node.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $createdGroup = New-AdDelegatedGroup @Splat

            $varparam = @{
                Name  = "$('SG{0}{1}' -f $NC['Delim'], $Node.LocalName)"
                Value = $createdGroup
                Force = $true
            }
            New-Variable @varparam


            #Clear variable for next use
            $createdGroup = $null
        } # End ForEach


        # Create Servers Area / Tier1 Domain Local & Global Groups
        $Splat = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.Operations.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.Servers.GG.Operations.DisplayName
            Path                          = $ItAdminGroupsOuDn
            Description                   = $confXML.n.Servers.GG.Operations.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $createdGroup = New-AdDelegatedGroup @Splat
        New-Variable -Name "$('SG{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.Operations.LocalName)" -Value $createdGroup -Force
        $createdGroup = $null

        $Splat = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.Servers.GG.ServerAdmins.DisplayName
            Path                          = $ItAdminGroupsOuDn
            Description                   = $confXML.n.Servers.GG.ServerAdmins.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $createdGroup = New-AdDelegatedGroup @Splat
        New-Variable -Name "$('SG{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.LocalName)" -Value $createdGroup -Force
        $createdGroup = $null

        $Splat = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.Servers.LG.SvrOpsRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.Servers.LG.SvrOpsRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $createdGroup = New-AdDelegatedGroup @Splat
        New-Variable -Name "$('SL{0}{1}' -f  $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.LocalName)" -Value $createdGroup -Force
        $createdGroup = $null

        $Splat = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.Servers.LG.SvrAdmRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.Servers.LG.SvrAdmRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $createdGroup = New-AdDelegatedGroup @Splat
        New-Variable -Name "$('SL{0}{1}' -f  $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.LocalName)" -Value $createdGroup -Force
        $createdGroup = $null



        # Get all Privileged groups into an array $AllGroups
        If ($null -ne $SG_InfraAdmins) {
            [Void]$AllGroups.Add($SG_InfraAdmins)
        }
        If ($null -ne $SG_AdAdmins) {
            [Void]$AllGroups.Add($SG_AdAdmins)
        }
        If ($null -ne $SG_Tier0ServiceAccount) {
            [Void]$AllGroups.Add($SG_Tier0ServiceAccount)
        }
        If ($null -ne $SG_Tier1ServiceAccount) {
            [Void]$AllGroups.Add($SG_Tier1ServiceAccount)
        }
        If ($null -ne $SG_Tier2ServiceAccount) {
            [Void]$AllGroups.Add($SG_Tier2ServiceAccount)
        }
        If ($null -ne $SG_GpoAdmins) {
            [Void]$AllGroups.Add($SG_GpoAdmins)
        }
        If ($null -ne $SG_Tier0Admins) {
            [Void]$AllGroups.Add($SG_Tier0Admins)
        }
        If ($null -ne $SG_Tier1Admins) {
            [Void]$AllGroups.Add($SG_Tier1Admins)
        }
        If ($null -ne $SG_Tier2Admins) {
            [Void]$AllGroups.Add($SG_Tier2Admins)
        }
        If ($null -ne $SG_AllSiteAdmins) {
            [Void]$AllGroups.Add($SG_AllSiteAdmins)
        }
        If ($null -ne $SG_AllGALAdmins) {
            [Void]$AllGroups.Add($SG_AllGALAdmins)
        }

        # Move the groups to PG OU
        foreach ($item in $AllGroups) {
            # AD Object operations ONLY supports DN and GUID as identity

            # Remove the ProtectedFromAccidentalDeletion, otherwise throws error when moving
            Set-ADObject -Identity $item.ObjectGUID -ProtectedFromAccidentalDeletion $false

            # Move objects to PG OU
            Move-ADObject -TargetPath $ItPrivGroupsOUDn -Identity $item.ObjectGUID

            # Set back again the ProtectedFromAccidentalDeletion flag.
            #The group has to be fetch again because of the previous move
            Set-ADObject -Identity $item.ObjectGUID -ProtectedFromAccidentalDeletion $true

            #refresh the variable because DistinguishedName changed
            Set-Variable -Name $item.SamAccountName -Value (Get-ADGroup -Identity $item.SID) -Force
        }

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create Group Managed Service Account

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Create Group Managed Service Account')

        # Get the current OS build
        # Create the KDS Root Key (only once per domain).  This is used by the KDS service
        # on DCs (along with other information) to generate passwords
        # http://blogs.technet.com/b/askpfeplat/archive/2012/12/17/windows-server-2012-group-managed-service-accounts.aspx
        # If working in a test environment with a minimal number of DCs and the ability to guarantee immediate replication, please use:
        Add-KdsRootKey -EffectiveTime ((Get-Date).addhours(-10))



        # Check if ServiceAccount exists
        $gMSASamAccountName = '{0}$' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name
        $ExistSA = Get-ADServiceAccount -Filter { SamAccountName -like $gMSASamAccountName }

        If (-not $ExistSA) {
            Write-Verbose -Message ('Creating {0} Service Account {0}.' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name)
            If ([System.Environment]::OSVersion.Version.Build -ge 9200) {

                $Splat = @{
                    Name                   = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                    SamAccountName         = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                    DNSHostName            = ('{0}.{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN)
                    AccountNotDelegated    = $true
                    Description            = $confXML.n.Admin.gMSA.AdTaskScheduler.Description
                    DisplayName            = $confXML.n.Admin.gMSA.AdTaskScheduler.DisplayName
                    KerberosEncryptionType = 'AES128,AES256'
                    Path                   = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $ItServiceAccountsOuDn
                    enabled                = $True
                    TrustedForDelegation   = $false
                    ServicePrincipalName   = ('HOST/{0}.{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN)
                    ErrorAction            = 'SilentlyContinue'
                }

                $ReplaceValues = @{
                    'company'           = $confXML.n.RegisteredOrg
                    'department'        = $confXML.n.Admin.gMSA.AdTaskScheduler.Department
                    'employeeID'        = 'T0'
                    'employeeType'      = 'ServiceAccount'
                    'info'              = $confXML.n.Admin.gMSA.AdTaskScheduler.Description
                    'title'             = $confXML.n.Admin.gMSA.AdTaskScheduler.DisplayName
                    'userPrincipalName' = '{0}@{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN
                }
                If (($null -or '') -ne $confXML.n.Admin.gMSA.AdTaskScheduler.c) {
                    $ReplaceValues.Add('c', $confXML.n.Admin.gMSA.AdTaskScheduler.c)
                }
                If (($null -or '') -ne $confXML.n.Admin.gMSA.AdTaskScheduler.Co) {
                    $ReplaceValues.Add('Co', $confXML.n.Admin.gMSA.AdTaskScheduler.co)
                }
                If (($null -or '') -ne $confXML.n.Admin.gMSA.AdTaskScheduler.l) {
                    $ReplaceValues.Add('l', $confXML.n.Admin.gMSA.AdTaskScheduler.l)
                }

                $ReplaceParams = @{
                    Replace     = $ReplaceValues
                    ErrorAction = 'SilentlyContinue'
                }

                try {
                    New-ADServiceAccount @Splat | Set-ADServiceAccount @ReplaceParams
                } catch {
                    Write-Error -Message 'Error when creating AD Scheduler service account.'
                    throw
                } #end Try-Catch
            } else {
                $Splat = @{
                    name        = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                    Description = $confXML.n.Admin.gMSA.AdTaskScheduler.Description
                    Path        = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $ItServiceAccountsOuDn
                    enabled     = $True
                    ErrorAction = 'SilentlyContinue'
                }

                New-ADServiceAccount @Splat
            } #end If-Else
        } else {
            Write-Warning -Message ('Service Account {0} already exists.' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name)
        }# End If-Else


        # Ensure the gMSA is member of Tier0 ServiceAccount group. This group will be configured on the Rights assignment.
        # Add-AdGroupNesting -Identity $SG_Tier0ServiceAccount -Members $gMSASamAccountName

        #Configure gMSA so all members of group "Domain Controllers" can retrieve the password
        Set-ADServiceAccount $gMSASamAccountName -PrincipalsAllowedToRetrieveManagedPassword 'Domain Controllers'

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create a New Fine Grained Password Policy for Admins Accounts

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Create a New Fine Grained Password Policy for Admins Accounts...')

        $PSOexists = $null

        [String]$PsoName = $confXML.n.Admin.PSOs.ItAdminsPSO.Name

        $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -like $PsoName }

        if (-not($PSOexists)) {
            Write-Verbose -Message ('Creating {0} PSO.' -f $PsoName)
            $Splat = @{
                Name                        = $confXML.n.Admin.PSOs.ItAdminsPSO.Name
                Precedence                  = $confXML.n.Admin.PSOs.ItAdminsPSO.Precedence
                ComplexityEnabled           = [System.Boolean]$confXML.n.Admin.PSOs.ItAdminsPSO.ComplexityEnabled
                Description                 = $confXML.n.Admin.PSOs.ItAdminsPSO.Description
                DisplayName                 = $confXML.n.Admin.PSOs.ItAdminsPSO.DisplayName
                LockoutDuration             = $confXML.n.Admin.PSOs.ItAdminsPSO.LockoutDuration
                LockoutObservationWindow    = $confXML.n.Admin.PSOs.ItAdminsPSO.LockoutObservationWindow
                LockoutThreshold            = $confXML.n.Admin.PSOs.ItAdminsPSO.LockoutThreshold
                MaxPasswordAge              = $confXML.n.Admin.PSOs.ItAdminsPSO.MaxPasswordAge
                MinPasswordAge              = $confXML.n.Admin.PSOs.ItAdminsPSO.MinPasswordAge
                MinPasswordLength           = $confXML.n.Admin.PSOs.ItAdminsPSO.MinPasswordLength
                PasswordHistoryCount        = $confXML.n.Admin.PSOs.ItAdminsPSO.PasswordHistoryCount
                ReversibleEncryptionEnabled = [System.Boolean]$confXML.n.Admin.PSOs.ItAdminsPSO.ReversibleEncryptionEnabled
                Passthru                    = $true
            }

            $PSOexists = New-ADFineGrainedPasswordPolicy @Splat
            If ( -not $PSOexists ) {
                $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -like $PsoName }
            }

        } # End If PSO exists


        Write-Verbose -Message ('Apply the {0} PSO to the corresponding accounts and groups.' -f $PsoName)
        Start-Sleep -Seconds 5
        # Apply the PSO to the corresponding accounts and groups
        $ArrayList.Clear()
        [void]$ArrayList.Add($DomainAdmins)
        [void]$ArrayList.Add($EnterpriseAdmins)
        if ($null -ne $SG_InfraAdmins) {
            [void]$ArrayList.Add($SG_InfraAdmins)
        }
        if ($null -ne $SG_AdAdmins) {
            [void]$ArrayList.Add($SG_AdAdmins)
        }
        if ($null -ne $SG_GpoAdmins) {
            [void]$ArrayList.Add($SG_GpoAdmins)
        }
        if ($null -ne $SG_Tier0Admins) {
            [void]$ArrayList.Add($SG_Tier0Admins)
        }
        if ($null -ne $SG_Tier1Admins) {
            [void]$ArrayList.Add($SG_Tier1Admins)
        }
        if ($null -ne $SG_Tier2Admins) {
            [void]$ArrayList.Add($SG_Tier2Admins)
        }
        if ($null -ne $SG_Operations) {
            [void]$ArrayList.Add($SG_Operations)
        }
        if ($null -ne $SG_ServerAdmins) {
            [void]$ArrayList.Add($SG_ServerAdmins)
        }
        if ($null -ne $SG_AllSiteAdmins) {
            [void]$ArrayList.Add($SG_AllSiteAdmins)
        }
        if ($null -ne $SG_AllGALAdmins) {
            [void]$ArrayList.Add($SG_AllGALAdmins)
        }
        if ($null -ne $SG_GlobalUserAdmins) {
            [void]$ArrayList.Add($SG_GlobalUserAdmins)
        }
        if ($null -ne $SG_GlobalPcAdmins) {
            [void]$ArrayList.Add($SG_GlobalPcAdmins)
        }
        if ($null -ne $SG_GlobalGroupAdmins) {
            [void]$ArrayList.Add($SG_GlobalGroupAdmins)
        }
        if ($null -ne $SG_ServiceDesk) {
            [void]$ArrayList.Add($SG_ServiceDesk)
        }
        if ($null -ne $SL_InfraRight) {
            [void]$ArrayList.Add($SL_InfraRight)
        }
        if ($null -ne $SL_AdRight) {
            [void]$ArrayList.Add($SL_AdRight)
        }
        if ($null -ne $SL_UM) {
            [void]$ArrayList.Add($SL_UM)
        }
        if ($null -ne $SL_GM) {
            [void]$ArrayList.Add($SL_GM)
        }
        if ($null -ne $SL_PUM) {
            [void]$ArrayList.Add($SL_PUM)
        }
        if ($null -ne $SL_PGM) {
            [void]$ArrayList.Add($SL_PGM)
        }
        if ($null -ne $SL_GpoAdminRight) {
            [void]$ArrayList.Add($SL_GpoAdminRight)
        }
        if ($null -ne $SL_DnsAdminRight) {
            [void]$ArrayList.Add($SL_DnsAdminRight)
        }
        if ($null -ne $SL_DirReplRight) {
            [void]$ArrayList.Add($SL_DirReplRight)
        }
        if ($null -ne $SL_PromoteDcRight) {
            [void]$ArrayList.Add($SL_PromoteDcRight)
        }
        if ($null -ne $SL_TransferFSMOright) {
            [void]$ArrayList.Add($SL_TransferFSMOright)
        }
        if ($null -ne $SL_DcManagement) {
            [void]$ArrayList.Add($SL_DcManagement)
        }
        if ($null -ne $SL_PISM) {
            [void]$ArrayList.Add($SL_PISM)
        }
        if ($null -ne $SL_PAWM) {
            [void]$ArrayList.Add($SL_PAWM)
        }
        if ($null -ne $SL_PSAM) {
            [void]$ArrayList.Add($SL_PSAM)
        }
        if ($null -ne $SL_SvrAdmRight) {
            [void]$ArrayList.Add($SL_SvrAdmRight)
        }
        if ($null -ne $SL_SvrOpsRight) {
            [void]$ArrayList.Add($SL_SvrOpsRight)
        }
        if ($null -ne $SL_GlobalGroupRight) {
            [void]$ArrayList.Add($SL_GlobalGroupRight)
        }
        if ($null -ne $SL_GlobalAppAccUserRight) {
            [void]$ArrayList.Add($SL_GlobalAppAccUserRight)
        }
        # Adding groups
        Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $ArrayList



        $ArrayList.Clear()
        if ($null -ne $AdminName) {
            [void]$ArrayList.Add($AdminName)
        }
        if ($null -ne $NewAdminExists) {
            [void]$ArrayList.Add($NewAdminExists)
        }

        # Adding Users.
        Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $ArrayList

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create a New Fine Grained Password Policy for Service Accounts

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Create a New Fine Grained Password Policy for Service Accounts.')

        $PSOexists = $null


        [String]$PsoName = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Name

        $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -like $PsoName }

        if (-not($PSOexists)) {
            Write-Verbose -Message ('Creating {0} PSO.' -f $PsoName)
            $Splat = @{
                Name                        = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Name
                Precedence                  = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Precedence
                ComplexityEnabled           = [System.Boolean]$confXML.n.Admin.PSOs.ServiceAccountsPSO.ComplexityEnabled
                Description                 = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Description
                DisplayName                 = $confXML.n.Admin.PSOs.ServiceAccountsPSO.DisplayName
                LockoutDuration             = $confXML.n.Admin.PSOs.ServiceAccountsPSO.LockoutDuration
                LockoutObservationWindow    = $confXML.n.Admin.PSOs.ServiceAccountsPSO.LockoutObservationWindow
                LockoutThreshold            = $confXML.n.Admin.PSOs.ServiceAccountsPSO.LockoutThreshold
                MaxPasswordAge              = $confXML.n.Admin.PSOs.ServiceAccountsPSO.MaxPasswordAge
                MinPasswordAge              = $confXML.n.Admin.PSOs.ServiceAccountsPSO.MinPasswordAge
                MinPasswordLength           = $confXML.n.Admin.PSOs.ServiceAccountsPSO.MinPasswordLength
                PasswordHistoryCount        = $confXML.n.Admin.PSOs.ServiceAccountsPSO.PasswordHistoryCount
                ReversibleEncryptionEnabled = [System.Boolean]$confXML.n.Admin.PSOs.ServiceAccountsPSO.ReversibleEncryptionEnabled
                Passthru                    = $true
            }
            $PSOexists = New-ADFineGrainedPasswordPolicy @Splat
            If (-not $PSOexists) {
                $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -like $PsoName }
            }

            #$PSOexists = Get-ADFineGrainedPasswordPolicy -Identity $PsoName
        }

        Write-Verbose -Message ('Apply the {0} PSO to the corresponding accounts and groups.' -f $PsoName)
        Start-Sleep -Seconds 5
        # Apply the PSO to all Tier Service Accounts
        $ArrayList.Clear()
        if ($null -ne $SG_Tier0ServiceAccount) {
            [void]$ArrayList.Add($SG_Tier0ServiceAccount)
        }
        if ($null -ne $SG_Tier1ServiceAccount) {
            [void]$ArrayList.Add($SG_Tier1ServiceAccount)
        }
        if ($null -ne $SG_Tier2ServiceAccount) {
            [void]$ArrayList.Add($SG_Tier2ServiceAccount)
        }
        # todo: Fix error "The name reference is invalid."
        Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $ArrayList

        #endregion
        ###############################################################################

        ###############################################################################
        #region Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Nesting groups...')

        $ArrayList.Clear()

        [void]$ArrayList.Add($DomainAdmins)
        [void]$ArrayList.Add($EnterpriseAdmins)

        if ($null -ne $SG_InfraAdmins) {
            [void]$ArrayList.Add($SG_InfraAdmins)
        }
        if ($null -ne $SG_AdAdmins) {
            [void]$ArrayList.Add($SG_AdAdmins)
        }
        if ($null -ne $SG_GpoAdmins) {
            [void]$ArrayList.Add($SG_GpoAdmins)
        }
        if ($null -ne $SG_Tier0Admins) {
            [void]$ArrayList.Add($SG_Tier0Admins)
        }
        if ($null -ne $SG_Tier1Admins) {
            [void]$ArrayList.Add($SG_Tier1Admins)
        }
        if ($null -ne $SG_Tier2Admins) {
            [void]$ArrayList.Add($SG_Tier2Admins)
        }
        if ($null -ne $SG_Operations) {
            [void]$ArrayList.Add($SG_Operations)
        }
        if ($null -ne $SG_ServerAdmins) {
            [void]$ArrayList.Add($SG_ServerAdmins)
        }
        if ($null -ne $SG_AllSiteAdmins) {
            [void]$ArrayList.Add($SG_AllSiteAdmins)
        }
        if ($null -ne $SG_AllGALAdmins) {
            [void]$ArrayList.Add($SG_AllGALAdmins)
        }
        if ($null -ne $SG_GlobalUserAdmins) {
            [void]$ArrayList.Add($SG_GlobalUserAdmins)
        }
        if ($null -ne $SG_GlobalPcAdmins) {
            [void]$ArrayList.Add($SG_GlobalPcAdmins)
        }
        if ($null -ne $SG_GlobalGroupAdmins) {
            [void]$ArrayList.Add($SG_GlobalGroupAdmins)
        }
        if ($null -ne $SG_ServiceDesk) {
            [void]$ArrayList.Add($SG_ServiceDesk)
        }
        if ($null -ne $SL_InfraRight) {
            [void]$ArrayList.Add($SL_InfraRight)
        }
        if ($null -ne $SL_AdRight) {
            [void]$ArrayList.Add($SL_AdRight)
        }
        if ($null -ne $SL_UM) {
            [void]$ArrayList.Add($SL_UM)
        }
        if ($null -ne $SL_GM) {
            [void]$ArrayList.Add($SL_GM)
        }
        if ($null -ne $SL_PUM) {
            [void]$ArrayList.Add($SL_PUM)
        }
        if ($null -ne $SL_PGM) {
            [void]$ArrayList.Add($SL_PGM)
        }
        if ($null -ne $SL_GpoAdminRight) {
            [void]$ArrayList.Add($SL_GpoAdminRight)
        }
        if ($null -ne $SL_DnsAdminRight) {
            [void]$ArrayList.Add($SL_DnsAdminRight)
        }
        if ($null -ne $SL_DirReplRight) {
            [void]$ArrayList.Add($SL_DirReplRight)
        }
        if ($null -ne $SL_PromoteDcRight) {
            [void]$ArrayList.Add($SL_PromoteDcRight)
        }
        if ($null -ne $SL_TransferFSMOright) {
            [void]$ArrayList.Add($SL_TransferFSMOright)
        }
        if ($null -ne $SL_DcManagement) {
            [void]$ArrayList.Add($SL_DcManagement)
        }
        if ($null -ne $SL_PISM) {
            [void]$ArrayList.Add($SL_PISM)
        }
        if ($null -ne $SL_PAWM) {
            [void]$ArrayList.Add($SL_PAWM)
        }
        if ($null -ne $SL_PSAM) {
            [void]$ArrayList.Add($SL_PSAM)
        }
        if ($null -ne $SL_SvrAdmRight) {
            [void]$ArrayList.Add($SL_SvrAdmRight)
        }
        if ($null -ne $SL_SvrOpsRight) {
            [void]$ArrayList.Add($SL_SvrOpsRight)
        }
        if ($null -ne $SL_GlobalGroupRight) {
            [void]$ArrayList.Add($SL_GlobalGroupRight)
        }
        if ($null -ne $SL_GlobalAppAccUserRight) {
            [void]$ArrayList.Add($SL_GlobalAppAccUserRight)
        }
        # Add groups
        Add-AdGroupNesting -Identity $DeniedRODC -Members $ArrayList

        # Add Users
        $ArrayList.Clear()
        if ($null -ne $AdminName) {
            [void]$ArrayList.Add($AdminName)
        }
        if ($null -ne $NewAdminExists) {
            [void]$ArrayList.Add($NewAdminExists)
        }
        Add-AdGroupNesting -Identity $DeniedRODC -Members $ArrayList


        #endregion
        ###############################################################################

        ###############################################################################
        #region Enabling Management Accounts to Modify the Membership of Protected Groups

        Write-Verbose -Message ($Variables.NewRegionMessage -f
            'Enabling Management Accounts to Modify the Membership of Protected Groups...'
        )

        # Enable PUM to manage Privileged Accounts (Reset PWD, enable/disable Administrator built-in account)
        Set-AdAclMngPrivilegedAccount -Group $SL_PUM

        # Enable PGM to manage Privileged Groups (Administrators, Domain Admins...)
        Set-AdAclMngPrivilegedGroup -Group $SL_PGM

        #endregion
        ###############################################################################

        ###############################################################################
        #region Nest Groups - Delegate Rights through Builtin groups
        # https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups
        # http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Nest Groups - Delegate Rights through Builtin groups...')

        Add-AdGroupNesting -Identity $CryptoOperators -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity $DnsAdmins -Members $SG_AdAdmins, $SG_Tier0Admins

        Add-AdGroupNesting -Identity $EvtLogReaders -Members $SG_AdAdmins, $SG_Operations

        Add-AdGroupNesting -Identity $NetConfOperators -Members $SG_AdAdmins, $SG_Tier0Admins

        Add-AdGroupNesting -Identity $PerfLogUsers -Members $SG_AdAdmins, $SG_Operations, $SG_Tier0Admins

        Add-AdGroupNesting -Identity $PerfMonitorUsers -Members $SG_AdAdmins, $SG_Operations, $SG_Tier0Admins

        Add-AdGroupNesting -Identity $RemoteDesktopUsers -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity $ServerOperators -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity $RemoteMngtUsers -Members $SG_AdAdmins, $SG_Tier0Admins

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
        }
        Add-AdGroupNesting -Identity $RemoteWMI -Members $SG_AdAdmins, $SG_Tier0Admins

        # https://technet.microsoft.com/en-us/library/dn466518(v=ws.11).aspx
        $ArrayList.Clear()
        if ($null -ne $AdminName) {
            [void][void]$ArrayList.Add($AdminName)
        }
        if ($null -ne $NewAdminExists) {
            [void]$ArrayList.Add($NewAdminExists)
        }
        if ($null -ne $SG_InfraAdmins) {
            [void]$ArrayList.Add($SG_InfraAdmins)
        }
        if ($null -ne $SG_AdAdmins) {
            [void]$ArrayList.Add($SG_AdAdmins)
        }
        if ($null -ne $SG_GpoAdmins) {
            [void]$ArrayList.Add($SG_GpoAdmins)
        }
        if ($null -ne $SG_Tier0Admins) {
            [void]$ArrayList.Add($SG_Tier0Admins)
        }
        if ($null -ne $SG_Tier1Admins) {
            [void]$ArrayList.Add($SG_Tier1Admins)
        }
        if ($null -ne $SG_Tier2Admins) {
            [void]$ArrayList.Add($SG_Tier2Admins)
        }
        if ($null -ne $SG_Operations) {
            [void]$ArrayList.Add($SG_Operations)
        }
        if ($null -ne $SG_ServerAdmins) {
            [void]$ArrayList.Add($SG_ServerAdmins)
        }
        if ($null -ne $SG_AllSiteAdmins) {
            [void]$ArrayList.Add($SG_AllSiteAdmins)
        }
        if ($null -ne $SG_AllGALAdmins) {
            [void]$ArrayList.Add($SG_AllGALAdmins)
        }
        if ($null -ne $SG_GlobalUserAdmins) {
            [void]$ArrayList.Add($SG_GlobalUserAdmins)
        }
        if ($null -ne $SG_GlobalPcAdmins) {
            [void]$ArrayList.Add($SG_GlobalPcAdmins)
        }
        if ($null -ne $SG_GlobalGroupAdmins) {
            [void]$ArrayList.Add($SG_GlobalGroupAdmins)
        }
        if ($null -ne $SG_ServiceDesk) {
            [void]$ArrayList.Add($SG_ServiceDesk)
        }
        Add-AdGroupNesting -Identity $ProtectedUsers -Members $ArrayList


        #endregion
        ###############################################################################

        ###############################################################################
        #region Nest Groups - Extend Rights through delegation model groups
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Nest Groups - Extend Rights through delegation model groups...')

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

        # AdAdmins as member of DcManagement
        $Splat = @{
            Identity = $SL_DcManagement
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @Splat



        # Tier0Admins as member of DcManagement
        $Splat = @{
            Identity = $SL_DcManagement
            Members  = $SG_Tier0Admins
        }
        Add-AdGroupNesting @Splat



        # GpoAdmins as member of GpoAdminRight
        $Splat = @{
            Identity = $SL_GpoAdminRight
            Members  = $SG_GpoAdmins
        }
        Add-AdGroupNesting @Splat



        # AllSiteAdmins as member of AllGalAdmins
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


        #endregion
        ###############################################################################

        ###############################################################################
        #region redirect Users & Computers containers

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'redirect Users & Computers containers...')

        $Splat = @{
            ouName                   = $ItQuarantinePcOu
            ouPath                   = $Variables.AdDn
            ouDescription            = $confXML.n.Admin.OUs.ItNewComputersOU.description
            RemoveAuthenticatedUsers = $true
        }
        New-DelegateAdOU @Splat

        $Splat = @{
            ouName                   = $ItQuarantineUserOu
            ouPath                   = $Variables.AdDn
            ouDescription            = $confXML.n.Admin.OUs.ItNewUsersOU.description
            RemoveAuthenticatedUsers = $true
        }
        New-DelegateAdOU @Splat

        # START Remove Delegation to BuiltIn groups BEFORE REDIRECTION
        $Splat = @{
            Group      = $AccountOperators
            LDAPPath   = 'CN=Computers,{0}' -f $Variables.AdDn
            RemoveRule = $True
        }
        ### COMPUTERS
        # Remove the Account Operators group from ACL to Create/Delete Users
        Set-AdAclCreateDeleteUser @Splat

        # Remove the Account Operators group from ACL to Create/Delete Computers
        Set-AdAclCreateDeleteComputer @Splat

        # Remove the Account Operators group from ACL to Create/Delete Groups
        Set-AdAclCreateDeleteGroup @Splat

        # Remove the Account Operators group from ACL to Create/Delete Contacts
        Set-AdAclCreateDeleteContact @Splat

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-CreateDeleteInetOrgPerson @Splat

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-AdAclCreateDeletePrintQueue @Splat

        $Splat = @{
            Group      = $AccountOperators
            LDAPPath   = 'CN=Users,{0}' -f $Variables.AdDn
            RemoveRule = $True
        }
        ### USERS
        # Remove the Account Operators group from ACL to Create/Delete Users
        Set-AdAclCreateDeleteUser @Splat

        # Remove the Account Operators group from ACL to Create/Delete Computers
        Set-AdAclCreateDeleteComputer @Splat

        # Remove the Account Operators group from ACL to Create/Delete Groups
        Set-AdAclCreateDeleteGroup @Splat

        # Remove the Account Operators group from ACL to Create/Delete Contacts
        Set-AdAclCreateDeleteContact @Splat

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-CreateDeleteInetOrgPerson @Splat

        # Remove the Print Operators group from ACL to Create/Delete PrintQueues
        Set-AdAclCreateDeletePrintQueue @Splat

        ###############################################################################
        # Redirect Default USER & COMPUTERS Containers
        redircmp.exe ('OU={0},{1}' -f $ItQuarantinePcOu, $Variables.AdDn)
        redirusr.exe ('OU={0},{1}' -f $ItQuarantineUserOu, $Variables.AdDn)

        #endregion
        ###############################################################################

        ###############################################################################
        #region Delegation to ADMIN area (Tier 0)

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Delegate Admin Area (Tier 0)...')

        # Computer objects within this ares MUST have read access, otherwise GPO will not apply

        # UM - Semi-Privileged User Management
        Set-AdAclDelegateUserAdmin -Group $SL_UM -LDAPpath $ItAdminAccountsOuDn
        Set-AdAclDelegateGalAdmin -Group $SL_UM -LDAPpath $ItAdminAccountsOuDn





        # GM - Semi-Privileged Group Management
        Set-AdAclCreateDeleteGroup -Group $SL_GM -LDAPpath $ItAdminGroupsOuDn
        Set-AdAclChangeGroup -Group $SL_GM -LDAPpath $ItAdminGroupsOuDn





        # PUM - Privileged User Management
        Set-AdAclDelegateUserAdmin -Group $SL_PUM -LDAPpath $ItAdminAccountsOuDn
        Set-AdAclDelegateGalAdmin -Group $SL_PUM -LDAPpath $ItAdminAccountsOuDn





        # PGM - Privileged Group Management
        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_PGM -LDAPpath $ItPrivGroupsOUDn
        Set-AdAclCreateDeleteGroup -Group $SL_PGM -LDAPpath $ItRightsOuDn
        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_PGM -LDAPpath $ItPrivGroupsOUDn
        Set-AdAclChangeGroup -Group $SL_PGM -LDAPpath $ItRightsOuDn




        # Local Admin groups management
        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_SAGM -LDAPpath $ItAdminSrvGroupsOUDn
        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_SAGM -LDAPpath $ItAdminSrvGroupsOUDn





        # PISM - Privileged Infrastructure Services Management
        # Create/Delete Computers
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM -LDAPpath $ItInfraT0OuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM -LDAPpath $ItInfraT1OuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM -LDAPpath $ItInfraT2OuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM -LDAPpath $ItInfraStagingOuDn





        # PAWM - Privileged Access Workstation Management
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM -LDAPpath $ItPawT0OuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM -LDAPpath $ItPawT1OuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM -LDAPpath $ItPawT2OuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM -LDAPpath $ItPawStagingOuDn






        # DC_Management - Domain Controllers Management
        Set-AdAclDelegateComputerAdmin -Group $SL_DcManagement -LDAPpath $DCsOuDn
        # DC_Management - Service Control Management (Permission to services)
        Add-GroupToSCManager -Group $SL_DcManagement
        # DC_Management - Give permissions on each service
        Foreach ($item in (Get-Service)) {
            Add-ServiceAcl -Group $SL_DcManagement -Service $Item.Name
        }



        # PSAM - Privileged Service Account Management - Create/Delete Managed Service Accounts & Standard user service accounts
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
        # Create/Delete GPOs
        Set-AdAclCreateDeleteGPO -Group $SL_GpoAdminRight
        # Link existing GPOs to OUs
        Set-AdAclLinkGPO -Group $SL_GpoAdminRight
        # Change GPO options
        Set-AdAclGPoption -Group $SL_GpoAdminRight





        # Delegate Directory Replication Rights
        Set-AdDirectoryReplication -Group $SL_DirReplRight





        # Infrastructure Admins
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
        Set-AdAclFMSOtransfer -Group $SL_TransferFSMOright -FSMOroles 'Schema', 'Infrastructure', 'DomainNaming', 'RID', 'PDC'




        # AD Admins
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

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create Baseline GPO

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Baseline GPOs and configure them accordingly...')

        # Domain
        $Splat = @{
            gpoDescription = 'Baseline'
            gpoLinkPath    = $Variables.AdDn
            GpoAdmin       = $sl_GpoAdminRight
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
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
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
        }
        New-DelegateAdGpo @Splat

        # Admin Area
        $Splat = @{
            gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.GPOs.Adminbaseline.Name
            gpoLinkPath    = $ItAdminOuDn
            GpoAdmin       = $sl_GpoAdminRight
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
        }
        New-DelegateAdGpo -gpoScope 'C' @Splat -gpoBackupID $confXML.n.Admin.GPOs.Adminbaseline.backupID
        New-DelegateAdGpo -gpoScope 'U' @Splat -gpoBackupID $confXML.n.Admin.GPOs.AdminUserbaseline.backupID

        # Users
        $Splat = @{
            gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.OUs.ItAdminAccountsOU.Name
            gpoScope       = 'U'
            gpoLinkPath    = $ItAdminAccountsOuDn
            GpoAdmin       = $sl_GpoAdminRight
            gpoBackupId    = $confXML.n.Admin.GPOs.AdminUserbaseline.backupID
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
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
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
        }
        New-DelegateAdGpo @Splat @Splat1

        $Splat1 = @{
            gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name)
            gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT0OU.Name, $ItPawOuDn)
            gpoBackupID    = $confXML.n.Admin.GPOs.PawT0baseline.backupID
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
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
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
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
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
        }
        New-DelegateAdGpo @Splat @Splat1

        $Splat1 = @{
            gpoDescription = ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0Ou.Name)
            gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT0Ou.Name, $ItInfraOuDn)
            gpoBackupID    = $confXML.n.Admin.GPOs.INFRAT0baseline.backupID
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
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
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
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
                path       = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
            }
            Import-GPO @splat
        }





        ###############################################################################
        # Configure Kerberos Claims

        $Splat = @{
            DomainDNSName       = $env:USERDNSDOMAIN
            GeneralGPO          = 'C-Baseline'
            DomainControllerGPO = 'C-{0}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Name
        }
        Enable-KerberosClaimSupport @Splat





        ###############################################################################
        # Configure GPO Restrictions based on Tier Model

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Configure GPO Restrictions based on Tier Model...')

        #region Domain
        #------------------------------------------------------------------------------

        # Access this computer from the network
        $NetworkLogon = [System.Collections.Generic.List[object]]::New()
        [void]$NetworkLogon.Add($Administrators)
        [void]$NetworkLogon.Add('Authenticated Users')
        [void]$NetworkLogon.Add('enterprise domain controllers')

        # Deny access to this computer from the network
        $DenyNetworkLogon = [System.Collections.Generic.List[object]]::New()
        [void]$DenyNetworkLogon.Add('ANONYMOUS LOGON')
        [void]$DenyNetworkLogon.Add('Local Account')
        [void]$DenyNetworkLogon.Add('Local Account and member of administrators group')

        # Allow Logon Locally
        # $InteractiveLogon = [System.Collections.Generic.List[object]]::New()

        # Deny Logon Locally
        $DenyInteractiveLogon = [System.Collections.Generic.List[object]]::New()
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

        # Allow Logon through RDS/TerminalServices
        # $RemoteInteractiveLogon = [System.Collections.Generic.List[object]]::New()

        # Deny logon through RDS/TerminalServices
        $DenyRemoteInteractiveLogon = [System.Collections.Generic.List[object]]::New()
        [void]$DenyRemoteInteractiveLogon.Add('Local Account')
        [void]$DenyRemoteInteractiveLogon.Add('Guests')
        [void]$DenyRemoteInteractiveLogon.Add($AccountOperators)
        [void]$DenyRemoteInteractiveLogon.Add('Backup Operators')
        [void]$DenyRemoteInteractiveLogon.Add('Print Operators')
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

        # Allow Logon as a Batch job
        # $BatchLogon = [System.Collections.Generic.List[object]]::New()

        # Deny Logon as a Batch job / Deny Logon as a Service
        $DenyBatchLogon = [System.Collections.Generic.List[object]]::New()
        [void]$DenyBatchLogon.Add($SchemaAdmins)
        [void]$DenyBatchLogon.Add($EnterpriseAdmins)
        [void]$DenyBatchLogon.Add($DomainAdmins)
        [void]$DenyBatchLogon.Add($Administrators)
        [void]$DenyBatchLogon.Add($AccountOperators)
        [void]$DenyBatchLogon.Add('Backup Operators')
        [void]$DenyBatchLogon.Add('Print Operators')
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
        if ($null -ne $NewAdminExists) {
            [void]$DenyBatchLogon.Add($NewAdminExists)
        }

        # Logon as a Service
        $ServiceLogon = [System.Collections.Generic.List[object]]::New()
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

        #endregion






        #region Domain Controllers
        #------------------------------------------------------------------------------

        # Access this computer from the network
        $NetworkLogon = [System.Collections.Generic.List[object]]::New()
        [void]$NetworkLogon.Add($Administrators)
        [void]$NetworkLogon.Add('Authenticated Users')
        [void]$NetworkLogon.Add('Enterprise Domain Controllers')

        # Allow Logon Locally / Allow Logon through RDP/TerminalServices
        $InteractiveLogon = [System.Collections.Generic.List[object]]::New()
        [void]$InteractiveLogon.Add($SchemaAdmins)
        [void]$InteractiveLogon.Add($EnterpriseAdmins)
        [void]$InteractiveLogon.Add($DomainAdmins)
        [void]$InteractiveLogon.Add($Administrators)
        if ($null -ne $AdminName) {
            [void]$InteractiveLogon.Add($AdminName)
        }
        if ($null -ne $NewAdminExists) {
            [void]$InteractiveLogon.Add($NewAdminExists)
        }
        if ($null -ne $SG_Tier0Admins) {
            [void]$InteractiveLogon.Add($SG_Tier0Admins)
        }
        $RemoteInteractiveLogon = [System.Collections.Generic.List[object]]::New()
        $RemoteInteractiveLogon = $InteractiveLogon


        # Deny Logon Locally / Deny Logon through RDP/TerminalServices
        $DenyInteractiveLogon = [System.Collections.Generic.List[object]]::New()
        [void]$DenyInteractiveLogon.Add($AccountOperators)
        [void]$DenyInteractiveLogon.Add('Backup Operators')
        [void]$DenyInteractiveLogon.Add('Print Operators')
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
        $DenyRemoteInteractiveLogon = [System.Collections.Generic.List[object]]::New()
        $DenyRemoteInteractiveLogon = $DenyInteractiveLogon


        # Deny Logon as a Batch job / Deny Logon as a Service
        $DenyBatchLogon = [System.Collections.Generic.List[object]]::New()
        [void]$DenyBatchLogon.Add($SchemaAdmins)
        [void]$DenyBatchLogon.Add($EnterpriseAdmins)
        [void]$DenyBatchLogon.Add($DomainAdmins)
        [void]$DenyBatchLogon.Add($Administrators)
        [void]$DenyBatchLogon.Add($AccountOperators)
        [void]$DenyBatchLogon.Add('Backup Operators')
        [void]$DenyBatchLogon.Add('Print Operators')
        [void]$DenyBatchLogon.Add($ServerOperators)
        [void]$DenyBatchLogon.Add($GPOCreatorsOwner)
        [void]$DenyBatchLogon.Add($CryptoOperators)
        [void]$DenyBatchLogon.Add('Guests')
        if ($null -ne $AdminName) {
            [void]$DenyBatchLogon.Add($AdminName)
        }
        if ($null -ne $NewAdminExists) {
            [void]$DenyBatchLogon.Add($NewAdminExists)
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
        $DenyServiceLogon = [System.Collections.Generic.List[object]]::New()
        $DenyServiceLogon = $DenyBatchLogon


        # Back up files and directories / Bypass traverse checking / Create Global Objects / Create symbolic links
        # Change System Time / Change Time Zone / Force shutdown from a remote system
        # Create Page File / Enable computer and user accounts to be trusted for delegation
        # Impersonate a client after authentication / Load and unload device drivers
        # Increase scheduling priority / Manage auditing and security log
        # Modify firmware environment values / Perform volume maintenance tasks
        # Profile single process / Profile system performance / Restore files and directories
        # Shut down the system / Take ownership of files or other objects
        $Backup = [System.Collections.Generic.List[object]]::New()
        [void]$Backup.Add($Administrators)
        if ($null -ne $SG_Tier0Admins) {
            [void]$Backup.Add($SG_Tier0Admins)
        }
        if ($null -ne $SG_AdAdmins) {
            [void]$Backup.Add($SG_AdAdmins)
        }

        <#
        # Not modified for this GPO

            $DenyNetworkLogon = [System.Collections.Generic.List[object]]::New()
            $MachineAccount = [System.Collections.Generic.List[object]]::New()
            $IncreaseQuota = [System.Collections.Generic.List[object]]::New()
            $CreateGlobal = [System.Collections.Generic.List[object]]::New()
            $Audit = [System.Collections.Generic.List[object]]::New()
            $IncreaseWorkingSet = [System.Collections.Generic.List[object]]::New()
            $Relabel = [System.Collections.Generic.List[object]]::New()
            $DelegateSessionUserImpersonate = [System.Collections.Generic.List[object]]::New()
            $Undock = [System.Collections.Generic.List[object]]::New()
            $SyncAgent = [System.Collections.Generic.List[object]]::New()
        #>

        # Modify all rights in one shot
        $Splat = @{
            GpoToModify                = 'C-{0}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Name
            NetworkLogon               = $NetworkLogon
            InteractiveLogon           = $InteractiveLogon
            RemoteInteractiveLogon     = $RemoteInteractiveLogon
            DenyRemoteInteractiveLogon = $DenyRemoteInteractiveLogon
            DenyInteractiveLogon       = $DenyInteractiveLogon
            BatchLogon                 = $SG_Tier0ServiceAccount, 'Performance Log Users'
            ServiceLogon               = $SG_Tier0ServiceAccount, 'Network Service'
            DenyServiceLogon           = $DenyServiceLogon
            DenyBatchLogon             = $DenyBatchLogon
            Backup                     = $Backup
            ChangeNotify               = $Backup, 'LOCAL SERVICE', 'NETWORK SERVICE'
            CreateGlobal               = $Backup, 'LOCAL SERVICE', 'NETWORK SERVICE'
            Systemtime                 = $Backup, 'LOCAL SERVICE'
            TimeZone                   = $Backup
            CreatePagefile             = $Backup
            CreateSymbolicLink         = $Backup
            EnableDelegation           = $Backup
            RemoteShutDown             = $Backup
            Impersonate                = $Backup, 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE'
            IncreaseBasePriority       = $Backup
            LoadDriver                 = $Backup
            AuditSecurity              = $Backup
            SystemEnvironment          = $Backup
            ManageVolume               = $Backup
            ProfileSingleProcess       = $Backup
            SystemProfile              = $Backup
            AssignPrimaryToken         = 'LOCAL SERVICE', 'NETWORK SERVICE'
            Restore                    = $Backup
            Shutdown                   = $Backup
            TakeOwnership              = $Backup
        }
        Set-GpoPrivilegeRight @Splat


        # Additional configuration for File permissions and Registry permissions
        # these settings are intended to "delegate" software maintenance tasks to Dc_Management group

        # File Security
        Set-GpoFileSecurity -GpoToModify 'C-DomainControllers-Baseline' -Group $SL_DcManagement -Verbose
        # Registry Keys
        Set-GpoRegistryKey -GpoToModify 'C-DomainControllers-Baseline' -Group $SL_DcManagement -Verbose

        #endregion





        #region Admin Area
        #------------------------------------------------------------------------------

        # Logon as a Batch job / Logon as a Service
        $BatchLogon = [System.Collections.Generic.List[object]]::New()

        [void]$BatchLogon.Add('Network Service')
        [void]$BatchLogon.Add('All Services')
        if ($null -ne $SG_Tier0ServiceAccount) {
            [void]$BatchLogon.Add($SG_Tier0ServiceAccount)
        }
        $ServiceLogon = [System.Collections.Generic.List[object]]::New()
        $ServiceLogon = $BatchLogon

        # Deny Logon as a Batch job / Deny Logon as a Service
        $DenyBatchLogon = [System.Collections.Generic.List[object]]::New()
        [void]$DenyBatchLogon.Add($SchemaAdmins)
        [void]$DenyBatchLogon.Add($EnterpriseAdmins)
        [void]$DenyBatchLogon.Add($DomainAdmins)
        [void]$DenyBatchLogon.Add($Administrators)
        [void]$DenyBatchLogon.Add($AccountOperators)
        [void]$DenyBatchLogon.Add('Backup Operators')
        [void]$DenyBatchLogon.Add('Print Operators')
        [void]$DenyBatchLogon.Add($ServerOperators)
        [void]$DenyBatchLogon.Add($RODC)
        [void]$DenyBatchLogon.Add($GPOCreatorsOwner)
        [void]$DenyBatchLogon.Add($CryptoOperators)
        [void]$DenyBatchLogon.Add('Guests')
        if ($null -ne $AdminName) {
            [void]$DenyBatchLogon.Add($AdminName)
        }
        if ($null -ne $NewAdminExists) {
            [void]$DenyBatchLogon.Add($NewAdminExists)
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
        $DenyServiceLogon = [System.Collections.Generic.List[object]]::New()
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
            SystemTime           = $ArrayList, 'LOCAL SERVICE'
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
        Set-GpoPrivilegeRight @Splat



        # Admin Area = HOUSEKEEPING
        #------------------------------------------------------------------------------

        # Access this computer from the network / Allow Logon Locally
        $NetworkLogon = [System.Collections.Generic.List[object]]::New()
        [void]$NetworkLogon.Add($DomainAdmins)
        [void]$NetworkLogon.Add($Administrators)
        if ($null -ne $SG_Tier0Admins) {
            [void]$NetworkLogon.Add($SG_Tier0Admins)
        }
        $InteractiveLogon = [System.Collections.Generic.List[object]]::New()
        $InteractiveLogon = $NetworkLogon

        # Logon as a Batch job / Logon as a Service
        $BatchLogon = [System.Collections.Generic.List[object]]::New()
        [void]$ArrayList.Add('Network Service')
        [void]$ArrayList.Add('All Services')
        if ($null -ne $SG_Tier0ServiceAccount) {
            [void]$ArrayList.Add($SG_Tier0ServiceAccount)
        }
        $ServiceLogon = [System.Collections.Generic.List[object]]::New()
        $ServiceLogon = $BatchLogon

        # Modify all rights in one shot
        $Splat = @{
            GpoToModify      = 'C-Housekeeping-LOCKDOWN'
            NetworkLogon     = $NetworkLogon
            InteractiveLogon = $InteractiveLogon
            BatchLogon       = $BatchLogon
            ServiceLogon     = $ServiceLogon
        }
        Set-GpoPrivilegeRight @Splat



        # Admin Area = Infrastructure
        #------------------------------------------------------------------------------

        # Allow Logon Locally / Allow Logon through RDP/TerminalServices
        $InteractiveLogon = [System.Collections.Generic.List[object]]::New()
        [void]$InteractiveLogon.Add($DomainAdmins)
        [void]$InteractiveLogon.Add($Administrators)
        if ($null -ne $SL_PISM) {
            [void]$InteractiveLogon.Add($SL_PISM)
        }
        if ($null -ne $SG_Tier0Admins) {
            [void]$InteractiveLogon.Add($SG_Tier0Admins)
        }
        $RemoteInteractiveLogon = [System.Collections.Generic.List[object]]::New()
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
            CreateGlobal           = $ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE'
            SystemTime             = $ArrayList, 'LOCAL SERVICE'
            TimeZone               = $ArrayList
            CreatePagefile         = $ArrayList
            CreateSymbolicLink     = $ArrayList
            RemoteShutdown         = $ArrayList
            Impersonate            = $ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE'
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
        Set-GpoPrivilegeRight @Splat


        # Admin Area = Tier0 Infrastructure
        #------------------------------------------------------------------------------

        # Allow Logon Locally / Allow Logon throug RDP/TerminalServices
        $InteractiveLogon = [System.Collections.Generic.List[object]]::New()
        [void]$ArrayList.Add($DomainAdmins)
        [void]$ArrayList.Add($Administrators)
        if ($null -ne $SL_PISM) {
            [void]$ArrayList.Add($SL_PISM)
        }
        if ($null -ne $SG_Tier0Admins) {
            [void]$ArrayList.Add($SG_Tier0Admins)
        }
        $RemoteInteractiveLogon = [System.Collections.Generic.List[object]]::New()
        $RemoteInteractiveLogon = $InteractiveLogon


        # Logon as a Batch job / Logon as a Service
        $BatchLogon = [System.Collections.Generic.List[object]]::New()
        [void]$ArrayList.Add('Network Service')
        [void]$ArrayList.Add('All Services')
        if ($null -ne $SG_Tier0ServiceAccount) {
            [void]$ArrayList.Add($SG_Tier0ServiceAccount)
        }
        $ServiceLogon = [System.Collections.Generic.List[object]]::New()
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
        Set-GpoPrivilegeRight @Splat



        # Admin Area = Tier1 Infrastructure
        #------------------------------------------------------------------------------

        # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
        $Splat = @{
            GpoToModify            = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1OU.Name
            InteractiveLogon       = $SG_Tier1Admins, $Administrators
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
        Set-GpoPrivilegeRight @Splat



        # Admin Area = Tier2 Infrastructure
        #------------------------------------------------------------------------------

        # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
        $Splat = @{
            GpoToModify            = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2OU.Name
            InteractiveLogon       = $SG_Tier2Admins, $Administrators
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
        Set-GpoPrivilegeRight @Splat




        # Admin Area = Staging Infrastructure
        #------------------------------------------------------------------------------

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
            GpoToModify            = ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.name)
            InteractiveLogon       = $ArrayList
            RemoteInteractiveLogon = $ArrayList
            RemoteShutdown         = $ArrayList
            SystemTime             = $ArrayList
            ChangeNotify           = $ArrayList
            ManageVolume           = $ArrayList
            SystemProfile          = $ArrayList
            Shutdown               = $ArrayList
        }
        Set-GpoPrivilegeRight @Splat





        #region Admin Area = PAWs
        #------------------------------------------------------------------------------

        # Not Defined




        # Admin Area = Staging PAWs
        #------------------------------------------------------------------------------

        # Allow Logon Locally / Allow Logon through RDP/TerminalServices
        $Splat = @{
            GpoToModify            = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name
            InteractiveLogon       = $SL_PAWM, $Administrators
            RemoteInteractiveLogon = $SL_PAWM
            RemoteShutdown         = $SL_PAWM
            SystemTime             = $SL_PAWM
            ChangeNotify           = $SL_PAWM
            ManageVolume           = $SL_PAWM
            SystemProfile          = $SL_PAWM
            Shutdown               = $SL_PAWM
        }
        Set-GpoPrivilegeRight @Splat




        # Admin Area = Tier0 PAWs
        #------------------------------------------------------------------------------

        # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
        # Deny Allow Logon Locally / Deny Allow Logon through RDP/TerminalServices
        # Deny Logon as a Batch job / Deny Logon as a Service
        $SystemProfile
        $Splat = @{
            GpoToModify                = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name
            InteractiveLogon           = $SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminExists
            RemoteInteractiveLogon     = $SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminExists
            BatchLogon                 = $SG_Tier0ServiceAccount
            ServiceLogon               = $SG_Tier0ServiceAccount
            DenyInteractiveLogon       = $SG_Tier1Admins, $SG_Tier2Admins
            DenyRemoteInteractiveLogon = $SG_Tier1Admins, $SG_Tier2Admins
            DenyBatchLogon             = $SG_Tier1ServiceAccount, $SG_Tier2ServiceAccount
            DenyServiceLogon           = $SG_Tier1ServiceAccount, $SG_Tier2ServiceAccount
            RemoteShutdown             = $SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminExists
            SystemTime                 = $SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminExists
            ChangeNotify               = $SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminExists
            ManageVolume               = $SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminExists
            SystemProfile              = $SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminExists
            Shutdown                   = $SL_PAWM, $Administrators, $SG_Tier0Admins, $AdminName, $NewAdminExists
        }
        Set-GpoPrivilegeRight @Splat



        # Admin Area = Tier1 PAWs
        #------------------------------------------------------------------------------

        # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
        # Deny Allow Logon Locally / Deny Allow Logon through RDP/TerminalServices
        # Deny Logon as a Batch job / Deny Logon as a Service
        $Splat = @{
            GpoToModify                = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name
            InteractiveLogon           = $SG_Tier1Admins, $Administrators
            RemoteInteractiveLogon     = $SG_Tier1Admins
            BatchLogon                 = $SG_Tier1ServiceAccount
            ServiceLogon               = $SG_Tier1ServiceAccount
            DenyInteractiveLogon       = $SG_Tier0Admins, $SG_Tier2Admins
            DenyRemoteInteractiveLogon = $SG_Tier0Admins, $SG_Tier2Admins
            DenyBatchLogon             = $SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount
            DenyServiceLogon           = $SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount
            RemoteShutdown             = $SG_Tier1Admins
            SystemTime                 = $SG_Tier1Admins
            ChangeNotify               = $SG_Tier1Admins
            ManageVolume               = $SG_Tier1Admins
            SystemProfile              = $SG_Tier1Admins
            Shutdown                   = $SG_Tier1Admins
        }
        Set-GpoPrivilegeRight @Splat



        # Admin Area = Tier2 PAWs
        #------------------------------------------------------------------------------

        # Allow Logon Locally / Allow Logon through RDP/TerminalServices / Logon as a Batch job / Logon as a Service
        # Deny Allow Logon Locally / Deny Allow Logon through RDP/TerminalServices
        # Deny Logon as a Batch job / Deny Logon as a Service
        $Splat = @{
            GpoToModify                = 'C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name
            InteractiveLogon           = $SG_Tier2Admins, $Administrators
            RemoteInteractiveLogon     = $SG_Tier2Admins
            BatchLogon                 = $SG_Tier2ServiceAccount
            ServiceLogon               = $SG_Tier2ServiceAccount
            DenyInteractiveLogon       = $SG_Tier0Admins, $SG_Tier1Admins
            DenyRemoteInteractiveLogon = $SG_Tier0Admins, $SG_Tier1Admins
            DenyBatchLogon             = $SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount
            DenyServiceLogon           = $SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount
            RemoteShutdown             = $SG_Tier2Admins
            SystemTime                 = $SG_Tier2Admins
            ChangeNotify               = $SG_Tier2Admins
            ManageVolume               = $SG_Tier2Admins
            SystemProfile              = $SG_Tier2Admins
            Shutdown                   = $SG_Tier2Admins
        }
        Set-GpoPrivilegeRight @Splat

        #endregion

        #endregion


        #endregion
        ###############################################################################



        ###############################################################################
        #region SERVERS OU (area)

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Servers Area (Tier 1)...')

        ###############################################################################
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

        $Splat1 = @{
            ouName        = $confXML.n.Servers.OUs.ApplicationOU.Name
            ouDescription = $confXML.n.Servers.OUs.ApplicationOU.Description
        }
        New-DelegateAdOU @Splat @Splat1
        $Splat1 = @{
            ouName        = $confXML.n.Servers.OUs.FileOU.Name
            ouDescription = $confXML.n.Servers.OUs.FileOU.Description
        }
        New-DelegateAdOU @Splat @Splat1
        $Splat1 = @{
            ouName        = $confXML.n.Servers.OUs.HypervOU.Name
            ouDescription = $confXML.n.Servers.OUs.HypervOU.Description
        }
        New-DelegateAdOU @Splat @Splat1
        $Splat1 = @{
            ouName        = $confXML.n.Servers.OUs.LinuxOU.Name
            ouDescription = $confXML.n.Servers.OUs.LinuxOU.Description
        }
        New-DelegateAdOU @Splat @Splat1
        $Splat1 = @{
            ouName        = $confXML.n.Servers.OUs.RemoteDesktopOU.Name
            ouDescription = $confXML.n.Servers.OUs.RemoteDesktopOU.Description
        }
        New-DelegateAdOU @Splat @Splat1
        $Splat1 = @{
            ouName        = $confXML.n.Servers.OUs.SqlOU.Name
            ouDescription = $confXML.n.Servers.OUs.SqlOU.Description
        }
        New-DelegateAdOU @Splat @Splat1
        $Splat1 = @{
            ouName        = $confXML.n.Servers.OUs.WebOU.Name
            ouDescription = $confXML.n.Servers.OUs.WebOU.Description
        }
        New-DelegateAdOU @Splat @Splat1









        # Create basic GPO for Servers
        $Splat = @{
            gpoDescription = '{0}-Baseline' -f $ServersOu
            gpoScope       = $confXML.n.Admin.GPOs.ServersBaseline.Scope
            gpoLinkPath    = $ServersOuDn
            GpoAdmin       = $sl_GpoAdminRight
            gpoBackupId    = $confXML.n.Admin.GPOs.ServersBaseline.backupID
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
        }
        New-DelegateAdGpo @Splat

        # Create basic GPOs for different types under Servers
        $Splat = @{
            gpoScope      = 'C'
            GpoAdmin      = $sl_GpoAdminRight
            gpoBackupPath = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
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



        # Tier1 Restrictions
        #------------------------------------------------------------------------------

        # Access this computer from the network / Deny Access this computer from the network
        # Not Defined

        # Allow Logon Locally / Allow Logon throug RDP/TerminalServices / Logon as a Batch job / Logon as a Service
        # Deny Allow Logon Locally / Deny Allow Logon throug RDP/TerminalServices / Deny Logon as a Batch job / Deny Logon as a Service
        $DenyLogon = [System.Collections.Generic.List[object]]::New()
        [void]$DenyLogon.Add($SchemaAdmins)
        [void]$DenyLogon.Add($EnterpriseAdmins)
        [void]$DenyLogon.Add($DomainAdmins)
        [void]$DenyLogon.Add($Administrators)
        [void]$DenyLogon.Add($AccountOperators)
        [void]$DenyLogon.Add('Backup Operators')
        [void]$DenyLogon.Add('Print Operators')
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
            DenyBatchLogon             = $SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount
            DenyServiceLogon           = $SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount
            Backup                     = $ArrayList
            MachineAccount             = $ArrayList
            CreateGlobal               = $ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE'
            Systemtime                 = $ArrayList, 'LOCAL SERVICE'
            TimeZone                   = $ArrayList
            CreatePagefile             = $ArrayList
            CreateSymbolicLink         = $ArrayList
            RemoteShutDown             = $ArrayList
            Impersonate                = $ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE'
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




        ###############################################################################
        #region Delegation to SL_SvrAdmRight and SL_SvrOpsRight groups to SERVERS area


        # Get the DN of 1st level OU underneath SERVERS area
        $Splat = @{
            Filter      = '*'
            SearchBase  = $ServersOuDn
            SearchScope = 'OneLevel'
        }
        $AllSubOu = Get-ADOrganizationalUnit @Splat | Select-Object -ExpandProperty DistinguishedName

        # Iterate through each sub OU and invoke delegation
        Foreach ($Item in $AllSubOu) {
            ###############################################################################
            # Delegation to SL_SvrAdmRight group to SERVERS area

            Set-AdAclDelegateComputerAdmin -Group $SL_SvrAdmRight -LDAPpath $Item

            ###############################################################################
            # Delegation to SL_SvrOpsRight group on SERVERS area

            # Change Public Info
            Set-AdAclComputerPublicInfo -Group $SL_SvrOpsRight -LDAPpath $Item

            # Change Personal Info
            Set-AdAclComputerPersonalInfo -Group $SL_SvrOpsRight -LDAPpath $Item

        }#end foreach

        # Create/Delete OUs within Servers
        Set-AdAclCreateDeleteOU -Group $SL_InfraRight -LDAPpath $ServersOuDn

        # Change OUs within Servers
        Set-AdAclChangeOU -Group $SL_AdRight -LDAPpath $ServersOuDn

        #endregion
        ###############################################################################

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create Sites OUs (Area)

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Sites Area (Tier 2)...')

        New-DelegateAdOU -ouName $SitesOu -ouPath $Variables.AdDn -ouDescription $confXML.n.Sites.OUs.SitesOU.Description

        # Create basic GPO for Users and Computers
        $Splat = @{
            gpoDescription = '{0}-Baseline' -f $SitesOu
            gpoLinkPath    = $SitesOuDn
            GpoAdmin       = $sl_GpoAdminRight
            gpoBackupPath  = Join-Path -Path $DMscripts -ChildPath 'SecTmpl' -Resolve
        }
        New-DelegateAdGpo @Splat -gpoScope 'C' -gpoBackupID $confXML.n.Sites.OUs.OuSiteComputer.backupID
        New-DelegateAdGpo @Splat -gpoScope 'U' -gpoBackupID $confXML.n.Sites.OUs.OuSiteUser.backupID




        # Tier2 Restrictions
        #------------------------------------------------------------------------------

        $DenyLogon = [System.Collections.Generic.List[object]]::New()
        [void]$DenyLogon.Add($SchemaAdmins)
        [void]$DenyLogon.Add($EnterpriseAdmins)
        [void]$DenyLogon.Add($DomainAdmins)
        [void]$DenyLogon.Add($Administrators)
        [void]$DenyLogon.Add($AccountOperators)
        [void]$DenyLogon.Add('Backup Operators')
        [void]$DenyLogon.Add('Print Operators')
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
            DenyBatchLogon             = $SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount
            DenyServiceLogon           = $SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount
            BatchLogon                 = $SG_Tier2ServiceAccount
            ServiceLogon               = $SG_Tier2ServiceAccount
            InteractiveLogon           = $SG_Tier2Admins
            RemoteInteractiveLogon     = $SG_Tier2Admins
            Backup                     = $ArrayList
            MachineAccount             = $ArrayList
            CreateGlobal               = $ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE'
            Systemtime                 = $ArrayList, 'LOCAL SERVICE'
            TimeZone                   = $ArrayList
            CreatePagefile             = $ArrayList
            CreateSymbolicLink         = $ArrayList
            RemoteShutDown             = $ArrayList
            Impersonate                = $ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE'
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





        # Create Global OU within SITES area
        $Splat = @{
            ouName        = $SitesGlobalOu
            ouPath        = $SitesOuDn
            ouDescription = $confXML.n.Sites.OUs.OuSiteGlobal.Description
        }
        New-DelegateAdOU @Splat

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


        # Sites OU
        # Create/Delete OUs within Sites
        Set-AdAclCreateDeleteOU -Group $SL_InfraRight -LDAPpath $SitesOuDn

        # Sites OU
        # Change OUs
        Set-AdAclChangeOU -Group $SL_AdRight -LDAPpath $SitesOuDn


        Write-Verbose -Message 'START APPLICATION ACCESS USER Global Delegation'
        ###############################################################################
        #region USER Site Administrator Delegation
        $Splat = @{
            Group    = $SL_GlobalAppAccUserRight
            LDAPPath = $SitesGlobalAppAccUserOuDn
        }
        Set-AdAclDelegateUserAdmin @Splat

        #### GAL
        Set-AdAclDelegateGalAdmin @Splat

        Add-AdGroupNesting -Identity $SL_GlobalAppAccUserRight -Members $SG_GlobalUserAdmins

        #endregion USER Site Delegation
        ###############################################################################

        Write-Verbose -Message 'START GROUP Global Delegation'
        ###############################################################################
        #region GROUP Site Admin Delegation

        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_GlobalGroupRight -LDAPpath $SitesGlobalGroupOuDn

        # Nest groups
        Add-AdGroupNesting -Identity $SL_GlobalGroupRight -Members $SG_GlobalGroupAdmins

        #### GAL

        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_GlobalGroupRight -LDAPpath $SitesGlobalGroupOuDn

        #endregion GROUP Site Delegation
        ###############################################################################

        Write-Verbose -Message 'Sites area was delegated correctly to the corresponding groups.'

        #endregion
        ###############################################################################


        ###############################################################################
        # Check if Exchange objects have to be created. Process if TRUE
        if ($CreateExchange) {

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Exchange On-Prem objects and delegations')

            # Get the Config.xml file
            $param = @{
                ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath 'Config.xml' -Resolve
                verbose       = $true
            }

            New-ExchangeObject @param
        }

        ###############################################################################
        # Check if DFS objects have to be created. Process if TRUE
        if ($CreateDfs) {

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating DFS objects and delegations')
            # Get the Config.xml file
            $param = @{
                ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath 'Config.xml' -Resolve
                verbose       = $true
            }
            New-DfsObject @param
        }

        ###############################################################################
        # Check if Certificate Authority (PKI) objects have to be created. Process if TRUE
        if ($CreateCa) {

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating CA Services, objects and delegations')

            New-CaObject -ConfigXMLFile $ConfXML
        }

        ###############################################################################
        # Check if Advanced Group Policy Management (AGPM) objects have to be created. Process if TRUE
        if ($CreateAGPM) {

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating AGPM objects and delegations')

            New-AGPMObject -ConfigXMLFile $ConfXML
        }

        ###############################################################################
        # Check if MS Local Administrator Password Service (LAPS) is to be used. Process if TRUE
        if ($CreateLAPS) {

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating LAPS objects and delegations')
            #To-Do
            #New-LAPSobjects -PawOuDn $ItPawOuDn -ServersOuDn $ServersOuDn -SitesOuDn $SitesOuDn
            New-LAPSobject -ConfigXMLFile $PSBoundParameters['ConfigXMLFile']
        }

        ###############################################################################
        # Check if DHCP is to be used. Process if TRUE
        if ($CreateDHCP) {

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating DHCP objects and delegations')

            #
            New-DHCPobject -ConfigXMLFile $ConfXML
        }

    } #end Process

    End {

        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'creating central OU.'
        )
        Write-Verbose -Message $txt

    } #end End

} #end Function
