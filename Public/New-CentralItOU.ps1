function New-CentralItOu
{
    <#
        .Synopsis
            Create Central OU and aditional Tier 0 infrastructure OUs
        .DESCRIPTION
            Create Central OU including sub-OUs, secure them accordingly, move built-in objects
            and secure them, create needed groups and secure them, make nesting and delegations
            and finaly create PSO and delegate accordingly.
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
                Remove-Everyone                        | EguibarIT.Delegation
                Remove-PreWin2000                      | EguibarIT.Delegation
                Set-AdAclChangeGroup                   | EguibarIT.Delegation
                Set-AdAclChangeOU                      | EguibarIT.Delegation
                Set-AdAclChangeSite                    | EguibarIT.Delegation
                Set-AdAclChangeSiteLink                | EguibarIT.Delegation
                Set-AdAclChangeSubnet                  | EguibarIT.Delegation
                Set-AdAclChangeUserPassword            | EguibarIT.Delegation
                Set-AdAclComputerPersonalInfo          | EguibarIT.Delegation
                Set-AdAclComputerPublicInfo            | EguibarIT.Delegation
                Set-AdAclCreateDeleteComputer          | EguibarIT.Delegation
                Set-AdAclCreateDeleteContact           | EguibarIT.Delegation
                Set-AdAclCreateDeleteGMSA              | EguibarIT.Delegation
                Set-AdAclCreateDeleteGPO               | EguibarIT.Delegation
                Set-AdAclCreateDeleteGroup             | EguibarIT.Delegation
                Set-AdAclCreateDeleteMSA               | EguibarIT.Delegation
                Set-AdAclCreateDeleteOU                | EguibarIT.Delegation
                Set-AdAclCreateDeleteOU                | EguibarIT.Delegation
                Set-AdAclCreateDeletePrintQueue        | EguibarIT.Delegation
                Set-AdAclCreateDeleteSite              | EguibarIT.Delegation
                Set-AdAclCreateDeleteSiteLink          | EguibarIT.Delegation
                Set-AdAclCreateDeleteSubnet            | EguibarIT.Delegation
                Set-AdAclCreateDeleteUser              | EguibarIT.Delegation
                Set-AdAclCreateDeleteUser              | EguibarIT.Delegation
                Set-AdAclGPoption                      | EguibarIT.Delegation
                Set-AdAclLinkGPO                       | EguibarIT.Delegation
                Set-AdAclMngPrivilegedAccounts         | EguibarIT.Delegation
                Set-AdAclMngPrivilegedGroups           | EguibarIT.Delegation
                Set-AdAclResetUserPassword             | EguibarIT.Delegation
                Set-AdAclUserAccountRestriction        | EguibarIT.Delegation
                Set-AdAclUserGroupMembership           | EguibarIT.Delegation
                Set-AdAclUserLogonInfo                 | EguibarIT.Delegation
                Set-AdDirectoryReplication             | EguibarIT.Delegation
                Set-AdInheritance                      | EguibarIT.Delegation
                Set-CreateDeleteInetOrgPerson          | EguibarIT.Delegation
                Set-DeleteOnlyComputer                 | EguibarIT.Delegation
                Set-GpoPrivilegeRights                 | EguibarIT.Delegation
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
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        # Param2 If present It will create all needed Exchange objects, containers and delegations
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects, containers and delegations.',
        Position = 1)]
        [switch]
        $CreateExchange,

        # Param3 Create DFS Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed DFS objects, containers and delegations.',
        Position = 2)]
        [switch]
        $CreateDfs,

        # Param4 Create CA (PKI) Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Certificate Authority (PKI) objects, containers and delegations.',
        Position = 3)]
        [switch]
        $CreateCa,

        # Param5 Create AGPM Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed AGPM objects, containers and delegations.',
        Position = 4)]
        [switch]
        $CreateAGPM,

        # Param6 Create LAPS Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed LAPS objects, containers and delegations.',
        Position = 5)]
        [switch]
        $CreateLAPS,

        # Param7 Create DHCP Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed DHCP objects, containers and delegations.',
        Position = 6)]
        [switch]
        $CreateDHCP,

        # Param8 Location of all scripts & files
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 7)]
        [string]
        $DMscripts = "C:\PsScripts\"
    )

    Begin {

        $error.clear()

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
        Import-Module -name ServerManager        -Verbose:$false
        Import-Module -name ActiveDirectory      -Verbose:$false
        Import-Module -name GroupPolicy          -Verbose:$false
        Import-Module -name EguibarIT            -Verbose:$false
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        ################################################################################
        #region Declarations

        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                $AdDn = ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        } catch { Get-CurrentErrorToDisplay -CurrentError $error[0] } # End Try

        # Read the value from parsed SWITCH parameters.
        try {
            # Check if CreateExchange parameter is parsed.
            If($PSBoundParameters['CreateExchange']) {
                # If parameter is parsed, then make variable TRUE
                $CreateExchange = $True
            } else {
                # Otherwise variable is FALSE
                $CreateExchange = $False
            }

            # Check if CreateDfs parameter is parsed.
            If($PSBoundParameters['CreateDfs']) {
                # If parameter is parsed, then make variable TRUE
                $CreateDfs = $True
            } else {
                # Otherwise variable is FALSE
                $CreateDfs = $False
            }

            # Check if CreateCa parameter is parsed.
            If($PSBoundParameters['CreateCa']) {
                # If parameter is parsed, then make variable TRUE
                $CreateCa = $True
            } else {
                # Otherwise variable is FALSE
                $CreateCa = $False
            }

            # Check if CreateAGPM  parameter is parsed.
            If($PSBoundParameters['CreateAGPM']) {
                # If parameter is parsed, then make variable TRUE
                $CreateAGPM = $True
            } else {
                # Otherwise variable is FALSE
                $CreateAGPM = $False
            }

            # Check if CreateLAPS  parameter is parsed.
            If($PSBoundParameters['CreateLAPS']) {
                # If parameter is parsed, then make variable TRUE
                $CreateLAPS = $True
            } else {
                # Otherwise variable is FALSE
                $CreateLAPS = $False
            }
        } catch { Get-CurrentErrorToDisplay -CurrentError $error[0] } # End Try

        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0





        # Global Groups
        Foreach($node in $confXML.n.Admin.GG.ChildNodes) {
            $param = @{
                Name        = "$('SG{0}{1}' -f $NC['Delim'], $Node.LocalName)"
                Value       = 'SG{0}{1}' -f $NC['Delim'], $Node.Name
                Description = $Node.Description
                Option      = 'ReadOnly'
                Force       = $true
            }
            # Create variable for each defined ADMIN GlobalGroup name, Appending SG prefix
            New-Variable @Param
        }

        New-Variable -Name "SG_Operations" -Value ('SGg{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.Operations.Name) -Force
        New-Variable -Name "SG_ServerAdmins" -Value ('SG{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name) -Force





        # Domain Local Groups
        Foreach($node in $confXML.n.Admin.LG.ChildNodes) {
            $param = @{
                Name        = "$('SL{0}{1}' -f $NC['Delim'], $Node.LocalName)"
                Value       = 'SL{0}{1}' -f $NC['Delim'], $Node.Name
                Description = $Node.Description
                Option      = 'ReadOnly'
                Force       = $true
            }
            # Create variable for each defined ADMIN LocalGroup name using the XML name, Appending SL prefix
            New-Variable @Param

        }

        New-Variable -Name "SL_SvrAdmRight" -Value ('SL{0}{1}' -f $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name) -Force
        New-Variable -Name "SL_SvrOpsRight" -Value ('SL{0}{1}' -f $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.Name) -Force





        # Users
        $AdminName    = $confXML.n.Admin.users.Admin.Name
        $newAdminName = $confXML.n.Admin.users.NEWAdmin.Name





        # Organizational Units Names
        # Iterate all OUs within Admin
        Foreach($node in $confXML.n.Admin.OUs.ChildNodes) {
            $param = @{
                Name        = "$($Node.LocalName)"
                Value       = $Node.Name
                Description = $Node.Description
                Option      = 'ReadOnly'
                Force       = $true
            }
            # Create variable for current OUs name, Using the XML LocalName of the node for the variable
            New-Variable @Param
        }

        # Organizational Units Distinguished Names

        # Domain Controllers DistinguishedName
        $DCsOuDn = ('OU=Domain Controllers,{0}' -f $AdDn)

        # Admin Area

        # IT Admin OU Distinguished Name
        New-Variable -Name 'ItAdminOuDn' -Value ('OU={0},{1}' -f $ItAdminOu, $AdDn) -Option ReadOnly -Force

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



        # Servers Area

        # Servers OU
        New-Variable -Name 'ServersOu' -Value $confXML.n.Servers.OUs.ServersOU.Name -Option ReadOnly -Force
        # Servers OU Distinguished Name
        $ServersOuDn = 'OU={0},{1}' -f $ServersOu, $AdDn



        # Sites Area

        # Sites OU
        New-Variable -Name 'SitesOu' -Value $confXML.n.Sites.OUs.SitesOU.name -Option ReadOnly -Force
        # Sites OU Distinguished Name
        $SitesOuDn = 'OU={0},{1}' -f $SitesOu, $AdDn

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




        # Quarantine OU for PCs
        New-Variable -Name 'ItQuarantinePcOu' -Value $confXML.n.Admin.OUs.ItNewComputersOU.name -Option ReadOnly -Force
        # Quarantine OU Distinguished Name
        $ItQuarantinePcOuDn = 'OU={0},{1}' -f $ItQuarantinePcOu, $AdDn

        # Quarantine OU for PCs
        New-Variable -Name 'ItQuarantineUserOu' -Value $confXML.n.Admin.OUs.ItNewUsersOU.name -Option ReadOnly -Force
        # Quarantine OU Distinguished Name
        $ItQuarantineUserOuDn = 'OU={0},{1}' -f $ItQuarantineUserOu, $AdDn

        # parameters variable for splatting CMDlets
        $parameters = $null


        #endregion Declarations
        ################################################################################
    }
    Process {
        ###############################################################################
        # Create IT Admin and Sub OUs
        Write-Verbose -Message 'Create Admin Area and related structure...'
        New-DelegateAdOU -ouName $ItAdminOu -ouPath $AdDn -ouDescription $confXML.n.Admin.OUs.ItAdminOU.description

        # Remove Inheritance and copy the ACE
        Set-AdInheritance -LDAPPath $ItAdminOuDn -RemoveInheritance $true -RemovePermissions $true
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

        # Computer objects within this ares MUST have read access, otherwise GPO will not apply - TO BE DONE

        ###############################################################################
        #region Create Sub-OUs for admin

        $Splat = @{
            ouPath = $ItAdminOuDn
            CleanACL =$True
        }
        New-DelegateAdOU -ouName $ItAdminAccountsOu   -ouDescription $confXML.n.Admin.OUs.ItAdminAccountsOU.description   @Splat
        New-DelegateAdOU -ouName $ItAdminGroupsOU     -ouDescription $confXML.n.Admin.OUs.ItAdminGroupsOU.description     @Splat
        New-DelegateAdOU -ouName $ItPrivGroupsOU      -ouDescription $confXML.n.Admin.OUs.ItPrivGroupsOU.description      @Splat
        New-DelegateAdOU -ouName $ItPawOu             -ouDescription $confXML.n.Admin.OUs.ItPawOU.description             @Splat
        New-DelegateAdOU -ouName $ItRightsOu          -ouDescription $confXML.n.Admin.OUs.ItRightsOU.description          @Splat
        New-DelegateAdOU -ouName $ItServiceAccountsOu -ouDescription $confXML.n.Admin.OUs.ItServiceAccountsOU.description @Splat
        New-DelegateAdOU -ouName $ItHousekeepingOu    -ouDescription $confXML.n.Admin.OUs.ItHousekeepingOU.description    @Splat
        New-DelegateAdOU -ouName $ItInfraOu           -ouDescription $confXML.n.Admin.OUs.ItInfraOU.description           @Splat
        New-DelegateAdOU -ouName $ItAdminSrvGroups    -ouDescription $confXML.n.Admin.OUs.ItAdminSrvGroups.description    @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPPath $ItAdminAccountsOuDn   @Splat
        Set-AdInheritance -LDAPPath $ItAdminGroupsOUDn     @Splat
        Set-AdInheritance -LDAPPath $ItPrivGroupsOUDn      @Splat
        Set-AdInheritance -LDAPPath $ItPawOuDn             @Splat
        Set-AdInheritance -LDAPPath $ItRightsOuDn          @Splat
        Set-AdInheritance -LDAPPath $ItServiceAccountsOuDn @Splat
        Set-AdInheritance -LDAPPath $ItHousekeepingOuDn    @Splat
        Set-AdInheritance -LDAPPath $ItInfraOuDn           @Splat
        Set-AdInheritance -LDAPPath $ItAdminSrvGroupsOUDn  @Splat

        # PAW Sub-OUs
        $Splat = @{
            ouPath = $ItPawOuDn
            CleanACL =$True
        }
        New-DelegateAdOU -ouName $ItPawT0Ou      -ouDescription $confXML.n.Admin.OUs.ItPawT0OU.description      @Splat
        New-DelegateAdOU -ouName $ItPawT1Ou      -ouDescription $confXML.n.Admin.OUs.ItPawT1OU.description      @Splat
        New-DelegateAdOU -ouName $ItPawT2Ou      -ouDescription $confXML.n.Admin.OUs.ItPawT2OU.description      @Splat
        New-DelegateAdOU -ouName $ItPawStagingOu -ouDescription $confXML.n.Admin.OUs.ItPawStagingOU.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPPath $ItPawT0OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItPawT1OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItPawT2OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItPawStagingOuDn @Splat

        # Service Accounts Sub-OUs
        $Splat = @{
            ouPath = $ItServiceAccountsOuDn
            CleanACL =$True
        }
        New-DelegateAdOU -ouName $ItSAT0OU -ouDescription $confXML.n.Admin.OUs.ItSAT0OU.description @Splat
        New-DelegateAdOU -ouName $ItSAT1OU -ouDescription $confXML.n.Admin.OUs.ItSAT1OU.description @Splat
        New-DelegateAdOU -ouName $ItSAT2OU -ouDescription $confXML.n.Admin.OUs.ItSAT2OU.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPPath $ItSAT0OuDn @Splat
        Set-AdInheritance -LDAPPath $ItSAT1OuDn @Splat
        Set-AdInheritance -LDAPPath $ItSAT2OuDn @Splat

        # Infrastructure Servers Sub-OUs
        $Splat = @{
            ouPath = $ItInfraOuDn
            CleanACL =$True
        }
        New-DelegateAdOU -ouName $ItInfraT0Ou      -ouDescription $confXML.n.Admin.OUs.ItInfraT0.description        @Splat
        New-DelegateAdOU -ouName $ItInfraT1Ou      -ouDescription $confXML.n.Admin.OUs.ItInfraT1.description        @Splat
        New-DelegateAdOU -ouName $ItInfraT2Ou      -ouDescription $confXML.n.Admin.OUs.ItInfraT2.description        @Splat
        New-DelegateAdOU -ouName $ItInfraStagingOu -ouDescription $confXML.n.Admin.OUs.ItInfraStagingOU.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPPath $ItInfraT0OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItInfraT1OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItInfraT2OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItInfraStagingOuDn @Splat

        #endregion

        ###############################################################################
        #region  Move Built-In Admin user & Groups (Builtin OU groups can't be moved)

        Write-Verbose -Message 'Moving objects...'

        Get-ADUser -Identity $AdminName |                                 Move-ADObject -TargetPath $ItAdminAccountsOuDn
        Get-ADUser -Identity $confXML.n.Admin.users.Guest.Name |          Move-ADObject -TargetPath $ItAdminAccountsOuDn
        Get-ADUser -Identity krbtgt |                                     Move-ADObject -TargetPath $ItAdminAccountsOuDn

        Get-ADGroup -Identity 'Domain Admins' |                           Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Enterprise Admins' |                       Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Schema Admins' |                           Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Domain Controllers' |                      Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Group Policy Creator Owners' |             Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Read-only Domain Controllers' |            Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Enterprise Read-only Domain Controllers' | Move-ADObject -TargetPath $ItPrivGroupsOUDn

        Get-ADGroup -Identity 'DnsUpdateProxy' |                          Move-ADObject -TargetPath $ItAdminGroupsOuDn
        Get-ADGroup -Identity 'Domain Users' |                            Move-ADObject -TargetPath $ItAdminGroupsOuDn
        Get-ADGroup -Identity 'Domain Computers' |                        Move-ADObject -TargetPath $ItAdminGroupsOuDn
        Get-ADGroup -Identity 'Domain Guests' |                           Move-ADObject -TargetPath $ItAdminGroupsOuDn

        Get-ADGroup -Identity 'Allowed RODC Password Replication Group' | Move-ADObject -TargetPath $ItRightsOuDn
        Get-ADGroup -Identity 'RAS and IAS Servers' |                     Move-ADObject -TargetPath $ItRightsOuDn
        Get-ADGroup -Identity 'DNSAdmins' |                               Move-ADObject -TargetPath $ItRightsOuDn
        Get-ADGroup -Identity 'Cert Publishers' |                         Move-ADObject -TargetPath $ItRightsOuDn
        Get-ADGroup -Identity 'Denied RODC Password Replication Group' |  Move-ADObject -TargetPath $ItRightsOuDn

        # Following groups only exist on Win 2012
        If ($Global:OsBuild -ge 9200) {
            Get-ADGroup -Identity 'Protected Users' |              Move-ADObject -TargetPath $ItPrivGroupsOUDn
            Get-ADGroup -Identity 'Cloneable Domain Controllers' | Move-ADObject -TargetPath $ItPrivGroupsOUDn

            Get-ADGroup -Identity 'Access-Denied Assistance Users' | Move-ADObject -TargetPath $ItPrivGroupsOUDn
            Get-ADGroup -Filter { SamAccountName -like "WinRMRemoteWMIUsers*" } |           Move-ADObject -TargetPath $ItPrivGroupsOUDn
        }

        # Following groups only exist on Win 2019
        If ($Global:OsBuild -ge 17763) {
            Get-ADGroup -Identity 'Enterprise Key Admins'               | Move-ADObject -TargetPath $ItPrivGroupsOUDn
            Get-ADGroup -Identity 'Key Admins'                          | Move-ADObject -TargetPath $ItPrivGroupsOUDn
            #Get-ADGroup -Identity 'Windows Admin Center CredSSP Admins' | Move-ADObject -TargetPath $ItPrivGroupsOUDn
        }

        # Get-ADGroup "Administrators" |                          Move-ADObject -TargetPath $ItRightsOuDn
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
        # Get-ADGroup "Network Configuration Operators" |         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Performance Log Users" |                   Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Performance Monitor Users" |               Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Pre-Windows 2000 Compatible Access" |      Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Print Operators" |                         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Replicator" |                              Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Terminal Server License Servers" |         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Users" |                                   Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Windows Authorization Access Group" |      Move-ADObject -TargetPath $ItRightsOuDn

        #endregion
        ###############################################################################

        ###############################################################################
        #region Creating Secured Admin accounts

        Write-Verbose -Message 'Creating and securing Admin accounts...'

        #try {

        # Try to get the new Admin
        $NewAdminExists = Get-AdUser -Filter { SamAccountName -eq $newAdminName }

        # Get picture if exist. Use default if not.
        If(Test-Path -Path ('{0}\Pic\{1}.jpg' -f $DMscripts, $newAdminName)) {
            # Read the path and file name of JPG picture
            $PhotoFile = '{0}\Pic\{1}.jpg' -f $DMscripts, $newAdminName
            # Get the content of the JPG file
            $photo = [byte[]](Get-Content -Path $PhotoFile -Encoding byte)
        } else {
            If(Test-Path -Path ('{0}\Pic\Default.jpg' -f $DMscripts)) {
                # Read the path and file name of JPG picture
                $PhotoFile = '{0}\Pic\Default.jpg' -f $DMscripts
                # Get the content of the JPG file
                $photo = [byte[]](Get-Content -Path $PhotoFile -Encoding byte)
            } else {
                $photo = $null
            } #end If-Else
        } #end If-Else

        # Check if the new Admin account already exist. If not, then create it.
        If($NewAdminExists) {
            #The user was found. Proceed to modify it accordingly.
            $parameters = @{
                Enabled               = $true
                UserPrincipalName     = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                SamAccountName        = $newAdminName
                DisplayName           = $newAdminName
                Description           = $confXML.n.Admin.users.NEWAdmin.description
                employeeId            = '0123456'
                TrustedForDelegation  = $false
                AccountNotDelegated   = $true
                Company               = $confXML.n.RegisteredOrg
                Country               = 'MX'
                Department            = $confXML.n.Admin.users.NEWAdmin.department
                State                 = 'Puebla'
                EmailAddress          = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                Replace               = @{
                    'employeeType'                  = $confXML.n.NC.AdminAccSufix0
                    'msNpAllowDialin'               = $false
                    'msDS-SupportedEncryptionTypes' = '24'
                }
            }

            # If photo exist, add it to parameters
            If($photo) {
                # Only if photo exists, add it to splatting
                $parameters.Replace.Add('thumbnailPhoto',$photo)
            }

            Set-AdUser -Identity $NewAdminExists
        }  Else {
            # User was not Found! create new.
            $parameters = @{
                Path                  = $ItAdminAccountsOuDn
                Name                  = $newAdminName
                AccountPassword       = (ConvertTo-SecureString -String $confXML.n.DefaultPassword -AsPlainText -Force)
                ChangePasswordAtLogon = $false
                Enabled               = $true
                UserPrincipalName     = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                SamAccountName        = $newAdminName
                DisplayName           = $newAdminName
                Description           = $confXML.n.Admin.users.NEWAdmin.description
                employeeId            = '0123456'
                TrustedForDelegation  = $false
                AccountNotDelegated   = $true
                Company               = $confXML.n.RegisteredOrg
                Country               = 'MX'
                Department            = $confXML.n.Admin.users.NEWAdmin.department
                State                 = 'Puebla'
                EmailAddress          = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                OtherAttributes       = @{
                    'employeeType'                  = $confXML.n.NC.AdminAccSufix0
                    'msNpAllowDialin'               = $false
                    'msDS-SupportedEncryptionTypes' = '24'
                }
            }

            If($photo) {
                # Only if photo exists, add it to splatting
                $parameters.OtherAttributes.Add('thumbnailPhoto',$photo)
            } #end If

            # Create the new Admin with special values
            New-AdUser @parameters
            $NewAdminExists = Get-AdUser -Identity $newAdminName

            #http://blogs.msdn.com/b/openspecification/archive/2011/05/31/windows-configurations-for-kerberos-supported-encryption-type.aspx
            # 'msDS-SupportedEncryptionTypes'= Kerberos DES Encryption = 2, Kerberos AES 128 = 8, Kerberos AES 256 = 16
        } #end esle-if new user created

        # Set the Protect against accidental deletions attribute
        Get-AdUser -Identity $AdminName | Set-ADObject -ProtectedFromAccidentalDeletion $true
        $NewAdminExists                 | Set-ADObject -ProtectedFromAccidentalDeletion $true

        # Make it member of administrative groups
        Add-AdGroupNesting -Identity 'Domain Admins'                          -Members $NewAdminExists
        Add-AdGroupNesting -Identity 'Enterprise Admins'                      -Members $NewAdminExists
        Add-AdGroupNesting -Identity 'Group Policy Creator Owners'            -Members $NewAdminExists
        Add-AdGroupNesting -Identity 'Denied RODC Password Replication Group' -Members $NewAdminExists

        # http://blogs.msdn.com/b/muaddib/archive/2013/12/30/how-to-modify-security-inheritance-on-active-directory-objects.aspx

        ####
        # Remove Everyone group from Admin-User & Administrator
        Remove-Everyone -LDAPPath $NewAdminExists.DistinguishedName
        Remove-Everyone -LDAPPath ('CN={0},{1}' -f $AdminName, $ItAdminAccountsOuDn)

        ####
        # Remove AUTHENTICATED USERS group from Admin-User & Administrator
        #Remove-AuthUser -LDAPPath $NewAdminExists.DistinguishedName
        #Remove-AuthUser -LDAPPath ('CN={0},{1}' -f $AdminName, $ItAdminAccountsOuDn)

        ####
        # Remove Pre-Windows 2000 Compatible Access group from Admin-User & Administrator
        Remove-PreWin2000 -LDAPPath $NewAdminExists.DistinguishedName
        Remove-PreWin2000 -LDAPPath ('CN={0},{1}' -f $AdminName, $ItAdminAccountsOuDn)

        ###
        # Configure TheGood account
        $params = @{
            'employeeType'                  = $confXML.n.NC.AdminAccSufix0
            'msNpAllowDialin'               = $false
            'msDS-SupportedEncryptionTypes' = 24
        }

        If($photo) {
            # Only if photo exists, add it to splatting
            $params.Add('thumbnailPhoto',$photo)
        }

        Set-AdUser -Identity $AdminName -TrustedForDelegation $false -AccountNotDelegated $true -Add $params

        Write-Verbose -Message 'Admin accounts created and secured.'

        #endregion Creating Secured Admin accounts
        ###############################################################################

        ###############################################################################
        #region Create Admin groups

        # Iterate through all Admin-LocalGroups child nodes
        Foreach($Node in $confXML.n.Admin.LG.ChildNodes) {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $Node.Name))
            $parameters = @{
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
            $varparam = @{
                Name  = "$('SL{0}{1}' -f$NC['Delim'], $Node.LocalName)"
                Value = New-AdDelegatedGroup @parameters
                Force = $true
            }
            New-Variable @varparam
        } # End ForEach

        # Iterate through all Admin-GlobalGroups child nodes
        Foreach($Node in $confXML.n.Admin.GG.ChildNodes) {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.localname))
            $parameters = @{
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
            $varparam = @{
                Name  = "$('SG{0}{1}' -f $NC['Delim'], $Node.LocalName)"
                Value = New-AdDelegatedGroup @parameters
                Force = $true
            }
            New-Variable @varparam
        } # End ForEach


        # Create Servers Area / Tier1 Domain Local & Global Groups
        $parameters = @{
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
        New-Variable -Name "$('SG{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.Operations.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force

        $parameters = @{
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
        New-Variable -Name "$('SG{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force

        $parameters = @{
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
        New-Variable -Name "$('SL{0}{1}' -f  $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force

        $parameters = @{
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
        New-Variable -Name "$('SL{0}{1}' -f  $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force



        # Get all Privileged groups into an array
        $AllGroups = @(
            $SG_InfraAdmins,
            $SG_AdAdmins,
            $SG_Tier0ServiceAccount,
            $SG_Tier1ServiceAccount,
            $SG_Tier2ServiceAccount,
            $SG_GpoAdmins,
            $SG_Tier0Admins,
            $SG_Tier1Admins,
            $SG_Tier2Admins,
            $SG_AllSiteAdmins,
            $SG_AllGALAdmins
        )

        # Move the groups to PG OU
        foreach($item in $AllGroups) {
            # Remove the ProtectedFromAccidentalDeletion, otherwise throws error when moving
            $item | Set-ADObject -ProtectedFromAccidentalDeletion $false

            # Move objects to PG OU
            $item | Move-ADObject -TargetPath $ItPrivGroupsOUDn

            # Set back again the ProtectedFromAccidentalDeletion flag.
            #The group has to be fetch again because of the previus move
            Get-ADGroup -Identity $item.SamAccountName | Set-ADObject -ProtectedFromAccidentalDeletion $true
        }

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create Group Managed Service Account

        # Get the current OS build
        Get-OsBuild

        If ($Global:OsBuild -ge 9200) {
            # Create the KDS Root Key (only once per domain).  This is used by the KDS service on DCs (along with other information) to generate passwords
            # http://blogs.technet.com/b/askpfeplat/archive/2012/12/17/windows-server-2012-group-managed-service-accounts.aspx
            # If working in a test environment with a minimal number of DCs and the ability to guarantee immediate replication, please use:
            #    Add-KdsRootKey â€“EffectiveTime ((get-date).addhours(-10))
            Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10))
        }


        # Check if ServiceAccount exists
        $gMSASamAccountName = '{0}$' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name
        $ExistSA = Get-ADServiceAccount -filter { SamAccountName -like $gMSASamAccountName }

        If(-not $ExistSA) {
            Write-Verbose -Message ('Creating {0} Service Account {0}.' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name)
            If ($Global:OsBuild -ge 9200) {

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

                $ReplaceParams = @{
                    Replace = @{
                        'c'="MX"
                        'co'="Mexico"
                        'company'=$confXML.n.RegisteredOrg
                        'department'="IT"
                        'employeeID'='T0'
                        'employeeType'="ServiceAccount"
                        'info'=$confXML.n.Admin.gMSA.AdTaskScheduler.Description
                        'l'="Puebla"
                        'title'=$confXML.n.Admin.gMSA.AdTaskScheduler.DisplayName
                        'userPrincipalName'='{0}@{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN
                    }
                    ErrorAction = 'SilentlyContinue'
                }

                try {
                    New-ADServiceAccount @Splat | Set-ADServiceAccount @ReplaceParams
                } catch { Get-CurrentErrorToDisplay -CurrentError $error[0] }
            } else {
                $Splat = @{
                    name        = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                    Description = $confXML.n.Admin.gMSA.AdTaskScheduler.Description
                    Path        = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $ItServiceAccountsOuDn
                    enabled     = $True
                    ErrorAction = 'SilentlyContinue'
                }

                New-ADServiceAccount @Splat
            }
        } else {
            Write-Warning -Message ('Service Account {0} already exists.' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name)
        }# End If

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create a New Fine Grained Password Policy for Admins Accounts

        $PSOexists = $null

        [String]$PsoName = $confXML.n.Admin.PSOs.ItAdminsPSO.Name

        $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -eq $PsoName }

        if(-not($PSOexists)) {
            Write-Verbose -Message ('Creating {0} PSO.' -f $PsoName)
            $parameters = @{
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
            }

            New-ADFineGrainedPasswordPolicy @parameters
            Start-Sleep -Seconds 5
            $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -eq $PsoName }
        } # End If PSO exists


        Write-Verbose -Message ('Apply the {0} PSO to the corresponding accounts and groups.' -f $PsoName)
        Start-Sleep -Seconds 5
        # Apply the PSO to the corresponding accounts and groups
        $parameters = @( $AdminName,
                         $newAdminName,
                         'Domain Admins',
                         'Enterprise Admins',
                         $SG_InfraAdmins.SamAccountName,
                         $SG_AdAdmins.SamAccountName,
                         $SG_GpoAdmins.SamAccountName,
                         $SG_Tier0Admins.SamAccountName,
                         $SG_Tier1Admins.SamAccountName,
                         $SG_Tier2Admins.SamAccountName,
                         $SG_Operations.SamAccountName,
                         $SG_ServerAdmins.SamAccountName,
                         $SG_AllSiteAdmins.SamAccountName,
                         $SG_AllGALAdmins.SamAccountName,
                         $SG_GlobalUserAdmins.SamAccountName,
                         $SG_GlobalPcAdmins.SamAccountName,
                         $SG_GlobalGroupAdmins.SamAccountName,
                         $SG_ServiceDesk.SamAccountName,
                         $SL_InfraRight.SamAccountName,
                         $SL_AdRight.SamAccountName,
                         $SL_UM.SamAccountName,
                         $SL_GM.SamAccountName,
                         $SL_PUM.SamAccountName,
                         $SL_PGM.SamAccountName,
                         $SL_GpoAdminRight.SamAccountName,
                         $SL_DnsAdminRight.SamAccountName,
                         $SL_DirReplRight.SamAccountName,
                         $SL_PromoteDcRight.SamAccountName,
                         $SL_TransferFSMOright.SamAccountName,
                         $SL_PISM.SamAccountName,
                         $SL_PAWM.SamAccountName,
                         $SL_PSAM.SamAccountName,
                         $SL_SvrAdmRight.SamAccountName,
                         $SL_SvrOpsRight.SamAccountName,
                         $SL_GlobalGroupRight.SamAccountName,
                         $SL_GlobalAppAccUserRight.SamAccountName
        )
        Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $parameters


        #endregion
        ###############################################################################

        ###############################################################################
        #region Create a New Fine Grained Password Policy for Service Accounts

        $PSOexists = $null


        [String]$PsoName = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Name

        $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -eq $PsoName }

        if(-not($PSOexists)) {
            Write-Verbose -Message ('Creating {0} PSO.' -f $PsoName)
            $parameters = @{
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
            }
            New-ADFineGrainedPasswordPolicy @parameters
            Start-Sleep -Seconds 5
            $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { cn -eq $PsoName }
            #$PSOexists = Get-ADFineGrainedPasswordPolicy -Identity $PsoName
        }

        Write-Verbose -Message ('Apply the {0} PSO to the corresponding accounts and groups.' -f $PsoName)
        Start-Sleep -Seconds 5
        # Apply the PSO to all Tier Service Accounts
        $parameters = @( $SG_Tier0ServiceAccount,
                         $SG_Tier1ServiceAccount,
                         $SG_Tier2ServiceAccount
                        )
        Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $parameters

        #endregion
        ###############################################################################

        ###############################################################################
        #region Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Write-Verbose -Message 'Nesting groups...'

        $parameters = @( $AdminName,
                         $newAdminName,
                         'Domain Admins',
                         'Enterprise Admins',
                         $SG_InfraAdmins,
                         $SG_AdAdmins,
                         $SG_GpoAdmins,
                         $SG_Tier0Admins,
                         $SG_Tier1Admins,
                         $SG_Tier2Admins,
                         $SG_Tier0ServiceAccount,
                         $SG_Tier1ServiceAccount,
                         $SG_Tier2ServiceAccount,
                         $SG_Operations,
                         $SG_ServerAdmins,
                         $SG_AllSiteAdmins,
                         $SG_AllGALAdmins,
                         $SG_GlobalUserAdmins,
                         $SG_GlobalPcAdmins,
                         $SG_GlobalGroupAdmins,
                         $SG_ServiceDesk,
                         $SL_InfraRight,
                         $SL_AdRight,
                         $SL_UM,
                         $SL_GM,
                         $SL_PUM,
                         $SL_PGM,
                         $SL_GpoAdminRight,
                         $SL_DnsAdminRight,
                         $SL_DirReplRight,
                         $SL_PromoteDcRight,
                         $SL_TransferFSMOright,
                         $SL_PISM,
                         $SL_PAWM,
                         $SL_PSAM,
                         $SL_SvrAdmRight,
                         $SL_SvrOpsRight,
                         $SL_GlobalGroupRight,
                         $SL_GlobalAppAccUserRight
        )
        Add-AdGroupNesting -Identity 'Denied RODC Password Replication Group' -Members $parameters

        #endregion
        ###############################################################################

        ###############################################################################
        #region Enabling Management Accounts to Modify the Membership of Protected Groups

        # Enable PUM to manage Privileged Accounts (Reset PWD, enable/disable Administrator built-in account)
        Set-AdAclMngPrivilegedAccounts -Group $SL_PUM.SamAccountName

        # Enable PGM to manage Privileged Groups (Administrators, Domain Admins...)
        Set-AdAclMngPrivilegedGroups -Group $SL_PGM.SamAccountName

        #endregion
        ###############################################################################

        ###############################################################################
        #region Nest Groups - Delegate Rights through Builtin groups
        # https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups
        # http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/

        Add-AdGroupNesting -Identity 'Cryptographic Operators'         -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity DnsAdmins                         -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity 'Event Log Readers'               -Members $SG_AdAdmins, $SG_Operations

        Add-AdGroupNesting -Identity 'Network Configuration Operators' -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity 'Performance Log Users'            -Members $SG_AdAdmins, $SG_Operations

        Add-AdGroupNesting -Identity 'Performance Monitor Users'        -Members $SG_AdAdmins, $SG_Operations

        Add-AdGroupNesting -Identity 'Remote Desktop Users'             -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity 'Remote Management Users'          -Members $SG_AdAdmins

        # https://technet.microsoft.com/en-us/library/dn466518(v=ws.11).aspx
        $parameters = @($AdminName,
                        $NewAdminName,
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
        Add-AdGroupNesting -Identity 'Protected Users' -Members $parameters


        #endregion
        ###############################################################################

        ###############################################################################
        #region Nest Groups - Extend Rights through delegation model groups
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/

        # InfraAdmins as member of InfraRight
        $parameters = @{
            Identity = $SL_InfraRight
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PUM
        $parameters = @{
            Identity = $SL_PUM
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PGM
        $parameters = @{
            Identity = $SL_PGM
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PISM
        $parameters = @{
            Identity = $SL_PISM
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PAWM
        $parameters = @{
            Identity = $SL_PAWM
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PSAM
        $parameters = @{
            Identity = $SL_PSAM
            Members  = $SG_InfraAdmins.SamAccountName
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of Tier0Admins
        $parameters = @{
            Identity = $SG_Tier0Admins.SamAccountName
            Members  = $SG_InfraAdmins.SamAccountName
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of DirReplRight
        $parameters = @{
            Identity = $SL_DirReplRight.SamAccountName
            Members  = $SG_InfraAdmins.SamAccountName
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of AdAdmins
        $parameters = @{
            Identity = $SG_AdAdmins
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters



        # AdAdmins as member of AdRight
        $parameters = @{
            Identity = $SL_AdRight
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of UM
        $parameters = @{
            Identity = $SL_UM
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of GM
        $parameters = @{
            Identity = $SL_GM
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of GpoAdmins
        $parameters = @{
            Identity = $SG_GpoAdmins
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of AllSiteAdmins
        $parameters = @{
            Identity = $SG_AllSiteAdmins
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of ServerAdmins
        $parameters = @{
            Identity = $SG_ServerAdmins
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters



        # GpoAdmins as member of GpoAdminRight
        $parameters = @{
            Identity = $SL_GpoAdminRight
            Members  = $SG_GpoAdmins
        }
        Add-AdGroupNesting @parameters



        # AllSiteAdmins as member of AllGalAdmins
        $parameters = @{
            Identity = $SG_AllGALAdmins
            Members  = $SG_AllSiteAdmins
        }
        Add-AdGroupNesting @parameters

        # AllGalAdmins as member of ServiceDesk
        $parameters = @{
            Identity = $SG_ServiceDesk
            Members  = $SG_AllGALAdmins
        }
        Add-AdGroupNesting @parameters



        # ServerAdmins as member of SvrAdmRight
        $parameters = @{
            Identity = $SL_SvrAdmRight
            Members  = $SG_ServerAdmins
        }
        Add-AdGroupNesting @parameters

        # Operations as member of SvrOpsRight
        $parameters = @{
            Identity = $SL_SvrOpsRight
            Members  = $SG_Operations
        }
        Add-AdGroupNesting @parameters

        # ServerAdmins as member of Operations
        $parameters = @{
            Identity = $SG_Operations
            Members  = $SG_ServerAdmins
        }
        Add-AdGroupNesting @parameters


        #endregion
        ###############################################################################

        ###############################################################################
        #region redirect Users & Computers containers

        New-DelegateAdOU -ouName $ItQuarantinePcOu   -ouPath $AdDn -ouDescription $confXML.n.Admin.OUs.ItNewComputersOU.description -RemoveAuthenticatedUsers
        New-DelegateAdOU -ouName $ItQuarantineUserOu -ouPath $AdDn -ouDescription $confXML.n.Admin.OUs.ItNewUsersOU.description     -RemoveAuthenticatedUsers

        # START Remove Delegation to BuiltIn groups BEFORE REDIRECTION

        $parameters = @{
            Group      = 'Account Operators'
            LDAPPath   = 'CN=Computers,{0}' -f $AdDn
            RemoveRule = $True
        }
        ### COMPUTERS
        # Remove the Account Operators group from ACL to Create/Delete Users
        Set-AdAclCreateDeleteUser @parameters

        # Remove the Account Operators group from ACL to Create/Delete Computers
        Set-AdAclCreateDeleteComputer @parameters

        # Remove the Account Operators group from ACL to Create/Delete Groups
        Set-AdAclCreateDeleteGroup @parameters

        # Remove the Account Operators group from ACL to Create/Delete Contacts
        Set-AdAclCreateDeleteContact @parameters

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-CreateDeleteInetOrgPerson @parameters

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-AdAclCreateDeletePrintQueue @parameters

        $parameters = @{
            Group      = 'Account Operators'
            LDAPPath   = 'CN=Users,{0}' -f $AdDn
            RemoveRule = $True
        }
        ### USERS
        # Remove the Account Operators group from ACL to Create/Delete Users
        Set-AdAclCreateDeleteUser @parameters

        # Remove the Account Operators group from ACL to Create/Delete Computers
        Set-AdAclCreateDeleteComputer @parameters

        # Remove the Account Operators group from ACL to Create/Delete Groups
        Set-AdAclCreateDeleteGroup @parameters

        # Remove the Account Operators group from ACL to Create/Delete Contacts
        Set-AdAclCreateDeleteContact @parameters

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-CreateDeleteInetOrgPerson @parameters

        # Remove the Print Operators group from ACL to Create/Delete PrintQueues
        Set-AdAclCreateDeletePrintQueue @parameters

        ###############################################################################
        # Redirect Default USER & COMPUTERS Containers
        redircmp.exe ('OU={0},{1}' -f $ItQuarantinePcOu, $AdDn)
        redirusr.exe ('OU={0},{1}' -f $ItQuarantineUserOu, $AdDn)

        #endregion
        ###############################################################################

        ###############################################################################
        #region Delegation to ADMIN area (Tier 0)

        Write-Verbose -Message 'Delegate Admin Area...'

        # Computer objects within this ares MUST have read access, otherwise GPO will not apply

        # UM - Semi-Privileged User Management
        Set-AdAclDelegateUserAdmin -Group $SL_UM.SamAccountName -LDAPpath $ItAdminAccountsOuDn
        Set-AdAclDelegateGalAdmin  -Group $SL_UM.SamAccountName -LDAPpath $ItAdminAccountsOuDn





        # GM - Semi-Privileged Group Management
        Set-AdAclCreateDeleteGroup -Group $SL_GM.SamAccountName -LDAPPath $ItAdminGroupsOuDn
        Set-AdAclChangeGroup       -Group $SL_GM.SamAccountName -LDAPPath $ItAdminGroupsOuDn





        # PUM - Privileged User Management
        Set-AdAclDelegateUserAdmin -Group $SL_PUM.SamAccountName -LDAPpath $ItAdminAccountsOuDn
        Set-AdAclDelegateGalAdmin  -Group $SL_PUM.SamAccountName -LDAPpath $ItAdminAccountsOuDn





        # PGM - Privileged Group Management
        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_PGM.SamAccountName -LDAPPath $ItPrivGroupsOUDn
        Set-AdAclCreateDeleteGroup -Group $SL_PGM.SamAccountName -LDAPPath $ItRightsOuDn
        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_PGM.SamAccountName -LDAPPath $ItPrivGroupsOUDn
        Set-AdAclChangeGroup -Group $SL_PGM.SamAccountName -LDAPPath $ItRightsOuDn




        # Local Admin groups management
        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_SAGM.SamAccountName -LDAPPath $ItAdminSrvGroupsOUDn
        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_SAGM.SamAccountName -LDAPPath $ItAdminSrvGroupsOUDn





        # PISM - Privileged Infrastructure Services Management
        # Create/Delete Computers
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM.SamAccountName -LDAPPath $ItInfraT0OuDn      -QuarantineDN $ItQuarantinePcOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM.SamAccountName -LDAPPath $ItInfraT1OuDn      -QuarantineDN $ItQuarantinePcOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM.SamAccountName -LDAPPath $ItInfraT2OuDn      -QuarantineDN $ItQuarantinePcOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM.SamAccountName -LDAPPath $ItInfraStagingOuDn -QuarantineDN $ItQuarantinePcOuDn





        # PAWM - Privileged Access Workstation Management
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM.SamAccountName -LDAPPath $ItPawT0OuDn -QuarantineDN $ItQuarantinePcOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM.SamAccountName -LDAPPath $ItPawT1OuDn -QuarantineDN $ItQuarantinePcOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM.SamAccountName -LDAPPath $ItPawT2OuDn -QuarantineDN $ItQuarantinePcOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM.SamAccountName -LDAPPath $ItPawStagingOuDn -QuarantineDN $ItQuarantinePcOuDn






        # PSAM - Privileged Service Account Management - Create/Delete Managed Service Accounts & Standard user service accounts
        # Managed Service Accounts "Default Container"
        $parameters = @{
            Group    = $SL_PSAM.SamAccountName
            LDAPPath = ('CN=Managed Service Accounts,{0}' -f $AdDn)
        }
        Set-AdAclCreateDeleteGMSA       @parameters
        Set-AdAclCreateDeleteMSA        @parameters

        # TIER 0
        $parameters = @{
            Group    = $SL_PSAM.SamAccountName
            LDAPPath = $ItSAT0OuDn
        }
        Set-AdAclCreateDeleteGMSA       @parameters
        Set-AdAclCreateDeleteMSA        @parameters
        Set-AdAclCreateDeleteUser       @parameters
        Set-AdAclResetUserPassword      @parameters
        Set-AdAclChangeUserPassword     @parameters
        Set-AdAclUserGroupMembership    @parameters
        Set-AdAclUserAccountRestriction @parameters
        Set-AdAclUserLogonInfo          @parameters

        # TIER 1
        $parameters = @{
            Group    = $SL_PSAM.SamAccountName
            LDAPPath = $ItSAT1OuDn
        }
        Set-AdAclCreateDeleteGMSA       @parameters
        Set-AdAclCreateDeleteMSA        @parameters
        Set-AdAclCreateDeleteUser       @parameters
        Set-AdAclResetUserPassword      @parameters
        Set-AdAclChangeUserPassword     @parameters
        Set-AdAclUserGroupMembership    @parameters
        Set-AdAclUserAccountRestriction @parameters
        Set-AdAclUserLogonInfo          @parameters

        # TIER 2
       $parameters = @{
            Group    = $SL_PSAM.SamAccountName
            LDAPPath = $ItSAT2OuDn
        }
        Set-AdAclCreateDeleteGMSA       @parameters
        Set-AdAclCreateDeleteMSA        @parameters
        Set-AdAclCreateDeleteUser       @parameters
        Set-AdAclResetUserPassword      @parameters
        Set-AdAclChangeUserPassword     @parameters
        Set-AdAclUserGroupMembership    @parameters
        Set-AdAclUserAccountRestriction @parameters
        Set-AdAclUserLogonInfo          @parameters





        # GPO Admins
        # Create/Delete GPOs
        Set-AdAclCreateDeleteGPO -Group $SL_GpoAdminRight.SamAccountName
        # Link existing GPOs to OUs
        Set-AdAclLinkGPO -Group $SL_GpoAdminRight.SamAccountName
        # Change GPO options
        Set-AdAclGPoption -Group $SL_GpoAdminRight.SamAccountName





        # Delegate Directory Replication Rights
        Set-AdDirectoryReplication -Group $SL_DirReplRight.SamAccountName





        # Infrastructure Admins
        # Organizational Units at domain level
        Set-AdAclCreateDeleteOU      -Group $SL_InfraRight.SamAccountName -LDAPPath $AdDn
        # Organizational Units at Admin area
        Set-AdAclCreateDeleteOU      -Group $SL_InfraRight.SamAccountName -LDAPPath $ItAdminOuDn
        # Subnet Configuration Container
        # Create/Delete Subnet
        Set-AdAclCreateDeleteSubnet  -Group $SL_InfraRight.SamAccountName
        # Site Configuration Container
        # Create/Delete Sites
        Set-AdAclCreateDeleteSite    -Group $SL_InfraRight.SamAccountName
        # Site-Link Configuration Container
        # Create/Delete Site-Link
        Set-AdAclCreateDeleteSiteLink -Group $SL_InfraRight.SamAccountName
        # Transfer FSMO roles
        Set-AdAclFSMOtransfer -Group $SL_TransferFSMOright.SamAccountName -FSMOroles 'Schema', 'Infrastructure', 'DomainNaming', 'RID', 'PDC'




        # AD Admins
        # Domain Controllers management
        Set-AdAclDelegateComputerAdmin -Group $SL_AdRight.SamAccountName -LDAPPath $DCsOuDn          -QuarantineDN $ItQuarantinePcOuDn
        # Delete computers from default container
        Set-DeleteOnlyComputer         -Group $SL_AdRight.SamAccountName -LDAPPath $ItQuarantinePcOuDn
        # Subnet Configuration Container|
        # Change Subnet
        Set-AdAclChangeSubnet           -Group $SL_AdRight.SamAccountName
        # Site Configuration Container
        # Change Site
        Set-AdAclChangeSite             -Group $SL_AdRight.SamAccountName
        # Site-Link Configuration Container
        # Change SiteLink
        Set-AdAclChangeSiteLink         -Group $SL_AdRight.SamAccountName

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create Baseline GPO

        Write-Verbose -Message 'Creating Baseline GPOs and configure them accordingly...'

        # Domain
        $parameters = @{
            gpoDescription = 'Baseline'
            gpoLinkPath    = $AdDn
            GpoAdmin       = $sl_GpoAdminRight.SamAccountName
            gpoBackupPath  = Join-Path $DMscripts SecTmpl
        }
        New-DelegateAdGpo @parameters -gpoScope 'C' -gpoBackupID $confXML.n.Admin.GPOs.PCbaseline.backupID
        New-DelegateAdGpo @parameters -gpoScope 'U' -gpoBackupID $confXML.n.Admin.GPOs.Userbaseline.backupID

        # Domain Controllers
        $parameters = @{
            gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Name
            gpoScope       = $confXML.n.Admin.GPOs.DCBaseline.Scope
            gpoLinkPath    = 'OU=Domain Controllers,{0}' -f $AdDn
            GpoAdmin       = $sl_GpoAdminRight.SamAccountName
            gpoBackupId    = $confXML.n.Admin.GPOs.DCBaseline.backupID
            gpoBackupPath  = Join-Path $DMscripts SecTmpl
        }
        New-DelegateAdGpo @parameters

        # Admin Area
        New-DelegateAdGpo -gpoDescription 'ItAdmin-Baseline' -gpoScope 'C' -gpoLinkPath $ItAdminOuDn -GpoAdmin  $sl_GpoAdminRight.SamAccountName
        New-DelegateAdGpo -gpoDescription 'ItAdmin-Baseline' -gpoScope 'U' -gpoLinkPath $ItAdminOuDn -GpoAdmin  $sl_GpoAdminRight.SamAccountName
        $parameters = @{
            gpoDescription = '{0}-Baseline' -f $confXML.n.Admin.OUs.ItAdminAccountsOU.Name
            gpoScope       = 'U'
            gpoLinkPath    = $ItAdminAccountsOuDn
            GpoAdmin       = $sl_GpoAdminRight.SamAccountName
            gpoBackupId    = $confXML.n.Admin.GPOs.AdminUserbaseline.backupID
            gpoBackupPath  = Join-Path $DMscripts SecTmpl
        }
        New-DelegateAdGpo @parameters

        # Service Accounts
        $parameters = @{
            gpoScope = 'U'
            GpoAdmin = $sl_GpoAdminRight.SamAccountName
        }
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItServiceAccountsOU.Name)  -gpoLinkPath $ItServiceAccountsOuDn
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT0OU.Name)             -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.Name, $ItServiceAccountsOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT1OU.Name)             -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT1OU.Name, $ItServiceAccountsOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT2OU.Name)             -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT2OU.Name, $ItServiceAccountsOuDn)

        # PAWs
        $parameters = @{
            gpoScope = 'C'
            GpoAdmin = $sl_GpoAdminRight.SamAccountName
        }
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawOU.Name)        -gpoLinkPath $ItPawOuDn -gpoBackupId $confXML.n.Admin.GPOs.PAWbaseline.backupID -gpoBackupPath (Join-Path $DMscripts SecTmpl)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name)      -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT0OU.Name, $ItPawOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name)      -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT1OU.Name, $ItPawOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name)      -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT2OU.Name, $ItPawOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name) -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name, $ItPawOuDn)

        # Infrastructure Servers
        $parameters = @{
            gpoScope = 'C'
            GpoAdmin = $sl_GpoAdminRight.SamAccountName
        }
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraOU.Name) -gpoLinkPath $ItInfraOuDn -gpoBackupId $confXML.n.Admin.GPOs.INFRAbaseline.backupID -gpoBackupPath (Join-Path $DMscripts SecTmpl)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0Ou.Name) -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT0Ou.Name, $ItInfraOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1Ou.Name) -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT1Ou.Name, $ItInfraOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2Ou.Name) -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT2Ou.Name, $ItInfraOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name) -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name, $ItInfraOuDn)

        # redirected containers (X-Computers & X-Users)
        New-DelegateAdGpo -gpoDescription ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItNewComputersOU.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItNewComputersOU.Name, $AdDn) -GpoAdmin  $sl_GpoAdminRight.SamAccountName
        New-DelegateAdGpo -gpoDescription ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItNewUsersOU.Name)     -gpoScope U -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItNewUsersOU.Name, $AdDn) -GpoAdmin  $sl_GpoAdminRight.SamAccountName

        # Housekeeping
        New-DelegateAdGpo -gpoDescription ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItHousekeepingOU.Name) -gpoScope U -gpoLinkPath $ItHousekeepingOuDn -GpoAdmin  $sl_GpoAdminRight.SamAccountName
        New-DelegateAdGpo -gpoDescription ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItHousekeepingOU.Name) -gpoScope C -gpoLinkPath $ItHousekeepingOuDn -GpoAdmin  $sl_GpoAdminRight.SamAccountName


        ###############################################################################
        # Import GPO from Archive

        #Import the Default Domain Policy
        If($confXML.n.Admin.GPOs.DefaultDomain.backupID) {
            $splat = @{
                BackupId   = $confXML.n.Admin.GPOs.DefaultDomain.backupID
                TargetName = $confXML.n.Admin.GPOs.DefaultDomain.Name
                path       = (Join-Path -Path $DMscripts -ChildPath SecTmpl)
            }
            Import-GPO @splat
        }


        # C-ItAdmin-Baseline

        # U-ItAdmin-Baseline




        ###############################################################################
        # Configure GPO Restrictions based on Tier Model

        # Domain
        $Splat = @(
            'ALL SERVICES',
            'ANONYMOUS LOGON',
            'NT AUTHORITY\Local Account',
            'NT AUTHORITY\Local Account and member of administrators group'
            )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -DenyNetworkLogon $Splat

        $parameters = @(
            $SG_Tier0ServiceAccount.SamAccountName,
            $SG_Tier1ServiceAccount.SamAccountName,
            $SG_Tier2ServiceAccount.SamAccountName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -DenyInteractiveLogon $parameters

        $parameters = @(
            $SG_Tier0ServiceAccount.SamAccountName,
            $SG_Tier1ServiceAccount.SamAccountName,
            $SG_Tier2ServiceAccount.SamAccountName,
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -DenyRemoteInteractiveLogon $parameters

        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -DenyBatchLogon $parameters -DenyServiceLogon $parameters

        $parameters = @(
            'Network Service',
            'NT SERVICE\All Services'
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -ServiceLogon $parameters

        # Domain Controllers
        $parameters = @(
            $SG_Tier1ServiceAccount.SamAccountName,
            $SG_Tier2ServiceAccount.SamAccountName,
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-DomainControllers-Baseline' -DenyBatchLogon $parameters -DenyServiceLogon $parameters

        Set-GpoPrivilegeRights -GpoToModify 'C-DomainControllers-Baseline' -BatchLogon $SG_Tier0ServiceAccount.SamAccountName -ServiceLogon $SG_Tier0ServiceAccount.SamAccountName, 'Network Service'

        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-DomainControllers-Baseline' -InteractiveLogon $parameters -RemoteInteractiveLogon $parameters

        $parameters = @(
            $SG_Tier1ServiceAccount.SamAccountName,
            $SG_Tier2ServiceAccount.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Account Operators',
            'Backup Operators',
            'Print Operators'
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-DomainControllers-Baseline' -DenyInteractiveLogon $parameters

        # Admin Area
        $parameters = @(
            $SG_Tier1ServiceAccount.SamAccountName,
            $SG_Tier2ServiceAccount.SamAccountName,
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-ItAdmin-Baseline' -DenyBatchLogon $parameters -DenyServiceLogon $parameters

        $parameters = @(
            $SG_Tier0ServiceAccount.SamAccountName
            'Network Service',
            'NT SERVICE\All Services'
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-ItAdmin-Baseline' -BatchLogon $SG_Tier0ServiceAccount.SamAccountName -ServiceLogon $parameters

        # Admin Area = HOUSEKEEPING
        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            'Domain Admins',
            'Administrators'
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Housekeeping-LOCKDOWN' -NetworkLogon $parameters -InteractiveLogon $parameters

        # Admin Area = Infrastructure

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0.Name) -InteractiveLogon $SL_PISM.SamAccountName, 'Domain Admins', Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0.Name) -RemoteInteractiveLogon $SL_PISM.SamAccountName
        $parameters = @(
            $SG_Tier0ServiceAccount.SamAccountName
            'Network Service',
            'NT SERVICE\All Services'
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0.Name) -BatchLogon $SG_Tier0ServiceAccount.SamAccountName -ServiceLogon $parameters

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1.Name) -InteractiveLogon $SG_Tier1Admins.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1.Name) -RemoteInteractiveLogon $SG_Tier1Admins.SamAccountName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1.Name) -BatchLogon $SG_Tier1ServiceAccount.SamAccountName -ServiceLogon $SG_Tier1ServiceAccount.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2.Name) -InteractiveLogon $SG_Tier2Admins.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1.Name) -RemoteInteractiveLogon $SG_Tier2Admins.SamAccountName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2.Name) -BatchLogon $SG_Tier2ServiceAccount.SamAccountName -ServiceLogon $SG_Tier2ServiceAccount.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name) -InteractiveLogon $SL_PISM.SamAccountName, 'Domain Admins', Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name) -RemoteInteractiveLogon $SL_PISM.SamAccountName

        # Admin Area = PAWs

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name) -InteractiveLogon $SL_PAWM.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name) -RemoteInteractiveLogon $SL_PAWM.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name) -InteractiveLogon $SL_PAWM.SamAccountName, Administrators, $SG_Tier0Admins.SamAccountName, $AdminName, $newAdminName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name) -RemoteInteractiveLogon $SL_PAWM.SamAccountName, Administrators, $SG_Tier0Admins.SamAccountName, $AdminName, $newAdminName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name) -BatchLogon $SG_Tier0ServiceAccount.SamAccountName -ServiceLogon $SG_Tier0ServiceAccount.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name) -InteractiveLogon $SG_Tier1Admins.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name) -RemoteInteractiveLogon $SG_Tier1Admins.SamAccountName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name) -BatchLogon $SG_Tier1ServiceAccount.SamAccountName -ServiceLogon $SG_Tier1ServiceAccount.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name) -InteractiveLogon $SG_Tier2Admins.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name) -RemoteInteractiveLogon $SG_Tier2Admins.SamAccountName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name) -BatchLogon $SG_Tier2ServiceAccount.SamAccountName -ServiceLogon $SG_Tier2ServiceAccount.SamAccountName


        #endregion
        ###############################################################################

        ###############################################################################
        #region SERVERS OU (area)

        Write-Verbose -Message 'Creating Servers Area...'

        ###############################################################################
        # Create Servers and Sub OUs
        New-DelegateAdOU -ouName $ServersOu -ouPath $AdDn -ouDescription $confXML.n.Servers.OUs.ServersOU.Description

        # Create Sub-OUs for Servers
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.SqlOU.Name           -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.SqlOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.WebOU.Name           -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.WebOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.FileOU.Name          -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.FileOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.ApplicationOU.Name   -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.ApplicationOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.HypervOU.Name        -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.HypervOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.RemoteDesktopOU.Name -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.RemoteDesktopOU.Description





        # Create basic GPO for Servers
        $parameters = @{
            gpoDescription = '{0}-Baseline' -f $ServersOu
            gpoScope       = $confXML.n.Servers.GPOs.Servers.Scope
            gpoLinkPath    = $ServersOuDn
            GpoAdmin       = $sl_GpoAdminRight.SamAccountName
            gpoBackupId    = $confXML.n.Servers.GPOs.Servers.backupID
            gpoBackupPath  = Join-Path $DMscripts SecTmpl
        }
        New-DelegateAdGpo @parameters

        # Create basic GPOs for different types under Servers
        $parameters = @{
            gpoScope       = 'C'
            GpoAdmin       = $sl_GpoAdminRight.SamAccountName
            gpoBackupPath  = Join-Path $DMscripts SecTmpl
        }
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.ApplicationOU.Name)   -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.ApplicationOU.Name, $ServersOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.FileOU.Name)          -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.FileOU.Name, $ServersOuDn)          -gpoBackupId $confXML.n.Servers.GPOs.FileSrv.backupID
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.HypervOU.Name)        -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.HypervOU.Name, $ServersOuDn)        -gpoBackupId $confXML.n.Servers.GPOs.HyperV.backupID
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.RemoteDesktopOU.Name) -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.RemoteDesktopOU.Name, $ServersOuDn) -gpoBackupId $confXML.n.Servers.GPOs.RemoteDesktop.backupID
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.SqlOU.Name)           -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.SqlOU.Name, $ServersOuDn)
        New-DelegateAdGpo @parameters -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.WebOU.Name)           -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.WebOU.Name, $ServersOuDn)           -gpoBackupId $confXML.n.Servers.GPOs.WebSrv.backupID


        # Tier Restrictions
        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Guests',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $ServersOu) -DenyInteractiveLogon $parameters -DenyRemoteInteractiveLogon $parameters

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $ServersOu) -BatchLogon $SG_Tier1ServiceAccount.SamAccountName -ServiceLogon $SG_Tier1ServiceAccount.SamAccountName -InteractiveLogon $SG_Tier1Admins.SamAccountName -RemoteInteractiveLogon $SG_Tier0Admins.SamAccountName


        ###############################################################################
        #region Delegation to SL_SvrAdmRight and SL_SvrOpsRight groups to SERVERS area


        # Get the DN of 1st level OU underneath SERVERS area
        $AllSubOu = Get-AdOrganizationalUnit -Filter * -SearchBase $ServersOuDn -SearchScope OneLevel | Select-Object -ExpandProperty DistinguishedName

        # Iterate through each sub OU and invoke delegation
        Foreach ($Item in $AllSubOu) {
            ###############################################################################
            # Delegation to SL_SvrAdmRight group to SERVERS area

            Set-AdAclDelegateComputerAdmin -Group $SL_SvrAdmRight.SamAccountName -LDAPPath $Item -QuarantineDN $ItQuarantinePcOuDn

            ###############################################################################
            # Delegation to SL_SvrOpsRight group on SERVERS area

            # Change Public Info
            Set-AdAclComputerPublicInfo   -Group $SL_SvrOpsRight.SamAccountName -LDAPPath $Item

            # Change Personal Info
            Set-AdAclComputerPersonalInfo -Group $SL_SvrOpsRight.SamAccountName -LDAPPath $Item

        }#end foreach

        # Create/Delete OUs within Servers
        Set-AdAclCreateDeleteOU -Group $SL_InfraRight.SamAccountName -LDAPPath $ServersOuDn

        # Change OUs within Servers
        Set-AdAclChangeOU -Group $SL_AdRight.SamAccountName -LDAPPath $ServersOuDn

        #endregion
        ###############################################################################

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create Sites OUs (Area)

        Write-Verbose -Message 'Creating Sites Area...'

        New-DelegateAdOU -ouName $SitesOu -ouPath $AdDn -ouDescription $confXML.n.Sites.OUs.SitesOU.Description

        # Create basic GPO for Users and Computers
        $Splat = @{
            gpoDescription = '{0}-Baseline' -f $SitesOu
            gpoLinkPath    = $SitesOuDn
            GpoAdmin       = $sl_GpoAdminRight.SamAccountName
            gpoBackupPath  = Join-Path $DMscripts SecTmpl
        }
        New-DelegateAdGpo @Splat -gpoScope 'C' -gpoBackupID $confXML.n.Sites.OUs.OuSiteComputer.backupID
        New-DelegateAdGpo @Splat -gpoScope 'U' -gpoBackupID $confXML.n.Sites.OUs.OuSiteUser.backupID




        # Tier Restrictions
        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Guests',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $SitesOu) -DenyInteractiveLogon $parameters -DenyRemoteInteractiveLogon $parameters

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $SitesOu) -BatchLogon $SG_Tier2ServiceAccount.SamAccountName -ServiceLogon $SG_Tier2ServiceAccount.SamAccountName -InteractiveLogon $SG_Tier2Admins.SamAccountName -RemoteInteractiveLogon $SG_Tier2Admins.SamAccountName

        # Create Global OU within SITES area
        New-DelegateAdOU -ouName $SitesGlobalOu           -ouPath $SitesOuDn       -ouDescription $confXML.n.Sites.OUs.OuSiteGlobal.Description
        New-DelegateAdOU -ouName $SitesGlobalGroupOu      -ouPath $SitesGlobalOuDn -ouDescription $confXML.n.Sites.OUs.OuSiteGlobalGroups.Description
        New-DelegateAdOU -ouName $SitesGlobalAppAccUserOu -ouPath $SitesGlobalOuDn -ouDescription $confXML.n.Sites.OUs.OuSiteGlobalAppAccessUsers.Description


        # Sites OU
        # Create/Delete OUs within Sites
        Set-AdAclCreateDeleteOU  -Group $SL_InfraRight.SamAccountName -LDAPPath $SitesOuDn

        # Sites OU
        # Change OUs
        Set-AdAclChangeOU        -Group $SL_AdRight.SamAccountName -LDAPPath $SitesOuDn


        Write-Verbose -Message 'START APPLICATION ACCESS USER Global Delegation'
        ###############################################################################
        #region USER Site Administrator Delegation
        $parameters = @{
            Group    = $SL_GlobalAppAccUserRight.SamAccountName
            LDAPPath = $SitesGlobalAppAccUserOuDn
        }
        Set-AdAclDelegateUserAdmin @parameters

        #### GAL
        Set-AdAclDelegateGalAdmin @parameters

        Add-AdGroupNesting -Identity $SL_GlobalAppAccUserRight.SamAccountName -Members $SG_GlobalUserAdmins.SamAccountName

        #endregion USER Site Delegation
        ###############################################################################

        Write-Verbose -Message 'START GROUP Global Delegation'
        ###############################################################################
        #region GROUP Site Admin Delegation

        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_GlobalGroupRight.SamAccountName -LDAPPath $SitesGlobalGroupOuDn

        # Nest groups
        Add-AdGroupNesting -Identity $SL_GlobalGroupRight.SamAccountName -Members $SG_GlobalGroupAdmins.SamAccountName

        #### GAL

        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_GlobalGroupRight.SamAccountName -LDAPPath $SitesGlobalGroupOuDn

        #endregion GROUP Site Delegation
        ###############################################################################

        Write-Verbose 'Sites area was delegated correctly to the corresponding groups.'

        #endregion
        ###############################################################################


        ###############################################################################
        # Check if Exchange objects have to be created. Proccess if TRUE
        if($CreateExchange) {

            # Get the Config.xml file
            $param = @{
                ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve
                verbose = $true
            }

            New-ExchangeObjects @param
        }

        ###############################################################################
        # Check if DFS objects have to be created. Proccess if TRUE
        if($CreateDfs) {
            # Get the Config.xml file
            $param = @{
                ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve
                verbose = $true
            }

            New-DfsObjects @param
        }

        ###############################################################################
        # Check if Certificate Authority (PKI) objects have to be created. Proccess if TRUE
        if($CreateCa) {
            New-CaObjects -ConfigXMLFile $ConfXML
        }

        ###############################################################################
        # Check if Advanced Group Policy Management (AGPM) objects have to be created. Proccess if TRUE
        if($CreateAGPM) {
            New-AGPMObjects -ConfigXMLFile $ConfXML
        }

        ###############################################################################
        # Check if MS Local Administrator Password Service (LAPS) is to be used. Proccess if TRUE
        if($CreateLAPS) {
            #To-Do
            #New-LAPSobjects -PawOuDn $ItPawOuDn -ServersOuDn $ServersOuDn -SitesOuDn $SitesOuDn
            New-LAPSobjects -ConfigXMLFile $ConfXML
        }

        ###############################################################################
        # Check if DHCP is to be used. Proccess if TRUE
        if($CreateDHCP) {
            #
            New-DHCPobjects -ConfigXMLFile $ConfXML
        }

    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating central OU."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
