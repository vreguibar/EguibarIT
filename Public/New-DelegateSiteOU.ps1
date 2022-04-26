function New-DelegateSiteOU
{
    <#
        .Synopsis
            Create New delegated Site OU
        .DESCRIPTION
            Create the new OU representing the SITE root on the pre-defined
            container (Sites, Country, etc.), then adding additional OU structure
            below to host different object types, create the corresponding managing groups and
            GPOs and finally delegating right to those objects.
        .EXAMPLE
            New-DelegateSiteOU -ouName "Mexico" -ouDescription "Mexico Site root" -ConfigXMLFile "C:\PsScripts\Config.xml"
        .PARAMETER ouName
            [String] Name of the OU corresponding to the SITE root
        .PARAMETER ouDescription
            [String] Description of the OU
        .PARAMETER ouCity
        .PARAMETER ouCountry
        .PARAMETER ouStreetAddress
        .PARAMETER ouState
        .PARAMETER ouZIPCode
        .PARAMETER CreateExchange
            [switch] If present It will create all needed Exchange objects and containers.
        .PARAMETER CreateLAPS
            [switch] If present It will create all needed LAPS objects, containers and delegations.
        .PARAMETER ConfigXMLFile
            [String] Full path to the configuration.xml file
        .NOTES
            This function relies on Config.xml file.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Add-AdGroupNesting                     | EguibarIT
                Get-CurrentErrorToDisplay              | EguibarIT
                New-DelegateAdOU                       | EguibarIT
                New-DelegateAdGpo                      | EguibarIT
                Start-AdDelegateSite                   | EguibarIT
                Start-AdCleanOU                        | EguibarIT
                Set-AdAclLaps                          | EguibarIT
                Set-GpoPrivilegeRights                 | EguibarIT.Delegation
                Get-ADGroup                            | ActiveDirectory
                Get-AdOrganizationalUnit               | ActiveDirectory
                Import-GPO                             | GroupPolicy
                Set-GPPermissions                      | GroupPolicy



                LocalDomainGroupPreffix
                GlobalGroupPreffix
                UniversalGroupPreffix
                Delimiter
                AdminAccSufix0
                AdminAccSufix1
                AdminAccSufix2

                AllSiteAdmins
                AllGalAdmins
                ServiceDesk
                GlobalPcAdmins
                GlobalGroupAdmins
                GlobalUserAdmins


                ITAdminOu
                ItAdminGroupsOu
                ItRightsOu
                SitesOu
                ItQuarantineOu


                OuSiteUser
                OuSiteUser-Description
                OuSiteUser-BackupID
                OuSiteComputer
                OuSiteComputer-Description
                OuSiteComputer-BackupID
                OuSiteLaptop
                OuSiteLaptop-Description
                OuSiteLaptop-BackupID
                OuSiteGroup
                OuSiteGroup-Description
                OuSiteShares
                OuSiteShares-Description
                OuSitePrintQueue
                OuSitePrintQueue-Description

                PwdRight
                PwdRight-DisplayName
                PwdRight-Description
                PcRight
                PcRight-DisplayName
                PcRight-Description
                GroupRight
                GroupRight-DisplayName
                GroupRight-Description
                CreateUserRight
                CreateUserRight-DisplayName
                CreateUserRight-Description
                GALRight
                GALRight-DisplayName
                GALRight-Description
                SiteRight
                SiteRight-DisplayName
                SiteRight-Description


                PwdAdmins
                PwdAdmins-DisplayName
                PwdAdmins-Description
                ComputerAdmins
                ComputerAdmins-DisplayName
                ComputerAdmins-Description
                GroupAdmins
                GroupAdmins-DisplayName
                GroupAdmins-Description
                UserAdmins
                UserAdmins-DisplayName
                UserAdmins-Description
                GALAdmins
                GALAdmins-DisplayName
                GALAdmins-Description
                SiteAdmins
                SiteAdmins-DisplayName
                SiteAdmins-Description






        .NOTES
            Version:         1.2
            DateModified:    11/Feb/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([String])]
    Param
    (
        # Param1 Site Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the OU corresponding to the SITE root',
        Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ouName,

        # Param2 OU Description
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Description of the OU',
        Position = 1)]
        [string]
        $ouDescription,

        # Param3 OU City
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 2)]
        [string]
        $ouCity,

        # Param4 OU Country
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 3)]
        [ValidatePattern('[a-zA-Z]*')]
        [ValidateLength(2,2)]
        [string]
        $ouCountry,

        # Param5 OU Street Address
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 4)]
        [string]
        $ouStreetAddress,

        # Param6 OU State
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 5)]
        [string]
        $ouState,

        # Param7 OU Postal Code
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 6)]
        [string]
        $ouZIPCode,

        # Param8 Create Exchange Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects and containers.',
        Position = 7)]
        [switch]
        $CreateExchange,

        # Param9 Create LAPS Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed LAPS objects, containers and delegations.',
        Position = 8)]
        [switch]
        $CreateLAPS,

        # PARAM10 full path to the configuration.xml file
        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage='Full path to the configuration.xml file',
            Position=9)]
        [string]
        $ConfigXMLFile

    )

    Begin {
        $error.Clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Import-Module -name ServerManager        -Verbose:$false
        Import-Module -name ActiveDirectory      -Verbose:$false
        Import-Module -name GroupPolicy          -Verbose:$false
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        #------------------------------------------------------------------------------
        # Define the variables

        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        } Catch { Get-CurrentErrorToDisplay -CurrentError $error[0] }


        ####################
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

        ####################
        # Users

        ####################
        # Groups
        $SG_AllSiteAdmins = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllSiteAdmins.Name)
        $SG_AllGALAdmins  = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllGALAdmins.Name)


        ####################
        # OU DistinguishedNames

        # Admin Area

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $AdDn

        # It Admin Groups OU
        $ItGroupsOu = $confXML.n.Admin.OUs.ItAdminGroupsOU.name
        # It Admin Groups OU Distinguished Name
        $ItGroupsOuDn = 'OU={0},{1}' -f $ItGroupsOu, $ItAdminOuDn

        # It Privileged Groups OU
        #$ItPGOu = $confXML.n.Admin.OUs.ItPrivGroupsOU.name
        # It Privileged Groups OU Distinguished Name
        #$ItPGOuDn = 'OU={0},{1}' -f $ItPGOu, $ItAdminOuDn

        # It Admin Rights OU
        $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn





        # Sites Area

        # Sites OU
        $SitesOu = $confXML.n.Sites.OUs.SitesOU.name
        # Sites OU Distinguished Name
        $SitesOuDn = 'OU={0},{1}' -f $SitesOu, $AdDn

            # Sites GLOBAL OU
            #$SitesGlobalOu = $confXML.n.Sites.OUs.OuSiteGlobal.name
            # Sites GLOBAL OU Distinguished Name
            #$SitesGlobalOuDn = 'OU={0},{1}' -f $SitesGlobalOu, $SitesOuDn

                # Sites GLOBAL GROUPS OU
                #$SitesGlobalGroupOu = $confXML.n.Sites.OUs.OuSiteGlobalGroups.name
                # Sites GLOBAL GROUPS OU Distinguished Name
                #$SitesGlobalGroupOuDn = 'OU={0},{1}' -f $SitesGlobalGroupOu, $SitesGlobalOuDn

                # Sites GLOBAL APPACCUSERS OU
                #$SitesGlobalAppAccUserOu = $confXML.n.Sites.OUs.OuSiteGlobalAppAccessUsers.name
                # Sites GLOBAL APPACCUSERS OU Distinguished Name
                #$SitesGlobalAppAccUserOuDn = 'OU={0},{1}' -f $SitesGlobalAppAccUserOu, $SitesGlobalOuDn





        # Quarantine OU
        $ItQuarantineOu = $confXML.n.Admin.OUs.ItNewComputersOU.name
        # Quarantine OU Distinguished Name
        $ItQuarantineOuDn = 'OU={0},{1}' -f $ItQuarantineOu, $AdDn



        # Current OU DistinguishedName
        $ouNameDN = 'OU={0},{1}' -f $ouName, $SitesOuDn


        # parameters variable for splatting the CMDlets
        $splat = $null


        # END variables
        #------------------------------------------------------------------------------
    }
    Process {
        # Checking if the OU exist is done prior calling this function.

        Write-Verbose -Message ('Create Site root OU {0}' -f $PSBoundParameters['ouName'])

        # Check if the Site OU exists
        If(-not(Get-AdOrganizationalUnit -Filter { distinguishedName -eq $ouNameDN } -SearchBase $AdDn)) {
            $splat = @{
                ouName           = $PSBoundParameters['ouName']
                ouPath           = $SitesOuDn
                ouDescription    = $PSBoundParameters['ouDescription']
                ouCity           = $PSBoundParameters['ouCity']
                ouCountry        = $PSBoundParameters['ouCountry']
                ouStreetAddress  = $PSBoundParameters['ouStreetAddress']
                ouState          = $PSBoundParameters['ouState']
                ouZIPCode        = $PSBoundParameters['ouZIPCode']
                strOuDisplayName = $PSBoundParameters['ouName']
            }
            # If does not exist, create it.
            New-DelegateAdOU @splat
        } else {
            Write-Warning -Message ('Site {0} already exist. Continue to cleanup.' -f $PSBoundParameters['ouName'])
            # If OU already exist, clean it.
            Start-AdCleanOU -LDAPPath $ouNameDN  -RemoveUnknownSIDs
        }

        Write-Verbose -Message 'Create SITE Sub-OU'
        ###############################################################################
        #region Create SITE Sub-OU

        # --- USER CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteUser.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteUser.description
        }
        New-DelegateAdOU @splat

        # --- COMPUTER CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteComputer.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.description
        }
        New-DelegateAdOU @splat
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteLaptop.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.description
        }
        New-DelegateAdOU @splat

        # --- GROUP CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteGroup.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteGroup.description
        }
        New-DelegateAdOU @splat

        # --- VOLUME CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteShares.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteShares.description
        }
        New-DelegateAdOU @splat

        # --- PRINTQUEUE CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSitePrintQueue.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSitePrintQueue.description
        }
        New-DelegateAdOU @splat

        #endregion END
        ###############################################################################



        Write-Verbose -Message ('Create requiered groups for the site {0}' -f $PSBoundParameters['ouName'])

        ###############################################################################
        #region Create the required Right's Local Domain groups

        # Iterate through all Site-LocalGroups child nodes
        Foreach($node in $confXML.n.Sites.LG.ChildNodes) {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']))
            $parameters = @{
                Name                          = '{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = '{0} {1}' -f $PSBoundParameters['ouName'], $node.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = '{0} {1}' -f $PSBoundParameters['ouName'], $node.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }

            New-Variable -Name "$('SL{0}{1}' -f $NC['Delim'], $node.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force
        }

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create the required Admin Global groups


        # Iterate through all Site-GlobalGroups child nodes
        Foreach($node in $confXML.n.Sites.GG.ChildNodes) {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']))
            $parameters = @{
                Name                          = '{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = '{0} {1}' -f $PSBoundParameters['ouName'], $node.DisplayName
                Path                          = $ItGroupsOuDn
                Description                   = '{0} {1}' -f $PSBoundParameters['ouName'], $node.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            New-Variable -Name "$('SG{0}{1}' -f $NC['Delim'], $node.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force
        }

        #endregion
        ###############################################################################




        Write-Verbose -Message 'Add group membership & nesting'
        ###############################################################################
        #region Add group membership & nesting

        #region NESTING Global groups into Domain Local Groups -> order Less privileged to more privileged

        Add-AdGroupNesting -Identity $SL_PwdRight -Members $SG_PwdAdmins, $SG_GALAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_PcRight -Members $SG_ComputerAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_GroupRight -Members $SG_GroupAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_CreateUserRight -Members $SG_UserAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_GALRight -Members $SG_GALAdmins, $SG_SiteAdmins

        <# VIOLATES Tiering model  Add-AdGroupNesting -Identity $SL_LocalServerRight -Members $SG_SiteAdmins #>

        Add-AdGroupNesting -Identity $SL_SiteRight -Members $SG_SiteAdmins

        #endregion

        #region NESTING Global groups into Global Groups -> order Less privileged to more privileged

        Add-AdGroupNesting -Identity $SG_PwdAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.ServiceDesk.Name)

        Add-AdGroupNesting -Identity $SG_ComputerAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalPcAdmins.Name)

        Add-AdGroupNesting -Identity $SG_GroupAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalGroupAdmins.Name)

        Add-AdGroupNesting -Identity $SG_UserAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalUserAdmins.Name)

        Add-AdGroupNesting -Identity $SG_GALAdmins -Members $SG_AllGALAdmins

        Add-AdGroupNesting -Identity $SG_SiteAdmins -Members $SG_AllSiteAdmins

        #endregion

        #endregion
        ###############################################################################

        <#Write-Verbose -Message 'Nesting to Built-In groups'
        ###############################################################################
        #region Nest Groups - Delegate Rights through Builtin groups
        # http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx

        Add-AdGroupNesting -Identity 'Remote Desktop Users' -Members $SG_SiteAdmins

        #endregion
        ###############################################################################
        #>

        Write-Verbose -Message 'Create basic GPO'
        ###############################################################################
        #region Create basic GPO

        # Create Desktop Baseline
        $splat = @{
            gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteComputer.Name
            gpoScope       = $confXML.n.Sites.OUs.OuSiteComputer.Scope
            gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.Name, $ouNameDN
            GpoAdmin       = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        }
        New-DelegateAdGpo @splat

        # Create Laptop-Baseline Baseline
        $splat = @{
            gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLaptop.Name
            gpoScope       = $confXML.n.Sites.OUs.OuSiteLaptop.Scope
            gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Name, $ouNameDN
            GpoAdmin       = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        }
        New-DelegateAdGpo @splat

        # Create Users Baseline
        $splat = @{
            gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteUser.Name
            gpoScope       = $confXML.n.Sites.OUs.OuSiteUser.Scope
            gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteUser.Name, $ouNameDN
            GpoAdmin       = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        }
        New-DelegateAdGpo @splat

        #endregion Create basic GPO
        ###############################################################################

        Write-Verbose -Message 'Configure GPO'
        ###############################################################################
        #region Configure GPO

        # Configure Users
        If($confXML.n.Sites.OUs.OuSiteUser.backupID) {
            $splat = @{
                BackupId   = $confXML.n.Sites.OUs.OuSiteUser.backupID
                TargetName = '{0}-{1}-{2}' -f $confXML.n.Sites.OUs.OuSiteUser.Scope, $ouName, $confXML.n.Sites.OUs.OuSiteUser.Name
                path       = Join-Path -Path $DMscripts -ChildPath SecTmpl
            }
            Import-GPO @splat
        }






        # Configure Desktop Baseline
        If($confXML.n.Sites.OUs.OuSiteComputer.backupID) {
            $splat = @{
                BackupId   = $confXML.n.Sites.OUs.OuSiteComputer.backupID
                TargetName = '{0}-{1}-{2}' -f $confXML.n.Sites.OUs.OuSiteComputer.Scope, $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name
                path       = Join-Path -Path $DMscripts -ChildPath SecTmpl
            }
            Import-GPO @splat
        }

        # Desktop Baseline Tiering Restrictions
        $splat = @(
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Guests',
            $confXML.n.Admin.users.Admin.name,
            $confXML.n.Admin.users.newAdmin.name
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name) -DenyNetworkLogon $splat

        $splat = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            'Guests'
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name) -DenyInteractiveLogon $splat -DenyRemoteInteractiveLogon $splat

        $splat = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Guests',
            $confXML.n.Admin.users.Admin.name,
            $confXML.n.Admin.users.newAdmin.name
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteComputer.Name) -DenyBatchLogon $splat -DenyServiceLogon $splat

        $splat = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteComputer.Name) -BatchLogon $splat -ServiceLogon $splat







        # Configure Laptop Baseline
        If($confXML.n.Sites.OUs.OuSiteLaptop.backupID) {
            $splat = @{
                BackupId   = $confXML.n.Sites.OUs.OuSiteLaptop.backupID
                TargetName = '{0}-{1}-{2}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Scope, $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name
                path       = Join-Path -Path $DMscripts -ChildPath SecTmpl
            }
            Import-GPO @splat
        }

        # Laptop Baseline Tiering Restrictions
        $splat = @(
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Guests',
            $confXML.n.Admin.users.Admin.name,
            $confXML.n.Admin.users.newAdmin.name
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name) -DenyNetworkLogon $splat

        $splat = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            'Guests'
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name) -DenyInteractiveLogon $splat -DenyRemoteInteractiveLogon $splat

        $splat = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Guests',
            $confXML.n.Admin.users.Admin.name,
            $confXML.n.Admin.users.newAdmin.name
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLaptop.Name) -DenyBatchLogon $splat -DenyServiceLogon $splat

        $splat = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLaptop.Name) -BatchLogon $splat -ServiceLogon $splat





        #endregion Configure GPO
        ###############################################################################

        Write-Verbose -Message 'Delegate GPO'
        ###############################################################################
        #region Delegate GPO

        # Give Rights to SG_SiteAdmin_XXXX to $ouName + -Desktop
        Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name)
        $splat = @{
            Name            = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name)
            PermissionLevel = 'GpoEdit'
            TargetName      = $SG_SiteAdmins.SamAccountName
            TargetType      = 'group'
            ErrorAction     = 'SilentlyContinue'
            Verbose         = $true
        }
        Set-GPPermissions @splat

        Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name)
        $splat = @{
            Name            = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name)
            PermissionLevel = 'GpoEdit'
            TargetName      = $SG_SiteAdmins.SamAccountName
            TargetType      = 'group'
            ErrorAction     = 'SilentlyContinue'
            Verbose         = $true
        }
        Set-GPPermissions @splat




        Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteUser.Name)
        $splat = @{
            Name            = ('U-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteUser.Name)
            PermissionLevel = 'GpoEdit'
            TargetName      = $SG_SiteAdmins.SamAccountName
            TargetType      = 'group'
            ErrorAction     = 'SilentlyContinue'
            Verbose         = $true
        }
        Set-GPPermissions @splat


        #endregion Delegate GPO
        ###############################################################################

        Write-Verbose -Message 'Rights delegation'

        # --- Exchange Related
        ###############################################################################
        If($PSBoundParameters['CreateExchange']) {
            Start-AdDelegateSite -ConfigXMLFile $ConfigXMLFile -ouName $ouName -QuarantineDN $ItQuarantineOuDn -CreateExchange

            #create Sub-OUs
            # --- USER CLASS ---
            New-DelegateAdOU -ouName $confXML.n.Sites.OUs.OuSiteMailbox.Name   -ouPath $ouNameDN -ouDescription ('{0} {1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Description)

            # --- GROUP CLASS ---
            New-DelegateAdOU -ouName $confXML.n.Sites.OUs.OuSiteDistGroup.Name -ouPath $ouNameDN -ouDescription ('{0} {1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteDistGroup.Description)

            # --- CONTACT CLASS ---
            New-DelegateAdOU -ouName $confXML.n.Sites.OUs.OuSiteContact.Name   -ouPath $ouNameDN -ouDescription ('{0} {1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteContact.Description)

            #create Basic Gpo
            # Create Mailboxes Baseline
            $splat = @{
                gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Name
                gpoScope       = 'U'
                gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteMailbox.Name, $ouNameDN
                GpoAdmin       = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
            }
            New-DelegateAdGpo @splat

            # Delegate GPO
            Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Name)
            $splat = @{
                Name            = ('U-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Name)
                PermissionLevel = 'GpoEdit'
                TargetName      = $SG_SiteAdmins.SamAccountName
                TargetType      = 'group'
                ErrorAction     = 'SilentlyContinue'
            }
            Set-GPPermissions @splat
        } else {
            Start-AdDelegateSite -ConfigXMLFile $ConfigXMLFile -ouName $ouName -QuarantineDN $ItQuarantineOuDn
        } # end if CreateExchange

        # --- LAPS Related
        ###############################################################################
        If($PSBoundParameters['CreateLAPS']) {
            # Desktop LAPS delegation
            Set-AdAclLaps -ResetGroup $SL_PwdRight.SamAccountName -ReadGroup $SL_PwdRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.Name, $ouNameDN)

            # Laptop LAPS delegation
            Set-AdAclLaps -ResetGroup $SL_PwdRight.SamAccountName -ReadGroup $SL_PwdRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Name, $ouNameDN)

            If($PsBoundParameters['CreateSrvContainer']) {
                # File-Print LAPS delegation
                Set-AdAclLaps -ResetGroup $SL_LocalServerRight.SamAccountName -ReadGroup $SL_LocalServerRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteFilePrint.Name, $ouNameDN)

                # Local Server LAPS delegation
                Set-AdAclLaps -ResetGroup $SL_LocalServerRight.SamAccountName -ReadGroup $SL_LocalServerRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLocalServer.Name, $ouNameDN)
            }
        }
    }
    End {
        Write-Verbose -Message ("Function $($MyInvocation.InvocationName) finished creating creating Site {0}" -f $PSBoundParameters['ouName'])
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}