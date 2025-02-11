function New-DelegateSiteOU {
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
        .PARAMETER GpoBackupPath
            [string] Full path to theGPO backup files
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
                Set-GpoPrivilegeRight                  | EguibarIT.DelegationPS
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
                ItQuarantinePcOu


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
    [OutputType([void])]

    Param (
        # Param1 Site Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the OU corresponding to the SITE root',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ouName,

        # Param2 OU Description
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Description of the OU',
            Position = 1)]
        [string]
        $ouDescription,

        # Param3 OU City
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 2)]
        [string]
        $ouCity,

        # Param4 OU Country
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 3)]
        [ValidatePattern('[a-zA-Z]*')]
        [ValidateLength(2, 2)]
        [string]
        $ouCountry,

        # Param5 OU Street Address
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 4)]
        [string]
        $ouStreetAddress,

        # Param6 OU State
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 5)]
        [string]
        $ouState,

        # Param7 OU Postal Code
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 6)]
        [string]
        $ouZIPCode,

        # Param8 Create Exchange Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects and containers.',
            Position = 7)]
        [switch]
        $CreateExchange,

        # Param9 Create LAPS Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed LAPS objects, containers and delegations.',
            Position = 8)]
        [switch]
        $CreateLAPS,

        # PARAM10 full path to the configuration.xml file
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to theGPO backup files',
            Position = 9)]
        [string]
        $GpoBackupPath,

        # PARAM11 full path to the configuration.xml file
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 10)]
        [PSDefaultValue(Help = 'Default Value is "C:\PsScripts\Config.xml"')]
        [string]
        $ConfigXMLFile = 'C:\PsScripts\Config.xml'

    )

    Begin {
        $error.Clear()

        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-MyModule -Name 'ServerManager' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        try {
            # Check if Config.xml file is loaded. If not, proceed to load it.
            If (-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If (Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        } Catch {
            Write-Error -Message 'Error when reading XML file'
            throw
        }


        ####################
        # Naming conventions hashtable
        $NC = @{'sl' = $confXML.n.NC.LocalDomainGroupPreffix
            'sg'     = $confXML.n.NC.GlobalGroupPreffix
            'su'     = $confXML.n.NC.UniversalGroupPreffix
            'Delim'  = $confXML.n.NC.Delimiter
            'T0'     = $confXML.n.NC.AdminAccSufix0
            'T1'     = $confXML.n.NC.AdminAccSufix1
            'T2'     = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0

        ####################
        # Users

        ####################
        # Groups
        $SG_AllSiteAdmins = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllSiteAdmins.Name)
        $SG_AllGALAdmins = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllGALAdmins.Name)
        $GpoAdmin = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        $SG_ServiceDesk = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.ServiceDesk.Name)
        $SG_GlobalGroupAdmins = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalGroupAdmins.Name)
        $SG_GlobalPcAdmins = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalPcAdmins.Name)
        $SG_GlobalUserAdmins = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalUserAdmins.Name)

        # Get the AD Objects by Well-Known SID
        try {
            # Administrator - TheGood
            $AdminName = Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
            # NewAdministrator - TheUgly
            $newAdminName = Get-ADUser -Identity $confXML.n.Admin.users.newAdmin.name
            # Administrators
            $Administrators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-544' }
            # Domain Admins
            $DomainAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-512' }
            # Enterprise Admins
            $EnterpriseAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-519' }
            # Schema Admins
            $SchemaAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-518' }
            # DomainControllers
            $DomainGuests = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-514' }
            # Server Operators
            $ServerOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-549' }
            # Account Operators
            $AccountOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-548' }
            # Print Operators
            $PrintOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-550' }
            # Backup Operators
            $BackupOperators = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-32-551' }
        } catch {
            Write-Error -Message 'One or some of the User/Groups was not able to be retrieved. Please check'
        } #end Try-Catch



        ####################
        # OU DistinguishedNames

        # Admin Area

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $Variables.AdDn

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
        $SitesOuDn = 'OU={0},{1}' -f $SitesOu, $Variables.AdDn

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
        $ItQuarantinePcOu = $confXML.n.Admin.OUs.ItNewComputersOU.name
        # Quarantine OU Distinguished Name
        $ItQuarantinePcOuDn = 'OU={0},{1}' -f $ItQuarantinePcOu, $Variables.AdDn



        # Current OU DistinguishedName
        $ouNameDN = 'OU={0},{1}' -f $ouName, $SitesOuDn


        # parameters variable for splatting the CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {
        # Checking if the OU exist is done prior calling this function.

        Write-Verbose -Message ('Create Site root OU {0}' -f $PSBoundParameters['ouName'])

        # Check if the Site OU exists
        If (-not(Get-ADOrganizationalUnit -Filter { distinguishedName -eq $ouNameDN } -SearchBase $Variables.AdDn)) {
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
            Start-AdCleanOU -LDAPpath $ouNameDN -RemoveUnknownSIDs
        }

        Write-Verbose -Message 'Create SITE Sub-OU'
        ###############################################################################
        #region Create SITE Sub-OU

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Site sub-OUs')

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



        Write-Verbose -Message ('Create required groups for the site {0}' -f $PSBoundParameters['ouName'])

        ###############################################################################
        #region Create the required Right's Local Domain groups

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating the required Rights Local Domain groups')

        # Iterate through all Site-LocalGroups child nodes
        Foreach ($node in $confXML.n.Sites.LG.ChildNodes) {
            [String]$Name = '{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']
            Write-Verbose -Message ('Create group {0}' -f $Name)
            $Splat = @{
                Name                          = $Name
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

            New-Variable -Name "$('SL_{0}' -f $node.LocalName)" -Value (New-AdDelegatedGroup @Splat) -Force
        }

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create the required Admin Global groups

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating the required Admin Global groups')

        # Iterate through all Site-GlobalGroups child nodes
        Foreach ($node in $confXML.n.Sites.GG.ChildNodes) {
            [String]$Name = '{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']
            Write-Verbose -Message ('Create group {0}' -f $Name)
            $Splat = @{
                Name                          = $Name
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
            New-Variable -Name "$('SG_{0}' -f $node.LocalName)" -Value (New-AdDelegatedGroup @Splat) -Force
        }

        #endregion
        ###############################################################################




        Write-Verbose -Message 'Add group membership & nesting'
        ###############################################################################
        #region Add group membership & nesting

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Adding group membership & nesting')

        #region NESTING Global groups into Domain Local Groups -> order Less privileged to more privileged

        Add-AdGroupNesting -Identity $SL_PwdRight -Members $SG_PwdAdmins, $SG_GALAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_PcRight -Members $SG_ComputerAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_GroupRight -Members $SG_GroupAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_CreateUserRight -Members $SG_UserAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_GALRight -Members $SG_GALAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_SiteRight -Members $SG_SiteAdmins

        #endregion

        #region NESTING Global groups into Global Groups -> order Less privileged to more privileged

        Add-AdGroupNesting -Identity $SG_PwdAdmins -Members $SG_ServiceDesk

        Add-AdGroupNesting -Identity $SG_ComputerAdmins -Members $SG_GlobalPcAdmins

        Add-AdGroupNesting -Identity $SG_GroupAdmins -Members $SG_GlobalGroupAdmins

        Add-AdGroupNesting -Identity $SG_UserAdmins -Members $SG_GlobalUserAdmins

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

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating basic GPO')

        # Create Desktop Baseline
        $splat = @{
            gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteComputer.Name
            gpoScope       = $confXML.n.Sites.OUs.OuSiteComputer.Scope
            gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.Name, $ouNameDN
            GpoAdmin       = $GpoAdmin
        }
        New-DelegateAdGpo @splat

        # Create Laptop-Baseline Baseline
        $splat = @{
            gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLaptop.Name
            gpoScope       = $confXML.n.Sites.OUs.OuSiteLaptop.Scope
            gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Name, $ouNameDN
            GpoAdmin       = $GpoAdmin
        }
        New-DelegateAdGpo @splat

        # Create Users Baseline
        $splat = @{
            gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteUser.Name
            gpoScope       = $confXML.n.Sites.OUs.OuSiteUser.Scope
            gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteUser.Name, $ouNameDN
            GpoAdmin       = $GpoAdmin
        }
        New-DelegateAdGpo @splat

        #endregion Create basic GPO
        ###############################################################################

        Write-Verbose -Message 'Configure GPO'
        ###############################################################################
        #region Configure GPO

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Configuring GPO')

        # Configure Users
        If ($confXML.n.Sites.OUs.OuSiteUser.backupID) {
            $splat = @{
                BackupId   = $confXML.n.Sites.OUs.OuSiteUser.backupID
                TargetName = '{0}-{1}-{2}' -f $confXML.n.Sites.OUs.OuSiteUser.Scope, $ouName, $confXML.n.Sites.OUs.OuSiteUser.Name
                path       = $GpoBackupPath
            }
            Import-GPO @splat
        }






        # Configure Desktop Baseline
        If ($confXML.n.Sites.OUs.OuSiteComputer.backupID) {
            $splat = @{
                BackupId   = $confXML.n.Sites.OUs.OuSiteComputer.backupID
                TargetName = '{0}-{1}-{2}' -f $confXML.n.Sites.OUs.OuSiteComputer.Scope, $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name
                path       = $GpoBackupPath
            }
            Import-GPO @splat
        }

        # Desktop Baseline Tiering Restrictions
        $Splat = @{
            GpoToModify      = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name)
            DenyNetworkLogon = @(
                $SchemaAdmins,
                $EnterpriseAdmins,
                $DomainAdmins,
                $Administrators,
                $DomainGuests,
                $AdminName,
                $newAdminName
            )
        }
        Set-GpoPrivilegeRight @Splat



        $ArrayList = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            $DomainGuests
        )
        $Splat = @{
            GpoToModify                = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name)
            DenyInteractiveLogon       = $ArrayList
            DenyRemoteInteractiveLogon = $ArrayList
        }
        Set-GpoPrivilegeRight @Splat



        $ArrayList = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
            $SchemaAdmins,
            $EnterpriseAdmins,
            $DomainAdmins,
            $Administrators,
            $AccountOperators,
            $BackupOperators,
            $PrintOperators,
            $ServerOperators,
            $DomainGuests,
            $AdminName,
            $newAdminName
        )
        $Splat = @{
            GpoToModify      = ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteComputer.Name)
            DenyBatchLogon   = $ArrayList
            DenyServiceLogon = $ArrayList
        }
        Set-GpoPrivilegeRight @Splat


        $Splat = @{
            GpoToModify  = ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteComputer.Name)
            BatchLogon   = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name
            ServiceLogon = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name
        }
        Set-GpoPrivilegeRight @Splat







        # Configure Laptop Baseline
        If ($confXML.n.Sites.OUs.OuSiteLaptop.backupID) {
            $splat = @{
                BackupId   = $confXML.n.Sites.OUs.OuSiteLaptop.backupID
                TargetName = '{0}-{1}-{2}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Scope, $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name
                path       = $GpoBackupPath
            }
            Import-GPO @splat
        }

        # Laptop Baseline Tiering Restrictions
        $Splat = @{
            GpoToModify      = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name)
            DenyNetworkLogon = @(
                $SchemaAdmins,
                $EnterpriseAdmins,
                $DomainAdmins,
                $DomainGuests,
                $AdminName,
                $newAdminName
            )
        }
        Set-GpoPrivilegeRight @Splat



        $ArrayList = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            $DomainGuests
        )
        $Splat = @{
            GpoToModify                = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name)
            DenyInteractiveLogon       = $ArrayList
            DenyRemoteInteractiveLogon = $ArrayList
        }
        Set-GpoPrivilegeRight @Splat



        $ArrayList = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
            $SchemaAdmins,
            $EnterpriseAdmins,
            $DomainAdmins,
            $Administrators,
            $AccountOperators,
            $BackupOperators,
            $PrintOperators,
            $ServerOperators,
            $DomainGuests,
            $AdminName,
            $newAdminName
        )
        $Splat = @{
            GpoToModify      = ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLaptop.Name)
            DenyBatchLogon   = $ArrayList
            DenyServiceLogon = $ArrayList
        }
        Set-GpoPrivilegeRight @Splat



        $Splat = @{
            GpoToModify  = ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLaptop.Name)
            BatchLogon   = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name
            ServiceLogon = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name
        }
        Set-GpoPrivilegeRight @Splat





        #endregion Configure GPO
        ###############################################################################

        Write-Verbose -Message 'Delegate GPO'
        ###############################################################################
        #region Delegate GPO

        Write-Verbose -Message ($Variables.NewRegionMessage -f 'Delegating GPO')

        # Give Rights to SG_SiteAdmin_XXXX to $ouName + -Desktop
        Write-Verbose -Message ('
            Add Local Admin to new {0}-{1}' -f
            $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name
        )
        $splat = @{
            Name            = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name)
            PermissionLevel = 'GpoEdit'
            TargetName      = $SG_SiteAdmins.SamAccountName
            TargetType      = 'group'
            ErrorAction     = 'SilentlyContinue'
            Verbose         = $true
        }
        Set-GPPermissions @splat

        Write-Verbose -Message ('
            Add Local Admin to new {0}-{1}' -f
            $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name
        )
        $splat = @{
            Name            = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name)
            PermissionLevel = 'GpoEdit'
            TargetName      = $SG_SiteAdmins.SamAccountName
            TargetType      = 'group'
            ErrorAction     = 'SilentlyContinue'
            Verbose         = $true
        }
        Set-GPPermissions @splat




        Write-Verbose -Message ('
            Add Local Admin to new {0}-{1}' -f
            $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteUser.Name
        )
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
        If ($PSBoundParameters['CreateExchange']) {
            Start-AdDelegateSite -ConfigXMLFile $ConfigXMLFile -ouName $ouName -QuarantineDN $ItQuarantinePcOuDn -CreateExchange

            #create Sub-OUs
            # --- USER CLASS ---
            New-DelegateAdOU -ouName $confXML.n.Sites.OUs.OuSiteMailbox.Name -ouPath $ouNameDN -ouDescription ('{0} {1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Description)

            # --- GROUP CLASS ---
            New-DelegateAdOU -ouName $confXML.n.Sites.OUs.OuSiteDistGroup.Name -ouPath $ouNameDN -ouDescription ('{0} {1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteDistGroup.Description)

            # --- CONTACT CLASS ---
            New-DelegateAdOU -ouName $confXML.n.Sites.OUs.OuSiteContact.Name -ouPath $ouNameDN -ouDescription ('{0} {1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteContact.Description)

            #create Basic Gpo
            # Create Mailboxes Baseline
            $splat = @{
                gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Name
                gpoScope       = 'U'
                gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteMailbox.Name, $ouNameDN
                GpoAdmin       = $GpoAdmin
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
            Start-AdDelegateSite -ConfigXMLFile $ConfigXMLFile -ouName $ouName -QuarantineDN $ItQuarantinePcOuDn
        } # end if CreateExchange

        # --- LAPS Related
        ###############################################################################
        If ($PSBoundParameters['CreateLAPS']) {
            # Desktop LAPS delegation
            $Splat = @{
                ResetGroup = $SL_PwdRight
                ReadGroup  = $SL_PwdRight
                LDAPpath   = ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.Name, $ouNameDN)
            }
            Set-AdAclLaps @Splat

            # Laptop LAPS delegation
            $Splat = @{
                ResetGroup = $SL_PwdRight
                ReadGroup  = $SL_PwdRight
                LDAPpath   = ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Name, $ouNameDN)
            }
            Set-AdAclLaps @Splat
        } #end If
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'creating Site OU structure.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
