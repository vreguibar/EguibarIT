# Delegate Rights to SITE groups
function Start-AdDelegateSite {
    <#
        .Synopsis
            The function will create the corresponding Tier2 site
        .DESCRIPTION
            This function will create all needed objects and related delegations for the
            given site. This Tier2 site is intended to hold all related Tier2 objects, as Users, Computers, Groups, etc.
            and provide all delegated rights and permissions according to the delegation model.
        .EXAMPLE
            Start-AdDelegateSite -ConfigXMLFile "C:\PsScripts\Config.xml" -ouName "GOOD" -QuarantineDN "Quarantine" -CreateExchange
        .EXAMPLE
            $Splat = @{
                ConfigXMLFile  = "C:\PsScripts\Config.xml"
                ouName         = "GOOD"
                QuarantineDN   = "Quarantine"
                CreateExchange = $true
            }
            Start-AdDelegateSite @Splat
        .PARAMETER ConfigXMLFile
            Full path to the Configuration.XML file
        .PARAMETER ouName
            Name of the Site OU
        .PARAMETER QuarantineDN
            Name new redirected OU for computers
        .PARAMETER CreateExchange
            If present It will create all needed Exchange objects and containers.
        .NOTES
            This function relies on Config.xml file.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Set-AdAclResetUserPassword             | EguibarIT.DelegationPS
                Set-AdAclChangeUserPassword            | EguibarIT.DelegationPS
                Set-AdAclUnlockUser                    | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteUser              | EguibarIT.DelegationPS
                Set-AdAclEnableDisableUser             | EguibarIT.DelegationPS
                Set-AdAclUserAccountRestriction        | EguibarIT.DelegationPS
                Set-AdAclUserLogonInfo                 | EguibarIT.DelegationPS
                Set-AdAclUserGroupMembership           | EguibarIT.DelegationPS
                Set-AdAclUserPersonalInfo              | EguibarIT.DelegationPS
                Set-AdAclUserPublicInfo                | EguibarIT.DelegationPS
                Set-AdAclUserGeneralInfo               | EguibarIT.DelegationPS
                Set-AdAclUserWebInfo                   | EguibarIT.DelegationPS
                Set-AdAclUserEmailInfo                 | EguibarIT.DelegationPS
                Set-AdAclDelegateComputerAdmin         | EguibarIT
                Set-DeleteOnlyComputer                 | EguibarIT.DelegationPS
                Set-AdAclComputerPersonalInfo          | EguibarIT.DelegationPS
                Set-AdAclComputerPublicInfo            | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGroup             | EguibarIT.DelegationPS
                Set-AdAclChangeGroup                   | EguibarIT.DelegationPS
                Set-AdAclCreateDeletePrintQueue        | EguibarIT.DelegationPS
                Set-AdAclChangePrintQueue              | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteVolume            | EguibarIT.DelegationPS
                Set-AdAclChangeVolume                  | EguibarIT.DelegationPS
                Set-AdAclCreateDeleteContact           | EguibarIT.DelegationPS
        .NOTES
            Version:         1.3
            DateModified:    12/Feb/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ParamOptions')]
    [OutputType([void])]

    param (
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0)]
        [string]
        $ConfigXMLFile,

        #PARAM2
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            ParameterSetName = 'ParamOptions',
            HelpMessage = 'Enter the Name of the Site OU',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ouName,

        #PARAM3
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            ParameterSetName = 'ParamOptions',
            HelpMessage = 'Enter the Name new redirected OU for computers',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [validateScript({ Test-IsValidDN -ObjectDN $_ })]
        [Alias('DN', 'DistinguishedName', 'LDAPpath')]
        [String]
        $QuarantineDN,

        # Param4 Create Exchange Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects and containers.',
            Position = 3)]
        [switch]
        $CreateExchange
    )

    begin {
        $error.Clear()

        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition


        Write-Verbose -Message 'Delegate Rights Site Groups'


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

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0


        # Iterate through all Site-DomainLocalGroups child nodes
        Foreach ($node in $confXML.n.Sites.LG.ChildNodes) {

            $TempName = '{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']

            Write-Verbose -Message ('Get group {0}' -f $TempName)

            New-Variable -Name "$($TempName)" -Value (Get-ADGroup $TempName) -Force
        }


        # Sites OU Distinguished Name
        If (-Not (Test-Path -Path variable:ouNameDN)) {
            $ouNameDN = 'OU={0},OU={1},{2}' -f $ouName, $confXML.n.Sites.OUs.SitesOU.name, $Variables.AdDn
        }

        $OuSiteDefComputer = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.name, $ouNameDN
        $OuSiteDefLaptop = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.name, $ouNameDN

        $OuSiteDefMailbox = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteMailbox.name, $ouNameDN
        $OuSiteDefDistGroup = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteDistGroup.name, $ouNameDN
        $OuSiteDefContact = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteContact.name, $ouNameDN

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    process {

        ###############################################################################
        # USER Site Administrator Delegation

        Write-Verbose -Message ($Constants.NewRegionMessage -f 'USER Site Delegation')

        $OuSiteDefUser = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteUser.name, $ouNameDN

        $Splat = @{
            Group    = $SL_PwdRight.SamAccountName
            LDAPPath = $OuSiteDefUser
        }

        # Reset User Password
        Set-AdAclResetUserPassword @Splat
        #Set-AdAclResetUserPassword -Group $SL_CreateUserRight.SamAccountName -LDAPPath $OuSiteDefUser

        # Change User Password
        Set-AdAclChangeUserPassword @Splat

        # Unlock user account
        Set-AdAclUnlockUser @Splat


        $Splat = @{
            Group    = $SL_CreateUserRight.SamAccountName
            LDAPPath = $OuSiteDefUser
        }

        # Create/Delete Users
        Set-AdAclCreateDeleteUser @Splat

        # Enable and/or Disable user right
        Set-AdAclEnableDisableUser @Splat

        # Change User Restrictions
        Set-AdAclUserAccountRestriction @Splat

        # Change User Account Logon Info
        Set-AdAclUserLogonInfo @Splat


        #### GAL

        $Splat = @{
            Group    = $SL_GALRight.SamAccountName
            LDAPPath = $OuSiteDefUser
        }

        # Change Group Membership
        Set-AdAclUserGroupMembership @Splat

        # Change Personal Information
        Set-AdAclUserPersonalInfo @Splat

        # Change Public Information
        Set-AdAclUserPublicInfo @Splat

        # Change General Information
        Set-AdAclUserGeneralInfo @Splat

        # Change Web Info
        Set-AdAclUserWebInfo @Splat

        # Change Email Info
        Set-AdAclUserEmailInfo @Splat





        ###############################################################################
        # COMPUTER Site Admin Delegation

        Write-Verbose -Message ($Constants.NewRegionMessage -f 'COMPUTER Site Delegation')

        # Create/Delete Computers
        Set-AdAclDelegateComputerAdmin -Group $SL_PcRight.SamAccountName -LDAPpath $OuSiteDefComputer -QuarantineDN $PSBoundParameters['QuarantineDN']
        Set-AdAclDelegateComputerAdmin -Group $SL_PcRight.SamAccountName -LDAPpath $OuSiteDefLaptop -QuarantineDN $PSBoundParameters['QuarantineDN']

        # Grant the right to delete computers from default container. Move Computers
        Set-DeleteOnlyComputer -Group $SL_PcRight.SamAccountName -LDAPPath $PSBoundParameters['QuarantineDN']

        #### GAL

        # Change Personal Info
        Set-AdAclComputerPersonalInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefComputer
        Set-AdAclComputerPersonalInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefLaptop

        # Change Public Info
        Set-AdAclComputerPublicInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefComputer
        Set-AdAclComputerPublicInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefLaptop




        ###############################################################################
        # GROUP Site Admin Delegation

        Write-Verbose -Message ($Constants.NewRegionMessage -f 'GROUP Site Delegation')

        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_GroupRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteGroup.name, $ouNameDN)

        #### GAL

        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_GroupRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteGroup.name, $ouNameDN)




        Write-Verbose -Message 'START PRINTQUEUE Site Admin Delegation'
        ###############################################################################
        # PRINTQUEUE Site Admin Delegation

        # Create/Delete Print Queue
        Set-AdAclCreateDeletePrintQueue -Group $SL_SiteRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSitePrintQueue.name, $ouNameDN)



        Write-Verbose -Message 'START PRINTQUEUE Site GAL Delegation'
        ###############################################################################
        # PRINTQUEUE Site GAL Delegation

        Set-AdAclChangePrintQueue -Group $SL_GALRight.SamAccountName -LDAPpath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSitePrintQueue.name, $ouNameDN)


        Write-Verbose -Message 'START VOLUME Site Admin Delegation'
        ###############################################################################
        # VOLUME Site Admin Delegation

        # Create/Delete Volume
        Set-AdAclCreateDeleteVolume -Group $SL_SiteRight.SamAccountName -LDAPpath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteShares.name, $ouNameDN)



        Write-Verbose -Message 'START VOLUME Site GAL Delegation'
        ###############################################################################
        # VOLUME Site GAL Delegation

        # Change Volume Properties
        Set-AdAclChangeVolume -Group $SL_GALRight.SamAccountName -LDAPpath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteShares.name, $ouNameDN)



        Write-Verbose -Message 'START Exchange Related delegation'
        ###############################################################################
        #region Exchange Related delegation
        ###############################################################################
        If ($PSBoundParameters['CreateExchange']) {
            # USER class
            # Create/Delete Users
            Set-AdAclCreateDeleteUser -Group $SL_CreateUserRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Reset User Password
            Set-AdAclResetUserPassword -Group $SL_PwdRight.SamAccountName -LDAPPath $OuSiteDefMailbox
            #Set-AdAclResetUserPassword -Group $SL_CreateUserRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change User Password
            Set-AdAclChangeUserPassword -Group $SL_PwdRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change User Restrictions
            Set-AdAclUserAccountRestriction -Group $SL_SiteRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change User Account Logon Info
            Set-AdAclUserLogonInfo -Group $SL_SiteRight.SamAccountName -LDAPPath $OuSiteDefMailbox
            #--------------------------------------------------
            # Change Group Membership
            Set-AdAclUserGroupMembership -Group $SL_SiteRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change Personal Information
            Set-AdAclUserPersonalInfo -Group $SL_GALRight.SamAccountName -LDAPpath $OuSiteDefMailbox

            # Change Public Information
            Set-AdAclUserPublicInfo -Group $SL_GALRight.SamAccountName -LDAPpath $OuSiteDefMailbox

            # Change General Information
            Set-AdAclUserGeneralInfo -Group $SL_GALRight.SamAccountName -LDAPpath $OuSiteDefMailbox

            # Change Web Info
            Set-AdAclUserWebInfo -Group $SL_GALRight.SamAccountName -LDAPpath $OuSiteDefMailbox

            # Change Email Info
            Set-AdAclUserEmailInfo -Group $SL_GALRight.SamAccountName -LDAPpath $OuSiteDefMailbox

            # GROUP Class
            # Create/Delete Groups
            Set-AdAclCreateDeleteGroup -Group $SL_GroupRight.SamAccountName -LDAPPath $OuSiteDefDistGroup
            #--------------------------------------------------
            # Change Group Properties
            Set-AdAclChangeGroup -Group $SL_GroupRight.SamAccountName -LDAPPath $OuSiteDefDistGroup

            # CONTACT Class
            # Create/Delete Contacts
            Set-AdAclCreateDeleteContact -Group $SL_SiteRight.SamAccountName -LDAPPath $OuSiteDefContact
            #--------------------------------------------------
            # Change Personal Info
            Set-AdAclContactPersonalInfo -Group $SL_GALRight.SamAccountName -LDAPpath $OuSiteDefContact

            # Change Web Info
            Set-AdAclContactWebInfo -Group $SL_GALRight.SamAccountName -LDAPpath $OuSiteDefContact
        }
        #endregion Exchange Related delegation
        ###############################################################################
    } #end Process

    end {
        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'Site delegation.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
