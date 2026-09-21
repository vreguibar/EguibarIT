# Delegate Rights to SITE groups
function Start-AdDelegateSite {
    <#
        .SYNOPSIS
            Creates and configures a complete Tier 2 delegated site structure in Active Directory.

        .DESCRIPTION
            Creates and configures the complete Tier 2 site structure in Active Directory,
            including all related delegation. The function:
            - Creates the Tier 2 site OU with sub-containers
            - Creates site-specific security groups
            - Delegates all required rights for users, computers, groups, contacts, print queues, volumes
            - Optionally creates Exchange objects and delegations
            - Implements the organization's delegation model for the site

        .PARAMETER ConfigXMLFile
            [String] Full path to the Configuration XML file.

        .PARAMETER ouName
            [String] Name of the Site OU to create.

        .PARAMETER QuarantineDN
            [String] Name of the new redirected OU for quarantined computers.

        .PARAMETER CreateExchange
            [Switch] When specified, creates Exchange-related objects and containers.

        .EXAMPLE
            Start-AdDelegateSite -ConfigXMLFile 'C:\PsScripts\Config.xml' -ouName 'GOOD' -QuarantineDN 'Quarantine' -CreateExchange

            Creates the GOOD site with all delegations including Exchange objects.

        .EXAMPLE
            $Splat = @{
                ConfigXMLFile  = 'C:\PsScripts\Config.xml'
                ouName         = 'GOOD'
                QuarantineDN   = 'Quarantine'
                CreateExchange = $true
            }
            Start-AdDelegateSite @Splat

            Creates the site using splatting.

        .EXAMPLE
            Start-AdDelegateSite -ConfigXMLFile 'C:\PsScripts\Config.xml' -ouName 'GOOD' -QuarantineDN 'Quarantine' -WhatIf

            Shows what would happen when creating the site structure.

        .INPUTS
            [System.String]
            You can pipe the configuration file path to this function.

        .OUTPUTS
            [void]
            This function does not return any output.

        .NOTES
            This function relies on Config.xml file for naming conventions and OU structure.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Set-AdAclResetUserPassword             ║ EguibarIT.DelegationPS
                Set-AdAclChangeUserPassword            ║ EguibarIT.DelegationPS
                Set-AdAclUnlockUser                    ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteUser              ║ EguibarIT.DelegationPS
                Set-AdAclEnableDisableUser             ║ EguibarIT.DelegationPS
                Set-AdAclUserAccountRestriction        ║ EguibarIT.DelegationPS
                Set-AdAclUserLogonInfo                 ║ EguibarIT.DelegationPS
                Set-AdAclDelegateComputerAdmin         ║ EguibarIT
                Set-AdAclCreateDeleteGroup             ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.4
            DateModified:    21/Sep/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Start-AdDelegatedSite.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Infrastructure Administration

        .FUNCTIONALITY
            Site Delegation Management
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
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
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

        ##############################
        # Variables Definition


        Write-Verbose -Message 'Delegate Rights Site Groups'


        try {
            # Check if Config.xml file is loaded. If not, proceed to load it.
            if (-not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                if (Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
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
        foreach ($node in $confXML.n.Sites.LG.ChildNodes) {

            $TempName = '{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']

            Write-Verbose -Message ('Get group {0}' -f $TempName)

            New-Variable -Name "$($TempName)" -Value (Get-ADGroup $TempName) -Force
        }


        # Sites OU Distinguished Name
        if (-not (Test-Path -Path variable:ouNameDN)) {
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
        if ($PSCmdlet.ShouldProcess($ouNameDN, 'Delegate Active Directory rights for site')) {

            ###############################################################################
            # USER Site Administrator Delegation

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'USER Site Delegation')

            $OuSiteDefUser = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteUser.name, $ouNameDN

            $Splat = @{
                Group    = $SL_PwdRight
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
                Group    = $SL_CreateUserRight
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
                Group    = $SL_GALRight
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

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'COMPUTER Site Delegation')

            # Create/Delete Computers
            Set-AdAclDelegateComputerAdmin -Group $SL_PcRight -LDAPpath $OuSiteDefComputer
            Set-AdAclDelegateComputerAdmin -Group $SL_PcRight -LDAPpath $OuSiteDefLaptop

            # Grant the right to delete computers from default container. Move Computers
            Set-DeleteOnlyComputer -Group $SL_PcRight -LDAPPath $PSBoundParameters['QuarantineDN']

            #### GAL

            # Change Personal Info
            Set-AdAclComputerPersonalInfo -Group $SL_GALRight -LDAPPath $OuSiteDefComputer
            Set-AdAclComputerPersonalInfo -Group $SL_GALRight -LDAPPath $OuSiteDefLaptop

            # Change Public Info
            Set-AdAclComputerPublicInfo -Group $SL_GALRight -LDAPPath $OuSiteDefComputer
            Set-AdAclComputerPublicInfo -Group $SL_GALRight -LDAPPath $OuSiteDefLaptop




            ###############################################################################
            # GROUP Site Admin Delegation

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'GROUP Site Delegation')

            # Create/Delete Groups
            $Splat = @{
                Group    = $SL_GroupRight
                LDAPPath = ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteGroup.name, $ouNameDN)
            }
            Set-AdAclCreateDeleteGroup @Splat

            #### GAL

            # Change Group Properties
            $Splat = @{
                Group    = $SL_GroupRight
                LDAPPath = ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteGroup.name, $ouNameDN)
            }
            Set-AdAclChangeGroup @Splat




            Write-Verbose -Message 'START PRINTQUEUE Site Admin Delegation'
            ###############################################################################
            # PRINTQUEUE Site Admin Delegation

            # Create/Delete Print Queue
            $Splat = @{
                Group    = $SL_SiteRight
                LDAPPath = ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSitePrintQueue.name, $ouNameDN)
            }
            Set-AdAclCreateDeletePrintQueue @Splat



            Write-Verbose -Message 'START PRINTQUEUE Site GAL Delegation'
            ###############################################################################
            # PRINTQUEUE Site GAL Delegation

            $Splat = @{
                Group    = $SL_GALRight
                LDAPpath = ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSitePrintQueue.name, $ouNameDN)
            }
            Set-AdAclChangePrintQueue @Splat


            Write-Verbose -Message 'START VOLUME Site Admin Delegation'
            ###############################################################################
            # VOLUME Site Admin Delegation

            # Create/Delete Volume
            $Splat = @{
                Group    = $SL_SiteRight
                LDAPpath = ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteShares.name, $ouNameDN)
            }
            Set-AdAclCreateDeleteVolume @Splat



            Write-Verbose -Message 'START VOLUME Site GAL Delegation'
            ###############################################################################
            # VOLUME Site GAL Delegation

            # Change Volume Properties
            $Splat = @{
                Group    = $SL_GALRight
                LDAPpath = ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteShares.name, $ouNameDN)
            }
            Set-AdAclChangeVolume @Splat



            Write-Verbose -Message 'START Exchange Related delegation'
            ###############################################################################
            #region Exchange Related delegation
            ###############################################################################
            if ($PSBoundParameters['CreateExchange']) {
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
        } #end If ShouldProcess
    } #end Process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'Site delegation.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
