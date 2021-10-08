Function New-ExchangeObjects {
  <#
      .Synopsis
      Create Exchange Objects and Containers
      .DESCRIPTION
      Create the Exchange OU structure and objects used to manage
      this organization by following the defined Delegation Model.
      .EXAMPLE
      New-ExchangeObjects
      .INPUTS

      .NOTES
      Version:         1.0
      DateModified:    19/Apr/2016
      LasModifiedBy:   Vicente Rodriguez Eguibar
      vicente@eguibar.com
      Eguibar Information Technology S.L.
      http://www.eguibarit.com
  #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param(
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        # Param2 Location of all scripts & files
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 1)]
        [string]
        $DMscripts = "C:\PsScripts\"
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

        ################################################################################
        # Initialisations
        Import-Module -name ServerManager        -Verbose:$false
        Import-Module -name ActiveDirectory      -Verbose:$false
        Import-Module -name GroupPolicy          -Verbose:$false
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        ################################################################################
        #region Declarations


        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile'])
                {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        catch { Get-CurrentErrorToDisplay -CurrentError $error[0] }



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


        # Organizational Units Distinguished Names

        # IT Admin OU
        New-Variable -Name 'ItAdminOu' -Value $confXML.n.Admin.OUs.ItAdminOU.name -Option ReadOnly -Force
        # IT Admin OU Distinguished Name
        New-Variable -Name 'ItAdminOuDn' -Value ('OU={0},{1}' -f $ItAdminOu, $AdDn) -Option ReadOnly -Force

            # It Admin Groups OU
            #$ItGroupsOu = $confXML.n.Admin.OUs.ItAdminGroupsOU.name
            # It Admin Groups OU Distinguished Name
            #$ItGroupsOuDn = 'OU={0},{1}' -f $ItGroupsOu, $ItAdminOuDn

            # It Privileged Groups OU
            $ItPGOu = $confXML.n.Admin.OUs.ItPrivGroupsOU.name
            # It Privileged Groups OU Distinguished Name
            $ItPGOuDn = 'OU={0},{1}' -f $ItPGOu, $ItAdminOuDn

            # It Admin Rights OU
            $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
            # It Admin Rights OU Distinguished Name
            $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

            # It Admin Exchange OU
            $ItExchangeOu = $confXML.n.AdminXtra.OUs.ItExchangeOU.name
            # It Admin Exchange OU Distinguished Name
            $ItExchangeOuDn = 'OU={0},{1}' -f $ItExchangeOu, $ItAdminOuDn

                # It Admin Exchange Distribution Groups OU
                $ItExDistGroupsOu = $confXML.n.AdminXtra.OUs.ItExDistGroups.name
                # It Admin Exchange Distribution Groups OU Distinguished Name
                $ItExDistGroupsOuDn = 'OU={0},{1}' -f $ItExDistGroupsOu, $ItExchangeOuDn

                # It Admin Exchange External Contacts OU
                $ItExExternalContactOu = $confXML.n.AdminXtra.OUs.ItExExternalContact.name
                # It Admin Exchange External Contacts OU Distinguished Name
                #$ItExExternalContactOuDn = 'OU={0},{1}' -f $ItExExternalContactOu, $ItExchangeOuDn

                # It Admin Exchange Resource OU
                $ItExResourceOu = $confXML.n.AdminXtra.OUs.ItExResource.name
                # It Admin Exchange Resource OU Distinguished Name
                #$ItExResourceOuDn = 'OU={0},{1}' -f $ItExResourceOu, $ItExchangeOuDn

                # It Admin Exchange Shared OU
                $ItExSharedOu = $confXML.n.AdminXtra.OUs.ItExShared.name
                # It Admin Exchange Shared OU Distinguished Name
                #$ItExSharedOuDn = 'OU={0},{1}' -f $ItExSharedOu, $ItExchangeOuDn

                # It Admin Exchange Equipment OU
                $ItExEquipOu = $confXML.n.AdminXtra.OUs.ItExEquip.name
                # It Admin Exchange Equipment OU Distinguished Name
                #$ItExEquipOuDn = 'OU={0},{1}' -f $ItExEquipOu, $ItExchangeOuDn

        # Servers OU
        $ServersOu = $confXML.n.Servers.OUs.ServersOU.name
        # Servers OU Distinguished Name
        $ServersOuDn = 'OU={0},{1}' -f $ServersOu, $AdDn

            # Exchange Servers
            $ExServersOu = $confXML.n.Servers.OUs.ExchangeOU.Name
            # Exchange Servers Distinguished Name
            $ExServersOuDn = 'OU={0},{1}' -f $ExServersOu, $ServersOuDn

                # Exchange CAS Servers
                $ExCasOu = $confXML.n.Servers.OUs.ExCasOU.Name
                # Exchange CAS Servers Distinguished Name
                $ExCasOuDn = 'OU={0},{1}' -f $ExCasOu, $ExServersOuDn

                # Exchange HUB Servers
                $ExHubOu = $confXML.n.Servers.OUs.ExHubOU.Name
                # Exchange HUB Servers Distinguished Name
                $ExHubOuDn = 'OU={0},{1}' -f $ExHubOu, $ExServersOuDn

                # Exchange EDGE Servers
                $ExEdgeOu = $confXML.n.Servers.OUs.ExEdgeOU.Name
                # Exchange EDGE Servers Distinguished Name
                $ExEdgeOuDn = 'OU={0},{1}' -f $ExEdgeOu, $ExServersOuDn

                # Exchange MAILBOX Servers
                $ExMailboxOu = $confXML.n.Servers.OUs.ExMailboxOU.Name
                # Exchange MAILBOX Servers Distinguished Name
                $ExMailboxOuDn = 'OU={0},{1}' -f $ExMailboxOu, $ExServersOuDn

                # Exchange MIXED ROLE Servers
                $ExMixedOu = $confXML.n.Servers.OUs.ExMixedRolOU.Name
                # Exchange MIXED ROLE Servers Distinguished Name
                $ExMixedOuDn = 'OU={0},{1}' -f $ExMixedOu, $ExServersOuDn

        # Quarantine OU
        $ItQuarantineOu = $confXML.n.Admin.OUs.ItNewComputersOU.name
        # Quarantine OU Distinguished Name
        $ItQuarantineOuDn = 'OU={0},{1}' -f $ItQuarantineOu, $AdDn

        #endregion Declarations
        ################################################################################
    }
    Process {
        ###############################################################################
        # Create Sub-OUs for admin

        New-DelegateAdOU -ouName $ItExchangeOu -ouPath $ItAdminOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExchangeOU.Description

        ###############################################################################
        # Create Sub-Sub-OUs
        New-DelegateAdOU -ouName $ItExDistGroupsOu      -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExDistGroups.Description
        New-DelegateAdOU -ouName $ItExExternalContactOu -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExExternalContact.Description
        New-DelegateAdOU -ouName $ItExResourceOu        -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExResource.Description
        New-DelegateAdOU -ouName $ItExSharedOu          -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExShared.Description
        New-DelegateAdOU -ouName $ItExEquipOu           -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExEquip.Description

        ###############################################################################
        # Create OU Admin groups
        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.ExAdmins.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.AdminXtra.GG.ExAdmins.DisplayName
            Path                          = $ItPGOuDn
            Description                   = $confXML.n.AdminXtra.GG.ExAdmins.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SG_ExAdmins = New-AdDelegatedGroup @parameters

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.ExRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.ExRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.ExRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_ExRight = New-AdDelegatedGroup @parameters

        ###############################################################################
        # Create a New Fine Grained Password Policy for Admins Accounts
        #  and apply the PSO to the account ()
        Add-ADFineGrainedPasswordPolicySubject -Identity $confXML.n.Admin.PSOs.ItAdminsPSO.Name -Subjects $SG_ExAdmins.SamAccountName, $SL_ExRight.SamAccountName

        ###############################################################################
        # Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Add-AdGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SG_ExAdmins, $SL_ExRight


        ###############################################################################
        # Nest Groups - Extend  Rights

        Add-AdGroupNesting -Identity $SG_ExAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.InfraAdmins.Name)
        Add-AdGroupNesting -Identity $SL_ExRight -Members $SG_ExAdmins

        ###############################################################################
        # START Delegation to SL_InfraRights group on ADMIN area

        $SL_InfraRight = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraRight.Name)
        $SL_AdRight    = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.AdRight.Name)
        $SL_PGM        = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PGM.Name)

        # Administration OU
        Set-AdAclCreateDeleteGroup -Group $SL_InfraRight.SamAccountName -LDAPPath $ItExDistGroupsOuDn
        Set-AdAclCreateDeleteGroup -Group $SL_PGM.SamAccountName        -LDAPPath $ItExDistGroupsOuDn
        Set-AdAclCreateDeleteGroup -Group $SL_ExRight.SamAccountName    -LDAPPath $ItExDistGroupsOuDn

        ###############################################################################
        # START Delegation to SL_AdRights group on ADMIN area

        # Administration OU
        Set-AdAclChangeGroup     -Group $SL_AdRight.SamAccountName -LDAPPath $ItExDistGroupsOuDn
        Set-AdAclChangeGroup     -Group $SL_PGM.SamAccountName     -LDAPPath $ItExDistGroupsOuDn
        Set-AdAclChangeGroup     -Group $SL_ExRight.SamAccountName -LDAPPath $ItExDistGroupsOuDn

        ###############################################################################
        # Create Servers and Sub OUs
        # Create Sub-Sub-OUs for Exchange
        New-DelegateAdOU -ouName $ExServersOu -ouPath $ServersOuDn   -ouDescription $confXML.n.Servers.OUs.ExchangeOU.Description
        New-DelegateAdOU -ouName $ExCasOu     -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExCasOU.Description
        New-DelegateAdOU -ouName $ExHubOu     -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExHubOU.Description
        New-DelegateAdOU -ouName $ExEdgeOu    -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExEdgeOU.Description
        New-DelegateAdOU -ouName $ExMailboxOu -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExMailboxOU.Description
        New-DelegateAdOU -ouName $ExMixedOu   -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExMixedRolOU.Description

        ###############################################################################
        # START Delegation to SL_InfraRights group on SERVERS area

        # Servers OU
        # Create/Delete Computers
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExServersOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExCasOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExHubOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExEdgeOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExMailboxOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExMixedOuDn -QuarantineDN $ItQuarantineOuDn

        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExServersOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExCasOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExHubOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExEdgeOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExMailboxOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExMixedOuDn -QuarantineDN $ItQuarantineOuDn

        ###############################################################################
        # START Delegation to SL_AdRights group

        # Servers OU
        # Change Public Info
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExServersOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExCasOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExHubOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExEdgeOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExMailboxOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExMixedOuDn

        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExServersOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExCasOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExHubOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExEdgeOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExMailboxOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExMixedOuDn

        # Change Personal Info
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExServersOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExCasOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExHubOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExEdgeOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExMailboxOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight.SamAccountName -LDAPPath $ExMixedOuDn

        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExServersOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExCasOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExHubOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExEdgeOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExMailboxOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExMixedOuDn

        ###############################################################################
        # Create basic GPOs for different types under Servers
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $ExCasOu)     -gpoScope C -gpoLinkPath $ExCasOuDn     -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $ExHubOu)     -gpoScope C -gpoLinkPath $ExHubOuDn     -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $ExMailboxOu) -gpoScope C -gpoLinkPath $ExMailboxOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $ExEdgeOuDn)  -gpoScope C -gpoLinkPath $ExEdgeOuDn    -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        ###############################################################################
        # Import the security templates to the corresponding GPOs under Servers

        # Configure Exchange ClientAccess GPO
        #Import-GPO -BackupId $confXML.n.AdminXtra.GPOs.ExCas.backupID     -TargetName ('C-{0}-Baseline' -f $ExCasOu) -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)

        # Configure Exchange Hub GPO
        #Import-GPO -BackupId $confXML.n.AdminXtra.GPOs.ExHub.backupID     -TargetName ('C-{0}-Baseline' -f $ExHubOu) -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)

        # Configure Mailbox GPO
        #Import-GPO -BackupId $confXML.n.AdminXtra.GPOs.ExMailbox.backupID -TargetName ('C-{0}-Baseline' -f $ExMailboxOu) -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)

        # Configure EDGE GPO
        #Import-GPO -BackupId $confXML.n.AdminXtra.GPOs.ExEdge.backupID    -TargetName ('C-{0}-Baseline' -f $ExEdgeOuDn) -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating Exchange containers and objects."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}