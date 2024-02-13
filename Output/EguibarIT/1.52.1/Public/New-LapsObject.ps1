Function New-LAPSobject {
    <#
        .Synopsis
            Create Local Administration Password Services (LAPS) Objects and Delegations
        .DESCRIPTION
            Create the LAPS Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-LAPSobjects -PawOuDn "OU=PAW,OU=Admin,DC=EguibarIT,DC=local" -ServersOuDn "OU=Servers,DC=EguibarIT,DC=local" -SitesOuDn "OU=Sites,DC=EguibarIT,DC=local"
        .PARAMETER ConfigXMLFile
            [String] Full path to the configuration.xml file
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-CurrentErrorToDisplay              | EguibarIT
                Set-AdAclLaps                          | EguibarIT
                Get-AttributeSchemaHashTable           | EguibarIT.Delegation
                Get-ADGroup                            | ActiveDirectory
                Add-ADGroupMember                      | ActiveDirectory
                Get-AdOrganizationalUnit               | ActiveDirectory
                Remove-ADGroupMember                   | ActiveDirectory
                Update-AdmPwdADSchema                  | AdmPwd.PS
        .NOTES
            Version:         1.1
            DateModified:    11/Feb/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0)]
        [string]
        $ConfigXMLFile
    )
    Begin {
        $error.Clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition


        ################################################################################
        # Initialisations
        Import-Module -Name ActiveDirectory -Verbose:$false
        Import-Module -Name EguibarIT -Verbose:$false
        Import-Module -Name EguibarIT.Delegation -Verbose:$false
        Import-Module -Name AdmPwd.PS -Verbose:$false
        Import-Module -Name LAPS -Verbose:$false

        ################################################################################
        #region Declarations

        try {
            # Active Directory Domain Distinguished Name
            If (-Not (Test-Path -Path variable:AdDn)) {
                $AdDn = ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If (-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If (Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        }

        If (-Not (Test-Path -Path variable:NC)) {
            # Naming conventions hashtable
            $NC = @{'sl' = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'     = $confXML.n.NC.GlobalGroupPreffix;
                'su'     = $confXML.n.NC.UniversalGroupPreffix;
                'Delim'  = $confXML.n.NC.Delimiter;
                'T0'     = $confXML.n.NC.AdminAccSufix0;
                'T1'     = $confXML.n.NC.AdminAccSufix1;
                'T2'     = $confXML.n.NC.AdminAccSufix2
            }
        }
        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0

        If (-Not (Test-Path -Path variable:SL_InfraRight)) {
            $SL_InfraRight = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraRight.Name)
        }

        If (-Not (Test-Path -Path variable:SL_PISM)) {
            $SL_PISM = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PISM.Name)
        }

        If (-Not (Test-Path -Path variable:SL_PAWM)) {
            $SL_PAWM = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PAWM.Name)
        }

        # $SL_AdRight    = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.AdRight.Name)

        If (-Not (Test-Path -Path variable:SL_SvrAdmRight)) {
            $SL_SvrAdmRight = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name)
        }

        $guidmap = $null
        $guidmap = @{}
        $guidmap = Get-AttributeSchemaHashTable
        #$parameters = $null


        # Organizational Units Distinguished Names

        # IT Admin OU
        If (-Not (Test-Path -Path variable:ItAdminOu)) {
            $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        }
        # IT Admin OU Distinguished Name
        If (-Not (Test-Path -Path variable:ItAdminOuDn)) {
            New-Variable -Name 'ItAdminOuDn' -Value ('OU={0},{1}' -f $ItAdminOu, $AdDn) -Option ReadOnly -Force
        }

        # Servers OU
        If (-Not (Test-Path -Path variable:ServersOu)) {
            $ServersOu = $confXML.n.Servers.OUs.ServersOU.name
        }
        # Servers OU Distinguished Name
        If (-Not (Test-Path -Path variable:ServersOuDn)) {
            $ServersOuDn = 'OU={0},{1}' -f $ServersOu, $AdDn
        }

        # It InfraServers OU
        $ItInfraServersOu = $confXML.n.Admin.OUs.ItInfraOU.name
        # It PAW OU Distinguished Name
        $ItInfraServersOuDn = 'OU={0},{1}' -f $ItInfraServersOu, $ItAdminOuDn

        # It InfraServers Tier0 OU
        $ItInfraT0OU = $confXML.n.Admin.OUs.ItInfraT0OU.name
        #  It InfraServers Tier0 OU Distinguished Name
        $ItInfraT0OUDN = 'OU={0},{1}' -f $ItInfraT0OU, $ItInfraServersOuDn

        # It InfraServers Tier1 OU
        $ItInfraT1OU = $confXML.n.Admin.OUs.ItInfraT1OU.name
        #  It InfraServers Tier1 OU Distinguished Name
        $ItInfraT1OUDN = 'OU={0},{1}' -f $ItInfraT1OU, $ItInfraServersOuDn

        # It InfraServers Tier2 OU
        $ItInfraT2OU = $confXML.n.Admin.OUs.ItInfraT2OU.name
        #  It InfraServers Tier2 OU Distinguished Name
        $ItInfraT2OUDN = 'OU={0},{1}' -f $ItInfraT2OU, $ItInfraServersOuDn

        # It InfraServers Staging Tier0 OU
        $ItInfraStagingOU = $confXML.n.Admin.OUs.ItInfraStagingOU.name
        #  It InfraServers Staging Tier0 OU Distinguished Name
        $ItInfraStagingOUDN = 'OU={0},{1}' -f $ItInfraStagingOU, $ItInfraServersOuDn

        # It PAW OU
        $ItPawOu = $confXML.n.Admin.OUs.ItPawOU.name
        # It PAW OU Distinguished Name
        $ItPawOuDn = 'OU={0},{1}' -f $ItPawOu, $ItAdminOuDn

        # It PAW Tier0 OU
        $ItPawT0OU = $confXML.n.Admin.OUs.ItPawT0OU.name
        #  It PAW Tier0 OU Distinguished Name
        $ItPawT0OUDN = 'OU={0},{1}' -f $ItPawT0OU, $ItPawOuDn

        # It PAW Tier1 OU
        $ItPawT1OU = $confXML.n.Admin.OUs.ItPawT1OU.name
        #  It PAW Tier1 OU Distinguished Name
        $ItPawT1OUDN = 'OU={0},{1}' -f $ItPawT1OU, $ItPawOuDn

        # It PAW Tier2 OU
        $ItPawT2OU = $confXML.n.Admin.OUs.ItPawT2OU.name
        #  It PAW Tier2 OU Distinguished Name
        $ItPawT2OUDN = 'OU={0},{1}' -f $ItPawT2OU, $ItPawOuDn

        # It PAW Staging Tier0 OU
        $ItPawStagingOU = $confXML.n.Admin.OUs.ItPawStagingOU.name
        #  It PAW Tier2 OU Distinguished Name
        $ItPawStagingOUDN = 'OU={0},{1}' -f $ItPawStagingOU, $ItPawOuDn

        # Sites OU
        $SitesOu = $confXML.n.Sites.OUs.SitesOU.name
        # Sites OU Distinguished Name
        $SitesOuDn = 'OU={0},{1}' -f $SitesOu, $AdDn

        #endregion Declarations
        ################################################################################

        # Check if schema is extended for LAPS. Extend it if not.
        Try {
            if ($null -eq $guidmap['ms-Mcs-AdmPwd']) {
                Write-Verbose -Message 'LAPS is NOT supported on this environment. Proceeding to configure it by extending the Schema.'

                # Check if user can change schema
                if (-not ((Get-ADUser $env:UserName -Properties memberof).memberof -like 'CN=Schema Admins*')) {
                    Write-Verbose -Message 'Member is not a Schema Admin... adding it.'
                    Add-ADGroupMember -Identity 'Schema Admins' -Members $env:username

                    # Modify Schema
                    try {
                        Write-Verbose -Message 'Modify the schema...!'
                        Update-AdmPwdADSchema -Verbose
                        Update-LapsADSchema -Confirm:$false -Verbose
                    }
                    catch {
                        Get-CurrentErrorToDisplay -CurrentError $error[0]
                    }
                    finally {
                        # If Schema extension OK, remove user from Schema Admin
                        Remove-ADGroupMember -Identity 'Schema Admins' -Members $env:username -Confirm:$false
                    }
                }#end if
            }#end if
        }#end try
        catch {
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        }
        Finally {
            Write-Verbose -Message 'Schema was extended succesfully for LAPS.'
        }#end finally
    }

    Process {
        # Make Infrastructure Servers modifications
        Set-AdAclLaps -ResetGroup $SL_PISM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPpath $ItInfraT0OUDN
        Set-AdAclLaps -ResetGroup $SL_PISM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPpath $ItInfraT1OUDN
        Set-AdAclLaps -ResetGroup $SL_PISM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPpath $ItInfraT2OUDN
        Set-AdAclLaps -ResetGroup $SL_PISM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPpath $ItInfraStagingOUDN

        # Make PAW modifications
        Set-AdAclLaps -ResetGroup $SL_PAWM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPpath $ItPawT0OUDN
        Set-AdAclLaps -ResetGroup $SL_PAWM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPpath $ItPawT1OUDN
        Set-AdAclLaps -ResetGroup $SL_PAWM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPpath $ItPawT2OUDN
        Set-AdAclLaps -ResetGroup $SL_PAWM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPpath $ItPawStagingOUDN

        # Make Servers Modifications
        Set-AdAclLaps -ResetGroup $SL_SvrAdmRight.SamAccountName -ReadGroup $SL_SvrAdmRight.SamAccountName -LDAPpath $ServersOuDn

        # Make Sites Modifications
        # Get the DN of 1st level OU underneath SERVERS area
        $AllSubOu = Get-ADOrganizationalUnit -Filter * -SearchBase $SitesOuDn -SearchScope OneLevel | Select-Object -ExpandProperty DistinguishedName

        # Iterate through each sub OU and invoke delegation
        Foreach ($Item in $AllSubOu) {
            # Exclude _Global OU from delegation
            If (-not($item.Split(',')[0].Substring(3) -eq $confXML.n.Sites.OUs.OuSiteGlobal.name)) {
                # Get group who manages Desktops and Laptops
                $CurrentGroup = (Get-ADGroup -Identity ('{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $confXML.n.Sites.LG.PcRight.Name, ($item.Split(',')[0].Substring(3)))).SamAccountName

                # Desktops
                $CurrentLDAPPath = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.Name, $Item
                Set-AdAclLaps -ResetGroup $CurrentGroup.SamAccountName -ReadGroup $CurrentGroup.SamAccountName -LDAPpath $CurrentLDAPPath

                # Laptop
                $CurrentLDAPPath = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Name, $Item
                Set-AdAclLaps -ResetGroup $CurrentGroup.SamAccountName -ReadGroup $CurrentGroup.SamAccountName -LDAPpath $CurrentLDAPPath

                <# -- Not compliant with Tieriing model.
                    # Get group who manages Local Servers & File-Print
                    $CurrentGroup = (Get-ADGroup -Identity ('{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $confXML.n.Sites.LG.LocalServerRight.Name, ($item.Split(',')[0].Substring(3)))).SamAccountName

                    # File-Print
                    $CurrentLDAPPath = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteFilePrint.Name, $Item
                    Set-AdAclLaps -ResetGroup $CurrentGroup.SamAccountName -ReadGroup $CurrentGroup.SamAccountName -LDAPPath $CurrentLDAPPath

                    # Local Server
                    $CurrentLDAPPath = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLocalServer.Name, $Item
                    Set-AdAclLaps -ResetGroup $CurrentGroup.SamAccountName -ReadGroup $CurrentGroup.SamAccountName -LDAPPath $CurrentLDAPPath
                #>
            }
        }#end foreach
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) created LAPS and Delegations successfully."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
