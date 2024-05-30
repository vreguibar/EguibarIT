Function New-AGPMObject {
    <#
        .Synopsis
            Create Advanced Group Policy Management Objects and Delegations
        .DESCRIPTION
            Create the AGPM Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-AGPMObjects
        .INPUTS

        .NOTES
        Used Functions:
            Name                                   | Module
            ---------------------------------------|--------------------------
            Get-CurrentErrorToDisplay              | EguibarIT
            Get-FunctionDisplay                    | EguibarIT
            Add-AdGroupNesting                     | EguibarIT
        .NOTES
            Version:         1.3
            DateModified:    05/Feb/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param(
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0)]
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
        $DMscripts = 'C:\PsScripts\'
    )

    Begin {
        $error.Clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition


        ################################################################################
        # Initializations


        Import-MyModule -Name 'ActiveDirectory' -Force -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Force -Verbose:$false

        ################################################################################
        #region Declarations


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
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch



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

        # Organizational Units Distinguished Names

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $Variables.AdDn

        # It Admin ServiceAccount OU Distinguished Name
        $ItServiceAccountsOu = $confXML.n.Admin.OUs.ItServiceAccountsOU.name
        # It Admin ServiceAccount OU Distinguished Name
        $ItServiceAccountsOuDn = 'OU={0},{1}' -f $ItServiceAccountsOu, $ItAdminOuDn

        # It Admin Rights OU
        $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        #endregion Declarations
        ################################################################################
    }
    Process {
        ###############################################################################
        #region Creating Service account

        # Create the new Temporary Service Account with special values
        # This TEMP SA will be used for AGMP Server setup. Afterwards will be replaced by a MSA
        $Splat = @{
            Path                  = $ItServiceAccountsOuDn
            Name                  = 'SA_AGPM_Temp'
            AccountPassword       = (ConvertTo-SecureString -String $confXML.n.DefaultPassword -AsPlainText -Force)
            ChangePasswordAtLogon = $false
            Enabled               = $true
            UserPrincipalName     = ('AGPM@{0}' -f $env:USERDNSDOMAIN)
            SamAccountName        = 'SA_AGPM_Temp'
            DisplayName           = 'SA_AGPM_Temp'
            Description           = 'Service account used for Advanced Group Policy Management service'
            employeeId            = '0123456'
            TrustedForDelegation  = $false
            AccountNotDelegated   = $true
            Company               = $confXML.n.RegisteredOrg
            Country               = 'MX'
            Department            = 'IT Operations and Architecture'
            State                 = 'Puebla'
            EmailAddress          = ('AGPM@{0}' -f $env:USERDNSDOMAIN)
            OtherAttributes       = @{
                'employeeType'                  = 'ServiceAccount'
                'msNpAllowDialin'               = $false
                'msDS-SupportedEncryptionTypes' = '24'
            }
        }
        New-ADUser @Splat

        $SA_AGPM = Get-ADUser -Filter { samAccountName -eq 'SA_AGPM_Temp' }

        #http://blogs.msdn.com/b/openspecification/archive/2011/05/31/windows-configurations-for-kerberos-supported-encryption-type.aspx
        # 'msDS-SupportedEncryptionTypes'= Kerberos DES Encryption = 2, Kerberos AES 128 = 8, Kerberos AES 256 = 16

        # Make it member of Tier 0 ServiceAccount groups
        Add-AdGroupNesting -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name) -Members $SA_AGPM

        # http://blogs.msdn.com/b/muaddib/archive/2013/12/30/how-to-modify-security-inheritance-on-active-directory-objects.aspx

        # Remove Everyone group from Admin-User & Administrator
        Remove-Everyone -LDAPPath $SA_AGPM.DistinguishedName

        # Remove AUTHENTICATED USERS group from Admin-User & Administrator
        #Remove-AuthUser -LDAPPath $SA_AGPM.DistinguishedName

        # Remove Pre-Windows 2000 Compatible Access group from Admin-User & Administrator
        Remove-PreWin2000 -LDAPPath $SA_AGPM.DistinguishedName


        If ([System.Environment]::OSVersion.Version.Build -ge 9200) {
            $Splat = @{
                Name                   = $confXML.n.Admin.gMSA.AGPM.Name
                SamAccountName         = $confXML.n.Admin.gMSA.AGPM.Name
                DNSHostName            = ('{0}.{1}' -f $confXML.n.Admin.gMSA.AGPM.Name, $env:USERDNSDOMAIN)
                AccountNotDelegated    = $true
                Description            = $confXML.n.Admin.gMSA.AGPM.Description
                DisplayName            = $confXML.n.Admin.gMSA.AGPM.DisplayName
                KerberosEncryptionType = 'AES128,AES256'
                Path                   = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $ItServiceAccountsOuDn
                enabled                = $True
                TrustedForDelegation   = $false
            }

            $ReplaceParams = @{
                Replace = @{
                    'c'                 = 'MX'
                    'co'                = 'Mexico'
                    'company'           = $confXML.n.RegisteredOrg
                    'department'        = 'IT'
                    'employeeID'        = 'T0'
                    'employeeType'      = 'ServiceAccount'
                    'info'              = $confXML.n.Admin.gMSA.AGPM.Description
                    'l'                 = 'Puebla'
                    'title'             = $confXML.n.Admin.gMSA.AGPM.DisplayName
                    'userPrincipalName' = '{0}@{1}' -f $confXML.n.Admin.gMSA.AGPM.Name, $env:USERDNSDOMAIN
                }
            }

            try {
                New-ADServiceAccount @Splat | Set-ADServiceAccount @ReplaceParams
            } catch {
                Get-CurrentErrorToDisplay -CurrentError $error[0]
            }
        } else {
            $Splat = @{
                name        = $confXML.n.Admin.gMSA.AGPM.Name
                Description = $confXML.n.Admin.gMSA.AGPM.Description
                Path        = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $ItServiceAccountsOuDn
                enabled     = $True
            }
            New-ADServiceAccount @Splat
        }


        #endregion
        ###############################################################################

        ###############################################################################
        #region Create AGPM groups

        # AdminRights group is created by default on CentralItOU procedure. Is the default delegated Admin for OUs

        #New-ADGroup -Name "SG_AllSiteAdmins"      -SamAccountName SG_AllSiteAdmins      -GroupCategory Security -GroupScope Global      -DisplayName "All Sites Admins"        -Path $ItPGOuDn -Description "Members of this group are Site Administrators of all sites"

        $Splat = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.GpoApproverRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.GpoApproverRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.GpoApproverRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_GpoApproverRight = New-AdDelegatedGroup @Splat

        $Splat = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.GpoEditorRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.GpoEditorRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.GpoEditorRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_GpoEditorRight = New-AdDelegatedGroup @Splat

        $Splat = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.GpoReviewerRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.GpoReviewerRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.GpoReviewerRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_GpoReviewerRight = New-AdDelegatedGroup @Splat

        #endregion
        ###############################################################################

        # Apply the PSO to the corresponding Groups
        Add-ADFineGrainedPasswordPolicySubject -Identity $confXML.n.Admin.PSOs.ItAdminsPSO.Name -Subjects $SL_GpoApproverRight, $SL_GpoEditorRight, $SL_GpoReviewerRight


        ###############################################################################
        # Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Add-ADGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SL_GpoApproverRight, $SL_GpoEditorRight, $SL_GpoReviewerRight


        ###############################################################################
        #region Nest Groups - Delegate Rights through Builtin groups
        # http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx

        Add-AdGroupNesting -Identity 'Backup Operators' -Members $SA_AGPM

        Add-AdGroupNesting -Identity 'Group Policy Creator Owners' -Members $SA_AGPM

        #endregion

        ###############################################################################
        # Nest Groups - Extend Rights through delegation model groups

        # No nesting needed here

        ###############################################################################
        # START Delegation to

        # No delegation requiered because:
        #
        # 1.- Privileged groups are empty
        # 2.- AGPM will control all GPOs
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) created objects and Delegations successfully."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }#end End

} #end Function
