function New-Tier0Delegation {

    <#
        .SYNOPSIS
            Delegates rights and permissions to the Tier0 Admin area.

        .DESCRIPTION
            This function applies delegation permissions for administrative groups within the Tier0
            administrative area, following a tiered administration model and principle of least privilege.
            It configures access control lists (ACLs) for various security functions including:
            - User Management (UM - Semi-Privileged User Management)
            - Group Management (GM - Semi-Privileged Group Management)
            - Privileged User Management (PUM)
            - Privileged Group Management (PGM)
            - Server Admin Groups Management (SAGM)
            - Privileged Infrastructure Services Management (PISM)
            - Privileged Access Workstation Management (PAWM)
            - Domain Controller Management (DCManagement)
            - Privileged Service Account Management (PSAM)
            - GPO Administration
            - Directory Replication
            - Infrastructure Administration
            - FSMO Role Transfer
            - AD Administration

            This function is critical for implementing proper security boundaries in a tiered
            administrative model.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            [String] Path to all the scripts and files needed by this function.
            Should contain a SecTmpl subfolder.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0Delegation -ConfigXMLFile C:\PsScripts\Config.xml

            Delegates rights and permissions to the Tier0 Admin area using the default configuration file.

        .EXAMPLE
            $Splat = @{
                ConfigXMLFile = 'C:\CustomPath\Config.xml'
                DMScripts = 'D:\Scripts\'
                Verbose = $true
            }
            New-Tier0Delegation @Splat

            Delegates rights and permissions to the Tier0 Admin area with custom paths and verbose output.

        .INPUTS
            [System.IO.FileInfo]
            You can pipe the path to the XML configuration file to this function.

        .OUTPUTS
            [System.String]
            Returns completion status message.

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Set-StrictMode                             ║ Microsoft.PowerShell.Core
                Import-MyModule                            ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT
                Get-Content                                ║ Microsoft.PowerShell.Management
                Get-AdObjectType                           ║ EguibarIT
                Set-AdAclDelegateUserAdmin                 ║ EguibarIT.DelegationPS
                Set-AdAclDelegateGalAdmin                  ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGroup                 ║ EguibarIT.DelegationPS
                Set-AdAclChangeGroup                       ║ EguibarIT.DelegationPS
                Set-AdAclDelegateComputerAdmin             ║ EguibarIT.DelegationPS
                Add-GroupToSCManager                       ║ EguibarIT.DelegationPS
                Add-ServiceAcl                             ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGMSA                  ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteMSA                   ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteUser                  ║ EguibarIT.DelegationPS
                Set-AdAclResetUserPassword                 ║ EguibarIT.DelegationPS
                Set-AdAclChangeUserPassword                ║ EguibarIT.DelegationPS
                Set-AdAclUserGroupMembership               ║ EguibarIT.DelegationPS
                Set-AdAclUserAccountRestriction            ║ EguibarIT.DelegationPS
                Set-AdAclUserLogonInfo                     ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGPO                   ║ EguibarIT.DelegationPS
                Set-AdAclLinkGPO                           ║ EguibarIT.DelegationPS
                Set-AdAclGPoption                          ║ EguibarIT.DelegationPS
                Set-AdDirectoryReplication                 ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteOU                    ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteSubnet                ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteSite                  ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteSiteLink              ║ EguibarIT.DelegationPS
                Set-AdAclFMSOtransfer                      ║ EguibarIT.DelegationPS
                Set-DeleteOnlyComputer                     ║ EguibarIT.DelegationPS
                Set-AdAclChangeSubnet                      ║ EguibarIT.DelegationPS
                Set-AdAclChangeSite                        ║ EguibarIT.DelegationPS
                Set-AdAclChangeSiteLink                    ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Get-Service                                ║ Microsoft.PowerShell.Management

        .NOTES
            Version:         1.0
            DateModified:    30/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                        vicente@eguibar.com
                        Eguibar IT
                        http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Active Directory

        .ROLE
            Security

        .FUNCTIONALITY
            Tier 0 Delegation
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]

    param (
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
                        $null -eq $xml.n.Admin.OUs) {
                        throw 'XML file is missing required elements (Admin or OUs section)'
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

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
            Position = 1)]
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
        $DMScripts
    )

    Begin {
        Set-StrictMode -Version Latest

        # Display function header if variables exist
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

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [System.Collections.ArrayList]$ArrayList = [System.Collections.ArrayList]::new()

        # Load the XML configuration file
        try {
            [xml]$confXML = [xml](Get-Content -Path $PSBoundParameters['ConfigXMLFile'] -ErrorAction Stop)
            Write-Verbose -Message ('Successfully loaded configuration from {0}' -f $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        $AllLocalGroupVariables = @(
            $SL_UM,
            $SL_GM,
            $SL_PUM,
            $SL_PGM,
            $SL_SAGM,
            $SL_PISM,
            $SL_PAWM,
            $SL_DcManagement,
            $SL_PSAM,
            $SL_GpoAdminRight,
            $SL_DirReplRight,
            $SL_InfraRight,
            $SL_TransferFSMOright,
            $SL_AdRight
        )
        foreach ($Item in $AllLocalGroupVariables) {
            $GroupName = Get-AdObjectType -Identity $Item
            if ($null -ne $Item) {
                [void]$ArrayList.Add($GroupName)
            } else {
                Write-Error -Message ('Group not found: {0}' -f $Item)
            } #end If GroupName
        } #end ForEach

        # Build OU paths using string format for consistency
        [string]$ItAdminOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminOU.name, $Variables.AdDn)
        [string]$ItAdminAccountsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminAccountsOU.name, $ItAdminOuDn)
        [string]$ItAdminGroupsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminGroupsOU.name, $ItAdminOuDn)
        [string]$ItPrivGroupsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItPrivGroupsOU.name, $ItAdminOuDn)
        [string]$ItRightsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItRightsOU.name, $ItAdminOuDn)
        [string]$ItAdminSrvGroupsOUDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItAdminSrvGroupsOU.name, $ItAdminOuDn)

        [string]$ItInfraT0OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItInfraT0OU.name, $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)
        [string]$ItInfraT1OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItInfraT1OU.name, $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)
        [string]$ItInfraT2OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItInfraT2OU.name, $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)
        [string]$ItInfraStagingOuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItInfraStagingOU.name, $ConfXML.n.Admin.OUs.ItInfraOU.name, $ItAdminOuDn)

        [string]$ItPawT0OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItPawT0OU.name, $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)
        [string]$ItPawT1OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItPawT1OU.name, $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)
        [string]$ItPawT2OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItPawT2OU.name, $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)
        [string]$ItPawStagingOuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItPawStagingOU.name, $ConfXML.n.Admin.OUs.ItPawOU.name, $ItAdminOuDn)

        [string]$DCsOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.DCsOU.name, $Variables.AdDn)
        [string]$ItQuarantinePcOuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItQuarantinePcOU.name, $Variables.AdDn)

        [string]$ItSAT0OuDn = ('OU={0},OU={1},{2}' -f $ConfXML.n.Admin.OUs.ItSAT0OU.name, $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name, $ItAdminOuDn)
        [string]$ItSAT1OuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItSAT1OU.name, $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name, $ItAdminOuDn)
        [string]$ItSAT2OuDn = ('OU={0},{1}' -f $ConfXML.n.Admin.OUs.ItSAT2OU.name, $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name, $ItAdminOuDn)

        Write-Verbose -Message 'Starting the Tier0 delegation process...'
    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Active Directory Security', 'Delegate Rights and Permissions to Tier0 Admin area')) {

            # Computer objects within this area MUST have read access, otherwise GPO will not apply

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



            # todo: Check a possible error involving EguibarIT.DelegationPS\Private\Set-AclConstructor4.ps1:275
            # DC_Management - Domain Controllers Management
            Write-Verbose -Message 'Granting permissions Domain Controllers OU'
            Set-AdAclDelegateComputerAdmin -Group $SL_DcManagement -LDAPpath $DCsOuDn

            # DC_Management - Service Control Management (Permission to services)
            Add-GroupToSCManager -Group $SL_DcManagement -verbose

            # todo: fix errors due to access denied.
            # DC_Management - Give permissions on each service
            $AllServices = Get-Service -ErrorAction SilentlyContinue
            Foreach ($item in $AllServices) {

                # try to make the change
                try {
                    Write-Verbose -Message ('Granting permissions to service: {0}' -f $item.Name)
                    Add-ServiceAcl -Group $SL_DcManagement -Service $Item.Name -verbose
                } catch {
                    Write-Error -Message ('Error granting permissions to service: {0}' -f $item.Name)
                } #end Try-Catch
            } #end Foreach service



            # PSAM - Privileged Service Account Management -
            # Create/Delete Managed Service Accounts & Standard user service accounts
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
            Set-AdAclCreateDeleteGPO -Group $SL_GpoAdminRight -Confirm:$false
            # Link existing GPOs to OUs
            Set-AdAclLinkGPO -Group $SL_GpoAdminRight
            # Change GPO options
            Set-AdAclGPoption -Group $SL_GpoAdminRight




            # todo: error while trying to change object. Access denied.
            # Set-Acl: C:\Program Files\PowerShell\Modules\EguibarIT.DelegationPS\Private\Set-AclConstructor4.ps1:275
            # Delegate Directory Replication Rights
            Write-Error -Message 'Error while trying to change Directory Replication Rights. Access denied.'
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

        } #end If ShouldProcess

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Delegate Rights and Permissions to Tier0 Admin area.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function New-Tier0Delegation
