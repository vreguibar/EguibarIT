Function New-LAPSobject {
    <#
        .SYNOPSIS
            Configures and manages Local Administrator Password Solution (LAPS) objects and delegations in Active Directory.

        .DESCRIPTION
            This function provides comprehensive LAPS configuration and management capabilities:

            Key Features:
            - Extends AD schema for LAPS if not already configured
            - Creates and configures LAPS delegations across all infrastructure tiers
            - Sets up tiered PAW (Privileged Access Workstation) LAPS permissions
            - Implements site-specific LAPS delegations
            - Supports bulk operations for multiple OUs
            - Provides detailed logging and error handling

            The function follows Microsoft's tiered administration model:
            - Tier 0: Domain Controllers and critical infrastructure
            - Tier 1: Member servers and infrastructure services
            - Tier 2: User workstations and devices

            Prerequisites:
            - Active Directory PowerShell module
            - LAPS PowerShell module
            - Schema Admin rights (for initial setup)
            - Enterprise Admin rights (for delegation setup)
            - Valid configuration XML file

            Configuration Requirements:
            The XML file must contain:
            - Naming conventions for groups and OUs
            - Tier definitions and delegations
            - Site-specific configurations
            - Security group mappings

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo]
            Full path to the configuration XML file containing LAPS settings.

            The XML file must include:
            - Group naming conventions
            - OU structure definitions
            - Security principal mappings
            - Tier-specific configurations

            Default value: 'C:\PsScripts\Config.xml'

            Validation:
            - Must exist and be accessible
            - Must contain valid XML structure
            - Must include required configuration elements

        .EXAMPLE
            New-LAPSobject -ConfigXMLFile 'C:\Config\Enterprise.xml' -Verbose

            Description:
            Configures LAPS using production configuration file:
            1. Validates XML configuration
            2. Extends schema if needed
            3. Creates tier-specific delegations
            4. Sets up PAW permissions
            5. Configures site-level access

        .EXAMPLE
            $params = @{
                ConfigXMLFile = 'D:\Scripts\Config.xml'
            }
            New-LAPSobject @params -WhatIf

            Shows what changes would be made using specified config file.

        .OUTPUTS
            [void]
            This function does not generate any output.
            Use -Verbose for detailed progress information.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬════════════════════════
                Import-MyModule                        ║ EguibarIT
                Get-FunctionDisplay                    ║ EguibarIT
                Set-AdAclLaps                          ║ EguibarIT.DelegationPS
                Get-ADGroup                            ║ ActiveDirectory
                Get-ADOrganizationalUnit               ║ ActiveDirectory
                Add-ADGroupMember                      ║ ActiveDirectory
                Remove-ADGroupMember                   ║ ActiveDirectory
                Update-LapsADSchema                    ║ LAPS
                New-Variable                           ║ Microsoft.PowerShell.Utility
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Debug                            ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility
                Test-Path                              ║ Microsoft.PowerShell.Management
                Get-Content                            ║ Microsoft.PowerShell.Management
                Get-Variable                           ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:   31/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .LINK
            https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/local-administrator-password-solution-laps-implementation-hints-and/ba-p/258019

        .LINK
            https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview

        .LINK
            https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material

    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([void])]

    Param
    (
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0)]
        [ValidateScript(
            { Test-Path $_ },
            ErrorMessage = 'Config file not found or not accessible: {0}'
        )]
        [PSDefaultValue(Help = 'Default Value is "C:\PsScripts\Config.xml"')]
        [System.IO.FileInfo]
        $ConfigXMLFile = 'C:\PsScripts\Config.xml'
    )

    Begin {
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

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false
        Import-MyModule -Name 'LAPS' -Verbose:$false

        ##############################
        # Variables Definition

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        try {
            # Check if Config.xml file is loaded. If not, proceed to load it.
            If (-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If (Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                    Write-Debug -Message 'Successfully loaded configuration XML'
                } #end if
            } #end if
        } catch {
            Write-Error -Message 'Error when reading XML file'
            throw
        }

        If (-Not (Test-Path -Path variable:NC)) {
            # Naming conventions hashtable
            $NC = @{'sl' = $confXML.n.NC.LocalDomainGroupPreffix
                'sg'     = $confXML.n.NC.GlobalGroupPreffix
                'su'     = $confXML.n.NC.UniversalGroupPreffix
                'Delim'  = $confXML.n.NC.Delimiter
                'T0'     = $confXML.n.NC.AdminAccSufix0
                'T1'     = $confXML.n.NC.AdminAccSufix1
                'T2'     = $confXML.n.NC.AdminAccSufix2
            }
        }
        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0

        $securityGroups = @{
            'SL_InfraRight'  = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraRight.Name
            'SL_PISM'        = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PISM.Name
            'SL_PAWM'        = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PAWM.Name
            'SL_SvrAdmRight' = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name
        }

        foreach ($group in $securityGroups.GetEnumerator()) {
            if (-not (Test-Path -Path variable:$($group.Key))) {
                New-Variable -Name $group.Key -Value (Get-ADGroup -Identity $group.Value) -ErrorAction Stop
            } #end If
        } #end Foreach




        # Organizational Units Distinguished Names

        # IT Admin OU
        If (-Not (Test-Path -Path variable:ItAdminOu)) {
            $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        }
        # IT Admin OU Distinguished Name
        If (-Not (Test-Path -Path variable:ItAdminOuDn)) {
            New-Variable -Name 'ItAdminOuDn' -Value ('OU={0},{1}' -f $ItAdminOu, $Variables.AdDn) -Option ReadOnly -Force
        }

        # Servers OU
        If (-Not (Test-Path -Path variable:ServersOu)) {
            $ServersOu = $confXML.n.Servers.OUs.ServersOU.name
        }
        # Servers OU Distinguished Name
        If (-Not (Test-Path -Path variable:ServersOuDn)) {
            $ServersOuDn = 'OU={0},{1}' -f $ServersOu, $Variables.AdDn
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
        $SitesOuDn = 'OU={0},{1}' -f $SitesOu, $Variables.AdDn

        #endregion Declarations

        # Check if schema is extended for LAPS. Extend it if not.
        Write-Debug -Message 'Checking LAPS schema configuration'
        Try {

            if ($null -eq $Variables.GuidMap['msLAPS-Password']) {

                if ($PSCmdlet.ShouldProcess('AD Schema', 'Extend for LAPS')) {

                    Write-Verbose -Message '
                    LAPS is NOT supported on this environment.
                    Proceeding to configure it by extending the Schema.'

                    # Temporarily add to Schema Admins if needed
                    $isSchemaAdmin = (Get-ADUser $env:UserName -Properties memberof).memberof -like 'CN=Schema Admins*'
                    if (-not $isSchemaAdmin) {
                        Write-Verbose -Message 'Member is not a Schema Admin... adding it.'
                        Add-ADGroupMember -Identity 'Schema Admins' -Members $env:username
                    }#end if

                    # Modify Schema
                    try {

                        Write-Verbose -Message 'Extending AD schema for LAPS...!'

                        Update-LapsADSchema -Confirm:$false -Verbose

                    } catch {

                        Write-Error -Message ('Failed to extend schema: {0}' -f $_.Exception.Message)
                        throw

                    } finally {

                        # If Schema extension OK, remove user from Schema Admin
                        if (-not $isSchemaAdmin) {
                            Remove-ADGroupMember -Identity 'Schema Admins' -Members $env:username -Confirm:$false
                        }
                    } #end Try-Catch-Finally


                }#end if
            }#end if
        }#end try
        catch {
            Write-Error -Message 'Error when trying to update LAPS schema'
            throw
        } Finally {
            Write-Verbose -Message 'Schema was extended successfully for LAPS.'
        }#end finally
    } #end Begin

    Process {
        # Make Infrastructure Servers modifications
        $Splat = @{
            ResetGroup = $SL_PISM.SamAccountName
            ReadGroup  = $SL_InfraRight.SamAccountName
        }
        Set-AdAclLaps @Splat -LDAPpath $ItInfraT0OUDN
        Set-AdAclLaps @Splat -LDAPpath $ItInfraT1OUDN
        Set-AdAclLaps @Splat -LDAPpath $ItInfraT2OUDN
        Set-AdAclLaps @Splat -LDAPpath $ItInfraStagingOUDN

        # Make PAW modifications
        $Splat = @{
            ResetGroup = $SL_PAWM.SamAccountName
            ReadGroup  = $SL_InfraRight.SamAccountName
        }
        Set-AdAclLaps @Splat -LDAPpath $ItPawT0OUDN
        Set-AdAclLaps @Splat -LDAPpath $ItPawT1OUDN
        Set-AdAclLaps @Splat -LDAPpath $ItPawT2OUDN
        Set-AdAclLaps @Splat -LDAPpath $ItPawStagingOUDN

        # Make Servers Modifications
        Set-AdAclLaps -ResetGroup $SL_SvrAdmRight.SamAccountName -ReadGroup $SL_SvrAdmRight.SamAccountName -LDAPpath $ServersOuDn

        # Make Sites Modifications
        # Get the DN of 1st level OU underneath SERVERS area
        $Splat = @{
            Filter      = '*'
            SearchBase  = $SitesOuDn
            SearchScope = 'OneLevel'
        }
        $AllSubOu = Get-ADOrganizationalUnit @Splat | Select-Object -ExpandProperty DistinguishedName

        # Iterate through each sub OU and invoke delegation
        Foreach ($Item in $AllSubOu) {
            # Exclude _Global OU from delegation
            If (-not($item.Split(',')[0].Substring(3) -eq $confXML.n.Sites.OUs.OuSiteGlobal.name)) {

                # Get group who manages Desktops and Laptops
                $Id = ('{0}{1}{2}{1}{3}' -f $NC['sl'],
                    $NC['Delim'],
                    $confXML.n.Sites.LG.PcRight.Name,
                    ($item.Split(',')[0].Substring(3))
                )
                $CurrentGroup = (Get-ADGroup -Identity $Id).SamAccountName

                # Desktops
                $Splat = @{
                    ResetGroup = $CurrentGroup.SamAccountName
                    ReadGroup  = $CurrentGroup.SamAccountName
                    LDAPpath   = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.Name, $Item
                }
                Set-AdAclLaps @Splat

                # Laptop
                $Splat = @{
                    ResetGroup = $CurrentGroup.SamAccountName
                    ReadGroup  = $CurrentGroup.SamAccountName
                    LDAPpath   = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Name, $Item
                }
                Set-AdAclLaps @Splat

            }
        }#end foreach
    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating LAPS and Delegations.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End

} #end Function New-LapsObject
