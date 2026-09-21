function New-DHCPobject {
    <#
        .SYNOPSIS
            Creates DHCP objects and delegations.

        .DESCRIPTION
            Creates the DHCP objects used to manage this organization by following the defined
            Delegation Model. Key features:
            - Creates DHCP-specific security groups
            - Configures DHCP server permissions
            - Delegates DHCP management rights

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the configuration XML file.
            The XML file must contain required naming conventions and OU structure.

        .EXAMPLE
            New-DHCPobject -ConfigXMLFile 'C:\PsScripts\Config.xml'

            Creates DHCP objects using the specified configuration file.

        .EXAMPLE
            New-DHCPobject -ConfigXMLFile 'C:\PsScripts\Config.xml' -Verbose

            Creates DHCP objects with verbose output.

        .EXAMPLE
            New-DHCPobject -ConfigXMLFile 'C:\PsScripts\Config.xml' -WhatIf

            Shows what would happen when creating DHCP objects.
        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Get-FunctionDisplay                    ║ EguibarIT
                Add-AdGroupNesting                     ║ EguibarIT
                New-AdDelegatedGroup                   ║ EguibarIT
                Import-MyModule                        ║ EguibarIT
                Set-AdAclFullControlDHCP               ║ EguibarIT.DelegationPS
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    21/Sep/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/New-DhcpObject.ps1

        .INPUTS
            [System.String]
            You can pipe the path to the XML configuration file to this function.

        .OUTPUTS
            [void]
            This function does not return any output.

        .COMPONENT
            Active Directory

        .ROLE
            Infrastructure Administration

        .FUNCTIONALITY
            DHCP Object Management
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param
    (
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0)]
        [string]
        $ConfigXMLFile
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

        Import-MyModule 'ActiveDirectory' -Verbose:$false
        Import-MyModule 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

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

        $parameters = $null


        # Organizational Units Distinguished Names

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $Variables.AdDn

        # It Privileged Groups OU
        $ItPGOu = $confXML.n.Admin.OUs.ItPrivGroupsOU.name
        # It Privileged Groups OU Distinguished Name
        $ItPGOuDn = 'OU={0},{1}' -f $ItPGOu, $ItAdminOuDn

        # It Admin Rights OU
        $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

    } #end Begin

    process {
        if ($PSCmdlet.ShouldProcess('Active Directory', 'Create DHCP objects and delegations')) {
            ###############################################################################
            # Create OU Admin groups
            $parameters = @{
                Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.DHCPAdmins.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = $confXML.n.AdminXtra.GG.DHCPAdmins.DisplayName
                Path                          = $ItPGOuDn
                Description                   = $confXML.n.AdminXtra.GG.DHCPAdmins.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $SG_DHCPAdmins = New-AdDelegatedGroup @parameters

            $parameters = @{
                Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.DHCPRight.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = $confXML.n.AdminXtra.LG.DHCPRight.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = $confXML.n.AdminXtra.LG.DHCPRight.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $SL_DHCPRight = New-AdDelegatedGroup @parameters

            # Apply the PSO to the SL_DfsRights and SG_DfsAdmin Group
            Add-ADFineGrainedPasswordPolicySubject -Identity $confXML.n.Admin.PSOs.ItAdminsPSO.Name -Subjects $SG_DHCPAdmins, $SL_DHCPRight


            ###############################################################################
            # Nest Groups - Security for RODC
            # Avoid having privileged or semi-privileged groups copy to RODC

            Add-ADGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SG_DHCPAdmins, $SL_DHCPRight


            ###############################################################################
            # Nest Groups - Extend Rights through delegation model groups

            Add-AdGroupNesting -Identity $SL_DHCPRight -Members $SG_DHCPAdmins

            Add-AdGroupNesting -Identity $SG_DHCPAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AdAdmins.Name)


            ###############################################################################
            # START Delegation to SL_DHCPRight

            # Dynamic Host Configuration Protocol (DHCP)
            Set-AdAclFullControlDHCP -Group $SL_DHCPRight.SamAccountName

        } #end If ShouldProcess
    } #end Process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'creating DHCP objects and Delegations.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
