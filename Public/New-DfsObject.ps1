function New-DfsObject {
    <#
        .SYNOPSIS
            Creates Distributed File System (DFS) objects and delegations.

        .DESCRIPTION
            Creates the DFS objects used to manage this organization by following the defined
            Delegation Model. Key features:
            - Creates DFS-specific security groups
            - Configures DFS namespace permissions
            - Delegates DFS management rights

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the configuration XML file.
            The XML file must contain required naming conventions and OU structure.

        .EXAMPLE
            New-DfsObject -ConfigXMLFile 'C:\PsScripts\Config.xml'

            Creates DFS objects using the specified configuration file.

        .EXAMPLE
            New-DfsObject -ConfigXMLFile 'C:\PsScripts\Config.xml' -Verbose

            Creates DFS objects with verbose output.

        .EXAMPLE
            New-DfsObject -ConfigXMLFile 'C:\PsScripts\Config.xml' -WhatIf

            Shows what would happen when creating DFS objects.
        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Get-FunctionDisplay                    ║ EguibarIT
                Add-AdGroupNesting                     ║ EguibarIT
                New-AdDelegatedGroup                   ║ EguibarIT
                Import-MyModule                        ║ EguibarIT
                Set-AdAclFullControlDFS                ║ EguibarIT.DelegationPS
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.4
            DateModified:    21/Sep/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/New-DfsObject.ps1

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
            DFS Object Management
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param(
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
        } #end if

        ##############################
        # Module imports

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        try {
            # Check if Config.xml file is loaded. if not, proceed to load it.
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

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    } #end begin

    process {
        if ($PSCmdlet.ShouldProcess('Active Directory', 'Create DFS objects and delegations')) {
            # Check if feature is installed, if not then proceed to install it.
            if (-not((Get-WindowsFeature -Name FS-DFS-Namespace).Installed)) {
                Install-WindowsFeature -Name FS-DFS-Namespace -IncludeAllSubFeature
            }
            if (-not((Get-WindowsFeature -Name FS-DFS-Replication).Installed)) {
                Install-WindowsFeature -Name FS-DFS-Replication -IncludeAllSubFeature
            }

            ###############################################################################
            # Create OU Admin groups
            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.DfsAdmins.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = $confXML.n.AdminXtra.GG.DfsAdmins.DisplayName
                Path                          = $ItPGOuDn
                Description                   = $confXML.n.AdminXtra.GG.DfsAdmins.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $SG_DfsAdmins = New-AdDelegatedGroup @Splat

            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.DfsRight.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = $confXML.n.AdminXtra.LG.DfsRight.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = $confXML.n.AdminXtra.LG.DfsRight.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $SL_DfsRight = New-AdDelegatedGroup @Splat

            # Apply the PSO to the SL_DfsRights and SG_DfsAdmin Group
            $Splat = @{
                Identity = $confXML.n.Admin.PSOs.ItAdminsPSO.Name
                Subjects = $SG_DfsAdmins, $SL_DfsRight
            }
            Add-ADFineGrainedPasswordPolicySubject @Splat


            ###############################################################################
            # Nest Groups - Security for RODC
            # Avoid having privileged or semi-privileged groups copy to RODC

            Add-ADGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SG_DfsAdmins, $SL_DfsRight


            ###############################################################################
            # Nest Groups - Extend Rights through delegation model groups

            $Splat = @{
                Identity = $SL_DfsRight
                Members  = $SG_DfsAdmins
            }
            Add-AdGroupNesting @Splat

            $Splat = @{
                Identity = $SG_DfsAdmins
                Members  = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AdAdmins.Name)
            }
            Add-AdGroupNesting @Splat

            ###############################################################################
            # START Delegation to SL_InfraRights group on ADMIN area

            # Distributed File System
            # Full control over DFS-Configuration & DFSR-GlobalSettings
            Set-AdAclFullControlDFS -Group $SL_DfsRight.SamAccountName
        } #end if ShouldProcess
    } #end process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'creating DFS objects and Delegations.'
        )
        Write-Verbose -Message $txt
    } #end end
} #end function
