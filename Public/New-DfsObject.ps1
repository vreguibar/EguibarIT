Function New-DfsObject {
    <#
        .Synopsis
            Create DFS Objects and Delegations
        .DESCRIPTION
            Create the DFS Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-DfsObjects -ConfigXMLFile 'C:\PsScripts\Config.xml'
        .PARAMETER ConfigXMLFile
            [String] Full path to the configuration.xml file
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Add-AdGroupNesting                     | EguibarIT
                Get-CurrentErrorToDisplay              | EguibarIT
                New-AdDelegatedGroup                   | EguibarIT
                Set-AdAclFullControlDFS                | EguibarIT.DelegationPS
                Add-ADFineGrainedPasswordPolicySubject | ActiveDirectory
        .NOTES
            Version:         1.3
            DateModified:    01/Feb/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param(
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
        Import-MyModule -name ActiveDirectory -Verbose:$false
        Import-MyModule -name EguibarIT.DelegationPS -Verbose:$false

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

        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        #endregion Declarations
        ################################################################################
    }
    Process {
        # Check if feature is installed, if not then proceed to install it.
        If (-not((Get-WindowsFeature -Name FS-DFS-Namespace).Installed)) {
            Install-WindowsFeature -Name FS-DFS-Namespace -IncludeAllSubFeature
        }
        If (-not((Get-WindowsFeature -Name FS-DFS-Replication).Installed)) {
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
        Add-ADFineGrainedPasswordPolicySubject -Identity $confXML.n.Admin.PSOs.ItAdminsPSO.Name -Subjects $SG_DfsAdmins, $SL_DfsRight


        ###############################################################################
        # Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Add-ADGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SG_DfsAdmins, $SL_DfsRight


        ###############################################################################
        # Nest Groups - Extend Rights through delegation model groups

        Add-AdGroupNesting -Identity $SL_DfsRight -Members $SG_DfsAdmins

        Add-AdGroupNesting -Identity $SG_DfsAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AdAdmins.Name)

        ###############################################################################
        # START Delegation to SL_InfraRights group on ADMIN area

        # Distributed File System
        # Full control over DFS-Configuration & DFSR-GlobalSettings
        Set-AdAclFullControlDFS -Group $SL_DfsRight.SamAccountName
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) created DFS objects and Delegations successfully."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
