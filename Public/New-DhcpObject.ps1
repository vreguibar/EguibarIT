Function New-DHCPobject {
    <#
        .Synopsis
            Create DHCP Objects and Delegations
        .DESCRIPTION
            Create the DHCP Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-DHCPobjects
        .EXAMPLE
            New-DfsObjects -ConfigXMLFile 'C:\PsScripts\Config.xml'
        .PARAMETER ConfigXMLFile
            [String] Full path to the configuration.xml file
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Add-AdGroupNesting                     | EguibarIT
                Get-CurrentErrorToDisplay              | EguibarIT
                New-AdDelegatedGroup                   | EguibarIT
                Set-AdAclFullControlDHCP               | EguibarIT.DelegationPS
                Add-ADFineGrainedPasswordPolicySubject | ActiveDirectory
        .NOTES
            Version:         1.0
            DateModified:    29/Oct/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
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
        [string]
        $ConfigXMLFile
    )

    Begin {
        $error.Clear()

        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-Module ActiveDirectory -SkipEditionCheck -Force -Verbose:$false | Out-Null
        Import-Module EguibarIT.DelegationPS -SkipEditionCheck -Force -Verbose:$false | Out-Null

        ##############################
        # Variables Definition

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

    Process {
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

    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'creating DHCP objects and Delegations.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
