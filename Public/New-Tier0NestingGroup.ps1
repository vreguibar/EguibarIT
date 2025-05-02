function New-Tier0NestingGroup {

    <#
        .SYNOPSIS
            Creates and applies nesting for Tier0 administration groups.

        .DESCRIPTION
            This function establishes and configures the nested group structure required for Tier0 security model.
            It configures which accounts/groups are denied from being replicated to Read-Only Domain Controllers (RODC).
            It configures group nesting for built-in groups with the correct delegated rights groups.
            It extends rights through the delegation model by nesting security groups appropriately.

            The function relies on pre-existing group variables that must be defined before calling this function.

        .EXAMPLE
            New-Tier0NestingGroup

            Creates the nesting structure for Tier0 administration groups using existing group variables.

        .INPUTS
            None. This function does not accept pipeline input.

        .OUTPUTS
            None. This function does not generate any output.

        .NOTES
            Used Functions:
                Name                              ║ Module/Namespace
                ══════════════════════════════════╬══════════════════════════════
                Import-MyModule                   ║ EguibarIT
                Get-FunctionDisplay               ║ EguibarIT
                Add-AdGroupNesting                ║ EguibarIT
                Get-ADGroup                       ║ ActiveDirectory
                New-ADGroup                       ║ ActiveDirectory
                Write-Verbose                     ║ Microsoft.PowerShell.Utility
                Write-Error                       ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    29/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                           vicente@eguibar.com
                           Eguibar IT
                           http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Active Directory

        .ROLE
            Security Administration

        .FUNCTIONALITY
            Tier 0 Security Group Management
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.Void])]

    param ()

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
        Import-MyModule -Name 'EguibarIT' -Verbose:$false

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        $ArrayList = [System.Collections.ArrayList]::new()

        $AllGlobalGroupVariables = @(
            $DomainAdmins,
            $EnterpriseAdmins,
            $SG_InfraAdmins,
            $SG_AdAdmins,
            $SG_GpoAdmins,
            $SG_Tier0Admins,
            $SG_Tier1Admins,
            $SG_Tier2Admins,
            $SG_Operations,
            $SG_ServerAdmins,
            $SG_AllSiteAdmins,
            $SG_AllGALAdmins,
            $SG_GlobalUserAdmins,
            $SG_GlobalPcAdmins,
            $SG_GlobalGroupAdmins,
            $SG_ServiceDesk
        )

        $AllLocalGroupVariables = @(
            $SL_AdRight,
            $SL_InfraRight,
            $SL_DnsAdminRight,
            $SL_GpoAdminRight,
            $SL_PGM,
            $SL_PUM,
            $SL_GM,
            $SL_UM,
            $SL_PSAM,
            $SL_PAWM,
            $SL_PISM,
            $SL_SAGM,
            $SL_DcManagement,
            $SL_TransferFSMOright,
            $SL_PromoteDcRight,
            $SL_DirReplRight,
            $SL_SvrOpsRight,
            $SL_SvrAdmRight,
            $SL_GlobalGroupRight,
            $SL_GlobalAppAccUserRight
        )

    } #end Begin

    Process {

        # Avoid having privileged or semi-privileged groups copy to RODC
        if ($PSCmdlet.ShouldProcess('Nesting Denied RODC groups')) {

            Write-Verbose -Message 'Configuring groups denied replication to RODC...'

            $ArrayList.Clear()

            foreach ($Item in @($AllGlobalGroupVariables, $AllLocalGroupVariables)) {
                $GroupName = Get-AdObjectType -Identity $Item
                if ($null -ne $Item) {
                    [void]$ArrayList.Add($GroupName)
                } else {
                    Write-Error -Message ('Group not found: {0}' -f $Item)
                } #end If GroupName
            } #end ForEach
            # Add groups
            Add-AdGroupNesting -Identity $DeniedRODC -Members $ArrayList
            Write-Verbose -Message 'Successfully added groups to DeniedRODC'

            # Add Users
            $ArrayList.Clear()
            if ($null -ne $AdminName) {
                [void]$ArrayList.Add($AdminName)
            }
            if ($null -ne $NewAdminExists) {
                [void]$ArrayList.Add($NewAdminExists)
            }
            Add-AdGroupNesting -Identity $DeniedRODC -Members $ArrayList
            Write-Verbose -Message 'Successfully added admin users to DeniedRODC'

        } #end If ShouldProcess

        # Nest Groups - Delegate Rights through Builtin groups
        # https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups
        # http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/
        if ($PSCmdlet.ShouldProcess('Delegate rights through nesting Builtin groups')) {

            Write-Verbose -Message 'Configuring builtin group membership...'

            Add-AdGroupNesting -Identity $CryptoOperators -Members $SG_AdAdmins
            Add-AdGroupNesting -Identity $DnsAdmins -Members $SG_AdAdmins, $SG_Tier0Admins
            Add-AdGroupNesting -Identity $EvtLogReaders -Members $SG_AdAdmins, $SG_Operations
            Add-AdGroupNesting -Identity $NetConfOperators -Members $SG_AdAdmins, $SG_Tier0Admins
            Add-AdGroupNesting -Identity $PerfLogUsers -Members $SG_AdAdmins, $SG_Operations, $SG_Tier0Admins
            Add-AdGroupNesting -Identity $PerfMonitorUsers -Members $SG_AdAdmins, $SG_Operations, $SG_Tier0Admins
            Add-AdGroupNesting -Identity $RemoteDesktopUsers -Members $SG_AdAdmins
            Add-AdGroupNesting -Identity $ServerOperators -Members $SG_AdAdmins
            Add-AdGroupNesting -Identity $RemoteMngtUsers -Members $SG_AdAdmins, $SG_Tier0Admins

            # Create and configure WinRMRemoteWMIUsers group if it doesn't exist
            $RemoteWMI = Get-ADGroup -Filter { SamAccountName -like 'WinRMRemoteWMIUsers*' } -ErrorAction SilentlyContinue
            If (-not $RemoteWMI) {
                $Splat = @{
                    GroupScope    = 'DomainLocal'
                    GroupCategory = 'Security'
                    Name          = 'WinRMRemoteWMIUsers__'
                    Path          = $ItRightsOuDn
                }
                New-ADGroup @Splat
                $RemoteWMI = Get-ADGroup 'WinRMRemoteWMIUsers__'
                Write-Verbose -Message 'Created WinRMRemoteWMIUsers__ group'
            }
            Add-AdGroupNesting -Identity $RemoteWMI -Members $SG_AdAdmins, $SG_Tier0Admins

            # Configure Protected Users group membership
            # https://technet.microsoft.com/en-us/library/dn466518(v=ws.11).aspx
            $ArrayList.Clear()
            if ($null -ne $AdminName) {
                [void]$ArrayList.Add($AdminName)
            }
            if ($null -ne $NewAdminExists) {
                [void]$ArrayList.Add($NewAdminExists)
            }
            Add-AdGroupNesting -Identity $ProtectedUsers -Members @($ArrayList, $AllGlobalGroupVariables)

            Write-Verbose -Message 'Successfully configured builtin group membership'

        } #end If ShouldProcess

        # Nest Groups - Extend Rights through delegation model groups
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/
        if ($PSCmdlet.ShouldProcess('Extend Rights through delegation model group nesting')) {

            # InfraAdmins as member of InfraRight
            $Splat = @{
                Identity = $SL_InfraRight
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PUM
            $Splat = @{
                Identity = $SL_PUM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PGM
            $Splat = @{
                Identity = $SL_PGM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PISM
            $Splat = @{
                Identity = $SL_PISM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PAWM
            $Splat = @{
                Identity = $SL_PAWM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of PSAM
            $Splat = @{
                Identity = $SL_PSAM
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of Tier0Admins
            $Splat = @{
                Identity = $SG_Tier0Admins
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of DirReplRight
            $Splat = @{
                Identity = $SL_DirReplRight
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            # InfraAdmins as member of AdAdmins
            $Splat = @{
                Identity = $SG_AdAdmins
                Members  = $SG_InfraAdmins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured InfraAdmins nesting'


            # AdAdmins as member of AdRight
            $Splat = @{
                Identity = $SL_AdRight
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of UM
            $Splat = @{
                Identity = $SL_UM
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of GM
            $Splat = @{
                Identity = $SL_GM
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of GpoAdmins
            $Splat = @{
                Identity = $SG_GpoAdmins
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of AllSiteAdmins
            $Splat = @{
                Identity = $SG_AllSiteAdmins
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of ServerAdmins
            $Splat = @{
                Identity = $SG_ServerAdmins
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of DcManagement
            $Splat = @{
                Identity = $SL_DcManagement
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat

            # AdAdmins as member of Tier0Admins
            $Splat = @{
                Identity = $SG_Tier0Admins
                Members  = $SG_AdAdmins
            }
            Add-AdGroupNesting @Splat



            # Tier0Admins as member of DcManagement
            $Splat = @{
                Identity = $SL_DcManagement
                Members  = $SG_Tier0Admins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured Tier0Admins nesting'

            # GpoAdmins nesting
            $Splat = @{
                Identity = $SL_GpoAdminRight
                Members  = $SG_GpoAdmins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured GpoAdmins nesting'

            # AllSiteAdmins and AllGalAdmins nesting
            $Splat = @{
                Identity = $SG_AllGALAdmins
                Members  = $SG_AllSiteAdmins
            }
            Add-AdGroupNesting @Splat

            # AllGalAdmins as member of ServiceDesk
            $Splat = @{
                Identity = $SG_ServiceDesk
                Members  = $SG_AllGALAdmins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured AllSiteAdmins and AllGalAdmins nesting'


            # ServerAdmins as member of SvrAdmRight
            $Splat = @{
                Identity = $SL_SvrAdmRight
                Members  = $SG_ServerAdmins
            }
            Add-AdGroupNesting @Splat

            # Operations as member of SvrOpsRight
            $Splat = @{
                Identity = $SL_SvrOpsRight
                Members  = $SG_Operations
            }
            Add-AdGroupNesting @Splat

            # ServerAdmins as member of Operations
            $Splat = @{
                Identity = $SG_Operations
                Members  = $SG_ServerAdmins
            }
            Add-AdGroupNesting @Splat

            Write-Verbose -Message 'Successfully configured ServerAdmins and Operations nesting'

        } #end If ShouldProcess

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Nesting Tier0 Groups.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function New-Tier0NestingGroup
