function New-Tier1 {

    <#
        .SYNOPSIS


        .DESCRIPTION


        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml
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
        [PSDefaultValue(
            Help = 'Default Value is "C:\PsScripts\"',
            Value = 'C:\PsScripts\'
        )]
        [Alias('ScriptPath')]
        [string]
        $DMScripts = 'C:\PsScripts\'

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

        Import-MyModule -Name 'ServerManager' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        $ArrayList = [System.Collections.ArrayList]::New()

        $DenyLogon = [System.Collections.Generic.List[object]]::New()

        # Load the XML configuration file
        try {
            $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message "Error reading XML file: $($_.Exception.Message)"
            throw
        } #end Try-Catch

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Create Tier1 Organizational Units')) {

            # Create Servers and Sub OUs
            $Splat = @{
                ouName        = $ServersOu
                ouPath        = $Variables.AdDn
                ouDescription = $confXML.n.Servers.OUs.ServersOU.Description
            }
            New-DelegateAdOU @Splat

            # Create Sub-OUs for Servers
            $Splat = @{
                ouPath = $ServersOuDn
            }

            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.ApplicationOU.Name
                ouDescription = $confXML.n.Servers.OUs.ApplicationOU.Description
            }
            New-DelegateAdOU @Splat @Splat1
            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.FileOU.Name
                ouDescription = $confXML.n.Servers.OUs.FileOU.Description
            }
            New-DelegateAdOU @Splat @Splat1
            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.HypervOU.Name
                ouDescription = $confXML.n.Servers.OUs.HypervOU.Description
            }
            New-DelegateAdOU @Splat @Splat1
            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.LinuxOU.Name
                ouDescription = $confXML.n.Servers.OUs.LinuxOU.Description
            }
            New-DelegateAdOU @Splat @Splat1
            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.RemoteDesktopOU.Name
                ouDescription = $confXML.n.Servers.OUs.RemoteDesktopOU.Description
            }
            New-DelegateAdOU @Splat @Splat1
            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.SqlOU.Name
                ouDescription = $confXML.n.Servers.OUs.SqlOU.Description
            }
            New-DelegateAdOU @Splat @Splat1
            $Splat1 = @{
                ouName        = $confXML.n.Servers.OUs.WebOU.Name
                ouDescription = $confXML.n.Servers.OUs.WebOU.Description
            }
            New-DelegateAdOU @Splat @Splat1

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier1 Baseline GPOs')) {

            # Create basic GPO for Servers
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $ServersOu
                gpoScope       = $confXML.n.Admin.GPOs.ServersBaseline.Scope
                gpoLinkPath    = $ServersOuDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupId    = $confXML.n.Admin.GPOs.ServersBaseline.backupID
                gpoBackupPath  = Join-Path -Path $DMScripts -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat

            # Create basic GPOs for different types under Servers
            $Splat = @{
                gpoScope      = 'C'
                GpoAdmin      = $sl_GpoAdminRight
                gpoBackupPath = Join-Path -Path $DMScripts -ChildPath 'SecTmpl' -Resolve
            }

            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.ApplicationOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.ApplicationOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.FileOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.FileOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.HypervOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.HypervOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.RemoteDesktopOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.RemoteDesktopOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.SqlOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.SqlOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1
            $Splat1 = @{
                gpoDescription = ('{0}-Baseline' -f $confXML.n.Servers.OUs.WebOU.Name)
                gpoLinkPath    = ('OU={0},{1}' -f $confXML.n.Servers.OUs.WebOU.Name, $ServersOuDn)
            }
            New-DelegateAdGpo @Splat @Splat1

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier1 GPO Restrictions')) {

            # Access this computer from the network / Deny Access this computer from the network
            # Not Defined

            # Allow Logon Locally / Allow Logon throug RDP/TerminalServices / Logon as a Batch job / Logon as a Service
            # Deny Allow Logon Locally / Deny Allow Logon throug RDP/TerminalServices / Deny Logon as a Batch job / Deny Logon as a Service
            $DenyLogon.Clear()
            [void]$DenyLogon.Add($SchemaAdmins)
            [void]$DenyLogon.Add($EnterpriseAdmins)
            [void]$DenyLogon.Add($DomainAdmins)
            [void]$DenyLogon.Add($Administrators)
            [void]$DenyLogon.Add($AccountOperators)
            [void]$DenyLogon.Add('Backup Operators')
            [void]$DenyLogon.Add('Print Operators')
            [void]$DenyLogon.Add($ServerOperators)
            if ($null -ne $AdminName) {
                [void]$DenyLogon.Add($AdminName)
            }
            if ($null -ne $NewAdminExists) {
                [void]$DenyLogon.Add($NewAdminExists)
            }
            if ($null -ne $SG_Tier0Admins) {
                [void]$DenyLogon.Add($SG_Tier0Admins)
            }
            if ($null -ne $SG_Tier2Admins) {
                [void]$DenyLogon.Add($SG_Tier2Admins)
            }


            # Back up files and directories / Bypass traverse checking / Create Global Objects / Create symbolic links
            # Change System Time / Change Time Zone / Force shutdown from a remote system
            # Create Page File / Enable computer and user accounts to be trusted for delegation
            # Impersonate a client after authentication / Load and unload device drivers
            # Increase scheduling priority / Manage auditing and security log
            # Modify firmware environment values / Perform volume maintenance tasks
            # Profile single process / Profile system performance / Restore files and directories
            # Shut down the system / Take ownership of files or other objects
            $ArrayList.Clear()
            [void]$ArrayList.Add($Administrators)
            if ($null -ne $SG_Tier1Admins) {
                [void]$ArrayList.Add($SG_Tier1Admins)
            }
            $Splat = @{
                GpoToModify                = 'C-{0}-Baseline' -f $ServersOu
                BatchLogon                 = $SG_Tier1ServiceAccount
                ServiceLogon               = $SG_Tier1ServiceAccount
                InteractiveLogon           = $SG_Tier1Admins
                RemoteInteractiveLogon     = $SG_Tier1Admins
                DenyInteractiveLogon       = $DenyLogon
                DenyRemoteInteractiveLogon = $DenyLogon
                DenyBatchLogon             = @($SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount)
                DenyServiceLogon           = @($SG_Tier0ServiceAccount, $SG_Tier2ServiceAccount)
                Backup                     = $ArrayList
                MachineAccount             = $ArrayList
                CreateGlobal               = @($ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE')
                Systemtime                 = @($ArrayList, 'LOCAL SERVICE')
                TimeZone                   = $ArrayList
                CreatePagefile             = $ArrayList
                CreateSymbolicLink         = $ArrayList
                RemoteShutDown             = $ArrayList
                Impersonate                = @($ArrayList, 'LOCAL SERVICE', 'NETWORK SERVICE', 'SERVICE')
                IncreaseBasePriority       = $ArrayList
                LoadDriver                 = $ArrayList
                AuditSecurity              = $ArrayList
                SystemEnvironment          = $ArrayList
                ManageVolume               = $ArrayList
                ProfileSingleProcess       = $ArrayList
                SystemProfile              = $ArrayList
                Restore                    = $ArrayList
                Shutdown                   = $ArrayList
                TakeOwnership              = $ArrayList
            }
            Set-GpoPrivilegeRight @Splat

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier1 Delegations')) {

            # Delegation to SL_SvrAdmRight and SL_SvrOpsRight groups to SERVERS area

            # Get the DN of 1st level OU underneath SERVERS area
            $Splat = @{
                Filter      = '*'
                SearchBase  = $ServersOuDn
                SearchScope = 'OneLevel'
            }
            $AllSubOu = Get-ADOrganizationalUnit @Splat | Select-Object -ExpandProperty DistinguishedName

            # Iterate through each sub OU and invoke delegation
            Foreach ($Item in $AllSubOu) {
                ###############################################################################
                # Delegation to SL_SvrAdmRight group to SERVERS area

                Set-AdAclDelegateComputerAdmin -Group $SL_SvrAdmRight -LDAPpath $Item

                ###############################################################################
                # Delegation to SL_SvrOpsRight group on SERVERS area

                # Change Public Info
                Set-AdAclComputerPublicInfo -Group $SL_SvrOpsRight -LDAPpath $Item

                # Change Personal Info
                Set-AdAclComputerPersonalInfo -Group $SL_SvrOpsRight -LDAPpath $Item

            }#end foreach

            # Create/Delete OUs within Servers
            Set-AdAclCreateDeleteOU -Group $SL_InfraRight -LDAPpath $ServersOuDn

            # Change OUs within Servers
            Set-AdAclChangeOU -Group $SL_AdRight -LDAPpath $ServersOuDn

        } #end If ShouldProcess

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating Tier1 objects.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function New-Tier1
