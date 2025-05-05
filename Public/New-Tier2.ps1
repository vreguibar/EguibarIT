function New-Tier2 {

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

        if ($PSCmdlet.ShouldProcess('Create Tier2 Organizational Units')) {


            New-DelegateAdOU -ouName $SitesOu -ouPath $Variables.AdDn -ouDescription $confXML.n.Sites.OUs.SitesOU.Description

            # Create Global OU within SITES area
            $Splat = @{
                ouName        = $SitesGlobalOu
                ouPath        = $SitesOuDn
                ouDescription = $confXML.n.Sites.OUs.OuSiteGlobal.Description
            }
            New-DelegateAdOU @Splat

            $Splat = @{
                ouName        = $SitesGlobalGroupOu
                ouPath        = $SitesGlobalOuDn
                ouDescription = $confXML.n.Sites.OUs.OuSiteGlobalGroups.Description
            }
            New-DelegateAdOU @Splat

            $Splat = @{
                ouName        = $SitesGlobalAppAccUserOu
                ouPath        = $SitesGlobalOuDn
                ouDescription = $confXML.n.Sites.OUs.OuSiteGlobalAppAccessUsers.Description
            }
            New-DelegateAdOU @Splat

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier2 Baseline GPOs')) {

            # Create basic GPO for Users and Computers
            $Splat = @{
                gpoDescription = '{0}-Baseline' -f $SitesOu
                gpoLinkPath    = $SitesOuDn
                GpoAdmin       = $sl_GpoAdminRight
                gpoBackupPath  = Join-Path -Path $DMScripts -ChildPath 'SecTmpl' -Resolve
            }
            New-DelegateAdGpo @Splat -gpoScope 'C' -gpoBackupID $confXML.n.Sites.OUs.OuSiteComputer.backupID
            New-DelegateAdGpo @Splat -gpoScope 'U' -gpoBackupID $confXML.n.Sites.OUs.OuSiteUser.backupID

        } #end If ShouldProcess

        if ($PSCmdlet.ShouldProcess('Create Tier2 GPO Restrictions')) {

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
            if ($null -ne $SG_Tier1Admins) {
                [void]$DenyLogon.Add($SG_Tier1Admins)
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
            if ($null -ne $SG_Tier2Admins) {
                [void]$ArrayList.Add($SG_Tier2Admins)
            }
            $Splat = @{
                GpoToModify                = 'C-{0}-Baseline' -f $SitesOu
                DenyInteractiveLogon       = $DenyLogon
                DenyRemoteInteractiveLogon = $DenyLogon
                DenyBatchLogon             = @($SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount)
                DenyServiceLogon           = @($SG_Tier0ServiceAccount, $SG_Tier1ServiceAccount)
                BatchLogon                 = $SG_Tier2ServiceAccount
                ServiceLogon               = $SG_Tier2ServiceAccount
                InteractiveLogon           = $SG_Tier2Admins
                RemoteInteractiveLogon     = $SG_Tier2Admins
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

        if ($PSCmdlet.ShouldProcess('Create Tier2 Delegations')) {

            # Sites OU
            # Create/Delete OUs within Sites
            Set-AdAclCreateDeleteOU -Group $SL_InfraRight -LDAPpath $SitesOuDn

            # Sites OU
            # Change OUs
            Set-AdAclChangeOU -Group $SL_AdRight -LDAPpath $SitesOuDn


            Write-Verbose -Message 'START APPLICATION ACCESS USER Global Delegation'

            # USER Site Administrator Delegation
            $Splat = @{
                Group    = $SL_GlobalAppAccUserRight
                LDAPPath = $SitesGlobalAppAccUserOuDn
            }
            Set-AdAclDelegateUserAdmin @Splat

            #### GAL
            Set-AdAclDelegateGalAdmin @Splat

            Add-AdGroupNesting -Identity $SL_GlobalAppAccUserRight -Members $SG_GlobalUserAdmins



            Write-Verbose -Message 'START GROUP Global Delegation'

            # Create/Delete Groups
            Set-AdAclCreateDeleteGroup -Group $SL_GlobalGroupRight -LDAPpath $SitesGlobalGroupOuDn

            # Nest groups
            Add-AdGroupNesting -Identity $SL_GlobalGroupRight -Members $SG_GlobalGroupAdmins

            #### GAL

            # Change Group Properties
            Set-AdAclChangeGroup -Group $SL_GlobalGroupRight -LDAPpath $SitesGlobalGroupOuDn

        } #end If ShouldProcess

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating Tier2 objects.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function New-Tier2
