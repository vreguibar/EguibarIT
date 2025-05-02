function New-DelegateAdGpo {
    <#
        .Synopsis
             Creates and Links new GPO with delegated permissions.

        .DESCRIPTION
            Create new custom delegated GPO, Delegate rights to an existing group and links it to
            the given OU.Key features:
            - Creates new GPO or modifies existing one
            - Delegates permissions to specified security group
            - Links GPO to target OU
            - Optionally imports settings from GPO backup
            - Disables user or computer settings based on scope
            - Supports idempotent operations
            - Implements security best practices

        .PARAMETER gpoDescription
            [String] Description of the GPO. Used to build the name. Only Characters a-z A-Z.
            The final GPO name will be constructed as: [Scope]-[Description]

        .PARAMETER gpoScope
            [ValidateSet] Scope of the GPO:
            - U: User settings (disables computer configuration)
            - C: Computer settings (disables user configuration)

        .PARAMETER gpoLinkPath
            [String] Distinguished Name of the OU where the GPO will be linked.
            Must be a valid AD path (CN=,DC=)

        .PARAMETER GpoAdmin
            [String] Security group that will be delegated GPO edit rights.
            Group must exist in AD. Permissions granted: GpoEditDeleteModifySecurity

        .PARAMETER gpoBackupID
            [String] GUID of the GPO backup to import settings from.
            Only used when restoring from backup.

        .PARAMETER gpoBackupPath
            [String] File system path containing the GPO backup.
            Must be accessible and contain valid backup.

        .EXAMPLE
            New-DelegateAdGpo -gpoDescription MyNewGPO -gpoScope C -gpoLinkPath "OU=Servers,OU=eguibarit,OU=local" -GpoAdmin "SL_GpoRight"

        .EXAMPLE
            New-DelegateAdGpo -gpoDescription MyNewGPO -gpoScope C -gpoLinkPath "OU=Servers,OU=eguibarit,OU=local" -GpoAdmin "SL_GpoRight" -gpoBackupID '1D872D71-D961-4FCE-87E0-1CD368B5616F' -gpoBackupPath 'C:\PsScripts\Backups'

        .EXAMPLE
            $Splat = @{
                gpoDescription = 'MyNewGPO'
                gpoScope       = 'C'
                gpoLinkPath    = 'OU=Servers,OU=eguibarit,OU=local'
                GpoAdmin       = 'SL_GpoRight'
                gpoBackupID    = '1D872D71-D961-4FCE-87E0-1CD368B5616F'
                gpoBackupPath  = 'C:\PsScripts\Backups'
            }
            New-DelegateAdGpo @Splat

        .OUTPUTS
        [Microsoft.GroupPolicy.Gpo]
        Returns the created or modified GPO object.

        .NOTES
            Used Functions:
                Name                                  ║ Module/Namespace
                ══════════════════════════════════════╬══════════════════════════════
                Get-FunctionDisplay                   ║ EguibarIT
                Get-AdObjectType                      ║ EguibarIT
                Test-IsValidDN                        ║ EguibarIT
                Get-ADDomainController                ║ ActiveDirectory
                Get-GPO                               ║ GroupPolicy
                Import-GPO                            ║ GroupPolicy
                New-GPO                               ║ GroupPolicy
                New-GPLink                            ║ GroupPolicy
                Set-GPPermissions                     ║ GroupPolicy

        .NOTES
            Version:         1.3
        DateModified:   31/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
        https://github.com/vreguibar/EguibarIT

        .LINK
            https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmi_v2/class-library/gppermissiontype-enumeration-microsoft-grouppolicy

    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium',
        DefaultParameterSetName = 'DelegatedAdGpo'
    )]
    [OutputType([Object])]

    Param (
        # Param1 GPO description, used to generate name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Description of the GPO. Used to build the name (letters and numbers only).',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-zA-Z0-9]+$')]
        [string]
        $gpoDescription,

        # Param2 GPO scope. U = Users, C = Computers
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Scope of the GPO. U for Users and C for Computers DEFAULT is U. The non-used part of the GPO will get disabled',
            Position = 1)]
        [ValidateSet('U', 'C', ignorecase = $false)]
        [string]
        $gpoScope,

        # Param3 GPO Link to OU
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'DistinguishedName where to link the newly created GPO',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName', 'LDAPpath')]
        [string]
        $gpoLinkPath,

        # Param4 Domain Local Group with GPO Rights to be assigned
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Domain Local Group with GPO Rights to be assigned',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        $GpoAdmin,

        # Param5 Restore GPO settings from backup using the BackupID GUID
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Restore GPO settings from backup using the BackupID GUID',
            ParameterSetName = 'DelegatedAdGpo',
            Position = 4)]
        [Parameter(ParameterSetName = 'GpoBackup', Position = 4)]
        [Alias('BackupID')]
        [string]
        $gpoBackupID,

        # Param6 Path where Backups are stored
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path where Backups are stored',
            ParameterSetName = 'GpoBackup',
            Position = 5)]
        [ValidateScript(
            { Test-Path $_ },
            ErrorMessage = 'Backup path does not exist or is not accessible.')]
        [string]
        $gpoBackupPath

    )

    Begin {
        Set-StrictMode -Version Latest

        # Load GroupPolicy types
        Add-Type -AssemblyName 'Microsoft.GroupPolicy'

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
        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false

        ##############################
        # Variables Definition

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        #$gpoAlreadyExist = [Microsoft.GroupPolicy.GroupPolicyObject]::New()

        $gpoName = '{0}-{1}' -f $PSBoundParameters['gpoScope'], $PSBoundParameters['gpoDescription']

        $GpoAdmin = Get-ADObjectType -Identity $GpoAdmin

        try {

            [system.string]$dcServer = (Get-ADDomainController -Discover -Service 'PrimaryDC').HostName

        } catch {

            Write-Warning -Message 'Unable to locate primary domain controller'

        } #end Try-Catch

    } # End Begin Section

    Process {
        # Check if the GPO already exist
        $gpoAlreadyExist = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        Write-Debug -Message ('Checking for existing GPO: {0}' -f $gpoName)

        if (-not $gpoAlreadyExist) {

            Write-Verbose -Message ('Policy: Create policy object {0}' -f $gpoName)
            $Splat = @{
                Name    = $gpoName
                Comment = $gpoName
                Server  = $dcServer
            }
            if ($PSCmdlet.ShouldProcess("Creating GPO '$gpoName'", 'Confirm creation?')) {
                $gpoAlreadyExist = New-GPO @Splat
                Start-Sleep -Seconds 1
            } #end If

            # https://learn.microsoft.com/en-us/previous-versions/windows/desktop/wmi_v2/class-library/gppermissiontype-enumeration-microsoft-grouppolicy
            # Give Rights to SL_GpoAdminRight
            Write-Debug -Message ('Add GpoAdminRight to {0}' -f $gpoAlreadyExist.Name)
            $Splat = @{
                GUID            = $gpoAlreadyExist.Id
                PermissionLevel = 'GpoEditDeleteModifySecurity'
                TargetName      = $GpoAdmin.SamAccountName
                TargetType      = 'group'
                Server          = $dcServer
            }
            if ($PSCmdlet.ShouldProcess("Giving permissions to GPO '$gpoName'", 'Confirm giving permissions?')) {
                Set-GPPermissions @Splat
            }  #end If


            # Disable the corresponding Settings section of the GPO
            If ($gpoScope -eq 'C') {
                if ($PSCmdlet.ShouldProcess("Disabling Users section on GPO '$gpoName'", 'Confirm disabling user section?')) {

                    Write-Debug -Message ('Disable Policy User Settings on GPO {0}' -f $gpoAlreadyExist.Name)
                    $gpoAlreadyExist.GpoStatus = 'UserSettingsDisabled'

                } #end If

            } else {

                if ($PSCmdlet.ShouldProcess("Disabling Computers section on GPO '$gpoName'", 'Confirm disabling computer section?')) {

                    Write-Debug -Message ('Disable Policy Computer Settings on GPO {0}' -f $gpoAlreadyExist.Name)
                    $gpoAlreadyExist.GpoStatus = 'ComputerSettingsDisabled'

                } #end If
            } #end If-Else

            Write-Debug -Message 'Add GPO-link to corresponding OU'
            $Splat = @{
                GUID        = $gpoAlreadyExist.Id
                Target      = $PSBoundParameters['gpoLinkPath']
                LinkEnabled = 'Yes'
                Server      = $dcServer
            }
            if ($PSCmdlet.ShouldProcess("Linking GPO '$gpoName'", 'Link GPO?')) {

                New-GPLink @Splat

            } #end If

            # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
            # Adding settings
            #Write-Host "Setting Screen saver timeout to 15 minutes"
            #Set-GPRegistryValue -Name $gpoName -key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName ScreenSaveTimeOut -Type String -value 900

            #Write-Host "Enable Screen Saver"
            #Set-GPRegistryValue -Name $gpoName -key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName ScreenSaveActive -Type String -value 1

        } else {

            Write-Verbose -Message ('
                {0} Policy already exist.
                Changing Permissions and disabling corresponding settings (User or Computer).' -f
                $gpoName
            )

            # Give Rights to SL_GpoAdminRight
            Write-Debug -Message ('Add GpoAdminRight to {0}' -f $gpoName)
            $Splat = @{
                GUID            = $gpoAlreadyExist.Id
                PermissionLevel = 'GpoEditDeleteModifySecurity'
                TargetName      = $GpoAdmin.SamAccountName
                TargetType      = 'group'
                Server          = $dcServer
            }
            if ($PSCmdlet.ShouldProcess("Giving permissions to GPO '$gpoName'", 'Confirm giving permissions?')) {

                Set-GPPermissions @Splat

                # WmiFilterFullControl
                # StarterGpoFullControl
                # SomWmiFilterFullControl
                # SomCreateGpo
                # SomCreateStarterGpo
                # SomLogging
                # SomPlanning
                # SomLink

            }  #end If

            # Disable the corresponding Settings section of the GPO
            If ($gpoScope -eq 'C') {

                if ($PSCmdlet.ShouldProcess("Disabling Users section on GPO '$gpoName'", 'Confirm disabling user section?')) {

                    Write-Debug -Message 'Disable Policy User Settings'
                    $gpoAlreadyExist.GpoStatus = 'UserSettingsDisabled'

                } #end If
            } else {

                if ($PSCmdlet.ShouldProcess("Disabling Computers section on GPO '$gpoName'", 'Confirm disabling computer section?')) {

                    Write-Debug -Message 'Disable Policy Computer Settings'
                    $gpoAlreadyExist.GpoStatus = 'ComputerSettingsDisabled'

                } #end If
            } #end If-Else
        } # End If


        # Check if Backup needs to be imported
        if ($PSBoundParameters.ContainsKey('gpoBackupID') -and
            $PSBoundParameters.ContainsKey('gpoBackupPath')) {

            # Import the Backup
            Write-Debug -Message ('
                Importing GPO Backup {0}
                from path {1}
                to GPO {2}' -f
                $PSBoundParameters['gpoBackupID'], $PSBoundParameters['gpoBackupPath'], $gpoName
            )

            Try {
                $Splat = @{
                    BackupId   = $PSBoundParameters['gpoBackupID']
                    TargetGuid = $gpoAlreadyExist.Id
                    path       = $PSBoundParameters['gpoBackupPath']
                }
                if ($PSCmdlet.ShouldProcess("Importing GPO Backup '$gpoBackupID' to GPO '$gpoName'", 'Confirm import')) {

                    Import-GPO @Splat

                } #end If

            } Catch {

                Write-Error -Message ('No valid backup was found on {0}!' -f $PSBoundParameters['gpoBackupPath'])

            } #end Try-Catch
        } # End If

    } # End Process Section

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating GPO.'
            )
            Write-Verbose -Message $txt
        } #end If

        return $gpoAlreadyExist
    } # End END Section
} #end Function New-DelegatedAdGpo
