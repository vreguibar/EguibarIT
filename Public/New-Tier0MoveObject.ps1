function New-Tier0MoveObject {

    <#
        .SYNOPSIS
            Moves Tier0 Active Directory objects to their proper OUs as per secure tiering model.

        .DESCRIPTION
            Moves default Tier0 Active Directory objects (privileged accounts and groups) to their
            designated Organizational Units according to a secure tiering model. This function is
            typically run once during initial AD structure setup to clean up the default
            container locations and implement proper object segregation.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            [System.String] Path to all the scripts and files needed by this function.
            The directory must contain a SecTmpl subfolder.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0MoveObject -ConfigXMLFile 'C:\PsScripts\Config.xml' -Verbose

            Moves Tier0 objects as defined in the configuration file with verbose output.

        .EXAMPLE
            New-Tier0MoveObject -ConfigXMLFile 'C:\PsScripts\Config.xml' -DMScripts 'C:\Scripts\'

            Moves Tier0 objects as defined in the configuration file, using scripts from the specified path.

        .INPUTS
            System.IO.FileInfo
            System.String

        .OUTPUTS
            System.String

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Import-MyModule                            ║ EguibarIT
                Get-ADUser                                 ║ ActiveDirectory
                Get-ADGroup                                ║ ActiveDirectory
                Get-ADDomain                               ║ ActiveDirectory
                Get-ADDomainController                     ║ ActiveDirectory
                Rename-ADObject                            ║ ActiveDirectory
                Move-ADObject                              ║ ActiveDirectory
                Set-ADUser                                 ║ ActiveDirectory
                Get-FunctionDisplay                        ║ EguibarIT
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility

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
            Administrator

        .FUNCTIONALITY
            AD Object Management
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]

    param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
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
                        $null -eq $xml.n.Admin.OUs -or
                        $null -eq $xml.n.Admin.Users) {
                        throw 'XML file is missing required elements (Admin, OUs or Users section)'
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

        Import-MyModule -Name 'ServerManager' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # Parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Load the XML configuration file
        try {
            [xml]$confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        # Get the current domain controller for all operations
        try {

            [string]$CurrentDC = (Get-ADDomainController -Discover -NextClosestSite -ErrorAction Stop).HostName[0]
            Write-Debug -Message ('Using domain controller: {0}' -f $CurrentDC)

        } catch {

            Write-Error -Message ('Error discovering domain controller: {0}' -f $_.Exception.Message)
            throw

        } #end Try-Catch

        # Define OU names from XML configuration
        [hashtable]$OuNames = @{
            # Main Admin OU
            ItAdminOu         = $ConfXML.n.Admin.OUs.ItAdminOU.name

            # Admin sub-OUs
            ItAdminAccountsOu = $ConfXML.n.Admin.OUs.ItAdminAccountsOU.name
            ItAdminGroupsOU   = $ConfXML.n.Admin.OUs.ItAdminGroupsOU.name
            ItPrivGroupsOU    = $ConfXML.n.Admin.OUs.ItPrivGroupsOU.name
            ItRightsOu        = $ConfXML.n.Admin.OUs.ItRightsOU.name
        }

        # Generate DN paths for OUs
        [string]$ItAdminAccountsOuDn = ('OU={0},OU={1},{2}' -f $OuNames.ItAdminAccountsOu, $OuNames.ItAdminOu, $Variables.AdDn)
        [string]$ItAdminGroupsOuDn = ('OU={0},OU={1},{2}' -f $OuNames.ItAdminGroupsOU, $OuNames.ItAdminOu, $Variables.AdDn)
        [string]$ItPrivGroupsOUDn = ('OU={0},OU={1},{2}' -f $OuNames.ItPrivGroupsOU, $OuNames.ItAdminOu, $Variables.AdDn)
        [string]$ItRightsOuDn = ('OU={0},OU={1},{2}' -f $OuNames.ItRightsOu, $OuNames.ItAdminOu, $Variables.AdDn)

        Write-Debug -Message ('Admin Accounts OU DN: {0}' -f $ItAdminAccountsOuDn)
        Write-Debug -Message ('Admin Groups OU DN: {0}' -f $ItAdminGroupsOuDn)
        Write-Debug -Message ('Privileged Groups OU DN: {0}' -f $ItPrivGroupsOUDn)
        Write-Debug -Message ('Rights OU DN: {0}' -f $ItRightsOuDn)

        # Get the AD Objects by Well-Known SID
        try {
            # Administrator
            $AdminName = Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
            # Domain Admins
            $DomainAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-512' }
            # Enterprise Admins
            $EnterpriseAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-519' }
            # Schema Admins
            $SchemaAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-518' }
            # DomainControllers
            $DomainControllers = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-516' }
            # RODC
            $RODC = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-521' }
            # Group Policy Creators Owner
            $GPOCreatorsOwner = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-520' }
            # Denied RODC Password Replication Group
            $DeniedRODC = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-572' }

            # DNS Administrators
            $DnsAdmins = Get-ADGroup -Identity 'DnsAdmins'
            # Protected Users
            $ProtectedUsers = Get-ADGroup -Identity 'Protected Users'

        } catch {
            Write-Error -Message ('Error initializing security principals: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

    } #end Begin

    Process {
        if ($PSCmdlet.ShouldProcess('Active Directory', 'Moving Tier0 objects')) {
            try {
                # Move, and if needed, rename the Admin account
                if ($null -ne $AdminName -and
                    $null -ne $confXML.n.Admin.users.Admin.Name) {

                    if ($AdminName.Name -ne $confXML.n.Admin.users.Admin.Name) {

                        Write-Debug -Message ('Renaming admin account to: {0}' -f $confXML.n.Admin.users.Admin.Name)
                        $Splat = @{
                            Identity = $AdminName.DistinguishedName
                            NewName  = $ConfXML.n.Admin.users.Admin.Name
                            Server   = $CurrentDC
                        }
                        Rename-ADObject @Splat

                        $Splat = @{
                            Identity       = $AdminName
                            SamAccountName = $ConfXML.n.Admin.users.Admin.Name
                            DisplayName    = $ConfXML.n.Admin.users.Admin.Name
                            Server         = $CurrentDC
                        }
                        Set-ADUser @Splat
                    } #end If

                    Write-Debug -Message ('Moving admin account to: {0}' -f $ItAdminAccountsOuDn)
                    $AdminName | Move-ADObject -TargetPath $ItAdminAccountsOuDn -Server $CurrentDC
                } #end If

                # Move the Guest Account if it exists
                if ($null -ne $GuestNewName) {

                    Write-Debug -Message ('Moving guest account to: {0}' -f $ItAdminAccountsOuDn)
                    $GuestNewName | Move-ADObject -TargetPath $ItAdminAccountsOuDn -Server $CurrentDC

                } #end If

                $DomainAdmins | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                $EnterpriseAdmins | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                Get-ADGroup -Identity $SchemaAdmins | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                Get-ADGroup -Identity $DomainControllers | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                Get-ADGroup -Identity $GPOCreatorsOwner | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                Get-ADGroup -Identity $RODC | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                Get-ADGroup -Identity 'Enterprise Read-only Domain Controllers' |
                    Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC

                Get-ADGroup -Identity 'DnsUpdateProxy' | Move-ADObject -TargetPath $ItAdminGroupsOuDn -Server $CurrentDC
                Get-ADGroup -Identity 'Domain Users' | Move-ADObject -TargetPath $ItAdminGroupsOuDn -Server $CurrentDC
                Get-ADGroup -Identity 'Domain Computers' | Move-ADObject -TargetPath $ItAdminGroupsOuDn -Server $CurrentDC
                Get-ADGroup -Identity 'Domain Guests' | Move-ADObject -TargetPath $ItAdminGroupsOuDn -Server $CurrentDC

                Get-ADGroup -Identity 'Allowed RODC Password Replication Group' |
                    Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
                Get-ADGroup -Identity 'RAS and IAS Servers' | Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
                $DnsAdmins | Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
                Get-ADGroup -Identity 'Cert Publishers' | Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
                Get-ADGroup -Identity $DeniedRODC | Move-ADObject -TargetPath $ItRightsOuDn -Server $CurrentDC
                $ProtectedUsers | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                Get-ADGroup -Identity 'Cloneable Domain Controllers' |
                    Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                Get-ADGroup -Identity 'Access-Denied Assistance Users' |
                    Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                Get-ADGroup -Filter { SamAccountName -like 'WinRMRemoteWMIUsers*' } |
                    Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC


                # ToDo: Check for group existence before moving
                # Following groups only exist on Win 2019
                If ([System.Environment]::OSVersion.Version.Build -ge 17763) {
                    Get-ADGroup -Identity 'Enterprise Key Admins' | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                    Get-ADGroup -Identity 'Key Admins' | Move-ADObject -TargetPath $ItPrivGroupsOUDn -Server $CurrentDC
                    #Get-ADGroup -Identity 'Windows Admin Center CredSSP Administrators' | Move-ADObject -TargetPath $ItPrivGroupsOUDn
                }

                # Get-ADGroup $Administrators |                          Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Account Operators" |                       Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Backup Operators" |                        Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Certificate Service DCOM Access" |         Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Cryptographic Operators" |                 Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Server Operators" |                        Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Remote Desktop Users" |                    Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Distributed COM Users" |                   Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Event Log Readers" |                       Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Guests" |                                  Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "IIS_IUSRS" |                               Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Incoming Forest Trust Builders" |          Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup $NetConfOperators |                         Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Performance Log Users" |                   Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Performance Monitor Users" |               Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Pre-Windows 2000 Compatible Access" |      Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Print Operators" |                         Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Replicator" |                              Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Terminal Server License Servers" |         Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Users" |                                   Move-ADObject -TargetPath $ItRightsOuDn
                # Get-ADGroup "Windows Authorization Access Group" |      Move-ADObject -TargetPath $ItRightsOuDn

                # REFRESH - Get the object after moving it.
                Write-Verbose -Message 'Refreshing security principal variables after moves'

                $Splat = @{
                    Name  = 'AdminName'
                    Value = (Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' })
                    Scope = 'Global'
                    Force = $true
                }
                New-Variable @Splat

                $Splat = @{
                    Name  = 'DomainAdmins'
                    Value = (Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-512' })
                    Scope = 'Global'
                    Force = $true
                }
                New-Variable @Splat

                $Splat = @{
                    Name  = 'EnterpriseAdmins'
                    Value = (Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-519' })
                    Scope = 'Global'
                    Force = $true
                }
                New-Variable @Splat

                $Splat = @{
                    Name  = 'GPOCreatorsOwner'
                    Value = (Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-520' })
                    Scope = 'Global'
                    Force = $true
                }
                New-Variable @Splat


                $Splat = @{
                    Name  = 'DeniedRODC'
                    Value = (Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-572' })
                    Scope = 'Global'
                    Force = $true
                }
                New-Variable @Splat

                $Splat = @{
                    Name  = 'DnsAdmins'
                    Value = (Get-ADGroup -Identity 'DnsAdmins' -Server $CurrentDC -ErrorAction SilentlyContinue)
                    Scope = 'Global'
                    Force = $true
                }
                New-Variable @Splat

                $Splat = @{
                    Name  = 'ProtectedUsers'
                    Value = (Get-ADGroup -Identity 'Protected Users' -Server $CurrentDC -ErrorAction SilentlyContinue)
                    Scope = 'Global'
                    Force = $true
                }
                New-Variable @Splat

                Write-Verbose -Message 'Successfully moved all Tier0 objects to their respective OUs'
                return 'Tier0 objects have been successfully moved to their respective OUs'

            } catch {
                Write-Error -Message ('Error moving Tier0 objects: {0}' -f $_.Exception.Message)
                throw
            } #end Try-Catch
        } #end If ShouldProcess
    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'moving Tier0 objects.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function New-Tier0MoveObject
