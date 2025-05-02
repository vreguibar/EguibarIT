function New-Tier0CreateOU {

    <#
        .SYNOPSIS
            Creates a new Tier0 Organizational Unit (OU) structure in Active Directory.

        .DESCRIPTION
            Creates and configures the Tier0 Organizational Units structure following Microsoft's tier model.
            This includes:
            - Creating the main Admin OU at the domain root
            - Creating child OUs for accounts, groups, rights, PAWs, service accounts
            - Configuring proper inheritance and permissions for each OU
            - Setting appropriate descriptions based on configuration
            - Applying security hardening by removing unnecessary permissions

            This function is part of the tier model implementation and establishes the
            foundation for secure Active Directory administration.

        .PARAMETER ConfigXMLFile
            Full path to the XML configuration file containing all naming conventions,
            OU structure, and security settings.
            The XML file must contain required Admin section with all OU definitions.

        .PARAMETER DMScripts
            Path to all the scripts and files needed by this function.
            Must contain a SecTmpl subfolder with required templates.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0CreateOU -ConfigXMLFile 'C:\PsScripts\Config.xml'

            Creates the Tier 0 OU structure using the specified configuration file.

        .EXAMPLE
            $params = @{
                ConfigXMLFile = 'C:\PsScripts\Config.xml'
                DMScripts = 'D:\AdminScripts\'
            }
            New-Tier0CreateOU @params

            Creates Tier 0 OU structure with enhanced security hardening using a custom scripts directory.

        .INPUTS
            [System.IO.FileInfo]
            You can pipe the path to the XML configuration file to this function.

        .OUTPUTS
            [System.String]
            Returns a status message upon successful completion with count of created OUs.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬════════════════════════════
                Import-MyModule                        ║ EguibarIT
                New-DelegateAdOU                       ║ EguibarIT
                Set-AdInheritance                      ║ EguibarIT.DelegationPS
                Remove-AuthUser                        ║ EguibarIT.DelegationPS
                Start-AdCleanOU                        ║ EguibarIT.DelegationPS
                Remove-PreWin2000FromOU                ║ EguibarIT.DelegationPS
                Remove-AccountOperator                 ║ EguibarIT.DelegationPS
                Remove-PrintOperator                   ║ EguibarIT.DelegationPS
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Progress                         ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.3
            DateModified:    28/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material

        .COMPONENT
            Active Directory

        .ROLE
            System Administrator

        .FUNCTIONALITY
            Active Directory, Security, Tier Model, Delegation Model, Security Hardening
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
                        $null -eq $xml.n.Servers -or
                        $null -eq $xml.n.Sites -or
                        $null -eq $xml.n.NC) {
                        throw 'XML file is missing required elements (Admin, Servers, Sites or NC section)'
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
            Value = 'C:\PsScripts\'
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
        [hashtable]$ProgressSplat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Load the XML configuration file
        try {
            $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        # Define OU names from XML configuration
        [hashtable]$OuNames = @{
            # Main Admin OU
            ItAdminOu           = $ConfXML.n.Admin.OUs.ItAdminOU.name

            # Admin sub-OUs
            ItAdminAccountsOu   = $ConfXML.n.Admin.OUs.ItAdminAccountsOU.name
            ItAdminGroupsOU     = $ConfXML.n.Admin.OUs.ItAdminGroupsOU.name
            ItPrivGroupsOU      = $ConfXML.n.Admin.OUs.ItPrivGroupsOU.name
            ItPawOu             = $ConfXML.n.Admin.OUs.ItPawOU.name
            ItRightsOu          = $ConfXML.n.Admin.OUs.ItRightsOU.name
            ItServiceAccountsOu = $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name
            ItHousekeepingOu    = $ConfXML.n.Admin.OUs.ItHousekeepingOU.name
            ItInfraOu           = $ConfXML.n.Admin.OUs.ItInfraOU.name
            ItAdminSrvGroupsOU  = $ConfXML.n.Admin.OUs.ItAdminSrvGroupsOU.name

            # PAW sub-OUs
            ItPawT0Ou           = $ConfXML.n.Admin.OUs.ItPawT0OU.name
            ItPawT1Ou           = $ConfXML.n.Admin.OUs.ItPawT1OU.name
            ItPawT2Ou           = $ConfXML.n.Admin.OUs.ItPawT2OU.name
            ItPawStagingOu      = $ConfXML.n.Admin.OUs.ItPawStagingOU.name

            # Service Accounts sub-OUs
            ItSAT0OU            = $ConfXML.n.Admin.OUs.ItSAT0OU.name
            ItSAT1OU            = $ConfXML.n.Admin.OUs.ItSAT1OU.name
            ItSAT2OU            = $ConfXML.n.Admin.OUs.ItSAT2OU.name

            # Infrastructure sub-OUs
            ItInfraT0Ou         = $ConfXML.n.Admin.OUs.ItInfraT0OU.name
            ItInfraT1Ou         = $ConfXML.n.Admin.OUs.ItInfraT1OU.name
            ItInfraT2Ou         = $ConfXML.n.Admin.OUs.ItInfraT2OU.name
            ItInfraStagingOu    = $ConfXML.n.Admin.OUs.ItInfraStagingOU.name
        }

        # Generate DN paths for created OUs
        [hashtable]$OuPaths = @{
            # Main Admin OU
            ItAdminOuDn           = ('OU={0},{1}' -f $OuNames.ItAdminOu, $Variables.AdDn)

            # Admin sub-OUs
            ItAdminAccountsOuDn   = ('OU={0},OU={1},{2}' -f $OuNames.ItAdminAccountsOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItAdminGroupsOUDn     = ('OU={0},OU={1},{2}' -f $OuNames.ItAdminGroupsOU, $OuNames.ItAdminOu, $Variables.AdDn)
            ItPrivGroupsOUDn      = ('OU={0},OU={1},{2}' -f $OuNames.ItPrivGroupsOU, $OuNames.ItAdminOu, $Variables.AdDn)
            ItPawOuDn             = ('OU={0},OU={1},{2}' -f $OuNames.ItPawOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItRightsOuDn          = ('OU={0},OU={1},{2}' -f $OuNames.ItRightsOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItServiceAccountsOuDn = ('OU={0},OU={1},{2}' -f $OuNames.ItServiceAccountsOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItHousekeepingOuDn    = ('OU={0},OU={1},{2}' -f $OuNames.ItHousekeepingOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItInfraOuDn           = ('OU={0},OU={1},{2}' -f $OuNames.ItInfraOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItAdminSrvGroupsOUDn  = ('OU={0},OU={1},{2}' -f $OuNames.ItAdminSrvGroupsOU, $OuNames.ItAdminOu, $Variables.AdDn)

            # PAW sub-OUs
            ItPawT0OuDn           = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItPawT0Ou, $OuNames.ItPawOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItPawT1OuDn           = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItPawT1Ou, $OuNames.ItPawOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItPawT2OuDn           = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItPawT2Ou, $OuNames.ItPawOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItPawStagingOuDn      = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItPawStagingOu, $OuNames.ItPawOu, $OuNames.ItAdminOu, $Variables.AdDn)

            # Service Accounts sub-OUs
            ItSAT0OuDn            = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItSAT0OU, $OuNames.ItServiceAccountsOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItSAT1OuDn            = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItSAT1OU, $OuNames.ItServiceAccountsOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItSAT2OuDn            = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItSAT2OU, $OuNames.ItServiceAccountsOu, $OuNames.ItAdminOu, $Variables.AdDn)

            # Infrastructure sub-OUs
            ItInfraT0OuDn         = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItInfraT0Ou, $OuNames.ItInfraOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItInfraT1OuDn         = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItInfraT1Ou, $OuNames.ItInfraOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItInfraT2OuDn         = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItInfraT2Ou, $OuNames.ItInfraOu, $OuNames.ItAdminOu, $Variables.AdDn)
            ItInfraStagingOuDn    = ('OU={0},OU={1},OU={2},{3}' -f $OuNames.ItInfraStagingOu, $OuNames.ItInfraOu, $OuNames.ItAdminOu, $Variables.AdDn)
        }

        # Initialize progress tracking
        [int]$TotalSteps = 23  # Total number of OUs to create
        [int]$CurrentStep = 0

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Active Directory', 'Create Tier0 Organizational Units')) {

            try {
                #region Create Main Admin OU
                $CurrentStep++

                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f $CurrentStep, $TotalSteps, $OuNames.ItAdminOu)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat

                # Create main Admin OU
                $Splat = @{
                    ouName        = $OuNames.ItAdminOu
                    ouPath        = $Variables.AdDn
                    ouDescription = $ConfXML.n.Admin.OUs.ItAdminOU.description
                    CleanACL      = $true
                }

                try {

                    New-DelegateAdOU @Splat
                    Write-Debug -Message ('Successfully created {0} OU at {1}' -f $OuNames.ItAdminOu, $Variables.AdDn)

                } catch {

                    Write-Error -Message ('Failed to create {0} OU: {1}' -f $OuNames.ItAdminOu, $_.Exception.Message)
                    throw

                } #end Try-Catch

                # Remove inheritance and copy ACEs
                $Splat = @{
                    LDAPpath          = $OuPaths.ItAdminOuDn
                    RemoveInheritance = $true
                    RemovePermissions = $true
                }

                Set-AdInheritance @Splat
                Write-Debug -Message ('Successfully configured inheritance settings for {0}' -f $OuPaths.ItAdminOuDn)

                # Implement security hardening if specified
                Write-Debug -Message ('Applying security hardening to {0}' -f $OuPaths.ItAdminOuDn)

                # Remove AUTHENTICATED USERS group from OU (but must retain on ACL)
                Remove-AuthUser -LDAPPath $OuPaths.ItAdminOuDn

                # Clean Ou
                Start-AdCleanOU -LDAPPath $OuPaths.ItAdminOuDn -RemoveUnknownSIDs

                # Remove Pre-Windows 2000 Access group from OU
                Remove-PreWin2000FromOU -LDAPPath $OuPaths.ItAdminOuDn

                # Remove ACCOUNT OPERATORS Access group from OU
                Remove-AccountOperator -LDAPPath $OuPaths.ItAdminOuDn

                # Remove PRINT OPERATORS Access group from OU
                Remove-PrintOperator -LDAPPath $OuPaths.ItAdminOuDn

                Write-Verbose -Message ('Security hardening completed for {0}' -f $OuPaths.ItAdminOuDn)


                <#
                    # Remove AUTHENTICATED USERS group from OU
                    #
                    # CHECK... This one should not "LIST" but must be on ACL
                    Remove-AuthUser -LDAPPath $ItAdminOuDn

                    # Clean Ou
                    Start-AdCleanOU -LDAPPath $ItAdminOuDn  -RemoveUnknownSIDs

                    # Remove Pre-Windows 2000 Access group from OU
                    Remove-PreWin2000FromOU -LDAPPath $ItAdminOuDn

                    # Remove ACCOUNT OPERATORS 2000 Access group from OU
                    Remove-AccountOperator -LDAPPath $ItAdminOuDn

                    # Remove PRINT OPERATORS 2000 Access group from OU
                    Remove-PrintOperator -LDAPPath $ItAdminOuDn
                    #>

                <#

                    Computer objects within this ares MUST have read access, otherwise GPO will not apply - TO BE DONE

                    Manually change Authenticated Users from "This Object Only" to "This and descendant objects"

                    then ACL will look like this:

                    Get-AclAccessRule -LDAPpath 'OU=Admin,DC=EguibarIT,DC=local' -SearchBy 'Authenticated Users'
                    VERBOSE:
                            ACE (Access Control Entry)  Filtered By: Authenticated Users
                    VERBOSE: ============================================================


                    ACENumber              : 1
                    DistinguishedName      : OU=Admin,DC=EguibarIT,DC=local
                    IdentityReference      : Authenticated Users
                    ActiveDirectoryRights : ReadProperty, GenericExecute
                    AccessControlType      : Allow
                    ObjectType             : GuidNULL
                    InheritanceType        : All
                    InheritedObjectType    : GuidNULL
                    IsInherited            : False

                #>
                #endregion
                #region Create Admin Sub-OUs
                Write-Verbose -Message 'Creating Sub-OUs for Admin (Tier0)...'

                # Create parameter for all sub-OUs
                $Splat = @{
                    ouPath   = $OuPaths.ItAdminOuDn
                    CleanACL = $true
                }

                # Create each Admin sub-OU with progress reporting
                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItAdminAccountsOu)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItAdminAccountsOu -ouDescription $ConfXML.n.Admin.OUs.ItAdminAccountsOU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItAdminGroupsOU)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItAdminGroupsOU -ouDescription $ConfXML.n.Admin.OUs.ItAdminGroupsOU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItPrivGroupsOU)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItPrivGroupsOU -ouDescription $ConfXML.n.Admin.OUs.ItPrivGroupsOU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItPawOu)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItPawOu -ouDescription $ConfXML.n.Admin.OUs.ItPawOU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItRightsOu)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItRightsOu -ouDescription $ConfXML.n.Admin.OUs.ItRightsOU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItServiceAccountsOu)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItServiceAccountsOu -ouDescription $ConfXML.n.Admin.OUs.ItServiceAccountsOU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItHousekeepingOu)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItHousekeepingOu -ouDescription $ConfXML.n.Admin.OUs.ItHousekeepingOU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItInfraOu)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItInfraOu -ouDescription $ConfXML.n.Admin.OUs.ItInfraOU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItAdminSrvGroupsOU)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItAdminSrvGroupsOU -ouDescription $ConfXML.n.Admin.OUs.ItAdminSrvGroupsOU.description @Splat

                # Ensure inheritance is enabled for child Admin OUs
                $Splat = @{
                    RemoveInheritance = $false
                    RemovePermissions = $true
                }

                Write-Verbose -Message 'Configuring inheritance for Admin sub-OUs...'
                Set-AdInheritance -LDAPpath $OuPaths.ItAdminAccountsOuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItAdminGroupsOUDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItPrivGroupsOUDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItPawOuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItRightsOuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItServiceAccountsOuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItHousekeepingOuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItInfraOuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItAdminSrvGroupsOUDn @Splat
                #endregion

                #region Create PAW Sub-OUs
                Write-Debug -Message 'Creating PAW Sub-OUs...'

                # Create parameter for PAW sub-OUs
                $Splat = @{
                    ouPath   = $OuPaths.ItPawOuDn
                    CleanACL = $true
                }

                # Create each PAW sub-OU with progress reporting
                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItPawT0Ou)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItPawT0Ou -ouDescription $ConfXML.n.Admin.OUs.ItPawT0OU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItPawT1Ou)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItPawT1Ou -ouDescription $ConfXML.n.Admin.OUs.ItPawT1OU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItPawT2Ou)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItPawT2Ou -ouDescription $ConfXML.n.Admin.OUs.ItPawT2OU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItPawStagingOu)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItPawStagingOu -ouDescription $ConfXML.n.Admin.OUs.ItPawStagingOU.description @Splat

                # Ensure inheritance is enabled for PAW sub-OUs
                $Splat = @{
                    RemoveInheritance = $false
                    RemovePermissions = $true
                }

                Write-Verbose -Message 'Configuring inheritance for PAW sub-OUs...'
                Set-AdInheritance -LDAPpath $OuPaths.ItPawT0OuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItPawT1OuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItPawT2OuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItPawStagingOuDn @Splat
                #endregion

                #region Create Service Accounts Sub-OUs
                Write-Debug -Message 'Creating Service Accounts Sub-OUs...'

                # Create parameter for Service Accounts sub-OUs
                $Splat = @{
                    ouPath   = $OuPaths.ItServiceAccountsOuDn
                    CleanACL = $true
                }

                # Create each Service Account sub-OU with progress reporting
                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItSAT0OU)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItSAT0OU -ouDescription $ConfXML.n.Admin.OUs.ItSAT0OU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItSAT1OU)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItSAT1OU -ouDescription $ConfXML.n.Admin.OUs.ItSAT1OU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItSAT2OU)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItSAT2OU -ouDescription $ConfXML.n.Admin.OUs.ItSAT2OU.description @Splat

                # Ensure inheritance is enabled for Service Accounts sub-OUs
                $Splat = @{
                    RemoveInheritance = $false
                    RemovePermissions = $true
                }

                Write-Verbose -Message 'Configuring inheritance for Service Accounts sub-OUs...'
                Set-AdInheritance -LDAPpath $OuPaths.ItSAT0OuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItSAT1OuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItSAT2OuDn @Splat
                #endregion

                #region Create Infrastructure Sub-OUs
                Write-Debug -Message 'Creating Infrastructure Sub-OUs...'

                # Create parameter for Infrastructure sub-OUs
                $Splat = @{
                    ouPath   = $OuPaths.ItInfraOuDn
                    CleanACL = $true
                }

                # Create each Infrastructure sub-OU with progress reporting
                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItInfraT0Ou)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItInfraT0Ou -ouDescription $ConfXML.n.Admin.OUs.ItInfraT0OU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItInfraT1Ou)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItInfraT1Ou -ouDescription $ConfXML.n.Admin.OUs.ItInfraT1OU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItInfraT2Ou)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItInfraT2Ou -ouDescription $ConfXML.n.Admin.OUs.ItInfraT2OU.description @Splat

                $CurrentStep++
                $ProgressSplat = @{
                    Activity        = 'Creating Tier 0 OU Structure'
                    Status          = ('Step {0} of {1}: Creating {2} OU' -f
                        $CurrentStep, $TotalSteps, $OuNames.ItInfraStagingOu)
                    PercentComplete = (($CurrentStep / $TotalSteps) * 100)
                }
                Write-Progress @ProgressSplat
                New-DelegateAdOU -ouName $OuNames.ItInfraStagingOu -ouDescription $ConfXML.n.Admin.OUs.ItInfraStagingOU.description @Splat

                # Ensure inheritance is enabled for Infrastructure sub-OUs
                $Splat = @{
                    RemoveInheritance = $false
                    RemovePermissions = $true
                }

                Write-Debug -Message 'Configuring inheritance for Infrastructure sub-OUs...'
                Set-AdInheritance -LDAPpath $OuPaths.ItInfraT0OuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItInfraT1OuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItInfraT2OuDn @Splat
                Set-AdInheritance -LDAPpath $OuPaths.ItInfraStagingOuDn @Splat
                #endregion

                # Ensure Authenticated Users have proper permissions to enable GPO application
                Write-Debug -Message 'Configuring Authenticated Users permissions for GPO application...'

                # Complete progress bar
                Write-Progress -Activity 'Creating Tier 0 OU Structure' -Completed

            } catch {

                Write-Error -Message ('Error creating Tier 0 OU structure: {0}' -f $_.Exception.Message)
                throw

            } finally {

                # Ensure progress bar is removed on error
                Write-Progress -Activity 'Creating Tier 0 OU Structure' -Completed

            } #end Try-Catch-Finally

        } #end If ShouldProcess

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating Tier0 Organizational Units.'
            )
            Write-Verbose -Message $txt
        } #end If

        # Return status message with count of created OUs and root OU path
        return ('Tier 0 OU structure successfully created with {0} OUs. Root: {1}' -f
            $OuPaths.Count, $OuPaths.ItAdminOuDn)
    } #end End
} #end Function New-Tier0CreateOU
