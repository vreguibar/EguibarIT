function New-Tier0AuthPolicyAndSilo {

    <#
        .SYNOPSIS
            Creates and configures Tier 0 Authentication Policies and Silos in Active Directory.

        .DESCRIPTION
            This function implements Authentication Policies and Silos specifically for Tier 0 assets
            in a tiered security model. It creates both audit and enforcement policies for users,
            computers, and service accounts, then creates corresponding policy silos.

            The function enables Kerberos claims support, which is a requirement for Authentication
            Policies and Silos, and then configures the necessary policies with appropriate
            Security Descriptor Definition Language (SDDL) strings.

            The Tier 0 Authentication Policies and Silos are designed to limit authentication paths
            for the most sensitive administrative accounts and resources in the environment,
            preventing lateral movement and credential theft attacks.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            Path to all the scripts and files needed by this function.
            Must contain a SecTmpl subfolder with necessary template files.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0AuthPolicyAndSilo -ConfigXMLFile "C:\PsScripts\Config.xml"

            Creates Tier 0 Authentication Policies and Silos using the specified XML configuration file.

        .EXAMPLE
            New-Tier0AuthPolicyAndSilo -ConfigXMLFile "C:\PsScripts\Config.xml" -DMScripts "C:\CustomScripts\"

            Creates Tier 0 Authentication Policies and Silos using the specified XML configuration file
            and a custom script directory.

        .EXAMPLE
            New-Tier0AuthPolicyAndSilo -ConfigXMLFile "C:\PsScripts\Config.xml" -Verbose

            Creates Tier 0 Authentication Policies and Silos with verbose output logging.

        .INPUTS
            [System.IO.FileInfo] - Path to the configuration XML file
            [System.String] - Path to the directory containing support scripts

        .OUTPUTS
            [System.String] - Status message indicating completion

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Import-MyModule                            ║ EguibarIT
                Enable-KerberosClaimSupport                ║ EguibarIT
                Get-ADAuthenticationPolicy                 ║ ActiveDirectory
                New-ADAuthenticationPolicy                 ║ ActiveDirectory
                New-ADAuthenticationPolicySilo             ║ ActiveDirectory
                Grant-ADAuthenticationPolicySiloAccess     ║ ActiveDirectory
                Set-ADUser                                 ║ ActiveDirectory
                Set-ADComputer                             ║ ActiveDirectory
                Get-ADComputer                             ║ ActiveDirectory
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Write-Progress                             ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                        ║ EguibarIT

        .NOTES
            Version:         1.1
            DateModified:    9/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                        vicente@eguibar.com
                        Eguibar IT
                        http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Active Directory Security

        .ROLE
            Security Administrator

        .FUNCTIONALITY
            Authentication Policy, Authentication Policy Silo, Tier 0, Security
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([void])]

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
                    if ($null -eq $xml.n.Admin -or
                        $null -eq $xml.n.Admin.LG -or
                        $null -eq $xml.n.Admin.Users -or
                        $null -eq $xml.n.Admin.GPOs -or
                        $null -eq $xml.n.NC) {
                        throw 'XML file is missing required elements (Admin, LG, Users, GPOs or NC section)'
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
        [PSDefaultValue(
            Help = 'Default Value is "C:\PsScripts\"',
            Value = 'C:\PsScripts\'
        )]
        [Alias('ScriptPath')]
        [string]
        $DMScripts = 'C:\PsScripts\',

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Start transcript logging to DMScripts path with function name',
            Position = 2)]
        [Alias('Transcript', 'Log')]
        [switch]
        $EnableTranscript

    )

    Begin {
        Set-StrictMode -Version Latest

        # Check if running with administrative privileges
        $CurrentIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentIdentity)
        $IsAdmin = $WindowsPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

        if (-not $IsAdmin) {
            $ErrorMessage = 'This function requires administrative privileges to create ' +
            'and manage Authentication Policies in Active Directory.'
            Write-Error -Message $ErrorMessage
            throw $ErrorMessage
        }

        # Check if running as Domain Admin or equivalent (needed for AD Authentication Policies)
        try {
            $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $IsDomainAdmin = $false

            # Check Domain Admins membership
            $DomainAdmins = Get-ADGroup -Identity 'Domain Admins' -ErrorAction SilentlyContinue
            if ($DomainAdmins) {
                $IsDomainAdmin = Get-ADGroupMember -Identity $DomainAdmins -Recursive -ErrorAction SilentlyContinue |
                    Where-Object { $_.SamAccountName -eq $CurrentUser.Split('\')[1] }
            }

            if (-not $IsDomainAdmin) {
                Write-Warning -Message 'Current user is not a member of Domain Admins. ' +
                'Authentication Policy operations may fail due to insufficient permissions.'
            }
        } catch {
            Write-Warning -Message "Failed to verify domain privileges: $($_.Exception.Message)"
        }

        If (-not $PSBoundParameters.ContainsKey('ConfigXMLFile')) {
            $PSBoundParameters['ConfigXMLFile'] = 'C:\PsScripts\Config.xml'
        } #end If

        If (-not $PSBoundParameters.ContainsKey('DMScripts')) {
            $PSBoundParameters['DMScripts'] = 'C:\PsScripts\'
        } #end If

        # If EnableTranscript is specified, start a transcript
        if ($EnableTranscript) {
            # Ensure DMScripts directory exists
            if (-not (Test-Path -Path $DMScripts -PathType Container)) {
                try {
                    New-Item -Path $DMScripts -ItemType Directory -Force | Out-Null
                    Write-Verbose -Message ('Created transcript directory: {0}' -f $DMScripts)
                } catch {
                    Write-Warning -Message ('Failed to create transcript directory: {0}' -f $_.Exception.Message)
                } #end try-catch
            } #end if

            # Create transcript filename using function name and current date/time
            $TranscriptFile = Join-Path -Path $DMScripts -ChildPath ('{0}_{1}.LOG' -f $MyInvocation.MyCommand.Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))

            try {
                Start-Transcript -Path $TranscriptFile -Force -ErrorAction Stop
                Write-Verbose -Message ('Transcript started: {0}' -f $TranscriptFile)
            } catch {
                Write-Warning -Message ('Failed to start transcript: {0}' -f $_.Exception.Message)
            } #end try-catch
        } #end if

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
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # Parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Progress reporting variables
        [int]$ProgressID = 1
        [int]$ProgressSteps = 5
        [int]$CurrentStep = 0
        [hashtable]$ProgressSplat = @{}

        # Authentication Policy variables
        [string]$AuditComputerPolicyName = 'T0_AuditOnly_Computers'
        [string]$AuditUserPolicyName = 'T0_AuditOnly_Users'
        [string]$AuditServicePolicyName = 'T0_AuditOnly_ServiceAccounts'
        [string]$EnforceComputerPolicyName = 'T0_Enforce_Computers'
        [string]$EnforceUserPolicyName = 'T0_Enforce_Users'
        [string]$EnforceServicePolicyName = 'T0_Enforce_ServiceAccounts'

        # Authentication Silo variables
        [string]$AuditingSiloName = 'T0_AuditingSilo'
        [string]$EnforceSiloName = 'T0_EnforcedSilo'

        # TGT Lifetime in minutes
        [int]$UserTGTLifetime = 240
        [int]$ComputerTGTLifetime = 120
        [int]$ServiceTGTLifetime = 120

        # Load the XML configuration file
        try {
            $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
            Write-Debug -Message ('Successfully loaded configuration XML from: {0}' -f $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch


        # Load naming conventions from XML
        [hashtable]$NC = @{
            'sl'    = $confXML.n.NC.LocalDomainGroupPreffix
            'sg'    = $confXML.n.NC.GlobalGroupPreffix
            'su'    = $confXML.n.NC.UniversalGroupPreffix
            'Delim' = $confXML.n.NC.Delimiter
            'T0'    = $confXML.n.NC.AdminAccSufix0
            'T1'    = $confXML.n.NC.AdminAccSufix1
            'T2'    = $confXML.n.NC.AdminAccSufix2
        }


        #region Users Variables
        $AdminName = Get-SafeVariable -Name 'AdminName' -CreateIfNotExist {
            try {
                Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Administrator account: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $newAdminName = Get-SafeVariable -Name 'newAdminName' -CreateIfNotExist {
            try {
                $name = $confXML.n.Admin.users.NEWAdmin.Name
                if ([string]::IsNullOrEmpty($name)) {
                    return $null
                }
                Get-AdObjectType -Identity $name
            } catch {
                Write-Debug -Message ('Failed to retrieve new admin account: {0}' -f $_.Exception.Message)
                $null
            }
        }
        #endregion Users Variables

        #region Local groups Variables
        $SL_PAWs = Get-SafeVariable -Name 'SL_PAWs' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PAWs.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_InfrastructureServers = Get-SafeVariable -Name 'SL_InfrastructureServers' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraServers.Name)
            Get-AdObjectType -Identity $groupName
        }
        #endregion Local groups Variables


    } #end Begin

    Process {

        try {
            # Configure Kerberos Claims and Authentication Policies/Silos
            if ($PSCmdlet.ShouldProcess('Active Directory Security', 'Create Authentication Policies and Silos')) {

                # Update progress: Enabling Kerberos Claims
                $CurrentStep++
                $ProgressSplat = @{
                    Id              = $ProgressID
                    Activity        = 'Creating Tier 0 Authentication Policies and Silos'
                    Status          = 'Step {0}/{1}: Enabling Kerberos Claims support' -f $CurrentStep, $ProgressSteps
                    PercentComplete = ($CurrentStep / $ProgressSteps) * 100
                }
                Write-Progress @ProgressSplat

                # Enable Kerberos Claims support first - required for Authentication Policies
                $Splat = @{
                    DomainDNSName       = $env:USERDNSDOMAIN
                    GeneralGPO          = 'C-Baseline'
                    DomainControllerGPO = 'C-{0}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Name
                    Confirm             = $false
                }
                Write-Verbose -Message 'Enabling Kerberos Claims support via Enable-KerberosClaimSupport'
                Enable-KerberosClaimSupport @Splat


                # Reference: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/authentication-policies-and-authentication-policy-silos

                # Build SDDL string with proper format
                # SDDL reference: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format

                # Using direct string instead of StringBuilder to avoid formatting issues
                [string]$AllowToAuthenticateFromSDDL = 'O:SYG:SY'

                # Build the condition part using Domain Controllers SID and our custom groups
                [string]$DCCondition = '(Member_of {SID(DD)})'
                [string]$PawsCondition = '(Member_of_any {SID(' + $SL_PAWs.SID.Value + ')})'
                [string]$InfraCondition = '(Member_of_any {SID(' + $SL_InfrastructureServers.SID.Value + ')})'

                # Combine conditions with OR operators
                [string]$FullCondition = '(((' + $DCCondition + ' || ' + $PawsCondition + ' || ' + $InfraCondition + ')))'

                # Add DACL with ACE - XA=ACCESS_ALLOWED_CALLBACK_ACE, OICI=inheritance flags, CR=control rights, WD=Everyone
                $AllowToAuthenticateFromSDDL += 'D:(XA;OICI;CR;;;WD;' + $FullCondition + ')'

                Write-Debug -Message ('SDDL string: {0}' -f $AllowToAuthenticateFromSDDL)

                #region Create AuditOnly Policies
                # Update progress: Creating audit policies
                $CurrentStep++
                $ProgressSplat = @{
                    Id              = $ProgressID
                    Activity        = 'Creating Tier 0 Authentication Policies and Silos'
                    Status          = 'Step {0}/{1}: Creating AuditOnly authentication policies' -f $CurrentStep, $ProgressSteps
                    PercentComplete = ($CurrentStep / $ProgressSteps) * 100
                }
                Write-Progress @ProgressSplat
                Write-Verbose -Message 'Creating AuditOnly authentication policies'

                # Computer AUDIT
                [bool]$PolicyExists = $false
                try {
                    $PolicyExists = $null -ne (Get-ADAuthenticationPolicy -Filter "Name -eq '$AuditComputerPolicyName'" -ErrorAction Stop)
                } catch {
                    Write-Debug -Message ('Error checking policy existence: {0}' -f $_.Exception.Message)
                    $PolicyExists = $false
                } #end Try-Catch

                If (-Not $PolicyExists) {
                    $Splat = @{
                        Name                            = $AuditComputerPolicyName
                        Description                     = 'This Kerberos Authentication policy used to AUDIT computer logon ' +
                        'from untrusted computers'
                        ComputerAllowedToAuthenticateTo = $AllowToAuthenticateFromSDDL.ToString()
                        ComputerTGTLifetimeMins         = $ComputerTGTLifetime
                        ProtectedFromAccidentalDeletion = $true
                    }
                    Write-Verbose -Message 'Creating T0_AuditOnly_Computers authentication policy'
                    New-ADAuthenticationPolicy @Splat

                } else {

                    Write-Verbose -Message 'T0_AuditOnly_Computers authentication policy already exists'

                } #end If-else

                # User AUDIT
                $PolicyExists = $false
                try {
                    $PolicyExists = $null -ne (Get-ADAuthenticationPolicy -Filter "Name -eq '$AuditUserPolicyName'" -ErrorAction Stop)
                } catch {
                    Write-Debug -Message ('Error checking policy existence: {0}' -f $_.Exception.Message)
                    $PolicyExists = $false
                } #end Try-Catch

                If (-Not $PolicyExists) {
                    $Splat = @{
                        Name                            = $AuditUserPolicyName
                        Description                     = 'This Kerberos Authentication policy used to AUDIT interactive logon ' +
                        'from untrusted users'
                        UserAllowedToAuthenticateFrom   = $AllowToAuthenticateFromSDDL.ToString()
                        UserAllowedToAuthenticateTo     = $AllowToAuthenticateFromSDDL.ToString()
                        UserTGTLifetimeMins             = $UserTGTLifetime
                        ProtectedFromAccidentalDeletion = $true
                    }
                    Write-Verbose -Message 'Creating T0_AuditOnly_Users authentication policy'
                    New-ADAuthenticationPolicy @Splat

                } else {

                    Write-Verbose -Message 'T0_AuditOnly_Users authentication policy already exists'

                } #end If-else

                # ServiceAccounts AUDIT
                $PolicyExists = $false
                try {
                    $PolicyExists = $null -ne (Get-ADAuthenticationPolicy -Filter "Name -eq '$AuditServicePolicyName'" -ErrorAction Stop)
                } catch {
                    Write-Debug -Message ('Error checking policy existence: {0}' -f $_.Exception.Message)
                    $PolicyExists = $false
                } #end Try-Catch

                If (-Not $PolicyExists) {
                    $Splat = @{
                        Name                             = $AuditServicePolicyName
                        Description                      = 'This Kerberos Authentication policy used to AUDIT ServiceAccount ' +
                        'logon from untrusted Service Accounts'
                        ServiceAllowedToAuthenticateFrom = $AllowToAuthenticateFromSDDL.ToString()
                        ServiceAllowedToAuthenticateTo   = $AllowToAuthenticateFromSDDL.ToString()
                        ServiceTGTLifetimeMins           = $ServiceTGTLifetime
                        ProtectedFromAccidentalDeletion  = $true
                    }
                    Write-Verbose -Message 'Creating T0_AuditOnly_ServiceAccounts authentication policy'
                    New-ADAuthenticationPolicy @Splat

                } else {

                    Write-Verbose -Message 'T0_AuditOnly_ServiceAccounts authentication policy already exists'

                } #end If-else
                #endregion Create AuditOnly Policies

                #region Create ENFORCE policies
                # Update progress: Creating enforce policies
                $CurrentStep++
                $ProgressSplat = @{
                    Id              = $ProgressID
                    Activity        = 'Creating Tier 0 Authentication Policies and Silos'
                    Status          = 'Step {0}/{1}: Creating Enforce authentication policies' -f $CurrentStep, $ProgressSteps
                    PercentComplete = ($CurrentStep / $ProgressSteps) * 100
                }
                Write-Progress @ProgressSplat
                Write-Verbose -Message 'Creating Enforcement authentication policies'

                # Computer ENFORCE
                $PolicyExists = $false
                try {
                    $PolicyExists = $null -ne (Get-ADAuthenticationPolicy -Filter "Name -eq '$EnforceComputerPolicyName'" -ErrorAction Stop)
                } catch {
                    Write-Debug -Message ('Error checking policy existence: {0}' -f $_.Exception.Message)
                    $PolicyExists = $false
                } #end Try-Catch

                If (-Not $PolicyExists) {
                    $Splat = @{
                        Name                            = $EnforceComputerPolicyName
                        Description                     = 'This Kerberos Authentication policy used to ENFORCE ' +
                        'interactive logon from untrusted computers'
                        ComputerAllowedToAuthenticateTo = $AllowToAuthenticateFromSDDL.ToString()
                        ComputerTGTLifetimeMins         = $ComputerTGTLifetime
                        Enforce                         = $true
                        ProtectedFromAccidentalDeletion = $true
                    }
                    Write-Verbose -Message 'Creating T0_Enforce_Computers authentication policy'
                    New-ADAuthenticationPolicy @Splat

                } else {

                    Write-Verbose -Message 'T0_Enforce_Computers authentication policy already exists'

                } #end If-else

                # User Enforce
                $PolicyExists = $false
                try {
                    $PolicyExists = $null -ne (Get-ADAuthenticationPolicy -Filter "Name -eq '$EnforceUserPolicyName'" -ErrorAction Stop)
                } catch {
                    Write-Debug -Message ('Error checking policy existence: {0}' -f $_.Exception.Message)
                    $PolicyExists = $false
                } #end Try-Catch

                If (-Not $PolicyExists) {
                    $Splat = @{
                        Name                            = $EnforceUserPolicyName
                        Description                     = 'This Kerberos Authentication policy used to ENFORCE ' +
                        'interactive logon from untrusted users'
                        UserAllowedToAuthenticateFrom   = $AllowToAuthenticateFromSDDL.ToString()
                        UserAllowedToAuthenticateTo     = $AllowToAuthenticateFromSDDL.ToString()
                        UserTGTLifetimeMins             = $UserTGTLifetime
                        Enforce                         = $true
                        ProtectedFromAccidentalDeletion = $true
                    }
                    Write-Verbose -Message 'Creating T0_Enforce_Users authentication policy'
                    New-ADAuthenticationPolicy @Splat

                } else {

                    Write-Verbose -Message 'T0_Enforce_Users authentication policy already exists'

                } #end If-else

                # ServiceAccounts ENFORCE
                $PolicyExists = $false
                try {
                    $PolicyExists = $null -ne (Get-ADAuthenticationPolicy -Filter "Name -eq '$EnforceServicePolicyName'" -ErrorAction Stop)
                } catch {
                    Write-Debug -Message ('Error checking policy existence: {0}' -f $_.Exception.Message)
                    $PolicyExists = $false
                } #end Try-Catch

                If (-Not $PolicyExists) {
                    $Splat = @{
                        Name                             = $EnforceServicePolicyName
                        Description                      = 'This Kerberos Authentication policy used to ENFORCE ' +
                        'interactive logon from untrusted ServiceAccounts'
                        ServiceAllowedToAuthenticateFrom = $AllowToAuthenticateFromSDDL.ToString()
                        ServiceAllowedToAuthenticateTo   = $AllowToAuthenticateFromSDDL.ToString()
                        ServiceTGTLifetimeMins           = $ServiceTGTLifetime
                        Enforce                          = $true
                        ProtectedFromAccidentalDeletion  = $true
                    }
                    Write-Verbose -Message 'Creating T0_Enforce_ServiceAccounts authentication policy'
                    New-ADAuthenticationPolicy @Splat

                } else {

                    Write-Verbose -Message 'T0_Enforce_ServiceAccounts authentication policy already exists'

                } #end If-else
                #endregion Create ENFORCE policies

                #region Create Audit-only authentication policy silo and assigning policies
                # Update progress: Creating policy silos
                $CurrentStep++
                $ProgressSplat = @{
                    Id              = $ProgressID
                    Activity        = 'Creating Tier 0 Authentication Policies and Silos'
                    Status          = 'Step {0}/{1}: Creating authentication policy silos' -f $CurrentStep, $ProgressSteps
                    PercentComplete = ($CurrentStep / $ProgressSteps) * 100
                }
                Write-Progress @ProgressSplat
                Write-Verbose -Message 'Creating authentication policy silos'

                # Check if the audit silo already exists using filter-based query
                [bool]$SiloExists = $false
                try {
                    $SiloExists = $null -ne (Get-ADAuthenticationPolicySilo -Filter "Name -eq '$AuditingSiloName'" -ErrorAction Stop)
                } catch {
                    Write-Debug -Message ('Error checking silo existence: {0}' -f $_.Exception.Message)
                    $SiloExists = $false
                } #end Try-Catch

                if (-Not $SiloExists) {
                    try {
                        $Splat = @{
                            ComputerAuthenticationPolicy    = (Get-ADAuthenticationPolicy -Identity $AuditComputerPolicyName)
                            ServiceAuthenticationPolicy     = (Get-ADAuthenticationPolicy -Identity $AuditServicePolicyName)
                            UserAuthenticationPolicy        = (Get-ADAuthenticationPolicy -Identity $AuditUserPolicyName)
                            Description                     = 'User, Computer and Service Account Auditing Silo'
                            Name                            = $AuditingSiloName
                            ProtectedFromAccidentalDeletion = $true
                        }
                        Write-Verbose -Message 'Creating T0_AuditingSilo authentication policy silo'
                        New-ADAuthenticationPolicySilo @Splat
                    } catch {
                        Write-Error -Message ('Failed to create AuditingSilo: {0}' -f $_.Exception.Message)
                    } #end Try-Catch
                } else {
                    Write-Verbose -Message 'T0_AuditingSilo authentication policy silo already exists'
                } #end If-else
                #endregion

                #region Create Enforced authentication policy silo and assigning policies
                # Check if the enforce silo already exists using filter-based query
                $SiloExists = $false
                try {
                    $SiloExists = $null -ne (Get-ADAuthenticationPolicySilo -Filter "Name -eq '$EnforceSiloName'" -ErrorAction Stop)
                } catch {
                    Write-Debug -Message ('Error checking silo existence: {0}' -f $_.Exception.Message)
                    $SiloExists = $false
                } #end Try-Catch

                if (-Not $SiloExists) {
                    try {
                        $Splat = @{
                            ComputerAuthenticationPolicy    = (Get-ADAuthenticationPolicy -Identity $EnforceComputerPolicyName)
                            ServiceAuthenticationPolicy     = (Get-ADAuthenticationPolicy -Identity $EnforceServicePolicyName)
                            UserAuthenticationPolicy        = (Get-ADAuthenticationPolicy -Identity $EnforceUserPolicyName)
                            Description                     = 'User, Computer and Service Account Enforced Silo'
                            Name                            = $EnforceSiloName
                            Enforce                         = $true
                            ProtectedFromAccidentalDeletion = $true
                        }
                        Write-Verbose -Message 'Creating T0_EnforcedSilo authentication policy silo'
                        New-ADAuthenticationPolicySilo @Splat
                    } catch {
                        Write-Error -Message ('Failed to create EnforcedSilo: {0}' -f $_.Exception.Message)
                    } #end Try-Catch
                } else {
                    Write-Verbose -Message 'T0_EnforcedSilo authentication policy silo already exists'
                } #end If-else
                #endregion

                #region Grant access to silos and assign accounts and computers
                # Update progress: Assigning accounts and computers
                $CurrentStep++
                $ProgressSplat = @{
                    Id              = $ProgressID
                    Activity        = 'Creating Tier 0 Authentication Policies and Silos'
                    Status          = 'Step {0}/{1}: Granting access to silos and assigning accounts' -f $CurrentStep, $ProgressSteps
                    PercentComplete = ($CurrentStep / $ProgressSteps) * 100
                }
                Write-Progress @ProgressSplat
                Write-Verbose -Message 'Granting access to silos and assigning accounts and computers'

                try {
                    # Verify accounts exist
                    if ($null -eq $NewAdminName) {

                        Write-Warning -Message 'NewAdminName account not defined'

                    } else {

                        Write-Verbose -Message ('Granting {0} access to T0_AuditingSilo' -f $NewAdminName.SamAccountName)
                        Grant-ADAuthenticationPolicySiloAccess -Identity 'T0_AuditingSilo' -Account $NewAdminName.SamAccountName

                    } #end If-else

                    if ($null -eq $AdminName) {

                        Write-Warning -Message 'AdminName account not defined'

                    } else {

                        Write-Verbose -Message ('Granting {0} access to T0_AuditingSilo' -f $AdminName.SamAccountName)
                        Grant-ADAuthenticationPolicySiloAccess -Identity 'T0_AuditingSilo' -Account $AdminName.SamAccountName

                    } #end If-else

                    # Get current computer account
                    $CurrentComputer = Get-ADComputer $env:COMPUTERNAME -ErrorAction Stop
                    Write-Verbose -Message ('Granting {0} access to T0_AuditingSilo' -f $env:COMPUTERNAME)
                    Grant-ADAuthenticationPolicySiloAccess -Identity 'T0_AuditingSilo' -Account $CurrentComputer

                    # Assign accounts to silo
                    if ($null -ne $AdminName) {

                        Write-Verbose -Message ('Setting {0} to use T0_AuditingSilo' -f $AdminName.SamAccountName)
                        Set-ADUser -Identity $AdminName -AuthenticationPolicySilo 'T0_AuditingSilo'

                    } #end If

                    if ($null -ne $NewAdminName) {

                        Write-Verbose -Message ('Setting {0} to use T0_AuditingSilo' -f $NewAdminName.SamAccountName)
                        Set-ADUser -Identity $NewAdminName -AuthenticationPolicySilo 'T0_AuditingSilo'

                    } # end If

                    # Assign computer to silo
                    Write-Verbose -Message ('Setting {0} to use T0_AuditingSilo' -f $env:COMPUTERNAME)
                    Set-ADComputer -Identity $env:COMPUTERNAME -AuthenticationPolicySilo 'T0_AuditingSilo'

                } catch {

                    Write-Error -Message ('Failed to assign authentication policy silos: {0}' -f $_.Exception.Message)

                } #end Try-Catch
                #endregion

                # Return success status
                Write-Verbose -Message 'Successfully created and configured Tier 0 Authentication Policies and Silos'

            } #end If ShouldProcess

        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {

            Write-Error -Message ('Identity not found: {0}' -f $_.Exception.Message)
            throw

        } catch [Microsoft.ActiveDirectory.Management.ADException] {

            Write-Error -Message ('Active Directory error: {0}' -f $_.Exception.Message)
            throw

        } catch [System.UnauthorizedAccessException] {

            Write-Error -Message ('Access denied: {0}' -f $_.Exception.Message)
            throw

        } catch {

            Write-Error -Message ('Unexpected error: {0}' -f $_.Exception.Message)
            throw

        } #end Try-Catch

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Creating Authentication Policies and Silos for Tier 0'
            )
            Write-Verbose -Message $txt
        } #end If

        # Stop transcript if it was started
        if ($EnableTranscript) {
            try {
                Stop-Transcript -ErrorAction Stop
                Write-Verbose -Message 'Transcript stopped successfully'
            } catch {
                Write-Warning -Message ('Failed to stop transcript: {0}' -f $_.Exception.Message)
            } #end Try-Catch
        } #end If
    } #end End
} #end Function New-Tier0AuthPolicyAndSilo
