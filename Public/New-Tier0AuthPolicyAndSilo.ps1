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
                Get-FunctionDisplay                        ║ EguibarIT

        .NOTES
            Version:         1.0
            DateModified:    30/Apr/2025
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

        # Parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

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
            Write-Verbose -Message ('Successfully loaded configuration XML from: {0}' -f $PSBoundParameters['ConfigXMLFile'])
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


        # Get SID information for PAWs and Infrastructure Servers
        try {
            # Verify that required security principal information is available
            if ($null -eq $SL_PAWs) {
                Write-Verbose -Message 'SL_PAWs variable not found, attempting to retrieve from configuration'

                $SL_PAWs = Get-AdObjectType -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PAWs.name)

            } #end If

            if ($null -eq $SL_InfrastructureServers) {
                Write-Verbose -Message 'SL_InfrastructureServers variable not found, attempting to retrieve from configuration'

                $InfrastructureServers = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraServers.name

                $SL_InfrastructureServers = Get-AdObjectType -Identity $InfrastructureServers

            } #end If

            if ($null -eq $AdminName) {
                Write-Verbose -Message 'AdminName variable not found, attempting to retrieve from configuration'

                $AdminName = Get-AdObjectType -Identity $confXML.n.Admin.Users.Admin.name

            } #end If

            if ($null -eq $NewAdminExists) {
                Write-Verbose -Message 'NewAdminExists variable not found, attempting to retrieve from configuration'

                $NewAdminExists = Get-AdObjectType -Identity $confXML.n.Admin.Users.NEWAdmin.name

            } #end If

        } catch {

            Write-Warning -Message ('Error retrieving security principal information: {0}' -f $_.Exception.Message)

        } #end Try-Catch

    } #end Begin

    Process {

        try {
            # Configure Kerberos Claims and Authentication Policies/Silos
            if ($PSCmdlet.ShouldProcess('Active Directory Security', 'Create Authentication Policies and Silos')) {

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

                # Build SDDL

                # Add Owner SYSTEM
                $AllowToAutenticateFromSDDL = 'O:SY'

                # Add PrimaryGroup Administrators
                $AllowToAutenticateFromSDDL += 'G:SY'

                # Add DACL with Enterprise Domain Controllers (ED) SID and dynamic group SIDs
                $AllowToAuthenticateFromSDDL += 'D:(XA;OICI;CR;;;WD;'  # Start DACL

                # Add Enterprise Domain Controllers (ED)
                $AllowToAuthenticateFromSDDL += '(Member_of_any {SID(ED)})'

                # Add our groups using OR (||)
                $AllowToAuthenticateFromSDDL += " || (Member_of_any {SID($($SL_PAWs.SID.value))})"
                $AllowToAuthenticateFromSDDL += " || (Member_of_any {SID($($SL_InfrastructureServers.SID.value))}))"

                #region Create AuditOnly Policies
                Write-Verbose -Message 'Creating AuditOnly authentication policies'

                # Computer AUDIT
                If (-Not (Get-ADAuthenticationPolicy -Identity $AuditComputerPolicyName -ErrorAction SilentlyContinue)) {

                    $Splat = @{
                        Name                            = $AuditComputerPolicyName
                        Description                     = 'This Kerberos Authentication policy used to AUDIT computer logon ' +
                        'from untrusted computers'
                        ComputerAllowedToAuthenticateTo = $AllowToAutenticateFromSDDL
                        ComputerTGTLifetimeMins         = $ComputerTGTLifetime
                        ProtectedFromAccidentalDeletion = $true
                    }
                    Write-Verbose -Message 'Creating T0_AuditOnly_Computers authentication policy'
                    New-ADAuthenticationPolicy @Splat

                } else {

                    Write-Verbose -Message 'T0_AuditOnly_Computers authentication policy already exists'

                } #end If-else

                # User AUDIT
                If (-Not (Get-ADAuthenticationPolicy -Identity $AuditUserPolicyName -ErrorAction SilentlyContinue)) {

                    $Splat = @{
                        Name                            = $AuditUserPolicyName
                        Description                     = 'This Kerberos Authentication policy used to AUDIT interactive logon ' +
                        'from untrusted users'
                        UserAllowedToAuthenticateFrom   = $AllowToAutenticateFromSDDL
                        UserAllowedToAuthenticateTo     = $AllowToAutenticateFromSDDL
                        UserTGTLifetimeMins             = $UserTGTLifetime
                        ProtectedFromAccidentalDeletion = $true
                    }
                    Write-Verbose -Message 'Creating T0_AuditOnly_Users authentication policy'
                    New-ADAuthenticationPolicy @Splat

                } else {

                    Write-Verbose -Message 'T0_AuditOnly_Users authentication policy already exists'

                } #end If-else

                # ServiceAccounts AUDIT
                If (-Not (Get-ADAuthenticationPolicy -Identity $AuditServicePolicyName -ErrorAction SilentlyContinue)) {

                    $Splat = @{
                        Name                             = $AuditServicePolicyName
                        Description                      = 'This Kerberos Authentication policy used to AUDIT ServiceAccount ' +
                        'logon from untrusted Service Accounts'
                        ServiceAllowedToAuthenticateFrom = $AllowToAutenticateFromSDDL
                        ServiceAllowedToAuthenticateTo   = $AllowToAutenticateFromSDDL
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
                Write-Verbose -Message 'Creating Enforcement authentication policies'

                # Computer ENFORCE
                If (-Not (Get-ADAuthenticationPolicy -Identity $EnforceComputerPolicyName -ErrorAction SilentlyContinue)) {

                    $Splat = @{
                        Name                            = $EnforceComputerPolicyName
                        Description                     = 'This Kerberos Authentication policy used to ENFORCE ' +
                        'interactive logon from untrusted computers'
                        ComputerAllowedToAuthenticateTo = $AllowToAutenticateFromSDDL
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
                If (-Not (Get-ADAuthenticationPolicy -Identity $EnforceUserPolicyName -ErrorAction SilentlyContinue)) {

                    $Splat = @{
                        Name                            = $EnforceUserPolicyName
                        Description                     = 'This Kerberos Authentication policy used to ENFORCE ' +
                        'interactive logon from untrusted users'
                        UserAllowedToAuthenticateFrom   = $AllowToAutenticateFromSDDL
                        UserAllowedToAuthenticateTo     = $AllowToAutenticateFromSDDL
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
                If (-Not (Get-ADAuthenticationPolicy -Identity $EnforceServicePolicyName -ErrorAction SilentlyContinue)) {

                    $Splat = @{
                        Name                             = $EnforceServicePolicyName
                        Description                      = 'This Kerberos Authentication policy used to ENFORCE ' +
                        'interactive logon from untrusted ServiceAccounts'
                        ServiceAllowedToAuthenticateFrom = $AllowToAutenticateFromSDDL
                        ServiceAllowedToAuthenticateTo   = $AllowToAutenticateFromSDDL
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
                Write-Verbose -Message 'Creating authentication policy silos'

                try {
                    # Check if the silo already exists
                    if (-Not (Get-ADAuthenticationPolicySilo -Identity $AuditingSiloName -ErrorAction SilentlyContinue)) {

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

                    } else {
                        Write-Verbose -Message 'T0_AuditingSilo authentication policy silo already exists'

                    } #end If-else

                } catch {

                    Write-Error -Message ('Failed to create AuditingSilo: {0}' -f $_.Exception.Message)

                } #end Try-Catch
                #endregion

                #region Create Enforced authentication policy silo and assigning policies
                try {
                    # Check if the silo already exists
                    if (-Not (Get-ADAuthenticationPolicySilo -Identity $EnforceSiloName -ErrorAction SilentlyContinue)) {

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

                    } else {

                        Write-Verbose -Message 'T0_EnforcedSilo authentication policy silo already exists'

                    } #end If-else

                } catch {

                    Write-Error -Message ('Failed to create EnforcedSilo: {0}' -f $_.Exception.Message)

                } #end Try-Catch
                #endregion

                #region Grant access to silos and assign accounts and computers
                Write-Verbose -Message 'Granting access to silos and assigning accounts and computers'

                try {
                    # Verify accounts exist
                    if ($null -eq $NewAdminExists) {

                        Write-Warning -Message 'NewAdminExists account not defined'

                    } else {

                        Write-Verbose -Message ('Granting {0} access to T0_AuditingSilo' -f $NewAdminExists.SamAccountName)
                        Grant-ADAuthenticationPolicySiloAccess -Identity 'T0_AuditingSilo' -Account $NewAdminExists.SamAccountName

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

                    if ($null -ne $NewAdminExists) {

                        Write-Verbose -Message ('Setting {0} to use T0_AuditingSilo' -f $NewAdminExists.SamAccountName)
                        Set-ADUser -Identity $NewAdminExists -AuthenticationPolicySilo 'T0_AuditingSilo'

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
    } #end End
} #end Function New-Tier0AuthPolicyAndSilo
