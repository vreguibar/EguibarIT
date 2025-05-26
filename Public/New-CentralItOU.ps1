function New-CentralItOu {
    <#
        .SYNOPSIS
            Creates and configures a complete Active Directory Tiered Administration model.

        .DESCRIPTION
            Creates and configures the complete Active Directory tiered administration model including:
            - Organizational Units structure following Microsoft's tier model
            - Security groups for delegated administration
            - Group Policy Objects (GPOs) with security baselines
            - Fine-grained password policies
            - Kerberos authentication policies and silos
            - Group Managed Service Accounts (gMSAs)
            - Rights delegation model across all tiers
            - Optional enterprise components (Exchange, DFS, PKI, AGPM, LAPS, DHCP)

            This function implements Microsoft's recommended three-tier administration model:
            - Tier 0: Domain Controllers and critical infrastructure
            - Tier 1: Servers and server administrators
            - Tier 2: User workstations and standard users

            The implementation provides:
            - Least-privilege security model
            - Isolated administration boundaries between tiers
            - Clear segregation of duties
            - Enhanced security for privileged accounts
            - Comprehensive auditing and monitoring

        .PARAMETER ConfigXMLFile
            Full path to the XML configuration file containing all naming conventions,
            OU structure, and security settings.
            The XML file must contain required elements: Admin, Servers, Sites, and NC sections.

        .PARAMETER CreateExchange
            If present, creates all Exchange-related objects, containers and delegations.
            Requires valid Exchange configuration in the XML file.

        .PARAMETER CreateDfs
            If present, creates all DFS-related objects, containers and delegations.
            Requires valid DFS configuration in the XML file.

        .PARAMETER CreateCa
            If present, creates Certificate Authority (PKI) objects and delegations.
            Requires valid PKI configuration in the XML file.

        .PARAMETER CreateAGPM
            If present, creates Advanced Group Policy Management objects and delegations.
            Requires valid AGPM configuration in the XML file.

        .PARAMETER CreateLAPS
            If present, creates Local Administrator Password Solution objects and delegations.
            Requires valid LAPS configuration in the XML file.

        .PARAMETER CreateDHCP
            If present, creates DHCP-related objects, containers and delegations.
            Requires valid DHCP configuration in the XML file.

        .PARAMETER DMScripts
            Path to all supporting scripts and files needed by this function.
            Must contain a SecTmpl subfolder with required templates.
            Default is C:\PsScripts\

        .EXAMPLE
            New-CentralItOu -ConfigXMLFile 'C:\PsScripts\Configuration.xml'

            Creates the basic tier model structure using the specified configuration file.

        .EXAMPLE
            New-CentralItOu -ConfigXMLFile 'C:\PsScripts\Configuration.xml' -CreateLAPS -CreateDHCP

            Creates the tier model structure including LAPS and DHCP components.

        .EXAMPLE
            # Create parameter hashtable
            $Params = @{
                ConfigXMLFile = 'C:\PsScripts\Config.xml'
                CreateExchange = $true
                CreateDfs = $true
                CreateCa = $true
                DMScripts = 'D:\AdminScripts\'
                Verbose = $true
            }

            # Create the complete AD structure
            New-CentralItOu @Params

            Creates a comprehensive tier model with Exchange, DFS and PKI components using
            a custom scripts directory and verbose output.

        .INPUTS
            [System.IO.FileInfo]
            You can pipe the path to the XML configuration file to this function.

        .OUTPUTS
            [String]
            Returns completion status message.

        .NOTES
            Used Functions:
                Name                                  ║ Module/Namespace
            ═══════════════════════════════════════╬════════════════════════
            Import-MyModule                        ║ EguibarIT
            New-Tier0CreateOU                      ║ EguibarIT
            New-Tier0MoveObject                    ║ EguibarIT
            New-Tier0AdminAccount                  ║ EguibarIT
            New-Tier0AdminGroup                    ║ EguibarIT
            New-Tier0gMSA                          ║ EguibarIT
            New-Tier0FineGrainPasswordPolicy       ║ EguibarIT
            New-Tier0NestingGroup                  ║ EguibarIT
            New-Tier0Redirection                   ║ EguibarIT
            New-Tier0Delegation                    ║ EguibarIT
            New-Tier0Gpo                           ║ EguibarIT
            New-Tier0AuthPolicyAndSilo             ║ EguibarIT
            New-Tier0GpoRestriction                ║ EguibarIT
            New-Tier1                              ║ EguibarIT
            New-Tier2                              ║ EguibarIT
            New-ExchangeObject                     ║ EguibarIT
            New-DfsObject                          ║ EguibarIT
            New-CaObject                           ║ EguibarIT
            New-AGPMObject                         ║ EguibarIT
            New-LAPSobject                         ║ EguibarIT
            New-DHCPobject                         ║ EguibarIT
            Set-AdAclMngPrivilegedAccount          ║ EguibarIT
            Set-AdAclMngPrivilegedGroup            ║ EguibarIT
            Get-FunctionDisplay                    ║ EguibarIT
            Get-SafeVariable                       ║ EguibarIT
            Get-ADUser                             ║ ActiveDirectory
            Get-ADGroup                            ║ ActiveDirectory

        .NOTES
            Version:         1.5
            DateModified:    07/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material

        .LINK
            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models

        .COMPONENT
            Active Directory

        .ROLE
            System Administrator

        .FUNCTIONALITY
            Active Directory, Security, Tier Model
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High',
        DefaultParameterSetName = 'Default'
    )]
    [OutputType([String])]

    Param (
        # PARAM1 full path to the configuration.xml file
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

        # Param2 If present It will create all needed Exchange objects, containers and delegations
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects, containers and delegations.',
            Position = 1)]
        [Alias('Exchange')]
        [switch]
        $CreateExchange,

        # Param3 Create DFS Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed DFS objects, containers and delegations.',
            Position = 2)]
        [Alias('DFS', 'DistributedFileSystem')]
        [switch]
        $CreateDfs,

        # Param4 Create CA (PKI) Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Certificate Authority (PKI) objects, containers and delegations.',
            Position = 3)]
        [Alias('PKI', 'CA', 'CertificateAuthority')]
        [switch]
        $CreateCa,

        # Param5 Create AGPM Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed AGPM objects, containers and delegations.',
            Position = 4)]
        [Alias('GPM')]
        [switch]
        $CreateAGPM,

        # Param6 Create LAPS Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed LAPS objects, containers and delegations.',
            Position = 5)]
        [switch]
        $CreateLAPS,

        # Param7 Create DHCP Objects
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed DHCP objects, containers and delegations.',
            Position = 6)]
        [switch]
        $CreateDHCP,

        # Param8 Location of all scripts & files
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
            Position = 7)]
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

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false


        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        If (-not $PSBoundParameters.ContainsKey('ConfigXMLFile')) {
            $PSBoundParameters['ConfigXMLFile'] = 'C:\PsScripts\Config.xml'
        } #end If

        If (-not $PSBoundParameters.ContainsKey('DMScripts')) {
            $PSBoundParameters['DMScripts'] = 'C:\PsScripts\'
        } #end If

        # Load the XML configuration file
        try {
            [xml]$ConfXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
            Write-Verbose -Message ('Successfully loaded configuration file: {0}' -f $PSBoundParameters['ConfigXMLFile'])
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


    } #end Begin

    Process {

        # Create splat hashtable ensuring case matches exactly with parameter name
        $Splat = @{
            ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
            DMScripts     = $PSBoundParameters['DMScripts']
            Confirm       = $false
        }

        if ($PSCmdlet.ShouldProcess('Active Directory', 'Create full tier model structure')) {

            ###############################################################################
            # Create IT Admin and Sub OUs
            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Create Admin Area and related structure...')

            # Create the IT Admin OU and sub OUs
            New-Tier0CreateOU @Splat -EnableTranscript



            ###############################################################################
            # Move Built-In Admin user & Groups (Builtin OU groups can't be moved)

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Moving objects to Admin (Tier 0)...')

            New-Tier0MoveObject @Splat -EnableTranscript



            ###############################################################################
            # Creating Secured Admin accounts

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating and securing Admin accounts...')

            New-Tier0AdminAccount @Splat -EnableTranscript


            ###############################################################################
            # Create Admin groups

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Admin groups...')

            New-Tier0AdminGroup @Splat -EnableTranscript



            ###############################################################################
            # Create Group Managed Service Account

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Create Group Managed Service Account')

            New-Tier0gMSA @Splat -EnableTranscript



            ###############################################################################
            # Create a New Fine Grained Password Policies

            Write-Verbose -Message ($Variables.NewRegionMessage -f
                'Create a New Fine Grained Password Policy for Admins Accounts...')

            New-Tier0FineGrainPasswordPolicy @Splat -EnableTranscript



            ###############################################################################
            # Nesting Groups


            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Nesting groups...')

            New-Tier0NestingGroup @Splat -EnableTranscript



            ###############################################################################
            # Enabling Management Accounts to Modify the Membership of Protected Groups

            Write-Verbose -Message ($Variables.NewRegionMessage -f
                'Enabling Management Accounts to Modify the Membership of Protected Groups...'
            )

            # ToDo: the GetSafeVariable is finding the variable, but variable has old DN. Interim fix filling the variable again
            $SL_PGM = Get-AdObjectType -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PGM.Name)

            # ToDo: the GetSafeVariable is finding the variable, but variable has old DN. Interim fix filling the variable again
            $SL_PUM = Get-AdObjectType -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PUM.Name)

            # Enable PUM to manage Privileged Accounts (Reset PWD, enable/disable Administrator built-in account)
            Set-AdAclMngPrivilegedAccount -Group $SL_PUM

            # Enable PGM to manage Privileged Groups (Administrators, Domain Admins...)
            Set-AdAclMngPrivilegedGroup -Group $SL_PGM





            ###############################################################################
            # redirect Users & Computers containers

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'redirect Users & Computers containers...')

            New-Tier0Redirection @Splat -EnableTranscript



            ###############################################################################
            # Delegation to ADMIN area (Tier 0)

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Delegate Admin Area (Tier 0)...')

            New-Tier0Delegation @Splat -EnableTranscript



            ###############################################################################
            # Create Baseline GPO

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Baseline GPOs and configure them accordingly...')

            New-Tier0Gpo @Splat -EnableTranscript

            # Configure Kerberos Claims and Authentication Policies/Silos

            New-Tier0AuthPolicyAndSilo @Splat -EnableTranscript




            ###############################################################################
            # Configure GPO Restrictions based on Tier Model

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Configure GPO Restrictions based on Tier Model...')

            New-Tier0GpoRestriction @Splat -EnableTranscript



            ###############################################################################
            # SERVERS OU (area)

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Servers Area (Tier 1)...')

            New-Tier1 @Splat -EnableTranscript



            ###############################################################################
            # Create Sites OUs (Area)

            Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Sites Area (Tier 2)...')

            New-Tier2 @Splat -EnableTranscript




            ###############################################################################
            # Check if Exchange objects have to be created. Process if TRUE
            if ($PSBoundParameters['CreateExchange']) {

                Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating Exchange On-Prem objects and delegations')

                # Get the Config.xml file
                $param = @{
                    ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                    verbose       = $true
                }

                New-ExchangeObject @param
            }

            ###############################################################################
            # Check if DFS objects have to be created. Process if TRUE
            if ($PSBoundParameters['CreateDfs']) {

                Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating DFS objects and delegations')
                # Get the Config.xml file
                $param = @{
                    ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                    verbose       = $true
                }
                New-DfsObject @param
            }

            ###############################################################################
            # Check if Certificate Authority (PKI) objects have to be created. Process if TRUE
            if ($PSBoundParameters['CreateCa']) {

                Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating CA Services, objects and delegations')

                New-CaObject -ConfigXMLFile $PSBoundParameters['ConfigXMLFile']
            }

            ###############################################################################
            # Check if Advanced Group Policy Management (AGPM) objects have to be created. Process if TRUE
            if ($PSBoundParameters['CreateAGPM']) {

                try {
                    Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating AGPM objects and delegations')

                    # Create parameter hashtable for AGPM
                    [hashtable]$AgpmParams = @{
                        ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                        Verbose       = $VerbosePreference -eq 'Continue'
                    }

                    # Execute AGPM configuration
                    New-AGPMObject $AgpmParams

                } catch {

                    Write-Error -Message ('Failed to create AGPM objects: {0}' -f $_.Exception.Message)

                } #end Try-Catch

            } #end If

            ###############################################################################
            # Check if MS Local Administrator Password Service (LAPS) is to be used. Process if TRUE
            if ($PSBoundParameters['CreateLAPS']) {
                try {

                    Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating LAPS objects and delegations')

                    # Create parameter hashtable for LAPS
                    [hashtable]$LapsParams = @{
                        ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                        Verbose       = $VerbosePreference -eq 'Continue'
                    }

                    # Execute LAPS configuration
                    New-LAPSobject @LapsParams

                } catch {

                    Write-Error -Message ('Failed to create LAPS objects: {0}' -f $_.Exception.Message)

                } #end Try-Catch

            } #end If

            ###############################################################################
            # Check if DHCP is to be used. Process if TRUE
            if ($PSBoundParameters['CreateDHCP']) {

                try {
                    Write-Verbose -Message ($Variables.NewRegionMessage -f 'Creating DHCP objects and delegations')

                    # Create parameter hashtable for DHCP
                    [hashtable]$DhcpParams = @{
                        ConfigXMLFile = $PSBoundParameters['ConfigXMLFile']
                        Verbose       = $VerbosePreference -eq 'Continue'
                    }

                    # Execute DHCP configuration
                    New-DHCPobject @DhcpParams

                } catch {

                    Write-Error -Message ('Failed to create DHCP objects: {0}' -f $_.Exception.Message)

                } #end Try-Catch

            } #end If

        } #end If ShouldProcess

    } #end Process

    End {

        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating Tier0 central IT OU structure and delegations.'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end End

} #end Function New-CentralItOu
