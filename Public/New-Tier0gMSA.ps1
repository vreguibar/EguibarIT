function New-Tier0gMSA {

    <#
        .SYNOPSIS
            Creates Tier 0 Group Managed Service Accounts in Active Directory.

        .DESCRIPTION
            This function creates the necessary Group Managed Service Accounts (gMSA) for Tier 0 operations.
            It ensures the KDS Root Key exists before creating the gMSAs. The service accounts are
            created in the designated Tier 0 Service Account OU defined in the configuration file.
            The function also adds the created gMSA to the appropriate Tier 0 security group.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            [System.String] Path to all the scripts and files needed by this function.
            The path must exist and contain a 'SecTmpl' subfolder.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0gMSA -ConfigXMLFile "C:\PsScripts\Config.xml" -Verbose

            Creates Tier 0 gMSAs as defined in the configuration file with verbose output.

        .EXAMPLE
            New-Tier0gMSA -ConfigXMLFile "C:\PsScripts\Config.xml" -DMScripts "C:\Scripts\" -WhatIf

            Shows what would happen if the command runs without actually creating the gMSAs.

        .INPUTS
            System.IO.FileInfo, System.String

        .OUTPUTS
            System.String

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Import-MyModule                            ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT
                Add-AdGroupNesting                         ║ EguibarIT
                Get-KdsRootKey                             ║ ActiveDirectory
                Add-KdsRootKey                             ║ ActiveDirectory
                Get-ADServiceAccount                       ║ ActiveDirectory
                New-ADServiceAccount                       ║ ActiveDirectory
                Set-ADServiceAccount                       ║ ActiveDirectory
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility

            Version:         1.2
            DateModified:    29/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Active Directory
            Group Managed Service Accounts

        .ROLE
            Infrastructure Administrator
            Domain Administrator

        .FUNCTIONALITY
            Group Managed Service Account Creation and Configuration
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.String])]

    param (

        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0
        )]
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
                        $null -eq $xml.n.Admin.GG -or
                        $null -eq $xml.n.Admin.gMSA -or
                        $null -eq $xml.n.Admin.OUs -or
                        $null -eq $xml.n.NC) {
                        throw 'XML file is missing required elements (Admin, GG, gMSA, OUs or NC section)'
                    }
                    return $true
                } catch {
                    throw ('Invalid XML file: {0}' -f $_.Exception.Message)
                }
            })]
        [PSDefaultValue(
            Help = 'Default Value is "C:\PsScripts\Config.xml"',
            Value = 'C:\PsScripts\Config.xml'
        )]
        [Alias('Config', 'XML', 'ConfigXml')]
        [System.IO.FileInfo]
        $ConfigXMLFile,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
            Position = 1
        )]
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
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$false)
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
            [xml]$confXML = [xml](Get-Content -Path $PSBoundParameters['ConfigXMLFile'] -ErrorAction Stop)

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

            $SG_Tier0ServiceAccount = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.T0SA.Name)

            # Set the OU DN where the gMSA will be created
            # Generate DN paths for OUs
            [string]$ItAdminOu = $ConfXML.n.Admin.OUs.ItAdminOU.name
            [string]$ItServiceAccountsOu = $ConfXML.n.Admin.OUs.ItServiceAccountsOU.name
            [string]$ItSAT0OU = $ConfXML.n.Admin.OUs.ItSAT0OU.name


            [string]$ItServiceAccountsOuDn = ('OU={0},OU={1},{2}' -f $ItServiceAccountsOu, $ItAdminOu, $Variables.AdDn)
            [string]$ItSAT0OuDn = ('OU={0},{1}' -f $ItSAT0OU, $ItServiceAccountsOuDn)

        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

    } #end Begin

    Process {

        try {
            if ($PSCmdlet.ShouldProcess('Active Directory', 'Create Tier0 Group Managed Service Accounts')) {

                #region KDS Root Key Management
                Write-Verbose -Message 'Checking if KDS Root Key exists'

                try {
                    # Check if a KDS Root Key already exists
                    $existingKey = Get-KdsRootKey -ErrorAction SilentlyContinue

                    if (-not $existingKey) {
                        Write-Verbose -Message 'No KDS Root Key found. Creating a new key.'

                        # Attempt to create the KDS Root Key based on OS version
                        if ([System.Environment]::OSVersion.Version.Build -ge 26100) {

                            # Windows Server 2022+ supports -EffectiveImmediately parameter
                            Write-Verbose -Message 'Using -EffectiveImmediately parameter for newer Windows Server version'

                            try {
                                Add-KdsRootKey -EffectiveImmediately -ErrorAction Stop
                                Write-Verbose -Message 'KDS Root Key created successfully using -EffectiveImmediately'
                            } catch {
                                # Handle specific errors
                                if ($_.Exception.Message -like '*0x80070032*') {
                                    Write-Verbose -Message 'KDS Root Key already exists (Error 0x80070032)'
                                } else {
                                    Write-Warning -Message (
                                        'Error creating KDS Root Key with EffectiveImmediately: {0}' -f
                                        $_.Exception.Message
                                    )
                                } #end If-Else
                            } #end Try-Catch

                        } else {
                            # For older versions, use backdated time approach
                            Write-Verbose -Message 'Using backdated time approach for older Windows Server versions'

                            try {
                                Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)) -ErrorAction Stop
                                Write-Verbose -Message 'KDS Root Key created successfully using backdated time'
                            } catch {
                                # Handle specific errors
                                if ($_.Exception.Message -like '*0x80070032*') {
                                    Write-Verbose -Message 'KDS Root Key already exists (Error 0x80070032)'
                                } else {
                                    Write-Warning -Message (
                                        'Error creating KDS Root Key with backdated time: {0}' -f
                                        $_.Exception.Message
                                    )
                                } #end If-Else
                            } #end Try-Catch
                        } #end If-Else

                    } else {
                        Write-Verbose -Message ('KDS Root Key already exists with ID: {0}' -f $existingKey.KeyId)
                    } #end If-Else

                    # Verify KDS Root Key exists after our operation
                    $kdsKey = Get-KdsRootKey -ErrorAction SilentlyContinue

                    if ($kdsKey) {
                        Write-Verbose -Message ('Using KDS Root Key with ID: {0}' -f $kdsKey.KeyId)
                    } else {
                        Write-Warning -Message (
                            'No KDS Root Key found after creation attempt.
                            This may indicate a replication issue or other problem.
                            Please check the domain controllers and ensure they are replicating correctly.
                            Group Managed Service Accounts may not function properly.'
                        )
                    } #end If-Else

                } catch {
                    Write-Error -Message (
                        'Unexpected error when checking or creating KDS Root Key: {0}' -f
                        $_.Exception.Message
                    )
                    # Don't throw here as we want to continue attempting gMSA creation
                } #end Try-Catch
                #endregion KDS Root Key Management

                #region gMSA Creation
                # Check if ServiceAccount exists
                $gMSASamAccountName = '{0}$' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                $AdSchedSAExists = $false

                try {
                    $ExistSA = Get-ADServiceAccount -Filter { SamAccountName -like $gMSASamAccountName } -ErrorAction Stop
                    $AdSchedSAExists = ($null -ne $ExistSA)

                    if ($AdSchedSAExists) {
                        Write-Verbose -Message ('Service Account {0} already exists with DN: {1}' -f
                            $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $ExistSA.DistinguishedName)
                    } #end If
                } catch {
                    Write-Warning -Message ('Error checking if service account exists: {0}' -f $_.Exception.Message)
                    # Continue and try to create it
                } #end Try-Catch

                if (-not $AdSchedSAExists) {
                    Write-Verbose -Message ('Creating service account: {0}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name)

                    # Create service account based on OS version
                    if ([System.Environment]::OSVersion.Version.Build -ge 9200) {
                        # Windows Server 2012 or newer
                        $Splat = @{
                            Name                   = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                            SamAccountName         = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                            DNSHostName            = ('{0}.{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN)
                            AccountNotDelegated    = $true
                            Description            = $confXML.n.Admin.gMSA.AdTaskScheduler.Description
                            DisplayName            = $confXML.n.Admin.gMSA.AdTaskScheduler.DisplayName
                            KerberosEncryptionType = 'AES128,AES256'
                            Path                   = $ItSAT0OuDn
                            Enabled                = $true
                            TrustedForDelegation   = $false
                            ServicePrincipalName   = ('HOST/{0}.{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN)
                            ErrorAction            = 'Stop'
                            PassThru               = $true
                        }

                        $ReplaceValues = @{
                            'company'           = $confXML.n.RegisteredOrg
                            'department'        = $confXML.n.Admin.gMSA.AdTaskScheduler.Department
                            'employeeID'        = 'T0'
                            'employeeType'      = 'ServiceAccount'
                            'info'              = $confXML.n.Admin.gMSA.AdTaskScheduler.Description
                            'title'             = $confXML.n.Admin.gMSA.AdTaskScheduler.DisplayName
                            'userPrincipalName' = '{0}@{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN
                        }

                        # Add optional attributes conditionally
                        if (-not [string]::IsNullOrEmpty($confXML.n.Admin.gMSA.AdTaskScheduler.c)) {
                            $ReplaceValues.Add('c', $confXML.n.Admin.gMSA.AdTaskScheduler.c)
                        }
                        if (-not [string]::IsNullOrEmpty($confXML.n.Admin.gMSA.AdTaskScheduler.co)) {
                            $ReplaceValues.Add('co', $confXML.n.Admin.gMSA.AdTaskScheduler.co)
                        }
                        if (-not [string]::IsNullOrEmpty($confXML.n.Admin.gMSA.AdTaskScheduler.l)) {
                            $ReplaceValues.Add('l', $confXML.n.Admin.gMSA.AdTaskScheduler.l)
                        }

                        try {
                            Write-Verbose -Message 'Creating gMSA with advanced properties'
                            $ExistSA = New-ADServiceAccount @Splat

                            Write-Verbose -Message 'Setting additional properties on gMSA'
                            Set-ADServiceAccount -Identity $ExistSA -Replace $ReplaceValues -ErrorAction Stop

                            Write-Verbose -Message ('Successfully created service account: {0}' -f $ExistSA.Name)
                        } catch {
                            Write-Error -Message (
                                'Error when creating AD Scheduler service account: {0}' -f
                                $_.Exception.Message
                            )
                            # Continue to try to use the account if it was created
                        } #end Try-Catch

                    } else {
                        # Older Windows Server
                        $Splat = @{
                            Name        = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                            Description = $confXML.n.Admin.gMSA.AdTaskScheduler.Description
                            Path        = $ItSAT0OuDn
                            Enabled     = $true
                            ErrorAction = 'Stop'
                            PassThru    = $true
                        }

                        try {
                            Write-Verbose -Message 'Creating gMSA with basic properties (older server version)'
                            $ExistSA = New-ADServiceAccount @Splat
                            Write-Verbose -Message ('Successfully created service account: {0}' -f $ExistSA.Name)
                        } catch {
                            Write-Error -Message (
                                'Error when creating AD Scheduler service account: {0}' -f
                                $_.Exception.Message
                            )
                            # Continue to try to use the account if it was created
                        } #end Try-Catch
                    } #end If-Else
                } else {
                    Write-Warning -Message (
                        'Service Account {0} already exists.' -f
                        $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                    )
                } #end If-Else
                #endregion gMSA Creation

                #region gMSA Configuration
                # Ensure the gMSA is retrieved for configuration
                if ($null -eq $ExistSA) {
                    try {
                        Write-Verbose -Message 'Retrieving the service account for configuration'
                        $ExistSA = Get-ADServiceAccount -Filter { SamAccountName -like $gMSASamAccountName } -ErrorAction Stop

                        if ($null -eq $ExistSA) {
                            throw 'Service account not found'
                        }
                    } catch {
                        Write-Error -Message (
                            'Cannot retrieve service account {0} for configuration: {1}' -f
                            $gMSASamAccountName, $_.Exception.Message
                        )
                        throw
                    }
                }

                # Ensure the gMSA is member of Tier0 ServiceAccount group
                try {
                    Write-Verbose -Message (
                        'Adding {0} to Tier0 service account group {1}' -f
                        $ExistSA.SamAccountName, $SG_Tier0ServiceAccount
                    )

                    Add-AdGroupNesting -Identity $SG_Tier0ServiceAccount -Members $ExistSA -ErrorAction Stop
                    Write-Verbose -Message 'Successfully added gMSA to Tier0 service account group'
                } catch {
                    Write-Error -Message ('Error adding gMSA to Tier0 service account group: {0}' -f $_.Exception.Message)
                }

                # Configure gMSA so all members of group "Domain Controllers" can retrieve the password
                try {

                    $Splat = @{
                        Identity                                   = $ExistSA
                        PrincipalsAllowedToRetrieveManagedPassword = 'Domain Controllers'
                        ErrorAction                                = 'Stop'
                    }
                    Set-ADServiceAccount @Splat
                    Write-Verbose -Message 'Successfully configured principals allowed to retrieve managed password'
                } catch {
                    Write-Error -Message (
                        'Error configuring principals allowed to retrieve managed password: {0}' -f
                        $_.Exception.Message
                    )
                }
                #endregion gMSA Configuration

                # Return the service account
                return $ExistSA.DistinguishedName
            } #end If ShouldProcess
        } catch {
            Write-Error -Message ('Error in New-Tier0gMSA: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Create Tier0 Group Managed Service Accounts.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function New-Tier0gMSA
