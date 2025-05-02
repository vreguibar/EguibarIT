function New-Tier0AdminAccount {

    <#
        .SYNOPSIS
            Creates and secures Tier0 administrative accounts.

        .DESCRIPTION
            This function creates or updates a new Tier0 administrative account,
            making it member of administrative groups, securing it properly,
            and configuring security attributes according to best practices.
            It also secures the built-in Administrator account.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMscripts
            [System.String] Path to all the scripts and files needed by this function.
            Must contain a SecTmpl subfolder and may contain a Pic subfolder for user pictures.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0AdminAccount -ConfigXMLFile C:\PsScripts\Config.xml
            Creates or updates Tier0 admin accounts using the specified configuration file.

        .EXAMPLE
            New-Tier0AdminAccount -ConfigXMLFile C:\PsScripts\Config.xml -DMscripts C:\Scripts
            Creates or updates Tier0 admin accounts using the specified configuration file and scripts path.

        .INPUTS
            [System.IO.FileInfo]
            [System.String]

        .OUTPUTS
            [System.Void]

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Import-MyModule                            ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT
                Add-AdGroupNesting                         ║ EguibarIT
                Remove-Everyone                            ║ EguibarIT.DelegationPS
                Remove-PreWin2000                          ║ EguibarIT.DelegationPS
                Get-ADUser                                 ║ ActiveDirectory
                Get-ADGroup                                ║ ActiveDirectory
                Set-ADUser                                 ║ ActiveDirectory
                New-ADUser                                 ║ ActiveDirectory
                Move-ADObject                              ║ ActiveDirectory
                Set-ADObject                               ║ ActiveDirectory

        .NOTES
            Version:         1.0
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
            User Management, Security Hardening
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.Void])]

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
                        $null -eq $xml.n.Admin.Users -or
                        $null -eq $xml.n.Admin.OUs -or
                        $null -eq $xml.n.RegisteredOrg -or
                        $null -eq $xml.n.DefaultPassword -or
                        $null -eq $xml.n.NC) {
                        throw 'XML file is missing required elements
                        (Admin, Users, OUs, RegisteredOwner, DefaultPassword or NC section)'
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
        $DMscripts

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

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Define current domain controller
        [string]$CurrentDC = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().FindDomainController().Name

        # Load the XML configuration file
        try {
            [xml]$ConfXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        # Set admin names
        [string]$AdminName = $ConfXML.n.Admin.users.Admin.Name
        [string]$NewAdminName = $ConfXML.n.Admin.users.NEWAdmin.Name

        # Get the AD Objects by Well-Known SID
        try {
            # Administrator
            $AdminName = Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
            # Domain Admins
            $DomainAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-512' }
            # Enterprise Admins
            $EnterpriseAdmins = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-519' }
            # Group Policy Creators Owner
            $GPOCreatorsOwner = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-520' }
            # Denied RODC Password Replication Group
            $DeniedRODC = Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-572' }
        } catch {
            Write-Error -Message ('Error initializing security principals: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        # Generate DN paths for OUs
        [string]$ItAdminOu = $ConfXML.n.Admin.OUs.ItAdminOU.name
        [string]$ItAdminAccountsOu = $ConfXML.n.Admin.OUs.ItAdminAccountsOU.name
        [string]$ItAdminAccountsOuDn = ('OU={0},OU={1},{2}' -f $ItAdminAccountsOu, $ItAdminOu, $Variables.AdDn)

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Active Directory Identity', 'Create and Secure Tier0 Admin Accounts')) {

            # Try to get the new Admin
            $NewAdminExists = Get-ADUser -Filter { SamAccountName -eq $NewAdminName } -ErrorAction SilentlyContinue

            # Get picture if exist. Use default if not.
            if (Test-Path -Path ('{0}\Pic\{1}.jpg' -f $PSBoundParameters['DMscripts'], $NewAdminName)) {
                # Read the path and file name of JPG picture
                $PhotoFile = '{0}\Pic\{1}.jpg' -f $PSBoundParameters['DMscripts'], $NewAdminName
                # Get the content of the JPG file
                [byte[]]$Photo = [System.IO.File]::ReadAllBytes($PhotoFile)
            } else {
                if (Test-Path -Path ('{0}\Pic\Default.jpg' -f $PSBoundParameters['DMscripts'])) {
                    # Read the path and file name of JPG picture
                    $PhotoFile = '{0}\Pic\Default.jpg' -f $PSBoundParameters['DMscripts']

                    # Get the content of the JPG file
                    [byte[]]$Photo = [System.IO.File]::ReadAllBytes($PhotoFile)
                } else {
                    $Photo = $null
                } #end If-Else

            } #end If-Else

            # Check if the new Admin account already exist. If not, then create it.
            if ($NewAdminExists) {
                # The user was found. Proceed to modify it accordingly.
                $Splat = @{
                    Enabled              = $true
                    UserPrincipalName    = ('{0}@{1}' -f $NewAdminName, $env:USERDNSDOMAIN)
                    SamAccountName       = $NewAdminName
                    DisplayName          = $NewAdminName
                    Description          = $ConfXML.n.Admin.users.NEWAdmin.description
                    employeeId           = '0123456'
                    TrustedForDelegation = $false
                    AccountNotDelegated  = $true
                    Company              = $ConfXML.n.RegisteredOrg
                    Country              = 'MX'
                    Department           = $ConfXML.n.Admin.users.NEWAdmin.department
                    State                = 'Puebla'
                    EmailAddress         = ('{0}@{1}' -f $NewAdminName, $env:USERDNSDOMAIN)
                    Replace              = @{
                        'employeeType'                  = $ConfXML.n.NC.AdminAccSufix0
                        'msNpAllowDialin'               = $false
                        'msDS-SupportedEncryptionTypes' = '24'
                    }
                }

                # If photo exist, add it to parameters
                if ($Photo) {
                    # Only if photo exists, add it to splatting
                    $Splat.Replace.Add('thumbnailPhoto', $Photo)
                } #end If

                # Update the existing admin user
                Set-ADUser -Identity $NewAdminName @Splat
            } else {
                # User was not Found! create new.
                $Splat = @{
                    Path                  = $ItAdminAccountsOuDn
                    Name                  = $NewAdminName
                    AccountPassword       = (ConvertTo-SecureString -String $ConfXML.n.DefaultPassword -AsPlainText -Force)
                    ChangePasswordAtLogon = $false
                    Enabled               = $true
                    UserPrincipalName     = ('{0}@{1}' -f $NewAdminName, $env:USERDNSDOMAIN)
                    SamAccountName        = $NewAdminName
                    DisplayName           = $NewAdminName
                    Description           = $ConfXML.n.Admin.users.NEWAdmin.description
                    employeeId            = $ConfXML.n.Admin.users.NEWAdmin.employeeId
                    TrustedForDelegation  = $false
                    AccountNotDelegated   = $true
                    Company               = $ConfXML.n.RegisteredOrg
                    Country               = $ConfXML.n.Admin.users.NEWAdmin.Country
                    Department            = $ConfXML.n.Admin.users.NEWAdmin.department
                    State                 = $ConfXML.n.Admin.users.NEWAdmin.State
                    EmailAddress          = ('{0}@{1}' -f $NewAdminName, $env:USERDNSDOMAIN)
                    OtherAttributes       = @{
                        'employeeType'                  = $ConfXML.n.NC.AdminAccSufix0
                        'msNpAllowDialin'               = $false
                        'msDS-SupportedEncryptionTypes' = '24'
                    }
                }

                if ($Photo) {
                    # Only if photo exists, add it to splatting
                    $Splat.OtherAttributes.Add('thumbnailPhoto', $Photo)
                } #end If

                # Create the new Admin with special values
                try {
                    New-ADUser @Splat
                } catch {
                    Write-Error -Message ('Error when creating new Admin account: {0}' -f $_.Exception.Message)
                    throw

                } #end Try-Catch

                # Note on encryption types:
                # msDS-SupportedEncryptionTypes:
                # Kerberos DES Encryption = 2
                # Kerberos AES 128 = 8
                # Kerberos AES 256 = 16
                # Value 24 = AES 128 + AES 256
            } #end If-Else new user created

            # Move AD object to proper OU
            Get-ADUser -Identity $NewAdminName | Move-ADObject -TargetPath $ItAdminAccountsOuDn -Server $CurrentDC

            # Refresh object
            $Splat = @{
                Name  = 'NewAdminExists'
                Value = (Get-ADUser -Identity $newAdminName)
                Scope = 'Global'
                Force = $true
            }
            New-Variable @Splat

            # Set the Protect against accidental deletions attribute
            # Identity ONLY accepts DistinguishedName or GUID -- DN fails I don't know why
            Set-ADObject -Identity $AdminName.ObjectGUID -ProtectedFromAccidentalDeletion $true
            Set-ADObject -Identity $NewAdminExists.ObjectGUID -ProtectedFromAccidentalDeletion $true

            # Make it member of administrative groups
            Add-AdGroupNesting -Identity $DomainAdmins -Members $NewAdminExists
            Add-AdGroupNesting -Identity $EnterpriseAdmins -Members $NewAdminExists
            Add-AdGroupNesting -Identity $GPOCreatorsOwner -Members $NewAdminExists
            Add-AdGroupNesting -Identity $DeniedRODC -Members $NewAdminExists

            # Security hardening
            # http://blogs.msdn.com/b/muaddib/archive/2013/12/30/how-to-modify-security-inheritance-on-active-directory-objects.aspx

            ####
            # Remove Everyone group from Admin-User & Administrator
            Remove-Everyone -LDAPpath $NewAdminExists.DistinguishedName
            Remove-Everyone -LDAPpath $AdminName.DistinguishedName

            ####
            # Remove AUTHENTICATED USERS group from Admin-User & Administrator
            # Uncomment if needed
            #Remove-AuthUser -LDAPPath $NewAdminExists.DistinguishedName
            #Remove-AuthUser -LDAPPath ('CN={0},{1}' -f $AdminName, $ItAdminAccountsOuDn)

            ####
            # Remove Pre-Windows 2000 Compatible Access group from Admin-User & Administrator
            Remove-PreWin2000 -LDAPpath $NewAdminExists.DistinguishedName
            Remove-PreWin2000 -LDAPpath $AdminName.DistinguishedName

            # Configure the built-in Administrator account
            $Params = @{
                'employeeType'                  = $ConfXML.n.NC.AdminAccSufix0
                'msNpAllowDialin'               = $false
                'msDS-SupportedEncryptionTypes' = 24
            }

            # Get picture for built-in Administrator if exists
            if (Test-Path -Path ('{0}\Pic\{1}.jpg' -f $PSBoundParameters['DMscripts'], $AdminName.SamAccountName)) {
                # Read the path and file name of JPG picture
                $PhotoFile = '{0}\Pic\{1}.jpg' -f $PSBoundParameters['DMscripts'], $AdminName.SamAccountName

                # Get the content of the JPG file
                [byte[]]$Photo = [System.IO.File]::ReadAllBytes($PhotoFile)
            } #end If

            if ($Photo) {
                # Only if photo exists, add it to splatting
                $Params.Add('thumbnailPhoto', $Photo)
            } #end If

            # Apply settings to the built-in Administrator account
            $Splat = @{
                Identity             = $AdminName
                TrustedForDelegation = $false
                AccountNotDelegated  = $true
                Add                  = $Params
                Server               = $CurrentDC
            }
            Set-ADUser @Splat

        } #end If ShouldProcess

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Create and Secure Tier0 Admin Accounts.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function New-Tier0AdminAccount
