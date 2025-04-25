function New-DelegateAdOU {
    <#
        .Synopsis
            Creates new custom delegated Active Directory Organizational Unit.

        .DESCRIPTION
            Creates a new Organizational Unit (OU) in Active Directory with enhanced security
            and delegation settings. Key features:
            - Creates new OU with specified attributes
            - Removes built-in groups like Account Operators and Print Operators
            - Optionally removes Authenticated Users
            - Supports cleaning ACLs and inheritance settings
            - Implements security best practices
            - Supports location-based attributes

        .PARAMETER ouName
            [String] Name of the OU. Must be 2-50 characters.

        .PARAMETER ouPath
            [String] LDAP path where this OU will be created.
            Must be a valid Distinguished Name path.

        .PARAMETER ouDescription
            [String] Full description of the OU.
            Supports detailed descriptions of OU purpose.

        .PARAMETER ouCity
            [String] City location for the OU.

        .PARAMETER ouCountry
            [String] Country location for the OU.

        .PARAMETER ouStreetAddress
            [String] Street address for the OU location.

        .PARAMETER ouState
            [String] State/Province for the OU location.

        .PARAMETER ouZIPCode
            [String] Postal/ZIP code for the OU location.

        .PARAMETER strOuDisplayName
            [String] Display name for the OU. Defaults to ouName if not specified.

        .PARAMETER RemoveAuthenticatedUsers
            [Switch] Remove Authenticated Users group.
            CAUTION: This might affect GPO application to objects.

        .PARAMETER CleanACL
            [Switch] Remove specific non-inherited ACEs and enable inheritance.

        .EXAMPLE
            New-DelegateAdOU -ouName "T0-Admins" `
                        -ouPath "OU=Admin,DC=EguibarIT,DC=local" `
                        -ouDescription "Tier 0 Admin Objects" `
                        -CleanACL

        Creates a new Tier 0 admin OU with cleaned ACLs.

        .EXAMPLE
            $Splat = @{
                ouPath        = 'OU=GOOD,OU=Sites,DC=EguibarIT,DC=local'
                CleanACL      = $True
                ouName        = 'Computers'
                ouDescription = 'Container for the secure computers'
            }
            New-DelegateAdOU @Splat

            Creates a new OU for remote sites with location attributes.

        .OUTPUTS
            [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]
            Returns the created OU object.

        .NOTES
            Used Functions:
                Name                                  ║ Module
                ══════════════════════════════════════╬════════════════════════
                Get-AdOrganizationalUnit              ║ ActiveDirectory
                New-ADOrganizationalUnit              ║ ActiveDirectory
                Start-AdCleanOU                       ║ EguibarIT
                Revoke-Inheritance                    ║ EguibarIT
                Remove-AuthUser                       ║ EguibarIT.DelegationPS
                Write-Verbose                         ║ Microsoft.PowerShell.Utility
                Write-Warning                         ║ Microsoft.PowerShell.Utility
                Write-Error                           ║ Microsoft.PowerShell.Utility

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
            https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/implementing-least-privilege-administrative-models

    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]

    # https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management?view=activedirectory-management-10.0
    [OutputType([Microsoft.ActiveDirectory.Management.ADOrganizationalUnit])]

    Param (
        # Param1 Site Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the OU (2-50 characters)',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(2, 50)]
        [ValidatePattern(
            '^[a-zA-Z0-9\s\-_]+$',
            ErrorMessage = 'OU name can only contain letters, numbers, spaces, hyphens and underscores'
        )]
        [string]
        $ouName,

        # Param2 OU DistinguishedName (Path)
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'LDAP path where this ou will be created',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName', 'LDAPpath')]
        [string]
        $ouPath,

        # Param3 OU Description
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full description of the OU',
            Position = 2)]
        [string]
        $ouDescription,

        # Param4 OU City
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 3)]
        [string]
        $ouCity,

        # Param5 OU Country
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 4)]
        [string]
        $ouCountry,

        # Param6 OU Street Address
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 5)]
        [string]
        $ouStreetAddress,

        # Param7 OU State
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 6)]
        [string]
        $ouState,

        # Param8 OU Postal Code
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 7)]
        [string]
        $ouZIPCode,

        # Param9 OU Display Name
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 8)]
        [string]
        $strOuDisplayName,

        #PARAM10 Remove Authenticated Users
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Remove Authenticated Users. CAUTION! This might affect applying GPO to objects.',
            Position = 9)]
        [switch]
        $RemoveAuthenticatedUsers,

        #PARAM11 Remove Specific Non-Inherited ACE and enable inheritance
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Remove Specific Non-Inherited ACE and enable inheritance.',
            Position = 10)]
        [switch]
        $CleanACL

    )

    Begin {
        Set-StrictMode -Version Latest

        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToShortDateString(),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Module imports

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false


        ##############################
        # Variables Definition

        # Sites OU Distinguished Name
        $ouNameDN = 'OU={0},{1}' -f $PSBoundParameters['ouName'], $PSBoundParameters['ouPath']

        $OUexists = [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]::New()
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    } #end Begin

    Process {
        #
        if (-not $strOuDisplayName) {
            $strOuDisplayName = $PSBoundParameters['ouName']
        } # End If

        try {
            # Check if OU exists
            Write-Debug -Message ('Checking for existing OU: {0}' -f $ouNameDN)

            $Splat = @{
                Filter      = { distinguishedName -eq $ouNameDN }
                SearchBase  = $Variables.AdDn
                ErrorAction = 'SilentlyContinue'
            }
            $OUexists = Get-ADOrganizationalUnit @Splat

            # Check if OU exists
            If ($OUexists) {
                # OU it does exists
                Write-Warning -Message ('Organizational Unit {0} already exists. Exit the script.' -f $ouNameDN)
                return
            } #end If

            if ($PSCmdlet.ShouldProcess("Creating the Organizational Unit '$OuName'")) {
                Write-Verbose -Message ('Creating the {0} Organizational Unit' -f $PSBoundParameters['ouName'])
                # Create    OU
                $Splat = @{
                    Name                            = $ouName
                    Path                            = $PSBoundParameters['ouPath']
                    ProtectedFromAccidentalDeletion = $true
                }

                # Add optional parameters if specified
                $optionalParams = @{
                    City          = 'ouCity'
                    Country       = 'ouCountry'
                    Description   = 'ouDescription'
                    DisplayName   = 'strOuDisplayName'
                    PostalCode    = 'ouZIPCode'
                    StreetAddress = 'ouStreetAddress'
                    State         = 'ouState'
                }

                foreach ($param in $optionalParams.GetEnumerator()) {

                    if ($PSBoundParameters.ContainsKey($param.Value)) {

                        $Splat[$param.Key] = $PSBoundParameters[$param.Value]

                    } #end If
                } #end Foreach

                # Create the OU
                $OUexists = New-ADOrganizationalUnit @Splat
            }

        } catch {

            Write-Error -Message ('Error creating OU: {0}' -f $_)
            throw

        } #end Try-Catch

        # Remove "Account Operators" and "Print Operators" built-in groups from OU. Any unknown/UnResolvable SID will be removed.
        Write-Debug -Message ('Cleaning OU permissions: {0}' -f $ouNameDN)
        Start-AdCleanOU -LDAPpath $ouNameDN -RemoveUnknownSIDs -Force -Confirm:$false

        # Handle ACL cleaning if requested
        if ($CleanACL) {

            Write-Verbose -Message ('Cleaning ACL inheritance: {0}' -f $ouNameDN)
            Revoke-Inheritance -LDAPpath $ouNameDN -RemoveInheritance -KeepPermissions

        } #end If

        # Remove Authenticated Users if requested
        if ($RemoveAuthenticatedUsers) {

            Write-Verbose -Message ('Removing Authenticated Users from: {0}' -f $ouNameDN)
            Remove-AuthUser -LDAPPath $ouNameDN

        } #end If
    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating new delegated OU.'
            )
            Write-Verbose -Message $txt
        } #end If

        return $OUexists
    } #end End
} #end Function New-DelegateAdOU
