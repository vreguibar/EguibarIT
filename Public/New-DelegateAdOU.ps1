function New-DelegateAdOU {
    <#
        .Synopsis
            Create New custom delegated AD OU
        .DESCRIPTION
            Create New custom delegated AD OU, and remove
            some groups as Account Operators and Print Operators
        .EXAMPLE
            New-DelegateAdOU OuName OuPath OuDescription ...
        .EXAMPLE
            $Splat = @{
                ouPath        = 'OU=GOOD,OU=Sites,DC=EguibarIT,DC=local'
                CleanACL      = $True
                ouName        = 'Computers'
                ouDescription = 'Container for the secure computers'
            }
            New-DelegateAdOU @Splat
        .PARAMETER ouName
            [STRING] Name of the OU
        .PARAMETER ouPath
            [STRING] LDAP path where this ou will be created
        .PARAMETER ouDescription
            [STRING] Full description of the OU
        .PARAMETER ouCity
        .PARAMETER ouCountry
        .PARAMETER ouStreetAddress
        .PARAMETER ouState
        .PARAMETER ouZIPCode
        .PARAMETER strOuDisplayName
        .PARAMETER RemoveAuthenticatedUsers
            [Switch] Remove Authenticated Users. CAUTION! This might affect applying GPO to objects.
        .PARAMETER CleanACL
            [Switch] Remove Specific Non-Inherited ACE and enable inheritance.
        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-CurrentErrorToDisplay              | EguibarIT
                Get-AdOrganizationalUnit               | EguibarIT
                Start-AdCleanOU                        | EguibarIT
                Remove-SpecificACLandEnableInheritance | EguibarIT
        .NOTES
            Version:         1.2
            DateModified:    01/Feb/2017
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]

    # https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management?view=activedirectory-management-10.0
    [OutputType([Microsoft.ActiveDirectory.Management.ADOrganizationalUnit])]

    Param (
        # Param1 Site Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the OU',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(2, 50)]
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
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ })]
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
        $error.Clear()

        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-Module -Name 'EguibarIT.DelegationPS' -SkipEditionCheck -Force -Verbose:$false | Out-Null


        ##############################
        # Variables Definition

        # Sites OU Distinguished Name
        $ouNameDN = 'OU={0},{1}' -f $PSBoundParameters['ouName'], $PSBoundParameters['ouPath']

        $OUexists = [Microsoft.ActiveDirectory.Management.ADOrganizationalUnit]::New()
        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
    } #end Begin

    Process {
        #
        if (-not $strOuDisplayName) {
            $strOuDisplayName = $PSBoundParameters['ouName']
        } # End If

        try {
            # Try to get Ou
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
            } else {
                Write-Verbose -Message ('Creating the {0} Organizational Unit' -f $PSBoundParameters['ouName'])
                # Create    OU
                $Splat = @{
                    Name                            = $ouName
                    Path                            = $PSBoundParameters['ouPath']
                    ProtectedFromAccidentalDeletion = $true
                }

                if ($PSBoundParameters['ouCity']) {
                    $Splat.City = $PSBoundParameters['ouCity']
                }
                if ($PSBoundParameters['ouCountry']) {
                    $Splat.Country = $PSBoundParameters['ouCountry']
                }
                if ($PSBoundParameters['ouDescription']) {
                    $Splat.Description = $PSBoundParameters['ouDescription']
                }
                if ($PSBoundParameters['strOuDisplayName']) {
                    $Splat.DisplayName = $PSBoundParameters['strOuDisplayName']
                }
                if ($PSBoundParameters['ouZIPCode']) {
                    $Splat.PostalCode = $PSBoundParameters['ouZIPCode']
                }
                if ($PSBoundParameters['ouStreetAddress']) {
                    $Splat.StreetAddress = $PSBoundParameters['ouStreetAddress']
                }
                if ($PSBoundParameters['ouState']) {
                    $Splat.State = $PSBoundParameters['ouState']
                }

                if ($PSCmdlet.ShouldProcess("Creating the Organizational Unit '$OuName'")) {
                    $OUexists = New-ADOrganizationalUnit @Splat
                }
            } #end If-Else
        } catch {
            Write-Error -Message ('Error creating OU: {0}' -f $_)
            ###Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } #end Try-Catch

        # Remove "Account Operators" and "Print Operators" built-in groups from OU. Any unknown/UnResolvable SID will be removed.
        Start-AdCleanOU -LDAPpath $ouNameDN -RemoveUnknownSIDs

        try {
            if ($PSBoundParameters['CleanACL']) {
                if ($PSCmdlet.ShouldProcess("Removing specific Non-Inherited ACE and enabling inheritance for '$OuName'")) {
                    #Remove-SpecificACLandEnableInheritance -LDAPpath $ouNameDN
                    Revoke-Inheritance -LDAPpath $ouNameDN -RemoveInheritance -KeepPermissions
                }
            } #end If
        } catch {
            Write-Error -Message ('Error cleaning ACL: {0}' -f $_)
            throw
        } #end Try-Catch
    } #end Process

    End {
        $txt = ($Constants.Footer -f $MyInvocation.InvocationName,
            'creating new delegated OU.'
        )
        Write-Verbose -Message $txt

        return $OUexists
    } #end End
} #end Function
