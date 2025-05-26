function Get-ADUserPermission {

    <#
        .SYNOPSIS
            Retrieves permissions assigned to Active Directory users.

        .DESCRIPTION
            This function retrieves and displays the effective permissions assigned to Active Directory users.
            It can retrieve permissions for a single user specified by their distinguished name or process
            multiple users via pipeline input. The function handles both direct permissions and those
            inherited through group memberships.

            The permissions are retrieved using the .NET DirectoryServices namespace, which provides
            a comprehensive way to access the security descriptor of AD objects.

        .PARAMETER Identity
            Distinguished Name of the Active Directory user to query.
            This parameter accepts pipeline input by value or by property name.
            Use this to specify which user's permissions to retrieve.

        .PARAMETER TargetObject
            Distinguished Name of the Active Directory object to check permissions against.
            If not specified, the function retrieves permissions on all objects the user has access to.

        .PARAMETER IncludeInherited
            When specified, includes inherited permissions in the results.
            By default, only direct permissions are displayed.

        .PARAMETER ExcludeGenericAll
            When specified, excludes objects where the user has GenericAll permissions to reduce output volume.

        .EXAMPLE
            Get-ADUserPermission -Identity "CN=John Doe,OU=Users,DC=contoso,DC=com"

            Retrieves all direct permissions for the user John Doe in the contoso.com domain.

        .EXAMPLE
            Get-ADUserPermission -Identity "CN=John Doe,OU=Users,DC=contoso,DC=com" -IncludeInherited

            Retrieves both direct and inherited permissions for the user John Doe.

        .EXAMPLE
            Get-ADUser -Filter {Department -eq "IT"} | Get-ADUserPermission

            Retrieves permissions for all users in the IT department.

        .EXAMPLE
            Get-ADUserPermission -Identity "CN=John Doe,OU=Users,DC=contoso,DC=com" -TargetObject "OU=Sales,DC=contoso,DC=com"

            Retrieves permissions that John Doe has on the Sales OU.

        .INPUTS
            [Microsoft.ActiveDirectory.Management.ADUser]
            [String]

        .OUTPUTS
            [PSCustomObject] containing the following properties:
                - User: The user account name
                - TargetObject: The AD object the permission applies to
                - ObjectClass: The class of the target object
                - AccessType: The type of access (Allow/Deny)
                - Permission: The permission type (e.g., ReadProperty, WriteProperty, etc.)
                - IsInherited: Whether the permission is inherited
                - InheritedFrom: The object from which the permission is inherited (if applicable)

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ADObject                               ║ ActiveDirectory
                Get-ADUser                                 ║ ActiveDirectory
                Get-FunctionDisplay                        ║ EguibarIT
                Test-IsValidDN                             ║ EguibarIT
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Debug                                ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Get-ADUserPermission.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Security Administrator

        .FUNCTIONALITY
            Permission Management
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low',
        DefaultParameterSetName = 'Default'
    )]
    [OutputType([PSCustomObject[]])]

    param (
        [Parameter(
            Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Distinguished Name of the AD user',
            Position = 0,
            ParameterSetName = 'Default'
        )]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [string]$Identity,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Distinguished Name of the target AD object to check permissions against',
            Position = 1,
            ParameterSetName = 'Default'
        )]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'Target DistinguishedName provided is not valid! Please Check.'
        )]
        [string]$TargetObject,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Include inherited permissions in the output',
            Position = 2,
            ParameterSetName = 'Default'
        )]
        [switch]$IncludeInherited,

        [Parameter(
            Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Exclude objects where the user has GenericAll permissions',
            Position = 3,
            ParameterSetName = 'Default'
        )]
        [switch]$ExcludeGenericAll
    )

    Begin {
        # Set strict mode
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
        } #end if

        ##############################
        # Module imports

        Import-Module -Name ActiveDirectory -Force -ErrorAction Stop

        ##############################
        # Variables Definition

        # Create dictionary to map Active Directory rights to human-readable permissions
        [hashtable]$ADRightsMapping = @{
            'GenericRead'                   = 'Read'
            'GenericWrite'                  = 'Write'
            'GenericExecute'                = 'Execute'
            'GenericAll'                    = 'Full Control'
            'ReadProperty'                  = 'Read Property'
            'WriteProperty'                 = 'Write Property'
            'CreateChild'                   = 'Create Child Object'
            'DeleteChild'                   = 'Delete Child Object'
            'ListObject'                    = 'List Contents'
            'DeleteTree'                    = 'Delete Tree'
            'ListContents'                  = 'List Contents'
            'ExtendedRight'                 = 'Extended Right'
            'Delete'                        = 'Delete'
            'ReadControl'                   = 'Read Control'
            'WriteDacl'                     = 'Write DACL'
            'WriteOwner'                    = 'Take Ownership'
            'AccessSystemSecurity'          = 'Access System Security'
            'Synchronize'                   = 'Synchronize'
            'CreateDirectoryService'        = 'Create Directory Service'
            'CreateDirectoryServiceObject'  = 'Create Directory Service Object'
            'DeleteDirectoryServiceObject'  = 'Delete Directory Service Object'
            'ReadDirectoryServiceData'      = 'Read Directory Service Data'
            'WriteDirectoryServiceData'     = 'Write Directory Service Data'
            'ControlDirectoryServiceAccess' = 'Control Directory Service Access'
        }

        # Create a hashtable for splatting
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Create an array to store results
        [System.Collections.ArrayList]$Results = @()

        Write-Verbose -Message 'Starting process'

    } #end Begin

    Process {

        try {
            # Get user object from AD
            $UserObject = Get-ADUser -Identity $Identity -Properties ObjectSID, SamAccountName -ErrorAction Stop
            Write-Debug -Message ('Found user: {0}' -f $UserObject.SamAccountName)

            # Get groups the user is a member of (direct and nested)
            $Groups = Get-ADGroup -LDAPFilter "(member:1.2.840.113556.1.4.1941:=$($UserObject.DistinguishedName))" -Properties ObjectSID
            Write-Debug -Message ('User is a member of {0} groups' -f $Groups.Count)

            # Build collection of security principals to check permissions for
            [System.Collections.ArrayList]$SecurityPrincipals = @()
            [void]$SecurityPrincipals.Add($UserObject)

            if ($null -ne $Groups) {
                foreach ($Group in $Groups) {
                    [void]$SecurityPrincipals.Add($Group)
                }
            }

            # If TargetObject is specified, only check that object
            if ($PSBoundParameters.ContainsKey('TargetObject')) {
                Write-Verbose -Message ('Checking permissions on target object: {0}' -f $TargetObject)
                $TargetObjects = Get-ADObject -Identity $TargetObject -Properties nTSecurityDescriptor -ErrorAction Stop
            } else {
                # Otherwise search the entire domain for objects with ACEs for the user or their groups
                Write-Verbose -Message 'Searching for objects with ACEs for the user or their groups'

                # Build LDAP filter for security principal SIDs
                [System.Text.StringBuilder]$LDAPFilter = [System.Text.StringBuilder]::new()
                [void]$LDAPFilter.Append('(|')

                foreach ($Principal in $SecurityPrincipals) {
                    [void]$LDAPFilter.Append("(nTSecurityDescriptor:1.2.840.113556.1.4.803:=*$($Principal.ObjectSID)*)")
                }

                [void]$LDAPFilter.Append(')')

                Write-Debug -Message ('LDAP filter: {0}' -f $LDAPFilter.ToString())

                # Get objects with matching security descriptors
                $TargetObjects = Get-ADObject -LDAPFilter $LDAPFilter.ToString() -Properties nTSecurityDescriptor -ResultSetSize 5000
                Write-Verbose -Message ('Found {0} objects with ACEs for the user or their groups' -f $TargetObjects.Count)
            }

            # Process each target object
            foreach ($Target in $TargetObjects) {
                Write-Debug -Message ('Processing target object: {0}' -f $Target.DistinguishedName)

                # Get security descriptor
                $SecurityDescriptor = $Target.nTSecurityDescriptor

                # Check DACL entries
                if ($null -ne $SecurityDescriptor -and $null -ne $SecurityDescriptor.DiscretionaryAcl) {
                    foreach ($Ace in $SecurityDescriptor.DiscretionaryAcl) {
                        # Check if ACE applies to one of our security principals
                        $AceSid = $Ace.SecurityIdentifier
                        $MatchingPrincipal = $SecurityPrincipals | Where-Object { $_.ObjectSID.Value -eq $AceSid.Value }

                        if ($null -ne $MatchingPrincipal) {
                            # Skip inherited permissions if not requested
                            if (-not $IncludeInherited -and $Ace.IsInherited) {
                                continue
                            }

                            # Skip GenericAll if requested
                            if ($ExcludeGenericAll -and $Ace.ActiveDirectoryRights -like '*GenericAll*') {
                                continue
                            }

                            # Map permissions to human-readable format
                            [System.Collections.ArrayList]$MappedPermissions = @()
                            foreach ($Right in $ADRightsMapping.Keys) {
                                if ($Ace.ActiveDirectoryRights -like "*$Right*") {
                                    [void]$MappedPermissions.Add($ADRightsMapping[$Right])
                                }
                            }

                            # If no mapped permissions found, use the raw value
                            if ($MappedPermissions.Count -eq 0) {
                                [void]$MappedPermissions.Add($Ace.ActiveDirectoryRights.ToString())
                            }

                            # Create result object
                            $ResultObject = [PSCustomObject]@{
                                User          = $UserObject.SamAccountName
                                TargetObject  = $Target.DistinguishedName
                                ObjectClass   = $Target.ObjectClass
                                AccessType    = $Ace.AccessControlType.ToString()
                                Permission    = ($MappedPermissions -join ', ')
                                IsInherited   = $Ace.IsInherited
                                InheritedFrom = if ($Ace.IsInherited) {
                                    $Ace.GetInheritanceSource()
                                } else {
                                    'N/A'
                                }
                                AppliesVia    = if ($MatchingPrincipal.ObjectClass -eq 'user') {
                                    'Direct'
                                } else {
                                    "Group: $($MatchingPrincipal.SamAccountName)"
                                }
                            }

                            # Add to results
                            [void]$Results.Add($ResultObject)
                        }
                    }
                }
            }

        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Error -Message ('Identity not found: {0}' -f $Identity)
        } catch [System.UnauthorizedAccessException] {
            Write-Error -Message ('Access denied when querying permissions: {0}' -f $_.Exception.Message)
        } catch {
            Write-Error -Message ('Error: {0}' -f $_.Exception.Message)
        } #end Try-Catch

    } #end Process

    End {
        # Return the results
        $Results

        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'processing AD user permissions.'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end End

} #end function Get-ADUserPermission
