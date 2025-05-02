function New-AclSddl {

    <#
        .SYNOPSIS
            Generates an SDDL (Security Descriptor Definition Language) string based on specified access control entries.

        .DESCRIPTION
            This function creates a security descriptor using .NET's FileSecurity class.
            Default permissions for `SYSTEM` and `Administrators` are always included.
            Additional custom access control entries can be specified as input.

        .PARAMETER IdentityPermissions
            An array of hashtable entries containing:
                - Identity: The user or group for which the permission applies.
                - Permission: The permission to grant or deny (e.g., Read, Write, FullControl).
                - AccessType: The type of access (Allow or Deny).

        .EXAMPLE
            $identityPermissions = @(
                @{ Identity = 'EguibarIT.local\SL_PAWs'; Permission = 'Read'; AccessType = 'Allow' },
                @{ Identity = 'EguibarIT.local\Domain Controllers'; Permission = 'Write'; AccessType = 'Deny' }
            )
            $sddl = New-AclSddl -IdentityPermissions $identityPermissions -Verbose
            Write-Output $sddl

        .INPUTS
            Array of hashtable with Identity, Permission, and AccessType.

        .OUTPUTS
            System.String
            Returns the SDDL string representation of the ACL.

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                AddAccessRule                          | .NET System.Security.AccessControl.FileSecurity
                GetSecurityDescriptorSddlForm          | .NET System.Security.AccessControl.FileSecurity
                Get-FunctionDisplay                    | EguibarIT

        .NOTES
            Version:         1.0
            DateModified:    18/Dec/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com

    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([string])]

    param (

        # Array of identity-permission-accessType tuples
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Array of Identity and permissions used to build the corresponding SDDL.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [array]
        $IdentityPermissions

    )

    begin {
        Set-StrictMode -Version Latest
        $error.clear()

        $txt = ($Variables.Header -f
            (Get-Date).ToString('dd/MMM/yyyy'),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        # Create a FileSecurity object to manage the ACL
        $fileSecurity = [System.Security.AccessControl.FileSecurity]::new()

        # Define default rules for SYSTEM and Administrators
        $defaultRules = @(
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                'NT AUTHORITY\SYSTEM',
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow
            ),
            [System.Security.AccessControl.FileSystemAccessRule]::new(
                'BUILTIN\Administrators',
                [System.Security.AccessControl.FileSystemRights]::FullControl,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
        )

        # Add default rules to the FileSecurity object
        foreach ($rule in $defaultRules) {
            $fileSecurity.AddAccessRule($rule)
        } #end Foreach

        Write-Verbose -Message 'Default rules for SYSTEM and Administrators added.'
    } #end begin

    process {
        foreach ($entry in $IdentityPermissions) {
            try {
                # Extract entry details
                $identity = $entry.Identity
                $permission = $entry.Permission
                $accessType = $entry.AccessType

                # Map permission to FileSystemRights using .NET Enum
                $fileSystemRights = [System.Security.AccessControl.FileSystemRights]::$permission

                # Map access type to AccessControlType using .NET Enum
                $accessControlType = [System.Security.AccessControl.AccessControlType]::$accessType

                # Create a FileSystemAccessRule object
                $accessRule = [System.Security.AccessControl.FileSystemAccessRule]::new(
                    $identity, # Identity as string
                    $fileSystemRights, # Permissions
                    $accessControlType      # Allow or Deny
                )

                # Add the access rule to the FileSecurity object
                $fileSecurity.AddAccessRule($accessRule)

                Write-Verbose -Message (
                    'Added rule for identity: {0}, permissions: {1}, access type: {2}' -f
                    $identity, $permission, $accessType
                )
            } catch {
                Write-Error -Message ('Failed to process entry for identity: {0}. Error: {1}' -f $identity, $_)
            } #end Try-Catch
        } #end Foreach
    } #end process

    end {
        # Convert ACL to SDDL string
        $sddl = $fileSecurity.GetSecurityDescriptorSddlForm('Access')
        Write-Verbose -Message ('Generated SDDL: {0}' -f $sddl)

        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'adding members to the group.'
        )
        Write-Verbose -Message $txt

        return $sddl
    } #end end
} #end function Generate-AclSddl
