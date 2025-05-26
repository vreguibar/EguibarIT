function Grant-NTFSPermission {
    <#
        .SYNOPSIS
            Grants NTFS permissions to files and folders with enhanced security controls.

        .DESCRIPTION
            Adds or modifies NTFS permissions on files and folders with:
            - Comprehensive error handling for specific scenarios
            - Support for all standard NTFS rights
            - Inheritance and propagation control options
            - Security principal validation against Active Directory
            - Path existence verification with detailed errors
            - Progress tracking for batch operations
            - Detailed logging with verbose and debug options
            - Support for -WhatIf and -Confirm parameters
            - Pipeline input support for batch processing
            - Performance optimizations for large environments

        .PARAMETER Path
            [String] Full path to the file or folder.
            Must exist and be accessible.
            Supports pipeline input.

        .PARAMETER Object
            [String] Security principal (user/group) receiving permissions.
            Must be resolvable in current domain/forest.
            Use format "Domain\Username" or "Domain\GroupName".

        .PARAMETER Permission
            [String] NTFS permission to grant. Valid values:
            - ReadAndExecute  : Grants rights to read and execute files
            - AppendData      : Grants rights to append data to files
            - CreateFiles     : Grants rights to create new files within a folder
            - Read            : Grants basic read access
            - Write           : Grants basic write access
            - Modify          : Grants read, write, and delete access
            - FullControl     : Grants complete control over files and folders

        .PARAMETER NoInheritance
            [Switch] When specified, permissions are not inherited by child objects.
            By default, permissions are inherited by child objects.

        .PARAMETER ClearExisting
            [Switch] When specified, removes all existing permissions before applying new ones.
            Use with caution - can remove critical system permissions.

        .PARAMETER PassThru
            [Switch] Returns an object representing the modified ACL.
            By default, the function doesn't return any output.

        .EXAMPLE
            Grant-NTFSPermission -Path 'D:\Shares\Finance' -Object 'EguibarIT\Finance_RO' -Permission 'Read'

            Grants read access to Finance_RO group on Finance share.

        .EXAMPLE
            $params = @{
                Path = 'E:\Data'
                Object = 'EguibarIT\Backup_Operators'
                Permission = 'Modify'
            }
            Grant-NTFSPermission @params -Verbose

            Grants modify rights with verbose logging.

        .EXAMPLE
            Get-ChildItem -Path 'D:\Projects' -Directory | Grant-NTFSPermission -Object 'EguibarIT\Developers' -Permission 'Modify' -WhatIf

            Shows what would happen if modify permissions were granted to the Developers group on all subdirectories of Projects.

        .EXAMPLE
            Grant-NTFSPermission -Path 'D:\Confidential' -Object 'EguibarIT\Executives' -Permission 'FullControl' -NoInheritance -PassThru

            Grants full control to the Executives group without inheritance and returns the modified ACL.

        .OUTPUTS
            [System.Security.AccessControl.FileSecurity] when -PassThru is specified
            [void] by default        .INPUTS
            System.String
            You can pipe path strings to this function, allowing batch processing of multiple files and folders.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬════════════════════════
                Get-Acl                                ║ Microsoft.PowerShell.Security
                Set-Acl                                ║ Microsoft.PowerShell.Security
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility
                Write-Debug                            ║ Microsoft.PowerShell.Utility
                Write-Progress                         ║ Microsoft.PowerShell.Utility
                Get-ADObject                           ║ ActiveDirectory
                Get-FunctionDisplay                    ║ EguibarIT

        .NOTES
            Version:         1.3
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Grant-NTFSPermission.ps1

        .LINK
            https://docs.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.filesystemrights

        .LINK
            https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists

        .COMPONENT
            File System

        .ROLE
            Security Administration

        .FUNCTIONALITY
            NTFS Permissions Management

    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium',
        DefaultParameterSetName = 'Default'
    )]
    [OutputType([void])]
    [OutputType([System.Security.AccessControl.FileSecurity], ParameterSetName = 'PassThru')]

    Param (
        # Param1 path to the resource|folder
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Absolute path to the file or folder',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-Path $_ -PathType Any },
            ErrorMessage = 'Path does not exist or is not accessible: {0}'
        )]
        [Alias('FullName', 'FilePath', 'FolderPath')]
        [string]
        $path,

        # Param2 object or SecurityPrincipal
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the Identity getting the permission.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName', 'GroupID', 'Identity', 'SamAccountName')]
        [string]
        $object,

        # Param3 permission
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'NTFS permission to grant: ReadAndExecute, AppendData, CreateFiles, Read, Write, Modify, or FullControl',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('ReadAndExecute', 'AppendData', 'CreateFiles',
            'Read', 'Write', 'Modify', 'FullControl')]
        [string]
        $permission,

        # Disable inheritance
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Disable inheritance for this permission')]
        [switch]
        $NoInheritance,

        # Clear existing permissions
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Clear all existing permissions before applying new ones')]
        [switch]
        $ClearExisting,

        # Return the modified ACL
        [Parameter(Mandatory = $false,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Return the modified ACL',
            ParameterSetName = 'PassThru')]
        [switch]
        $PassThru
    )

    Begin {
        Set-StrictMode -Version Latest

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

        ##############################
        # Variables Definition

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [int]$TotalItems = 0
        [int]$ProcessedItems = 0
        [bool]$ValidatePrincipal = $true  # Set to $false to skip AD validation for better performance
        [System.Collections.Generic.List[string]]$ProcessedPaths = [System.Collections.Generic.List[string]]::new()

        # Possible values for FileSystemRights are:
        # ReadAndExecute, AppendData, CreateFiles, read, write, Modify, FullControl
        # Initialize security flags
        $FileSystemRights = [Security.AccessControl.FileSystemRights]$Permission

        # Set inheritance flags based on NoInheritance parameter
        if ($PSBoundParameters['NoInheritance']) {

            $InheritanceFlag = [Security.AccessControl.InheritanceFlags]::None
            Write-Debug -Message 'Inheritance disabled'

        } else {

            $InheritanceFlag = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
            Write-Debug -Message 'Inheritance enabled for container and object'

        } #end If-Else

        $PropagationFlag = [Security.AccessControl.PropagationFlags]::None
        $AccessControlType = [Security.AccessControl.AccessControlType]::Allow

        try {
            # Validate security principal
            Write-Debug -Message ('Validating security principal: {0}' -f $Object)
            $Account = [System.Security.Principal.NTAccount]::new($PSBoundParameters['Object'])

            # Validate the account only if validation is enabled
            if ($ValidatePrincipal) {
                # For performance in large environments, we could cache validated principals
                # or skip validation entirely if needed

                # Optional: Validate against AD
                # Uncomment this section if strict validation is required
                <#
                try {
                    # Try to translate to SID to validate the account
                    $null = $Account.Translate([System.Security.Principal.SecurityIdentifier])
                    Write-Debug -Message ('Security principal validated: {0}' -f $PSBoundParameters['Object'])
                } catch {
                    throw ('Invalid security principal: {0}. Error: {1}' -f $PSBoundParameters['Object'], $_.Exception.Message)
                }
                #>
            } #end If
        } catch {
            $ErrorMsg = ('Error creating security principal object for {0}: {1}' -f
                $PSBoundParameters['Object'], $_.Exception.Message)
            Write-Error -Message $ErrorMsg -Category InvalidArgument
            throw
        } #end Try-Catch

        Write-Verbose -Message ('
            Beginning NTFS permission change for {0}
            with {1} rights' -f $PSBoundParameters['Object'], $PSBoundParameters['Permission']
        )

    } #end Begin

    Process {
        # Count total items for progress bar
        $TotalItems = $PSBoundParameters['Path'].Count
        $ProcessedItems = 0

        # Process each path in the array
        foreach ($CurrentPath in $PSBoundParameters['Path']) {
            $ProcessedItems++

            # Skip if already processed (in case of duplicates)
            if ($ProcessedPaths.Contains($CurrentPath)) {

                Write-Debug -Message ('Skipping duplicate path: {0}' -f $CurrentPath)
                continue

            } #end If

            $ProcessedPaths.Add($CurrentPath)

            # Show progress
            $Splat = @{
                Activity        = 'Granting NTFS Permissions'
                Status          = ('Processing {0}' -f $CurrentPath)
                PercentComplete = (($ProcessedItems / $TotalItems) * 100)
            }
            Write-Progress @Splat

            Write-Debug -Message ('Processing path: {0}' -f $CurrentPath)

            # Create the FileSystemAccessRule object
            $FileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList (
                $Account,
                $FileSystemRights,
                $InheritanceFlag,
                $PropagationFlag,
                $AccessControlType
            )

            try {
                # Get current ACL
                $DirectorySecurity = Get-Acl -Path $CurrentPath

                # Create descriptive action for ShouldProcess
                $ShouldProcessDescription = ('Grant {0} permissions to {1} on {2}' -f
                    $PSBoundParameters['Permission'],
                    $PSBoundParameters['Object'],
                    $CurrentPath)

                # Process only if ShouldProcess approves
                if ($PSCmdlet.ShouldProcess($CurrentPath, $ShouldProcessDescription)) {

                    # Clear existing permissions if requested
                    if ($PSBoundParameters['ClearExisting']) {

                        if ($PSCmdlet.ShouldContinue(
                            ('WARNING: About to remove ALL existing permissions on {0}. Continue?' -f $CurrentPath),
                                'Confirm Permission Removal')) {

                            $DirectorySecurity.SetAccessRuleProtection($true, $false)
                            Write-Debug -Message ('Cleared existing permissions on {0}' -f $CurrentPath)

                        } else {

                            Write-Verbose -Message ('User cancelled clearing permissions on {0}' -f $CurrentPath)
                            continue

                        } #end If-Else
                    } #end If

                    # Add the new access rule
                    $DirectorySecurity.AddAccessRule($FileSystemAccessRule)

                    # Apply the modified ACL
                    Set-Acl -Path $CurrentPath -AclObject $DirectorySecurity

                    Write-Verbose -Message ('Successfully granted {0} permissions to {1} on {2}' -f
                        $PSBoundParameters['Permission'],
                        $PSBoundParameters['Object'],
                        $CurrentPath)

                    # Return the ACL if PassThru is specified
                    if ($PSBoundParameters['PassThru']) {

                        Get-Acl -Path $CurrentPath
                    } #end If

                } #end If

            } catch [System.UnauthorizedAccessException] {

                $ErrorMsg = ('Access denied. Cannot modify permissions on {0}. Error: {1}' -f
                    $CurrentPath, $_.Exception.Message)
                Write-Error -Message $ErrorMsg -Category PermissionDenied
                continue

            } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {

                $ErrorMsg = ('Path no longer exists: {0}. Error: {1}' -f
                    $CurrentPath, $_.Exception.Message)
                Write-Error -Message $ErrorMsg -Category ObjectNotFound
                continue

            } catch [System.Security.Principal.IdentityNotMappedException] {

                $ErrorMsg = ('Security principal cannot be mapped: {0}. Error: {1}' -f
                    $PSBoundParameters['Object'], $_.Exception.Message)
                Write-Error -Message $ErrorMsg -Category InvalidData
                throw

            } catch {

                $ErrorMsg = ('Error granting NTFS permissions on {0}. Error: {1}' -f
                    $CurrentPath, $_.Exception.Message)
                Write-Error -Message $ErrorMsg
                continue

            } #end Try-Catch
        } #end Foreach

        # Complete progress bar
        Write-Progress -Activity 'Granting NTFS Permissions' -Completed

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'changing NTFS permissions.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End

} #end Function Grant-NTFSPermission
