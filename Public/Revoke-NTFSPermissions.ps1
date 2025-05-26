function Revoke-NTFSPermissions {
    <#
        .SYNOPSIS
            Revokes specific NTFS permissions from files and folders.

        .DESCRIPTION
            This function removes specific NTFS permissions from files and folders using
            the .NET Security model. It provides granular control over permission removal
            with support for:
            - File and folder targets
            - Specific security principals (users/groups)
            - Individual permission levels
            - Inheritance and propagation settings
            - Pipeline input for batch operations

        .PARAMETER path
            The full path to the file or folder where permissions will be removed.
            Must be a valid, accessible filesystem path.

        .PARAMETER object
            The security principal (user/group) from which permissions will be removed.
            Can be specified in "Domain\User" or "Domain\Group" format.

        .PARAMETER permission
            The specific permission to remove. Must be a valid FileSystemRights value.
            Common values include:
            - Read
            - Write
            - ReadAndExecute
            - Modify
            - FullControl

        .INPUTS
            System.String
            You can pipe path strings to this function.

        .OUTPUTS
            System.Void
            This function does not generate any output.

        .EXAMPLE
            Revoke-NTFSPermissions -Path "D:\Shares\Finance" -Object "CONTOSO\FinanceUsers" -Permission "Write"

            Removes Write permission for the FinanceUsers group from the Finance share.

        .EXAMPLE
            Revoke-NTFSPermissions -Path "E:\Data" -Object "CONTOSO\Contractors" -Permission "FullControl"

            Removes Full Control permission for the Contractors group from the Data folder.

        .EXAMPLE
            Get-ChildItem -Path "D:\Projects" -Directory | Select-Object -ExpandProperty FullName |
            Revoke-NTFSPermissions -Object "CONTOSO\Interns" -Permission "Modify"

            Removes Modify permission for Interns from all subdirectories in the Projects folder.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Get-Acl                                ║ Microsoft.PowerShell.Security
                Set-Acl                                ║ Microsoft.PowerShell.Security
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                    ║ EguibarIT

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Revoke-NTFSPermissions.ps1

        .COMPONENT
            File System

        .ROLE
            Security Administration

        .FUNCTIONALITY
            NTFS Permissions Management
#>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param
    (
        # Param1 path to the resource|folder
        [Parameter(Mandatory = $true,
            HelpMessage = 'Add help message for user',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $path,

        # Param2 object or SecurityPrincipal
        [Parameter(Mandatory = $true,
            HelpMessage = 'Add help message for user',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 1)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $object,

        # Param3 permission
        [Parameter(Mandatory = $true,
            HelpMessage = 'Add help message for user',
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 2)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $permission
    )

    Begin {
        $error.Clear()

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

        $FileSystemRights = [Security.AccessControl.FileSystemRights]$permission
        $InheritanceFlag = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $PropagationFlag = [Security.AccessControl.PropagationFlags]'None'
        $AccessControlType = [Security.AccessControl.AccessControlType]::Allow
        $Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList ($object)
        $FileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
        $DirectorySecurity = Get-Acl -Path $path
    } #end Begin

    Process {
        Try {
            $DirectorySecurity.RemoveAccessRuleAll($FileSystemAccessRule)
            Set-Acl -Path $path -AclObject $DirectorySecurity
        } Catch {
            Write-Error -Message 'Error when revoking NTFS permissions'
            throw
        } #end Try-Catch
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'removing User/Group from folder.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
