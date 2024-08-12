function Revoke-NTFSPermissions {
    <#
    .Synopsis
    Function to remove NTFS permissions to a folder
    .DESCRIPTION
    Function to remove NTFS permissions to a folder
    .EXAMPLE
    Revoke-NTFSPermissions path object permission
    .INPUTS
    Param1 path = The path to the folder
    Param2 object = the identity which will get the permissions
    Param3 permission = the permissions to be modified
    .NOTES
    Version:         1.0
    DateModified:    31/Mar/2015
    LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com
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
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
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
