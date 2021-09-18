function Revoke-NTFSPermissions
{
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
  Param
  (
    # Param1 path to the resource|folder
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 0)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]
    $path,

    # Param2 object or SecurityPrincipal
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 1)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]
    $object,

    # Param3 permission
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
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
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

    }

    Process {
        Try {
            $FileSystemRights = [Security.AccessControl.FileSystemRights]$permission
            $InheritanceFlag = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
            $PropagationFlag = [Security.AccessControl.PropagationFlags]'None'
            $AccessControlType = [Security.AccessControl.AccessControlType]::Allow
            $Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList ($object)
            $FileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
            $DirectorySecurity = Get-Acl -Path $path
            $DirectorySecurity.RemoveAccessRuleAll($FileSystemAccessRule)
            Set-Acl -Path $path -AclObject $DirectorySecurity
        }
        Catch { Throw }
    }
    End {
        Write-Verbose -Message ('The User/Group {0} was removed {1} from folder {2}.' -f $object, $permission, $path)
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}