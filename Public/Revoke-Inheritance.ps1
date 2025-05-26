function Revoke-Inheritance {
    <#
        .SYNOPSIS
            Manages inheritance settings on Active Directory object access control lists.

        .DESCRIPTION
            This function provides granular control over inheritance settings on Active Directory objects.
            It allows administrators to:
            - Block inheritance from parent objects
            - Control whether previously inherited permissions are preserved or removed
            - Apply these changes consistently across multiple objects via pipeline input

            This is an essential function for implementing secure and well-structured permission
            hierarchies in Active Directory.

        .PARAMETER LDAPpath
            Distinguished Name of the object (or container) to modify.
            Must be a valid DN that can be resolved in the current domain.

        .PARAMETER RemoveInheritance
            When specified, blocks inheritance from the parent object.
            If not specified, inheritance remains enabled.

        .PARAMETER KeepPermissions
            When specified, previously inherited permissions are converted to explicit permissions.
            If not specified, previously inherited permissions are removed.

        .INPUTS
            System.String
            You can pipe distinguished names to this function.

        .OUTPUTS
            System.Void
            This function does not generate any output.

        .EXAMPLE
            Revoke-Inheritance -LDAPpath 'OU=Admin,DC=EguibarIT,DC=local' -RemoveInheritance -KeepPermissions

            Blocks inheritance on the Admin OU while preserving all previously inherited permissions.

        .EXAMPLE
            Revoke-Inheritance -LDAPpath 'OU=Users,DC=EguibarIT,DC=local' -RemoveInheritance

            Blocks inheritance on the Users OU and removes all previously inherited permissions.

        .EXAMPLE
            Get-ADOrganizationalUnit -Filter {Name -like 'Tier*'} | Select-Object -ExpandProperty DistinguishedName | Revoke-Inheritance -RemoveInheritance -KeepPermissions

            Blocks inheritance while preserving permissions on all OUs with names starting with 'Tier'.        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Test-IsValidDN                             ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT
                Get-Acl                                    ║ Microsoft.PowerShell.Security
                Set-Acl                                    ║ Microsoft.PowerShell.Security
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility            Version:         1.3
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Revoke-Inheritance.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Security Administration

        .FUNCTIONALITY
            Access Control Management
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([void])]

    Param
    (
        # PARAM1 STRING for the Object Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the object (or container).',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript(
            { Test-IsValidDN -ObjectDN $_ },
            ErrorMessage = 'DistinguishedName provided is not valid! Please Check.'
        )]
        [Alias('DN', 'DistinguishedName')]
        [String]
        $LDAPpath,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remove inheritance from parent. If present Inheritance will be removed.',
            Position = 1)]
        [switch]
        $RemoveInheritance,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Previous inherited access rules will be kept. If present means rules will
            be copied and maintained, otherwise rules will be removed.',
            Position = 1)]
        [switch]
        $KeepPermissions
    )

    Begin {
        Set-StrictMode -Version Latest

        # Initialize logging
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


        If ($PSBoundParameters['RemoveInheritance']) {
            $isProtected = $true
        } else {
            $isProtected = $false
        }

        If ($PSBoundParameters['KeepPermissions']) {
            $preserveInheritance = $true
        } else {
            $preserveInheritance = $false
        }

    } #end Begin

    Process {
        Try {

            # Get the ACL
            $DirectorySecurity = Get-Acl -Path ('AD:\{0}' -f $PSBoundParameters['LDAPpath'])

            # SetAccessRuleProtection, which is a method to control whether inheritance from the parent folder should
            # be blocked ($True means no Inheritance) and if the previously inherited access rules should
            # be preserved ($False means remove previously inherited permissions).
            $DirectorySecurity.SetAccessRuleProtection($isProtected, $preserveInheritance)

            If ($PSCmdlet.ShouldProcess($PSBoundParameters['LDAPpath'], 'Remove inheritance?')) {

                Set-Acl -Path ('AD:\{0}' -f $PSBoundParameters['LDAPpath']) -AclObject $DirectorySecurity

            } #end If

        } Catch {
            Write-Error -Message 'Error when revoking inheritance'
            throw
        }
    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'removing inheritance.'
            )
            Write-Verbose -Message $txt
        } #end If
    } #end End

} #end Function Revoke-Inheritance
