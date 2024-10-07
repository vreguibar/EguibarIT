function Revoke-Inheritance {
    <#
    .Synopsis
      The function will Remove Specific/Non-Inherited ACL and enable inheritance on an object

    .DESCRIPTION
      The function will Remove Specific/Non-Inherited ACL and enable inheritance on an object.
      Control whether inheritance from the parent folder should be blocked ($True means no Inheritance)
      and if the previously inherited access rules should be preserved ($False means remove
      previously inherited permissions).

    .EXAMPLE
      Revoke-Inheritance -LDAPpath 'OU=Admin,DC=EguibarIT,DC=local' -RemoveInheritance -KeepPermissions

    .PARAMETER LDAPpath
      Distinguished Name of the object (or container)

    .PARAMETER RemoveInheritance
      Remove inheritance from parent. If present Inheritance will be removed.

    .PARAMETER KeepPermissions
      Previous inherited access rules will be kept. If present means rules will be copied
      and maintained, otherwise rules will be removed.

    .NOTES
      Version:         1.1
      DateModified:    27/Mar/2024
      LasModifiedBy:   Vicente Rodriguez Eguibar
        vicente@eguibar.com
        Eguibar Information Technology S.L.
        http://www.eguibarit.com
  #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
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
        [ValidateScript({ Test-IsValidDN -ObjectDN $_ }, ErrorMessage = 'DistinguishedName provided is not valid! Please Check.')]
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
        $error.Clear()

        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition


        If ($RemoveInheritance) {
            $isProtected = $true
        } else {
            $isProtected = $false
        }

        If ($KeepPermissions) {
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
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'removing inheritance.'
        )
        Write-Verbose -Message $txt
    } #end End
}
