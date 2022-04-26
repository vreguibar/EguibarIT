Function Get-ADCSTemplate {
    <#
        .SYNOPSIS
            Returns the properties of either a single or all Active Directory Certificate Template(s).
        .DESCRIPTION
            Returns the properties of either a single or list of Active Directory Certificate Template(s)
            depending on whether a DisplayName parameter was passed.
        .PARAMETER DisplayName
            Name of an AD CS template to retrieve.
        .PARAMETER Server
            FQDN of Active Directory Domain Controller to target for the operation.
            When not specified it will search for the nearest Domain Controller.
        .EXAMPLE
            Get-ADCSTemplate
        .EXAMPLE
            Get-ADCSTemplate -DisplayName PowerShellCMS
        .EXAMPLE
            Get-ADCSTemplate | Sort-Object Name | ft Name, Created, Modified
        .EXAMPLE
            ###View template permissions
            (Get-ADCSTemplate pscms).nTSecurityDescriptor
            (Get-ADCSTemplate pscms).nTSecurityDescriptor.Sddl
            (Get-ADCSTemplate pscms).nTSecurityDescriptor.Access
            ConvertFrom-SddlString -Sddl (Get-ADCSTemplate pscms).nTSecurityDescriptor.sddl -Type ActiveDirectoryRights
        .NOTES
            https://www.powershellgallery.com/packages/ADCSTemplate/1.0.1.0/Content/ADCSTemplate.psm1
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
        Position = 0)]
        [string]$DisplayName,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
        Position = 1)]
        [string]$Server
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

        if(-not $Server) {
            $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
        }

        If ($PSBoundParameters.ContainsKey('DisplayName')) {
            $LDAPFilter = "(&(objectClass=pKICertificateTemplate)(displayName=$DisplayName))"
        } Else {
            $LDAPFilter = '(objectClass=pKICertificateTemplate)'
        }
    }
    Process {
        $ConfigNC     = $((Get-ADRootDSE -Server $Server).configurationNamingContext)

        $TemplatePath = ('CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC)

        Get-ADObject -SearchScope Subtree -SearchBase $TemplatePath -LDAPFilter $LDAPFilter -Properties * -Server $Server
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}