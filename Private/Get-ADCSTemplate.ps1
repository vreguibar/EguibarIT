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
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        if(-not $Server) {
            $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
        }

        If ($PSBoundParameters.ContainsKey('DisplayName')) {
            $LDAPFilter = "(&(objectClass=pKICertificateTemplate)(displayName=$DisplayName))"
        } Else {
            $LDAPFilter = '(objectClass=pKICertificateTemplate)'
        } #end If
    } #end Begin
    Process {
        $ConfigNC     = $((Get-ADRootDSE -Server $Server).configurationNamingContext)

        $TemplatePath = ('CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC)

        $result = Get-ADObject -SearchScope Subtree -SearchBase $TemplatePath -LDAPFilter $LDAPFilter -Properties * -Server $Server

        # Output verbose information
        foreach ($item in $result) {
            Write-Verbose -Message ('Template Name: {0}' -f $item.Name)
            Write-Verbose -Message ('Created: {0}, Modified: {1}' -f $item.Created, $item.Modified)
        } #end ForEach
    } #end Process
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
        return $result
    } #end End
} #end Function
