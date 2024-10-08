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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([Microsoft.ActiveDirectory.Management.ADEntity])]

    param(
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 0)]
        [string]
        $DisplayName,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            Position = 1)]
        [string]
        $Server
    )

    Begin {
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

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        if (-not $Server) {
            $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
        }

        If ($PSBoundParameters.ContainsKey('DisplayName')) {
            $LDAPFilter = "(&(objectClass=pKICertificateTemplate)(displayName=$DisplayName))"
        } Else {
            $LDAPFilter = '(objectClass=pKICertificateTemplate)'
        } #end If
    } #end Begin

    Process {

        $TemplatePath = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $Variables.configurationNamingContext

        $Splat = @{
            SearchScope = 'Subtree'
            SearchBase  = $TemplatePath
            LDAPFilter  = $LDAPFilter
            Properties  = '*'
            Server      = $Server
        }
        $result = Get-ADObject @Splat

        # Output verbose information
        foreach ($item in $result) {
            Write-Verbose -Message ('Template Name: {0}' -f $item.Name)
            Write-Verbose -Message ('Created: {0}, Modified: {1}' -f $item.Created, $item.Modified)
        } #end ForEach

    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'getting Cert Template (Private Function).'
        )
        Write-Verbose -Message $txt

        return $result
    } #end End

} #end Function
