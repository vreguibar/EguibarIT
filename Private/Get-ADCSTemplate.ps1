Function Get-ADCSTemplate {
    <#
        .SYNOPSIS
            Returns properties of Active Directory Certificate Template(s).

        .DESCRIPTION
            Retrieves properties of one or all Active Directory Certificate Templates from the
            Configuration Naming Context. Supports pipeline input and credential delegation.

        .PARAMETER DisplayName
            Name of the certificate template to retrieve. If omitted, returns all templates.

        .PARAMETER Server
            FQDN of Active Directory Domain Controller to target. If not specified, discovers
            nearest writable DC.

        .PARAMETER Credential
            Credential object used for authentication. If omitted, uses current security context.

        .EXAMPLE
            Get-ADCSTemplate
            Returns all certificate templates.

        .EXAMPLE
            Get-ADCSTemplate -DisplayName 'PowerShellCMS'
            Returns specific template named 'PowerShellCMS'.

        .EXAMPLE
            Get-ADCSTemplate | Sort-Object Name | Format-Table Name, Created, Modified
            Lists all templates sorted by name showing creation and modification dates.

        .EXAMPLE
            'WebServer','UserCert' | Get-ADCSTemplate
            Returns templates via pipeline input.

        .OUTPUTS
            Microsoft.ActiveDirectory.Management.ADEntity

        .NOTES
            Used Functions:
                Name                                    ║ Module/Namespace
                ════════════════════════════════════════╬══════════════════════════════
                Get-ADObject                            ║ ActiveDirectory
                Get-ADDomainController                  ║ ActiveDirectory
                Write-Progress                          ║ Microsoft.PowerShell.Utility
                Write-Verbose                           ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                     ║ EguibarIT

        .NOTES
            Version:         2.0
            DateModified:   26/Mar/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://www.powershellgallery.com/packages/ADCSTemplate/1.0.1.0/Content/ADCSTemplate.psm1
            https://github.com/PowerShell/xCertificate

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Private/Get-ADCSTemplate.ps1
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
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
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController', 'DC')]
        [string]
        $Server
    )

    Begin {
        Set-StrictMode -Version Latest

        # Output header information
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        Import-MyModule -ModuleName 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$GetDCParams = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$CommonParams = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)


        try {
            # Get DC if not specified
            if (-not $PSBoundParameters.ContainsKey('Server')) {

                $GetDCParams = @{
                    Discover      = $true
                    ForceDiscover = $true
                    Writable      = $true
                    ErrorAction   = 'Stop'
                }
                $Server = (Get-ADDomainController @GetDCParams).HostName[0]
                Write-Verbose -Message ('Using Domain Controller: {0}' -f $Server)
            } #end If

            # Prepare common parameters
            $CommonParams = @{
                Server      = $Server
                ErrorAction = 'Stop'
            }

        } catch {

            Write-Error -Message ('Failed to initialize: {0}' -f $_.Exception.Message)
            return

        } #end Try

    } #end Begin

    Process {
        try {
            # Get template path from configuration NC
            $TemplatePath = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $Variables.configurationNamingContext

            # Process each template name if specified
            if ($PSBoundParameters.ContainsKey('DisplayName')) {

                $total = $DisplayName.Count
                $current = 0

                foreach ($template in $DisplayName) {

                    $current++

                    Write-Progress -Activity 'Processing Certificate Templates' `
                        -Status ('Processing template {0}' -f $template) `
                        -PercentComplete (($current / $total) * 100)

                    $LDAPFilter = '(&(objectClass=pKICertificateTemplate)(displayName={0}))' -f $template
                    Write-Verbose -Message ('Searching for template: {0}' -f $template)

                    $Splat = @{
                        SearchScope = 'Subtree'
                        SearchBase  = $TemplatePath
                        LDAPFilter  = $LDAPFilter
                        Properties  = '*'
                    }
                    $Splat += $CommonParams

                    $result = Get-ADObject @Splat

                    if ($result) {

                        Write-Verbose -Message ('Found template: {0}' -f $result.Name)
                        Write-Debug -Message ('
                            Template details:
                            Created={0},
                            Modified={1}' -f $result.Created, $result.Modified
                        )
                        $result

                    } else {

                        Write-Warning -Message ('Template not found: {0}' -f $template)

                    } #end If-Else
                } #end ForEach

                Write-Progress -Activity 'Processing Certificate Templates' -Completed

            } else {

                # Get all templates
                Write-Verbose -Message 'Retrieving all certificate templates'

                $Splat = @{
                    SearchScope = 'Subtree'
                    SearchBase  = $TemplatePath
                    LDAPFilter  = '(objectClass=pKICertificateTemplate)'
                    Properties  = '*'
                }
                $Splat += $CommonParams

                $result = Get-ADObject @Splat
                Write-Verbose -Message ('Found {0} templates' -f $result.Count)
                $result
            } #end If-Else

        } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {

            Write-Error -Message ('Domain Controller {0} is not accessible' -f $Server)

        } catch [System.UnauthorizedAccessException] {

            Write-Error -Message 'Access denied. Check credentials and permissions'

        } catch {

            Write-Error -Message ('An error occurred: {0}' -f $_.Exception.Message)

        } #end Try-Catch

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'getting Cert Template (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if
    } #end End

} #end Function Get-ADCSTemplate
