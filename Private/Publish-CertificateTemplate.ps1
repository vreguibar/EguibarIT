Function Publish-CertificateTemplate {
    <#
        .SYNOPSIS
            Publishes a certificate template to all available Certification Authorities (CAs).

        .DESCRIPTION
            This function publishes a specified certificate template to all Enterprise
            Certification Authorities in the Active Directory forest. It performs the following:
            - Discovers writable Domain Controllers
            - Locates all Enterprise CAs
            - Publishes the template to each CA
            - Validates the publication success

        .PARAMETER CertDisplayName
            Specifies the display name of the certificate template to be published.
            Spaces will be removed from the name during processing.

        .PARAMETER Server
            Optional. FQDN of the Domain Controller to use.
            If not specified, discovers nearest writable DC.

        .INPUTS
            System.String
            You can pipe the certificate template display name to this function.

        .OUTPUTS
            [System.Void]
            This function does not produce any output.

        .EXAMPLE
            Publish-CertificateTemplate -CertDisplayName "Web Server Template"

            Publishes the template to all CAs using default credentials.

        .EXAMPLE
            "User Auth" | Publish-CertificateTemplate -Verbose

            Pipes a template name to the function and publishes it with verbose output.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Get-ADDomainController                 ║ ActiveDirectory
                Get-ADObject                           ║ ActiveDirectory
                Set-ADObject                           ║ ActiveDirectory
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Debug                            ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility
                Write-Progress                         ║ Microsoft.PowerShell.Utility
                Get-FunctionDisplay                    ║ EguibarIT

        .NOTES
            Version:         1.2
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Private/Publish-CertificateTemplate.ps1

        .COMPONENT
            PKI

        .ROLE
            Certificate Management

        .FUNCTIONALITY
            Certificate Template Publication
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([void])]

    Param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Display name of the certificate template to publish')]
        [ValidateNotNullOrEmpty()]
        [string]
        $CertDisplayName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController', 'DC')]
        [string]
        $Server
    )

    begin {
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
        } #end If

        ######################
        # Initialize variables

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$CommonParams = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [hashtable]$GetDCParams = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)


        try {
            # Prepare common parameters
            $CommonParams = @{
                ErrorAction = 'Stop'
            }

            # Get DC if not specified
            if (-not $PSBoundParameters.ContainsKey('Server')) {

                $GetDCParams = @{
                    Discover      = $true
                    ForceDiscover = $true
                    Writable      = $true
                }
                $GetDCParams += $CommonParams

                $Server = (Get-ADDomainController @GetDCParams).HostName[0]
                Write-Debug -Message ('Using Domain Controller: {0}' -f $Server)

            } #end If
            $CommonParams['Server'] = $PSBoundParameters['Server']

            # Get enrollment path
            $EnrollmentPath = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $Variables.configurationNamingContext
            Write-Debug -Message ('Enrollment path: {0}' -f $EnrollmentPath)

            # Get all CAs
            $Splat = @{
                SearchBase  = $EnrollmentPath
                SearchScope = 'OneLevel'
                Filter      = '*'
            }
            $CAs = Get-ADObject @Splat @CommonParams
            if (-not $CAs) {

                throw 'No Certificate Authorities found in the forest'

            } #end If
            Write-Verbose -Message ('Found {0} Certificate Authorities' -f $CAs.Count)

        } catch {

            Write-Error -Message ('Failed to initialize: {0}' -f $_.Exception.Message)
            throw

        } #end Try-Catch

    } #end Begin

    process {

        # Remove spaces from template name
        $TemplateToAdd = $CertDisplayName.Replace(' ', '')
        Write-Debug -Message ('Processing template: {0}' -f $TemplateToAdd)

        $processedCAs = 0
        foreach ($CA in $CAs) {
            $processedCAs++
            Write-Progress -Activity 'Publishing Certificate Template' -Status $CA.Name `
                -PercentComplete (($processedCAs / $CAs.Count) * 100)

            try {
                $CAIdentity = $CA.DistinguishedName
                Write-Debug -Message ('Processing CA: {0}' -f $CAIdentity)

                if ($PSCmdlet.ShouldProcess(
                        "Certificate Template: $TemplateToAdd",
                        "Publish to CA: $($CA.Name)")) {

                    $Splat = @{
                        Identity = $CAIdentity
                        Add      = @{certificateTemplates = $TemplateToAdd }
                    }
                    Set-ADObject @Splat @CommonParams

                    Write-Verbose -Message ('Template published to CA: {0}' -f $CA.Name)
                }
            } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {

                Write-Error -Message ('CA server unavailable: {0}' -f $CA.Name)
                continue

            } catch {

                Write-Error -Message ('
                    Failed to publish template to CA {0}: {1}' -f
                    $CA.Name, $_.Exception.Message
                )
                continue

            }
        } #end foreach
        Write-Progress -Activity 'Publishing Certificate Template' -Completed

    } #end Process

    end {

        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'publishing Cert Template (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end End

} #end Function Publish-CertificateTemplate
