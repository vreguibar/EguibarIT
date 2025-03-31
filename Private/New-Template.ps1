Function New-Template {
    <#
        .SYNOPSIS
            Creates a new PKI template in Active Directory Certificate Services.

        .DESCRIPTION
            This function creates a new certificate template in Active Directory Certificate Services (AD CS).
            It performs the following actions:
            1. Generates a unique template OID
            2. Creates the OID object in AD
            3. Creates the certificate template with specified attributes
            All operations are performed against a writable Domain Controller.

        .PARAMETER DisplayName
            Display Name of the new template.
            Must be unique in the forest.
            Cannot contain special characters.

        .PARAMETER TemplateOtherAttributes
            Hashtable containing additional template attributes.
            Common attributes include:
            - msPKI-Certificate-Name-Flag
            - msPKI-Enrollment-Flag
            - msPKI-Private-Key-Flag
            - msPKI-RA-Signature
            - pKIExtendedKeyUsage
            - pKIKeyUsage
            - pKIMaxIssuingDepth
            - revision

        .EXAMPLE
            $attributes = @{
                'msPKI-Certificate-Name-Flag' = 1
                'msPKI-Enrollment-Flag' = 0
                'pKIKeyUsage' = [byte[]](0x80)
                'pKIExtendedKeyUsage' = '1.3.6.1.5.5.7.3.2'
            }
            New-Template -DisplayName "WebServer2025" -TemplateOtherAttributes $attributes
            Creates a new web server certificate template.

        .EXAMPLE
            $splat = @{
                DisplayName = "UserSign2025"
                TemplateOtherAttributes = @{
                    'KeyType' = 'ExchangeSignature'
                    'KeyUsage' = 'DigitalSignature'
                }
            }
            New-Template @splat -Verbose -WhatIf
            Shows what would happen when creating a new user signing template.

        .OUTPUTS
            [void]

        .NOTES
            Used Functions:
            Name                           ║ Module
            ═══════════════════════════════╬══════════════════════════
            Get-ADDomainController         ║ ActiveDirectory
            Get-ADRootDSE                  ║ ActiveDirectory
            New-ADObject                   ║ ActiveDirectory
            New-TemplateOID                ║ EguibarIT
            Write-Verbose                  ║ Microsoft.PowerShell.Utility
            Write-Error                    ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.5
            DateModified:    26/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Medium'
    )]
    [OutputType([void])]

    Param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Display Name of the new template.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-zA-Z0-9\s-_]+$')]
        [Alias('Name', 'Template')]
        [System.String]
        $DisplayName,

        [Parameter(Mandatory = $True,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Other attributes in form of HashTable of the new template.',
            Position = 1)]
        [ValidateNotNull()]
        [Alias('Attributes', 'Properties')]
        [System.Collections.Hashtable]
        $TemplateOtherAttributes
    )

    Begin {
        Set-StrictMode -Version Latest

        # Output header information
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToShortDateString(),
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

        [string]$WhatIfMessage = 'Creating PKI template: {0}' -f $DisplayName
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        try {
            # Get writable DC
            $GetDCParams = @{
                Discover      = $true
                ForceDiscover = $true
                Writable      = $true
                ErrorAction   = 'Stop'
            }
            $Server = (Get-ADDomainController @GetDCParams).HostName[0]
            Write-Debug -Message ('Using Domain Controller: {0}' -f $Server)

            # Get Configuration NC
            $ConfigNC = $Variables.configurationNamingContext
            Write-Debug -Message ('Using Configuration NC: {0}' -f $ConfigNC)

        } catch {

            Write-Error -Message ('Failed to initialize: {0}' -f $_.Exception.Message)
            throw

        } #end Try-Catch

    } # End BEGIN section

    Process {
        Try {

            Write-Debug -Message ('Creating template: {0}' -f $DisplayName)

            #Create OID
            $OID = New-TemplateOID -Server $Server -ConfigNC $ConfigNC
            Write-Debug -Message ('Generated OID: {0}' -f $OID.TemplateOID)

            if ($PSCmdlet.ShouldProcess($TemplateOIDPath, 'Create template OID')) {

                $TemplateOIDPath = 'CN=OID,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC
                $OIDOtherAttributes = @{
                    'DisplayName'             = $DisplayName
                    'flags'                   = [System.Int32]'1'
                    'msPKI-Cert-Template-OID' = $OID.TemplateOID
                }
                $Splat = @{
                    Path            = $TemplateOIDPath
                    OtherAttributes = $OIDOtherAttributes
                    Name            = $OID.TemplateName
                    Type            = 'msPKI-Enterprise-Oid'
                    Server          = $Server
                    ErrorAction     = 'Stop'
                }
                New-ADObject @Splat

                Write-Verbose -Message ('Created OID object: {0}' -f $OID.TemplateName)

            } #end If

            # Ensure if msPKI-Cert-Template-OID already add it to hashtable
            If (-not $TemplateOtherAttributes.ContainsKey('msPKI-Cert-Template-OID')) {

                #Create Template itself
                $TemplateOtherAttributes += @{
                    'msPKI-Cert-Template-OID' = $OID.TemplateOID
                }
            } #end If
            $TemplatePath = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC


            if ($PSCmdlet.ShouldProcess($TemplatePath, $WhatIfMessage)) {
                $Splat = @{
                    Path            = $TemplatePath
                    OtherAttributes = $TemplateOtherAttributes
                    Name            = $DisplayName
                    DisplayName     = $DisplayName
                    Type            = 'pKICertificateTemplate'
                    Server          = $Server
                    ErrorAction     = 'Stop'
                }
                New-ADObject @Splat

                Write-Verbose -Message ('Created template: {0}' -f $DisplayName)
            } #end If

        } catch {

            Write-Error -Message ('Failed to create template {0}: {1}' -f $DisplayName, $_.Exception.Message)
            throw

        } #end Try-Catch

    } # End PROCESS section

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'adding new PKI template (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if

    } #end End section

} # End Function New-Template
