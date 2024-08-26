Function New-Template {
    <#
        .Synopsis
            Creates a new PKI template.

        .DESCRIPTION
            This function creates a new PKI template in Active Directory Certificate Services.

        .EXAMPLE
            New-Template -DisplayName "CustomTemplate" -TemplateOtherAttributes @{
                'KeyType' = 'ExchangeSignature'
                'KeyUsage' = 'DigitalSignature'
            }

        .PARAMETER DisplayName
            Display Name of the new template.

        .PARAMETER TemplateOtherAttributes
             attributes in the form of a Hashtable for the new template.

        .NOTES
            Used Functions:
                Name                           | Module
                -------------------------------|--------------------------
                Get-ADDomainController         | ActiveDirectory
                Get-ADRootDSE                  | ActiveDirectory
                New-ADObject                   | ActiveDirectory
                New-TemplateOID                | EguibarIT

        .NOTES
            Version:         1.4
            DateModified:    08/Oct/2021
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([void])]

    Param(
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Display Name of the new template.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $DisplayName,

        [Parameter(Mandatory = $True,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Other attributes in form of HashTable of the new template.',
            Position = 1)]
        [System.Collections.Hashtable]
        $TemplateOtherAttributes
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

        $WhatIfMessage = "Creating a new PKI template with DisplayName: '$DisplayName'"

        #grab DC
        $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]

        #grab Naming Context
        $ConfigNC = (Get-ADRootDSE -Server $Server).configurationNamingContext

        # parameters variable for splatting CMDlets
        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    } # End BEGIN section

    Process {
        Try {
            #Create OID
            $OID = New-TemplateOID -Server $Server -ConfigNC $ConfigNC

            $TemplateOIDPath = 'CN=OID,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC
            $OIDOtherAttributes = @{
                'DisplayName'             = $DisplayName
                'flags'                   = [System.Int32]'1'
                'msPKI-Cert-Template-OID' = $OID.TemplateOID
            }
            New-ADObject -Path $TemplateOIDPath -OtherAttributes $OIDOtherAttributes -Name $OID.TemplateName -Type 'msPKI-Enterprise-Oid' -Server $Server

            # Ensure if msPKI-Cert-Template-OID already add it to hashtable
            If (-not $TemplateOtherAttributes.ContainsKey('msPKI-Cert-Template-OID')) {
                #Create Template itself
                $TemplateOtherAttributes += @{
                    'msPKI-Cert-Template-OID' = $OID.TemplateOID
                }
            }
            $TemplatePath = 'CN=Certificate Templates,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC


            if ($PSCmdlet.ShouldProcess($TemplatePath, $WhatIfMessage)) {
                $Splat = @{
                    Path            = $TemplatePath
                    OtherAttributes = $TemplateOtherAttributes
                    Name            = $DisplayName
                    DisplayName     = $DisplayName
                    Type            = 'pKICertificateTemplate'
                    Server          = $Server
                }
                New-ADObject @Splat
            }

        } catch {
            # Handle errors here
            ###Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } #end Try-Catch
    } # End PROCESS section

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'adding new PKI template (Private Function).'
        )
        Write-Verbose -Message $txt
    } #end End section

} # End Function New-Template
