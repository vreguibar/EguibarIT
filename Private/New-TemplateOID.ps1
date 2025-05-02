Function New-TemplateOID {
    <#
        .SYNOPSIS
            Generates a new OID for certificate templates.

        .DESCRIPTION
            This function generates a new OID (Object Identifier) for certificate templates within Active Directory.
            It creates a unique combination of:
            - Template Name: [10000000-99999999].[32 hex characters]
            - Template OID: [Forest base OID].[1000000-99999999].[10000000-99999999]
            The function ensures both the name and OID are unique in the forest.

        .PARAMETER Server
            FQDN of a Domain Controller.
            Used for all AD operations.
            Must be a valid DC with access to the Configuration NC.

        .PARAMETER ConfigNC
            Configuration Naming Context of the domain.
            Example: "CN=Configuration,DC=EguibarIT,DC=local"
            Must be a valid Configuration NC path.

        .EXAMPLE
            $result = New-TemplateOID -Server "DC01.EguibarIT.local" -ConfigNC "CN=Configuration,DC=EguibarIT,DC=local"
            $result.TemplateOID     # Output: 1.3.6.1.4.1.311.21.8.12345678.87654321
            $result.TemplateName    # Output: 87654321.0123456789ABCDEF0123456789ABCDEF

        .EXAMPLE
            $splat = @{
                Server = "DC01.EguibarIT.local"
                ConfigNC = "CN=Configuration,DC=EguibarIT,DC=local"
            }
            $newOID = New-TemplateOID @splat -Verbose
            Creates a new template OID with verbose output.

        .OUTPUTS
            System.Collections.Hashtable with properties:
            - TemplateOID: The full OID string
            - TemplateName: The template name string

        .NOTES
            Used Functions:
            Name                                   ║ Module/Namespace
            ═══════════════════════════════════════╬══════════════════════════════
            Get-RandomHex                          ║ EguibarIT
            Test-IsUniqueOID                       ║ EguibarIT
            Get-FunctionDisplay                    ║ EguibarIT
            Get-Random                             ║ Microsoft.PowerShell.Utility
            Get-ADObject                           ║ ActiveDirectory
            Write-Verbose                          ║ Microsoft.PowerShell.Utility
            Write-Error                            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         2.0
        DateModified:   26/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com
    #>
    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Hashtable])]

    Param(
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'FQDN of a Domain Controller')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController', 'DC')]
        [string]
        $Server,

        [Parameter(Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Configuration Naming Context path')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^CN=Configuration,(?:CN|DC)=')]
        [Alias('ConfigurationNC', 'ConfigurationNamingContext')]
        [string]
        $ConfigNC
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

        # Constants Definition
        $script:MaxAttempts = 100
        $script:AttemptCount = 0

    } # End BEGIN

    Process {
        try {
            <#
                OID CN/Name                    [10000000-99999999].[32 hex characters]
                OID msPKI-Cert-Template-OID    [Forest base OID].[1000000-99999999].[10000000-99999999]  <--- second number same as first number in OID name
            #>

            Write-Debug -Message ('Generating new template OID using server: {0}' -f $Server)

            do {
                $script:AttemptCount++
                Write-Debug -Message ('Attempt {0} of {1}' -f $script:AttemptCount, $script:MaxAttempts)

                $OID_Part_1 = Get-Random -Minimum 1000000 -Maximum 99999999
                $OID_Part_2 = Get-Random -Minimum 10000000 -Maximum 99999999
                $OID_Part_3 = Get-RandomHex -Length 32

                # Get forest base OID
                $Splat = @{
                    Server     = $Server
                    Identity   = 'CN=OID,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC
                    Properties = 'msPKI-Cert-Template-OID'
                }
                $OID_Forest = Get-ADObject @splat |
                    Select-Object -ExpandProperty msPKI-Cert-Template-OID

                if (-not $OID_Forest) {
                    throw 'Failed to retrieve forest base OID'
                } #end if

                # Construct OID and name
                $msPKICertTemplateOID = '{0}.{1}.{2}' -f $OID_Forest, $OID_Part_1, $OID_Part_2

                $Name = '{0}.{1}' -f $OID_Part_2, $OID_Part_3

                Write-Debug -Message ('Testing OID: {0}' -f $msPKICertTemplateOID)
                Write-Debug -Message ('Testing name: {0}' -f $Name)

                # Test uniqueness
                $isUnique = Test-IsUniqueOID -cn $Name -TemplateOID $msPKICertTemplateOID -Server $Server -ConfigNC $ConfigNC

                if ($script:AttemptCount -ge $script:MaxAttempts) {
                    throw 'Maximum attempts reached while trying to generate unique OID'
                } #end if

            } until ($isUnique)

            Write-Verbose -Message ('Successfully generated unique template OID after {0} attempts' -f $script:AttemptCount)

        } catch {

            Write-Error -Message ('Failed to generate template OID: {0}' -f $_.Exception.Message)
            throw

        } # End TRY/CATCH

    } # End PROCESS

    End {
        # Display function footer
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'creating new Template OID (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end if

        # Return results
        @{
            TemplateOID  = $msPKICertTemplateOID
            TemplateName = $Name
        }

    } # End END Section

} # End Function New-TemplateOID
