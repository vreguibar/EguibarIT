Function Test-IsUniqueOID {
    <#
        .SYNOPSIS
            Checks if a given Certificate Template OID is unique within the specified context.

        .DESCRIPTION
            This function queries Active Directory to determine if a given Certificate Template OID
            is already in use within the specified configuration context. It returns $True if the OID
            is unique and $False if it already exists.

            The function performs the following validations:
            - Verifies the OID format
            - Checks the connection to the specified AD server
            - Validates the configuration naming context
            - Ensures proper access rights

        .PARAMETER cn
            Specifies the Common Name (CN) of the Certificate Template.
            Must be a valid CN format string.

        .PARAMETER TemplateOID
            Specifies the OID (Object Identifier) of the Certificate Template.
            Must be in valid OID format (e.g., 1.3.6.1.4.1.311.21.8.1234567.1234567).

        .PARAMETER Server
            Specifies the Active Directory server to query.
            Must be a valid FQDN of a domain controller.

        .PARAMETER ConfigNC
            Specifies the Configuration Naming Context (ConfigNC) to search for the Certificate Template.
            Must be a valid AD path starting with "CN=Configuration,".

        .INPUTS
            System.String
            You can pipe string values for all parameters to this function.

        .OUTPUTS
            System.Boolean
            Returns $True if the Certificate Template OID is unique, and $False if it already exists.

        .EXAMPLE
            Test-IsUniqueOID -cn "WebServer2025" `
                            -TemplateOID "1.3.6.1.4.1.311.21.8.1234567.1234567" `
                            -Server "DC01.contoso.com" `
                            -ConfigNC "CN=Configuration,DC=contoso,DC=com"

            Checks if the Certificate Template OID is unique in the specified context.

        .EXAMPLE
            $splat = @{
                cn = "UserAuth2025"
                TemplateOID = "1.3.6.1.4.1.311.21.8.7654321.7654321"
                Server = "DC01.contoso.com"
                ConfigNC = "CN=Configuration,DC=contoso,DC=com"
            }
            Test-IsUniqueOID @splat -Verbose

            Checks template uniqueness with verbose output using splatting.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Get-ADObject                           ║ ActiveDirectory
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Debug                            ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         2.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Private/Test-IsUniqueOID.ps1

        .COMPONENT
            PKI

        .ROLE
            Certificate Management

        .FUNCTIONALITY
            OID Validation
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Boolean])]

    param (
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specifies the Common Name (CN) of the Certificate Template')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^[a-zA-Z0-9\s-_]+$')]
        [Alias('CommonName', 'Name')]
        [string]
        $cn,

        [Parameter(Mandatory = $true,
            Position = 1,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specifies the OID of the Certificate Template')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^\d+(\.\d+)*$')]
        [Alias('OID')]
        [string]
        $TemplateOID,

        [Parameter(Mandatory = $true,
            Position = 2,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specifies the Active Directory server to query')]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController', 'DC')]
        [string]
        $Server,

        [Parameter(Mandatory = $true,
            Position = 3,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specifies the Configuration Naming Context')]
        [ValidateNotNullOrEmpty()]
        [ValidatePattern('^CN=Configuration,(?:CN|DC)=')]
        [Alias('ConfigurationNC', 'ConfigurationNamingContext')]
        [string]
        $ConfigNC
    )

    Begin {
        Set-StrictMode -Version Latest

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        $SearchBase = 'CN=OID,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC
        $Filter = '{ cn -eq {0} -and msPKI-Cert-Template-OID -eq {1} }' -f $cn, $TemplateOID

        Write-Debug -Message ('Search base: {0}' -f $SearchBase)
        Write-Debug -Message ('Filter: {0}' -f $Filter)

    } #end Begin

    Process {
        try {
            Write-Debug -Message ('Checking uniqueness for OID {0} on server {1}' -f $TemplateOID, $Server)

            # Query Active Directory for the Certificate Template
            $Splat = @{
                Server      = $Server
                SearchBase  = $SearchBase
                Filter      = $Filter
                Properties  = 'cn', 'msPKI-Cert-Template-OID'
                ErrorAction = 'Stop'
            }
            $Search = Get-ADObject @Splat

            # If the Certificate Template is found, it's not unique
            if ($Search) {

                Write-Verbose -Message 'Certificate Template with OID {0} already exists.' -f $TemplateOID
                return $false

            } else {

                Write-Verbose -Message 'Certificate Template with OID {0} is unique.' -f $TemplateOID
                return $true

            } #end If

        } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {

            Write-Error -Message ('Failed to connect to server {0}' -f $Server)
            throw

        } catch [Microsoft.ActiveDirectory.Management.ADException] {

            Write-Error -Message ('Access denied or invalid search path: {0}' -f $SearchBase)
            throw

        } catch {

            Write-Error -Message ('An unexpected error occurred: {0}' -f $_.Exception.Message)
            throw

        } #end Try-Catch

    } #end Process

    End {
    } #end End

} #end Function Test-IsUniqueOID
