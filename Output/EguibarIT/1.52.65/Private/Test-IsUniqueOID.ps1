Function Test-IsUniqueOID {
    <#
        .SYNOPSIS
            Checks if a given Certificate Template OID is unique within the specified context.
        .DESCRIPTION
            This function queries Active Directory to determine if a given Certificate Template OID
            is already in use within the specified configuration context. It returns $True if the OID
            is unique and $False if it already exists.
        .PARAMETER cn
            Specifies the Common Name (CN) of the Certificate Template.
        .PARAMETER TemplateOID
            Specifies the OID (Object Identifier) of the Certificate Template.
        .PARAMETER Server
            Specifies the Active Directory server to query.
        .PARAMETER ConfigNC
            Specifies the Configuration Naming Context (ConfigNC) to search for the Certificate Template.
        .OUTPUTS
            System.Boolean
            Returns $True if the Certificate Template OID is unique, and $False if it already exists.
        .EXAMPLE
            Test-IsUniqueOID -cn "MyTemplate" -TemplateOID "1.2.3.4" -Server "ADServer01" -ConfigNC "DC=example,DC=com"
            Checks if the Certificate Template with the specified OID is unique in the given context.
    #>
    [CmdletBinding(ConfirmImpact = 'low')]
    [OutputType([System.Boolean])]
    param (
        [Parameter(Mandatory = $true)]
        [string]$cn,

        [Parameter(Mandatory = $true)]
        [string]$TemplateOID,

        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [string]$ConfigNC
    )

    try {
        # Query Active Directory for the Certificate Template
        $Search = Get-ADObject -Server $Server `
            -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
            -Filter {cn -eq $cn -and msPKI-Cert-Template-OID -eq $TemplateOID} -ErrorAction Stop

        # If the Certificate Template is found, it's not unique
        if ($Search) {
            Write-Verbose "Certificate Template with OID '$TemplateOID' already exists."
            return $false
        } else {
            Write-Verbose "Certificate Template with OID '$TemplateOID' is unique."
            return $true
        } #end If
    } catch {
        # Handle errors and provide verbose output
        Write-Error "Error: $_"
        Write-Verbose "An error occurred while checking the Certificate Template OID uniqueness."
        return $false
    } #end Try-Catch
} #end Function
