Function IsUniqueOID {
    [CmdletBinding(ConfirmImpact = 'low')]
    [OutputType([System.Boolean])]
    param (
        $cn,
        $TemplateOID,
        $Server,
        $ConfigNC
    )
    $Search = Get-ADObject -Server $Server `
        -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
        -Filter {cn -eq $cn -and msPKI-Cert-Template-OID -eq $TemplateOID}
    If ($Search) {$False} Else {$True}
}