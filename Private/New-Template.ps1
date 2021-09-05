Function New-Template {
Param($DisplayName,$TemplateOtherAttributes)

    #grab DC
    $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
    #grab Naming Context
    $ConfigNC = (Get-ADRootDSE -Server $Server).configurationNamingContext
    #Create OID
        $OID = New-TemplateOID -Server $Server -ConfigNC $ConfigNC
        $TemplateOIDPath = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
        $OIDOtherAttributes = @{
                'DisplayName' = $DisplayName
                'flags' = [System.Int32]'1'
                'msPKI-Cert-Template-OID' = $OID.TemplateOID
        }
        New-ADObject -Path $TemplateOIDPath -OtherAttributes $OIDOtherAttributes -Name $OID.TemplateName -Type 'msPKI-Enterprise-Oid' -Server $Server
    #Create Template itself
        $TemplateOtherAttributes+= @{
            'msPKI-Cert-Template-OID' = $OID.TemplateOID
        }
        $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
        New-ADObject -Path $TemplatePath -OtherAttributes $TemplateOtherAttributes -Name $DisplayName -DisplayName $DisplayName -Type pKICertificateTemplate -Server $Server
}