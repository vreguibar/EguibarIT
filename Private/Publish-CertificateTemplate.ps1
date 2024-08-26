Function Publish-CertificateTemplate {
    <#
        .SYNOPSIS
            Publishes a certificate template to all available Certification Authorities (CAs) in the Active Directory environment.

        .DESCRIPTION
            This function publishes a specified certificate template to all Certification Authorities in the Active Directory.

        .PARAMETER CertDisplayName
            Specifies the display name of the certificate template to be published.

        .EXAMPLE
            Publish-CertificateTemplate -CertDisplayName "MyCertificateTemplate"

        .NOTES
            Version:         1.0
                DateModified:    22/Jun/2016
                LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
        #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([void])]

    Param (
        [Parameter(Mandatory = $true)]
        [string]$CertDisplayName
    )

    begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ######################
        # Initialize variables

        $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
        $EnrollmentPath = 'CN=Enrollment Services,CN=Public Key Services,CN=Services,{0}' -f $variables.configurationNamingContext
        $CAs = Get-ADObject -SearchBase $EnrollmentPath -SearchScope OneLevel -Filter * -Server $Server
    } #end Begin

    process {
        foreach ($CA in $CAs) {
            $TemplateToAdd = $CertDisplayName.Replace(' ', '')
            $CAIdentity = $CA.DistinguishedName

            if ($PSCmdlet.ShouldProcess("Certificate Template: $TemplateToAdd", "Publish to CA: $CAIdentity")) {
                try {
                    Set-ADObject -Identity $CAIdentity -Add @{certificateTemplates = $TemplateToAdd } -Server $Server -ErrorAction Stop
                    Write-Verbose "Certificate template '$TemplateToAdd' published to CA: $CAIdentity"
                } catch {
                    Write-Error "Failed to publish certificate template to CA: $CAIdentity. $_"
                } #end Try-Catch
            } #end If
        } #end ForEach
    } #end Process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'publishing Cert Template (Private Function).'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
