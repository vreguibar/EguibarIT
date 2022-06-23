Function New-TemplateOID {
    <#
        .Synopsis

        .DESCRIPTION

        .EXAMPLE

        .PARAMETER Server

        .PARAMETER ConfigNC

        .INPUTS

        .NOTES
            Used Functions:
                Name                           | Module
                -------------------------------|--------------------------
                New-ADObject                   | ActiveDirectory

        .NOTES
            Version:         1.4
            DateModified:    08/Oct/2021
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    [OutputType([System.Collections.Hashtable])]

    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'FQDN of a Domain Controller.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $Server,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Configuration Namin Context of the domain.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ConfigNC
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

    } # End BEGIN Section

    Process {
        <#
            OID CN/Name                    [10000000-99999999].[32 hex characters]
            OID msPKI-Cert-Template-OID    [Forest base OID].[1000000-99999999].[10000000-99999999]  <--- second number same as first number in OID name
        #>
        do {
            $OID_Part_1 = Get-Random -Minimum 1000000  -Maximum 99999999
            $OID_Part_2 = Get-Random -Minimum 10000000 -Maximum 99999999
            $OID_Part_3 = Get-RandomHex -Length 32
            $Splat = @{
                Server     = $Server
                Identity   = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
                Properties = 'msPKI-Cert-Template-OID'
            }
            $OID_Forest = Get-ADObject @splat | Select-Object -ExpandProperty msPKI-Cert-Template-OID

            $msPKICertTemplateOID = '{0}.{1}.{2}' -f $OID_Forest, $OID_Part_1, $OID_Part_2

            $Name = '{0}.{1}' -f $OID_Part_2, $OID_Part_3

        } until (IsUniqueOID -cn $Name -TemplateOID $msPKICertTemplateOID -Server $Server -ConfigNC $ConfigNC)

    } # End PROCESS Section

    End {
        Return @{
            TemplateOID  = $msPKICertTemplateOID
            TemplateName = $Name
        }

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

    } # End END Section
} # End Function New-TemplateOID
