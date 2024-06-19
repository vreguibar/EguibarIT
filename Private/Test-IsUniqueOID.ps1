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
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Specifies the Common Name (CN) of the Certificate Template',
            Position = 0)]
        [string]
        $cn,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Specifies the OID (Object Identifier) of the Certificate Template',
            Position = 1)]
        [string]
        $TemplateOID,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Specifies the Active Directory server to query',
            Position = 2)]
        [string]
        $Server,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Specifies the Configuration Naming Context (ConfigNC) to search for the Certificate Template.',
            Position = 3)]
        [string]
        $ConfigNC
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        $SearchBase = 'CN=OID,CN=Public Key Services,CN=Services,{0}' -f $ConfigNC
        $Filter = '{ cn -eq {0} -and msPKI-Cert-Template-OID -eq {1} }' -f $cn, $TemplateOID

    } #end Begin

    Process {
        try {
            # Query Active Directory for the Certificate Template
            $Splat = @{
                Server      = $Server
                SearchBase  = $SearchBase
                Filter      = $filter
                ErrorAction = Stop
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

        } catch {
            # Handle errors and provide verbose output
            ###Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
            Write-Error -Message 'An error occurred while checking the Certificate Template OID uniqueness.'
            return $false
        } #end Try-Catch
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished checking the Certificate Template OID uniqueness."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} #end Function
