function Test-IsValidDN {
    <#
        .SYNOPSIS
            Cmdlet will check if the input string is a valid distinguishedname.

        .DESCRIPTION
            Cmdlet will check if the input string is a valid distinguishedname.

            Cmdlet is intended as a dignostic tool for input validation

        .PARAMETER ObjectDN
            A string representing the object distinguishedname.

        .EXAMPLE
            Test-IsValidDN -ObjectDN 'Value1'

        .NOTES
            https://pscustomobject.github.io/powershell/howto/identity%20management/PowerShell-Check-If-String-Is-A-DN/
    #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'String to ve validated as DistinguishedName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN', 'DistinguishedName')]
        [string]
        $ObjectDN
    )

    # Define DN Regex
    [regex]$distinguishedNameRegex = '^(?:(?<cn>CN=(?<name>(?:[^,]|\,)*)),)?(?:(?<path>(?:(?:CN|OU)=(?:[^,]|\,)+,?)+),)?(?<domain>(?:DC=(?:[^,]|\,)+,?)+)$'

    return $ObjectDN -match $distinguishedNameRegex
}