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
            Version:         1.0
            DateModified:    08/Oct/2021
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Low', SupportsShouldProcess = $true)]
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
    Begin {
        # Define DN Regex
        [regex]$distinguishedNameRegex = '^(?:(?<cn>CN=(?<name>(?:[^,]|\,)*)),)?(?:(?<path>(?:(?:CN|OU)=(?:[^,]|\,)+,?)+),)?(?<domain>(?:DC=(?:[^,]|\,)+,?)+)$'
    } #end Begin
    Process {
        Try {
            # Use ShouldProcess to confirm the operation
            if ($PSCmdlet.ShouldProcess($ObjectDN, 'Validate DistinguishedName')) {
                # Perform the actual validation
                $isValid = $ObjectDN -match $distinguishedNameRegex

                # Provide verbose output
                if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
                    Write-Verbose "DistinguishedName validation result: $isValid"
                } #end If
            } #end If
        }
        catch {
            # Handle exceptions gracefully
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        } #end Try-Catch
    } #end Process
    end {
        return $isValid
    } #end End
} #end Function
