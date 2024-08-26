function Test-IsValidDN {
    <#
        .SYNOPSIS
            Validates if the input string is a valid distinguished name (DN).

        .DESCRIPTION
            This cmdlet checks if the provided input string adheres to the structure of a valid distinguished name in Active Directory.

            It is designed as a diagnostic tool to facilitate input validation for scripts and functions that manipulate Active Directory objects.

        .PARAMETER ObjectDN
            The distinguished name to validate. This parameter accepts a string representing the DN of an Active Directory object.

        .EXAMPLE
            Test-IsValidDN -ObjectDN 'CN=Darth Vader,OU=Users,DC=EguibarIT,DC=local'

            Returns $true if the input string is a valid DN, $false otherwise.


        .NOTES
            https://pscustomobject.github.io/powershell/howto/identity%20management/PowerShell-Check-If-String-Is-A-DN/

            Version:         1.1
            DateModified:    09/Feb/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>

    [CmdletBinding(ConfirmImpact = 'Low', SupportsShouldProcess = $false)]
    [OutputType([bool])]

    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'String to ve validated as DistinguishedName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN', 'DistinguishedName')]
        [string]
        $ObjectDN
    )

    Begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        # Initialize a boolean variable to store validation result
        [bool]$isValid = $false

        Write-Verbose 'Begin block: Regex pattern for DN validation initialized.'

    } #end Begin

    Process {

        Try {

            # Perform the actual validation
            #$isValid = $ObjectDN -match $distinguishedNameRegex
            $isValid = $ObjectDN -match $Constants.DnRegEx

            # Provide verbose output
            if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
                Write-Verbose -Message ('DistinguishedName validation result: {0}' -f $isValid)
            } #end If

        } catch {
            # Handle exceptions gracefully
            Write-Error -Message 'Error when validating DistinguishedName'
            throw
        } #end Try-Catch

    } #end Process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'testing DistinguishedName (DN) (Private Function).'
        )
        Write-Verbose -Message $txt

        return $isValid
    } #end End

} #end Function
