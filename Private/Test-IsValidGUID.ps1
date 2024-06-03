function Test-IsValidGUID {
    <#
        .SYNOPSIS
            Validates if the input string is a valid Global Unique Identifier (GUID).

        .DESCRIPTION
            This cmdlet checks if the provided input string adheres to the structure of a valid GUID in Active Directory.

            It is designed as a diagnostic tool to facilitate input validation for scripts and functions that manipulate Active Directory objects.

        .PARAMETER ObjectDN
            The distinguished name to validate. This parameter accepts a string representing the DN of an Active Directory object.

        .EXAMPLE
            Test-IsValidGUID -ObjectDN 'CN=Darth Vader,OU=Users,DC=EguibarIT,DC=local'

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
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'String to be validated as Global Unique Identifier (GUID)',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID', 'GlobalUniqueIdentifier')]
        [string]
        $ObjectGUID
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        $isValid = $false

        <# Define GUID Regex
        Active Directory GUID is represented as a 128-bit number, typically displayed as a
        string of 32 hexadecimal characters, such as "550e8400-e29b-41d4-a716-446655440000"
            ^ asserts the start of the string.
            [0-9a-fA-F] matches any hexadecimal digit.
            {8} specifies that the preceding character class should appear exactly 8 times.
            - matches the hyphen character literally.
            {4} specifies that the preceding character class should appear exactly 4 times.
            {12} specifies that the preceding character class should appear exactly 12 times.
            $ asserts the end of the string.
        #>
        [regex]$guidNameRegex = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

        Write-Verbose 'Begin block: Regex pattern for GUID validation initialized.'

    } #end Begin

    Process {

        Try {

            # Perform the actual validation
            #$isValid = $ObjectDN -match $distinguishedNameRegex
            $isValid = $guidNameRegex.IsMatch($ObjectGUID)

            # Provide verbose output
            if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
                Write-Verbose -Message ('DistinguishedName validation result: {0}' -f $isValid)
            } #end If

        } catch {
            # Handle exceptions gracefully
            ## Get-CurrentErrorToDisplay -CurrentError $error[0]
            throw
        } #end Try-Catch

    } #end Process

    end {

        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished checking Global Unique Identifier (GUID)."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        return $isValid
    } #end End
} #end Function
