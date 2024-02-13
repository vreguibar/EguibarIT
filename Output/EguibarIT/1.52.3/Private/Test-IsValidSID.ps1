function Test-IsValidSID {
    <#
        .SYNOPSIS
            Cmdlet will check if the input string is a valid SID.

        .DESCRIPTION
            Cmdlet will check if the input string is a valid SID.

            Cmdlet is intended as a dignostic tool for input validation

        .PARAMETER ObjectSID
            A string representing the object Security Identifier (SID).

        .EXAMPLE
            Test-IsValidDN -ObjectSID 'S-1-5-21-2562450185-1914323539-512974444-1234'

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
            HelpMessage = 'String to be validated as SID',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('SID', 'SecurityIdentifier')]
        [string]
        $ObjectSID
    )
    Begin {
        # Define DN Regex
        $SidRegex = [RegEx]::new("^S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}")
    } #end Begin
    Process {
        Try {
            # Use ShouldProcess to confirm the operation
            if ($PSCmdlet.ShouldProcess($ObjectDN, 'Validate objectSID')) {
                # Perform the actual validation
                $isValid = $ObjectSID -match $SidRegex

                # Provide verbose output
                if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
                    Write-Verbose "objectSID validation result: $isValid"
                } #end If
            } #end If
        } catch {
            # Handle exceptions gracefully
            Write-Error "An error occurred: $_"
        } #end Try-Catch
    } #end Process
    end {
        return $isValid
    } #end End
} #end Function
