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
    [CmdletBinding(ConfirmImpact = 'Low', SupportsShouldProcess = $false)]
    [OutputType([bool])]

    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $true,
            HelpMessage = 'String to be validated as SID',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('SID', 'SecurityIdentifier')]
        [string]
        $ObjectSID
    )

    Begin {
        # Define DN Regex
        #$SidRegex = [RegEx]::new('^S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3}')
        $SidRegex = [RegEx]::new('^S-1-(0|1|2|3|4|5|59)-\d+(-\d+)*$')

    } #end Begin

    Process {
        # try RegEx
        Try {
            if ($SIDRegex.IsMatch($SID)) {

                $isValid = $tue

                # Provide verbose output
                if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
                    Write-Verbose -Message ('The SID {0} is valid.' -f $SID)
                } #end If
            } else {
                $isValid = $false

                # Provide verbose output
                if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
                    Write-Verbose -Message ('[WARNING] The SID {0} is NOT valid!.' -f $SID)
                } #end If
            }

        } catch {
            # Handle exceptions gracefully
            Write-Error -Message ('An error occurred when validating the SID: {0}' -f $_)
        } #end Try-Catch

        <#
        # try Native SID
        Try {
            # Perform the actual validation
            [System.Security.Principal.SecurityIdentifier]$sid = $Sid
            $isValid = $True

            # Provide verbose output
            if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
                Write-Verbose "objectSID validation result by [SecurityIdentifier]: $isValid"
            } #end If

        } catch {
            # Handle exceptions gracefully
            Write-Error "An error occurred on [SecurityIdentifier] comparison: $_"
        } #end Try-Catch
         #>
    } #end Process

    end {
        return $isValid
    } #end End

} #end Function
