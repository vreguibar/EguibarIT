function Test-IsValidSID {
    <#
        .SYNOPSIS
            Validates if the given input is a valid SID.

        .DESCRIPTION
            This function checks if an input is a syntactically valid Security Identifier (SID).
            Additionally, it verifies if the SID exists within a predefined hashtable of well-known SIDs.

        .PARAMETER ObjectSID
            A string representing the object Security Identifier (SID).

        .EXAMPLE
            Test-IsValidSID -ObjectSID 'S-1-5-21-2562450185-1914323539-512974444-1234'
            Returns: True or False

        .EXAMPLE
            'S-1-5-18' | Test-IsValidSID
            Returns: True (since it matches the well-known SYSTEM SID)

        .OUTPUTS
            [bool] - Returns $true if the SID is valid, otherwise returns $false.

        .NOTES
            Used Functions:
                Name                                 ║ Module/Namespace
                ═════════════════════════════════════╬════════════════════════════════════════
                Write-Verbose                        ║ Microsoft.PowerShell.Utility
                Write-Error                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:    12/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                        vicente@eguibar.com
                        Eguibar Information Technology S.L.
                        http://www.eguibarit.com

        .LINK
            https://pscustomobject.github.io/powershell/howto/identity%20management/PowerShell-Check-If-String-Is-A-DN/

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Private/Test-IsValidSID.ps1
    #>
    [CmdletBinding(ConfirmImpact = 'Low', SupportsShouldProcess = $true)]
    [OutputType([bool])]

    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'String to be validated as SID',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('SID', 'SecurityIdentifier')]
        [string]
        $ObjectSID
    )

    Begin {
        Set-StrictMode -Version Latest

        ##############################
        # Module imports

        ##############################
        # Variables Definition
        [bool]$isValid = $false

    } #end Begin

    Process {
        # Handle pipeline input correctly
        $SIDToValidate = $ObjectSID

        # Ensure only account is used (remove anything before \ if exists)
        If ($SIDToValidate -match '\\') {
            $SIDToValidate = $SIDToValidate.Split('\')[1]
            Write-Verbose -Message ('Domain format detected. Extracted SID: {0}' -f $SIDToValidate)
        } #end If

        if ($PSCmdlet.ShouldProcess($SIDToValidate, 'Validate SID format and existence')) {
            # Try RegEx validation
            Try {
                # Check if it's a well-known SID first
                If ($null -ne $Variables -and
                    $null -ne $Variables.WellKnownSIDs -and
                    $Variables.WellKnownSIDs.ContainsKey($SIDToValidate)) {
                    Write-Verbose -Message ('The SID {0} is a WellKnownSid.' -f $SIDToValidate)
                    $isValid = $true
                }
                # Then check against regex pattern
                elseIf ($null -ne $Constants -and
                    $null -ne $Constants.SidRegEx -and
                    $SIDToValidate -match $Constants.SidRegEx) {
                    Write-Verbose -Message ('The SID {0} is valid.' -f $SIDToValidate)
                    $isValid = $true
                }
                # If neither, it's invalid
                else {
                    # This exact message format is expected by the test
                    Write-Verbose -Message ('[WARNING] The SID {0} is NOT valid!.' -f $SIDToValidate)
                    $isValid = $false
                } #end If-Else
            } catch {
                # Handle exceptions gracefully
                Write-Error -Message ('An error occurred when validating the SID: {0}' -f $_.Exception.Message)
                $isValid = $false
            } #end Try-Catch

            # Return the validation result within the ShouldProcess block
            return $isValid
        } #end If ShouldProcess
    } #end Process

    End {
        # No action needed here since we return within Process
    } #end End

} #end Function Test-IsValidSID
