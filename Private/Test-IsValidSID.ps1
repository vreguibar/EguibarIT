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
            'S-1-5-18' | Test-SIDValidity
            Returns: True (since it matches the well-known SYSTEM SID)

        .OUTPUTS
            [bool] - Returns $true if the SID is valid, otherwise returns $false.

        .NOTES
            Used Functions:
                Name                                 ║ Module/Namespace
                ═════════════════════════════════════╬════════════════════════════════════════
                Get-ADObject                         ║ ActiveDirectory

        .NOTES
            Version:         1.1
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
            ValueFromRemainingArguments = $true,
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
        # Ensure only account is used (remove anything before \ if exist)
        If ($PSBoundParameters['ObjectSID'] -contains '\') {
            $ObjectSID = ($PSBoundParameters['ObjectSID']).Split('\')[1]
        } else {
            # Account does not contains \
            $ObjectSID = $PSBoundParameters['ObjectSID']
        } #end If-Else

        [bool]$isValid = $false

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess($ObjectSID, 'Validate SID format and existence')) {

            # try RegEx
            Try {

                #if ($Variables.WellKnownSIDs -Contains $ObjectSID) {
                If ($Variables.WellKnownSIDs.Keys.Contains($ObjectSID)) {

                    Write-Verbose -Message ('The SID {0} is a WellKnownSid.' -f $ObjectSID)
                    $isValid = $true

                } elseIf ($ObjectSID -match $Constants.SidRegEx) {

                    Write-Verbose -Message ('The SID {0} is valid.' -f $ObjectSID)
                    $isValid = $true

                } else {

                    Write-Verbose -Message ('[WARNING] The SID {0} is NOT valid!.' -f $ObjectSID)
                    $isValid = $false

                } #end If-Else
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
        } #end If
    } #end Process

    end {
        return $isValid
    } #end End

} #end Function
