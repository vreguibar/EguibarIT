﻿function Test-IsValidSID {
    <#
        .SYNOPSIS
            Cmdlet will check if the input string is a valid SID.

        .DESCRIPTION
            Cmdlet will check if the input string is a valid SID.

            Cmdlet is intended as a diagnostic tool for input validation

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
        # try RegEx
        Try {
            # Provide verbose output
            if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {

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

            } #end If VERBOSE
        } catch {
            # Handle exceptions gracefully
            Write-Error -Message ('An error occurred when validating the SID: {0}' -f $_)
            Get-ErrorDetail -ErrorRecord $_
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
