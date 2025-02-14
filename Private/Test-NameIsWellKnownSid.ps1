Function Test-NameIsWellKnownSid {

    <#
        .SYNOPSIS
            Checks if a given name corresponds to a well-known SID and returns the SID.

        .DESCRIPTION
            This function takes a name as input, processes it to remove common prefixes,
            and checks if it corresponds to a well-known SID.
            If found, it returns the SID as a [System.Security.Principal.SecurityIdentifier] object.

        .PARAMETER Name
            The name to check against the well-known SIDs.

        .EXAMPLE
            Test-NameIsWellKnownSid -Name 'NT AUTHORITY\SYSTEM'

        .INPUTS
            [String] Name

        .OUTPUTS
            [System.Security.Principal.SecurityIdentifier]
    #>

    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'low')]
    [OutputType([System.Security.Principal.SecurityIdentifier])]

    Param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Specify the name to check against Well-Known SIDs.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Name

    )

    Begin {
        $txt = ($Variables.HeaderDelegation -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        $Identity = $null

        # Clean the name by removing common prefixes and convert to lowercase
        $cleanedName = $Name -replace '^(built-in\\|builtin\\|built in\\|nt authority\\|ntauthority\\|ntservice\\|nt service\\|local\\|domain\\)', ''
        $cleanedName = $cleanedName.ToLower()
    } #end Begin

    Process {

        try {
            # Find matching SIDs for the cleaned name
            $matchingSids = $Variables.WellKnownSIDs.GetEnumerator() | Where-Object { $_.Value -eq $cleanedName }

            if ($matchingSids.Count -eq 1) {

                $sid = $matchingSids[0].Key

                Write-Verbose -Message ('
                    Matched SID: {0}
                    for name: {1}' -f
                    $sid, $cleanedName
                )

                # Create and return the SecurityIdentifier object
                $Identity = [System.Security.Principal.SecurityIdentifier]::New($sid)

            } elseif ($matchingSids.Count -gt 1) {

                Write-Warning -Message ('Multiple Well-Known SIDs found for name: {0}' -f $cleanedName)
                $Identity = $null

            } else {

                Write-Verbose -Message ('No Well-Known SID found for name: {0}' -f $cleanedName)
                $Identity = $null

            } #end if-elseif-else

        } catch {

            Write-Error -Message ('
                Error checking Well-Known SID for name: {0}.
                Error: {1}' -f $cleanedName, $_.Exception.Message
            )
            $Identity = $null

        } #end try-catch

    } #end Process

    End {

        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'testing Well-Known SID (Private Function).'
        )
        Write-Verbose -Message $txt

        return $Identity

    } #end End
}
