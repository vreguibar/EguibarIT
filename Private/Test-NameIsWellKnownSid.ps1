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
            PS> Test-NameIsWellKnownSid -Name 'NT AUTHORITY\SYSTEM'

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

        $Name = ($PSBoundParameters['Name']).ToLower()

        $cleanedName = $Name -replace '^(built-in\\|builtin\\|built in\\|nt authority\\|ntauthority\\|ntservice\\|nt service\\)', ''

    } #end Begin

    Process {

        Try {
            # Check if the cleaned name is in the Well-Known SID dictionary
            if ($Variables.WellKnownSIDs.Values.Contains($cleanedName)) {
                # Find the corresponding SID
                $sid = $Variables.WellKnownSIDs.keys.where{ $Variables.WellKnownSIDs[$_] -eq $cleanedName }

                if ($sid) {

                    # Create the SecurityIdentifier object
                    $Identity = [System.Security.Principal.SecurityIdentifier]::new($sid)
                    Write-Verbose -Message ('
                        Matched SID: {0}
                                For: {1}' -f
                        $Identity.Value, $cleanName
                    )

                    # Convert to SecurityIdentifier object
                    [System.Security.Principal.SecurityIdentifier]$Identity = [System.Security.Principal.SecurityIdentifier]::New($sid)
                } else {

                    Write-Error -Message ('
                        Error creating SecurityIdentifier object for {0}.' -f
                        $cleanName
                    )
                    #Get-ErrorDetail -ErrorRecord $_
                    $Identity = $null
                }
            } else {
                Write-Verbose -Message ('
                    The name {0} does not correspond to a well-known SID or is not recognized.' -f
                    $cleanedName
                )
                $Identity = $null
            } #end If-Else

        } catch {
            Write-Error -Message ('Error found when translating WellKnownSid for {0}.' -f $cleanedName)
            $Identity = $null
            #Get-ErrorDetail -ErrorRecord $_
        } #end Try-Catch

    } #end Process

    End {
        $txt = ($Variables.FooterDelegation -f $MyInvocation.InvocationName,
            'testing Well-Known SID (Private Function).'
        )
        Write-Verbose -Message $txt

        return $Identity.Value
    } #end End
}
