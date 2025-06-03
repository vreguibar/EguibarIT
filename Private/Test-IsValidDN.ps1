function Test-IsValidDN {
    <#
        .SYNOPSIS
            Validates if the input string is a valid distinguished name (DN).

        .DESCRIPTION
            This cmdlet checks if the provided input string adheres to the
            structure of a valid distinguished name in Active Directory.
            It uses regex pattern matching to validate the DN structure
            without making actual AD queries.

            The function is idempotent and can process multiple DNs
            through pipeline input efficiently.

        .PARAMETER ObjectDN
            The distinguished name to validate. This parameter accepts a
            string representing the DN of an Active Directory object.
            Multiple DNs can be processed through pipeline input.

        .INPUTS
            System.String
            You can pipe one or more distinguished name strings to this function.

        .OUTPUTS
            System.Boolean
            Returns $true if the string is a valid distinguished name, otherwise $false.

        .EXAMPLE
            Test-IsValidDN -ObjectDN 'CN=Darth Vader,OU=Users,DC=EguibarIT,DC=local'

            Returns $true as this is a valid DN format.

        .EXAMPLE
            'CN=Test User,DC=domain,DC=com', 'Invalid DN' | Test-IsValidDN

            Processes multiple DNs through pipeline, returning boolean results for each.

        .EXAMPLE
            Test-IsValidDN -ObjectDN 'Invalid DN' -Verbose

            Returns $false and shows verbose output about the validation process.

        .NOTES
            Used Functions:
                Name                    ║ Module/Namespace
                ════════════════════════╬══════════════════════════════
                Write-Verbose           ║ Microsoft.PowerShell.Utility
                Write-Debug             ║ Microsoft.PowerShell.Utility
                Write-Error             ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.3
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://pscustomobject.github.io/powershell/howto/identity%20management/PowerShell-Check-If-String-Is-A-DN/

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Private/Test-IsValidDN.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Identity Management

        .FUNCTIONALITY
            Distinguished Name Validation
    #>

    [CmdletBinding(ConfirmImpact = 'Low',
        SupportsShouldProcess = $false)]
    [OutputType([bool])]

    param
    (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Distinguished Name string to validate',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('DN', 'DistinguishedName')]
        [string]
        $ObjectDN
    )

    Begin {

        Set-StrictMode -Version Latest

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        # Initialize a boolean variable to store validation result
        [bool]$isValid = $false

        Write-Debug -Message 'Begin block: Regex pattern for DN validation initialized.'

    } #end Begin

    Process {

        Try {

            # Perform the actual validation
            $isValid = $ObjectDN -match $Constants.DnRegEx

            # Provide verbose output
            if ($PSCmdlet.MyInvocation.BoundParameters['Verbose']) {
                Write-Verbose -Message ('DistinguishedName validation result: {0}' -f $isValid)
            } #end If

        } catch {

            # Handle any exceptions gracefully
            Write-Error -Message ('Error validating DN: {0}. Error: {1}' -f $ObjectDN, $_.Exception.Message)
            $isValid = $false

        } #end Try-Catch

    } #end Process

    end {
        return $isValid
    } #end End
} #end Function Test-IsValidDN
