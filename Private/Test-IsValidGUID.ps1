function Test-IsValidGUID {
    <#
        .SYNOPSIS
            Validates if the input string is a valid Global Unique Identifier (GUID).

        .DESCRIPTION
            This cmdlet checks if the provided input string adheres to the structure of a valid GUID.
            It uses a RegEx pattern to validate the GUID format which must be in the format:
            "550e8400-e29b-41d4-a716-446655440000"

        .PARAMETER ObjectGUID
            The GUID string to validate. Must be in the format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
            where x represents hexadecimal digits (0-9, a-f, A-F).

        .EXAMPLE
            Test-IsValidGUID -ObjectGUID '550e8400-e29b-41d4-a716-446655440000'
            Returns $true as this is a valid GUID format.

        .EXAMPLE
            '550e8400-e29b-41d4-a716-446655440000' | Test-IsValidGUID
            Shows pipeline input usage. Returns $true.

        .EXAMPLE
            Test-IsValidGUID -ObjectGUID 'invalid-guid'
            Returns $false as this is not a valid GUID format.

        .OUTPUTS
            [bool]
            Returns $true if the input is a valid GUID, $false otherwise.

        .NOTES
            Used Functions:
                Name                   ║ Module/Namespace
                ═══════════════════════╬══════════════════════════════
                Write-Verbose          ║ Microsoft.PowerShell.Utility
                Write-Error            ║ Microsoft.PowerShell.Utility
                Write-Debug            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:    20/Mar/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar IT
                http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Private/Test-IsValidGUID.ps1
    #>

    [CmdletBinding(ConfirmImpact = 'Low',
        SupportsShouldProcess = $false)]
    [OutputType([bool])]

    param (
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'String to be validated as Global Unique Identifier (GUID)',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('GUID', 'GlobalUniqueIdentifier', 'Id')]
        [string]
        $ObjectGUID
    )

    Begin {

        Set-StrictMode -Version Latest

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        [bool]$isValid = $false

        Write-Debug 'Begin block: Regex pattern for GUID validation initialized.'

    } #end Begin

    Process {

        Try {

            # Perform the actual validation
            #$isValid = $ObjectDN -match $distinguishedNameRegex
            $isValid = $ObjectGUID -match $Constants.GuidRegEx

            Write-Verbose -Message ('GUID validation result: {0}' -f $isValid)

        } catch {

            # Handle exceptions gracefully
            Write-Error -Message 'Error when validating GUID'

        } #end Try-Catch

    } #end Process

    end {
        return $isValid
    } #end End
} #end Function Test-IsValidGUID
