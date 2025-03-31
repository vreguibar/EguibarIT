function Get-IniContent {
    <#
      .SYNOPSIS
        Gets the content of an INI file and returns it as a hashtable.

        .DESCRIPTION
            Parses an INI file and returns a nested hashtable of its contents.
            Supports sections, keys, values, and comments.
            Handles files with or without sections.

        .PARAMETER FilePath
            Specifies the path to the input INI file.
            Accepts pipeline input.
            Must be a valid file path.

        .EXAMPLE
            Get-IniContent -FilePath "C:\Config\settings.ini"
            Returns the content of settings.ini as a nested hashtable.

        .EXAMPLE
            "C:\Config\app.ini" | Get-IniContent
            Reads app.ini via pipeline and returns its content.

        .EXAMPLE
            $config = Get-IniContent "C:\Config\settings.ini"
            $value = $config["Section"]["Key"]
            Gets a specific value from the INI structure.

        .OUTPUTS
            System.Collections.Hashtable

        .NOTES
            Used Functions:
            Name                                   ║ Module/Namespace
            ═══════════════════════════════════════╬══════════════════════════════
            Write-Verbose                          ║ Microsoft.PowerShell.Utility
            Write-Error                            ║ Microsoft.PowerShell.Utility
            Get-FunctionDisplay                    ║ EguibarIT

        .NOTES
            Version:         2.0
            DateModified:   26/Mar/2025
            LastModifiedBy: Vicente Rodriguez Eguibar
                        vicente@eguibar.com
                        Eguibar IT
                        http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Private/Get-IniContent.ps1
    #>

    [CmdletBinding(
        SupportsShouldProcess = $false,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.Collections.Hashtable])]

    Param(
        [Parameter(Mandatory = $true,
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Path to the INI file to be parsed')]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
                if (-not (Test-Path -Path $_ -PathType Leaf)) {
                    throw "File not found: $_"
                } #end if
                return $true
            })]
        [Alias('Path', 'ConfigFile')]
        [string]
        $FilePath
    )

    Begin {
        Set-StrictMode -Version Latest

        # Output header information
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToShortDateString(),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Variables Definition

        $script:ini = [ordered]@{}
        $script:currentSection = $null
        $script:commentCount = 0

    } #end Begin

    Process {

        Try {
            $ini = @{}
            switch -regex -file $PSBoundParameters['FilePath'] {

                # Section
                '^\[(.+)\]$' {
                    $script:currentSection = $matches[1].Trim()
                    $script:ini[$currentSection] = [ordered]@{}
                    $script:commentCount = 0
                    Write-Debug -Message ('Found section: {0}' -f $currentSection)
                    continue
                } #end Section

                # Comment
                '^;(.*)$' {
                    if ($null -eq $script:currentSection) {
                        $script:currentSection = 'NoSection'
                        $script:ini[$currentSection] = [ordered]@{}
                    }
                    $script:commentCount++
                    $script:ini[$currentSection]["Comment$commentCount"] = $matches[1].Trim()
                    Write-Debug -Message ('Found comment: {0}' -f $matches[1])
                    continue
                } #end Comment

                # Key-Value Pair
                '(.+?)\s*=\s*(.*)' {
                    if ($null -eq $script:currentSection) {
                        $script:currentSection = 'NoSection'
                        $script:ini[$currentSection] = [ordered]@{}
                    }
                    $key = $matches[1].Trim()
                    $value = $matches[2].Trim()
                    $script:ini[$currentSection][$key] = $value
                    Write-Debug -Message ('Found key-value: {0} = {1}' -f $key, $value)
                    continue
                } #end Key-Value Pair

            } #end switch

        } catch {

            Write-Error -Message "An error occurred while processing the file: $_"
            throw

        } #end Try-Catch

    } # End Process

    End {
        # Display function footer
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                ('reading content from {0} file  (Private Function).' -f $PSBoundParameters['FilePath'])
            )
            Write-Verbose -Message $txt
        } #end if

        # Return the populated hashtable
        return $script:ini
    } #end End
} #end Function Get-IniContent
