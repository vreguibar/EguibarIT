Function Out-IniFile {
    <#
        .SYNOPSIS
            Write hash content to INI file

        .DESCRIPTION
            Writes a hashtable's content to an INI file with support for:
            - Sections and key-value pairs
            - Comments
            - Multiple encodings
            - File append mode
            - Read-only file overwrite

        .PARAMETER Append
            Adds the output to the end of an existing file, instead of replacing the file contents.

        .PARAMETER Encoding
            Specifies the character encoding. Default is Unicode.
            Valid values: Unicode, UTF7, UTF8, UTF32, ASCII, BigEndianUnicode, Default, OEM

        .PARAMETER FilePath
            Path to the output INI file.

        .PARAMETER Force
            Allows overwriting read-only files.

        .PARAMETER InputObject
            Hashtable containing the INI content to write.

        .PARAMETER PassThru
            Returns the file object after writing.

        .EXAMPLE
            $config = @{
                'Section1' = @{
                    'Key1' = 'Value1'
                    'Key2' = 'Value2'
                }
            }
            Out-IniFile -InputObject $config -FilePath 'C:\config.ini'

        .EXAMPLE
            $config | Out-IniFile -FilePath 'C:\config.ini' -Force -Encoding UTF8

        .OUTPUTS
            System.IO.FileSystemInfo when using -PassThru
            Void otherwise

        .NOTES
            Used Functions:
            Name                                   ║ Module/Namespace
            ═══════════════════════════════════════╬══════════════════════════════
            Write-Verbose                          ║ Microsoft.PowerShell.Utility
            Write-Error                            ║ Microsoft.PowerShell.Utility
            New-Item                               ║ Microsoft.PowerShell.Management
            Get-Item                               ║ Microsoft.PowerShell.Management
            Add-Content                            ║ Microsoft.PowerShell.Management
            Get-FunctionDisplay                    ║ EguibarIT

        .NOTES
            Version:         2.0
            DateModified:   26/Mar/2025
            LastModifiedBy: Vicente Rodriguez Eguibar
                        vicente@eguibar.com
                        Eguibar IT
                        http://www.eguibarit.com

            Based on work by: Oliver Lipkau <oliver@lipkau.net>
            Source: https://github.com/lipkau/PsIni

        .LINK
            https://github.com/vreguibar/eguibarit
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'Low'
    )]
    [OutputType([System.IO.FileSystemInfo], ParameterSetName = 'PassThru')]
    [OutputType([void])]

    Param(
        [Parameter(Position = 0)]
        [switch]
        $Append,

        [Parameter(Position = 1)]
        [ValidateSet('Unicode', 'UTF7', 'UTF8', 'UTF32', 'ASCII', 'BigEndianUnicode', 'Default', 'OEM', ignorecase = $false)]
        [PSDefaultValue(Help = 'Default Value is "Unicode"')]
        [string]
        $Encoding = 'Unicode',

        [Parameter(Mandatory = $true,
            Position = 2,
            HelpMessage = 'Path to the output INI file')]
        [ValidateNotNullOrEmpty()]
        [Alias('Path', 'File')]
        [string]
        $FilePath,

        [Parameter(Position = 3)]
        [switch]
        $Force,

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            HelpMessage = 'Hashtable containing INI content')]
        [ValidateNotNull()]
        [Alias('Hash', 'Content')]
        [hashtable]
        $InputObject,

        [Parameter(Position = 4)]
        [switch]
        $Passthru
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
        } #end If

        ##############################
        # Variables Definition

        # StringBuilder for better performance
        $sb = [System.Text.StringBuilder]::new()

    } #end Begin

    Process {

        try {
            # Create or get the file
            if ($PSBoundParameters['Append']) {

                $outFile = Get-Item -Path $FilePath -ErrorAction Stop
                Write-Debug -Message ('Appending to existing file: {0}' -f $FilePath)

            } else {

                if ($PSCmdlet.ShouldProcess($FilePath, 'Create new INI file')) {

                    $outFile = New-Item -ItemType File -Path $FilePath -Force:$Force -ErrorAction Stop
                    Write-Debug -Message ('Created new file: {0}' -f $FilePath)

                } #End If

            } #end If-Else

            if (-not $outFile) {
                Throw 'Could not create File'
            } #end If

            # Process each key in the hashtable
            foreach ($section in $InputObject.Keys) {

                Write-Debug -Message ('Processing section: {0}' -f $section)

                if ($InputObject[$section] -isnot [hashtable]) {

                    # Direct key-value pair
                    [void]$sb.AppendLine('{0}={1}' -f $section, $InputObject[$section])
                    Write-Debug -Message ('Writing key: {0}' -f $section)

                } else {

                    # Section with nested keys
                    [void]$sb.AppendLine('[{0}]' -f $section)
                    Write-Debug -Message ('Writing section: [{0}]' -f $section)

                    foreach ($key in ($InputObject[$section].Keys | Sort-Object)) {

                        if ($key -match '^Comment[\d]+') {

                            [void]$sb.AppendLine($InputObject[$section][$key])
                            Write-Debug -Message ('Writing comment: {0}' -f $InputObject[$section][$key])

                        } else {

                            [void]$sb.AppendLine('{0}={1}' -f $key, $InputObject[$section][$key])
                            Write-Debug -Message ('Writing key: {0}' -f $key)
                        } #end If-Else

                    } #end Foreach

                    [void]$sb.AppendLine()
                } #end If-Else
            } #end Foreach

            # Write content to file
            if ($PSCmdlet.ShouldProcess($FilePath, 'Write content')) {

                Add-Content -Path $outFile -Value $sb.ToString() -Encoding $Encoding -ErrorAction Stop

            } #end If

            if ($PSBoundParameters['Passthru']) {
                Return $outfile
            } #end If

        } catch {

            Write-Error -Message ('Failed to write INI file: {0}' -f $_.Exception.Message)
            throw

        } #end Try-Catch

    } #end Process

    End {

        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'writing to INI file (Private Function).'
            )
            Write-Verbose -Message $txt
        } #end If

    } #end End

} #end Function Out-IniFile
