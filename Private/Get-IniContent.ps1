function Get-IniContent {
    <#
      .Synopsis
      Gets the content of an INI file

      .Description
      Gets the content of an INI file and returns it as a hashtable

      .Notes
      Author        : Oliver Lipkau <oliver@lipkau.net>
      Blog        : http://oliver.lipkau.net/blog/
      Source        : https://github.com/lipkau/PsIni
      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91
      Version        : 1.0 - 2010/03/12 - Initial release
      1.1 - 2014/12/11 - Typo (Thx SLDR)
      Typo (Thx Dave Stiff)

      #Requires -Version 2.0

      .Inputs
      System.String

      .Outputs
      System.Collections.Hashtable

      .Parameter FilePath
      Specifies the path to the input file.

      .Example
      $FileContent = Get-IniContent "C:\myinifile.ini"
      -----------
      Description
      Saves the content of the c:\myinifile.ini in a hashtable called $FileContent

      .Example
      $inifilepath | $FileContent = Get-IniContent
      -----------
      Description
      Gets the content of the ini file passed through the pipe into a hashtable called $FileContent

      .Example
      C:\PS>$FileContent = Get-IniContent "c:\settings.ini"
      C:\PS>$FileContent["Section"]["Key"]
      -----------
      Description
      Returns the key "Key" of the section "Section" from the C:\settings.ini file

      .Link
      Out-IniFile
  #>

    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([System.Collections.Hashtable])]

    Param(
        [ValidateNotNullOrEmpty()]
        [Parameter(ValueFromPipeline = $true, HelpMessage = 'Path and Filename to the ini file to be read', Mandatory = $true)]
        [string]$FilePath
    )

    Begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Variables Definition
    } #end Begin

    Process {
        Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Processing file: $PSBoundParameters['FilePath']"

        Try {
            $ini = @{}
            switch -regex -file $PSBoundParameters['FilePath'] {
                '^\[(.+)\]$' {
                    # Section
                    $section = $matches[1]
                    $ini[$section] = @{}
                    $CommentCount = 0
                }
                '^(;.*)$' {
                    # Comment
                    if (!($section)) {
                        $section = 'No-Section'
                        $ini[$section] = @{}
                    }
                    $value = $matches[1]
                    $CommentCount = $CommentCount + 1
                    $name = 'Comment' + $CommentCount
                    $ini[$section][$name] = $value
                }
                '(.+?)\s*=\s*(.*)' {
                    # Key
                    if (!($section)) {
                        $section = 'No-Section'
                        $ini[$section] = @{}
                    }
                    $name, $value = $matches[1..2]
                    $ini[$section][$name] = $value
                }
            } #end Switch
        } catch {
            Write-Error -Message "An error occurred while processing the file: $_"
            throw
        } #end Try-Catch
        Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Finished Processing file: $PSBoundParameters['FilePath']"

    } # End Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            ('reading content from {0} file  (Private Function).' -f $PSBoundParameters['FilePath'])
        )
        Write-Verbose -Message $txt

        Return $ini
    } #end End
} #end Function
