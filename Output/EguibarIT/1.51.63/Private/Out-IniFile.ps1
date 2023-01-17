Function Out-IniFile
{
  <#
      .Synopsis
      Write hash content to INI file

      .Description
      Write hash content to INI file

      .Notes
      Author        : Oliver Lipkau <oliver@lipkau.net>
      Blog        : http://oliver.lipkau.net/blog/
      Source        : https://github.com/lipkau/PsIni
      http://gallery.technet.microsoft.com/scriptcenter/ea40c1ef-c856-434b-b8fb-ebd7a76e8d91
      Version        : 1.0 - 2010/03/12 - Initial release
      1.1 - 2012/04/19 - Bugfix/Added example to help (Thx Ingmar Verheij)
      1.2 - 2014/12/11 - Improved handling for missing output file (Thx SLDR)

      #Requires -Version 2.0

      .Inputs
      System.String
      System.Collections.Hashtable

      .Outputs
      System.IO.FileSystemInfo

      .Parameter Append
      Adds the output to the end of an existing file, instead of replacing the file contents.

      .Parameter InputObject
      Specifies the Hashtable to be written to the file. Enter a variable that contains the objects or type a command or expression that gets the objects.

      .Parameter FilePath
      Specifies the path to the output file.

      .Parameter Encoding
      Specifies the type of character encoding used in the file. Valid values are "Unicode", "UTF7",
      "UTF8", "UTF32", "ASCII", "BigEndianUnicode", "Default", and "OEM". "Unicode" is the default.

      "Default" uses the encoding of the system's current ANSI code page.

      "OEM" uses the current original equipment manufacturer code page identifier for the operating
      system.

      .Parameter Force
      Allows the cmdlet to overwrite an existing read-only file. Even using the Force parameter, the cmdlet cannot override security restrictions.

      .Parameter PassThru
      Passes an object representing the location to the pipeline. By default, this cmdlet does not generate any output.

      .Example
      Out-IniFile $IniVar "C:\myinifile.ini"
      -----------
      Description
      Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini

      .Example
      $IniVar | Out-IniFile "C:\myinifile.ini" -Force
      -----------
      Description
      Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and overwrites the file if it is already present

      .Example
      $file = Out-IniFile $IniVar "C:\myinifile.ini" -PassThru
      -----------
      Description
      Saves the content of the $IniVar Hashtable to the INI File c:\myinifile.ini and saves the file into $file

      .Example
      $Category1 = @{“Key1”=”Value1”;”Key2”=”Value2”}
      $Category2 = @{“Key1”=”Value1”;”Key2”=”Value2”}
      $NewINIContent = @{“Category1”=$Category1;”Category2”=$Category2}
      Out-IniFile -InputObject $NewINIContent -FilePath "C:\MyNewFile.INI"
      -----------
      Description
      Creating a custom Hashtable and saving it to C:\MyNewFile.INI
      .Link
      Get-IniContent
  #>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
  Param(
    [switch]$Append,

    [ValidateSet('Unicode','UTF7','UTF8','UTF32','ASCII','BigEndianUnicode','Default','OEM', ignorecase = $false)]
    [string]$Encoding = 'Unicode',

    [ValidateNotNullOrEmpty()]
    [Parameter(Mandatory = $true,HelpMessage = 'Path and Filename to write the file to.')]
    [string]$FilePath,

    [switch]$Force,

    [ValidateNotNullOrEmpty()]
    [Parameter(ValueFromPipeline = $true,HelpMessage = 'The HashTable object name to create the file from',Mandatory = $true)]
    [Hashtable]$InputObject,

    [switch]$Passthru
  )

  Begin
  {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
  }

  Process
  {
    Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Writing to file: $PSBoundParameters['FilePath']"

    if ($PSBoundParameters['Append'])
    {
      $outfile = Get-Item -Path $PSBoundParameters['FilePath']
    }
    else
    {
      $outfile = New-Item -ItemType file -Path $PSBoundParameters['FilePath'] -Force:$PSBoundParameters['Force']
    }
    if (!($outfile))
    {
      Throw 'Could not create File'
    }
    foreach ($i in $InputObject.keys)
    {
      if (!($($InputObject[$i].GetType().Name) -eq 'Hashtable'))
      {
        #No Sections
        Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Writing key: $i"
        Add-Content -Path $outfile -Value "$i=$($InputObject[$i])" -Encoding $PSBoundParameters['Encoding']
      }
      else
      {
        #Sections
        Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Writing Section: [$i]"
        Add-Content -Path $outfile -Value "[$i]" -Encoding $PSBoundParameters['Encoding']
        Foreach ($j in $($InputObject[$i].keys | Sort-Object))
        {
          if ($j -match '^Comment[\d]+')
          {
            Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Writing comment: $j"
            Add-Content -Path $outfile -Value "$($InputObject[$i][$j])" -Encoding $PSBoundParameters['Encoding']
          }
          else
          {
            Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Writing key: $j"
            Add-Content -Path $outfile -Value "$j=$($InputObject[$i][$j])" -Encoding $PSBoundParameters['Encoding']
          }
        }
        Add-Content -Path $outfile -Value '' -Encoding $PSBoundParameters['Encoding']
      }
    }
    Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Finished Writing to file: $path"
    if ($PSBoundParameters['Passthru'])
    {
      Return $outfile
    }
  }

  End
  {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished writing to $PSBoundParameters['FilePath'] INI file."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
  }
}
