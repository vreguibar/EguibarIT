Function Get-OsBuild {
<#
    .Synopsis
    Function to Identify OS Build number
    .DESCRIPTION
    Function to Identify OS Build number.
    .INPUTS
    No Imputs needed
    .EXAMPLE
    Get-OsBuild
    .NOTES
    Version:         1.0
    DateModified:    02/Dic/2014
    LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com
#>
  [CmdletBinding(ConfirmImpact = 'Low')]
  Param ()
  Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

  }
  Process {
    Try {
      # http://www.gaijin.at/en/lstwinver.php
      # http://en.wikipedia.org/wiki/Windows_NT
      # Get OS Information
      [int]$Global:OsMajorVersion    = ((Get-CimInstance -ClassName Win32_OperatingSystem).Version).split('.')[0]
      [int]$Global:OsMinorVersion    = ((Get-CimInstance -ClassName Win32_OperatingSystem).Version).split('.')[1]
      [int]$Global:OsBuild           = ((Get-CimInstance -ClassName Win32_OperatingSystem).Version).split('.')[2]
      #[String]$Global:OsCaption      = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
      [int]$Global:OsSpMajorVersion  = (Get-CimInstance -ClassName Win32_OperatingSystem).ServicePackMajorVersion
      #[int]$Global:OsSpMinorVersion  = (Get-CimInstance -ClassName Win32_OperatingSystem).ServicePackMinorVersion
    }
    catch
    {
      $error.clear()

      [Environment]::OSVersion.Version | ForEach-Object {
        [int]$Global:OsMajorVersion = $_.Major
        [int]$Global:OsMinorVersion = $_.Minor
        [int]$Global:OsBuild = $_.Build
      }

      $Global:OsSpMajorVersion  = [Environment]::OSVersion.ServicePack
    }
  }
  End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting OS build."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}