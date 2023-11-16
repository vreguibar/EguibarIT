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
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
  } #end Begin
  Process {
    Try {
      # http://www.gaijin.at/en/lstwinver.php
      # http://en.wikipedia.org/wiki/Windows_NT
      # Get OS Information
      # Retrieve OS Information
      $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
      [int]$Global:OsMajorVersion    = $osInfo.Version.Split('.')[0]
      [int]$Global:OsMinorVersion    = $osInfo.Version.Split('.')[1]
      [int]$Global:OsBuild           = $osInfo.Version.Split('.')[2]
      #[String]$Global:OsCaption     = $osInfo.Caption
      [int]$Global:OsSpMajorVersion  = $osInfo.ServicePackMajorVersion
      #[int]$Global:OsSpMinorVersion = $osInfo.ServicePackMinorVersion
    } catch {
      $error.clear()

      # Fallback to Environment.OSVersion if Get-CimInstance fails
      [Environment]::OSVersion.Version | ForEach-Object {
        [int]$Global:OsMajorVersion = $_.Major
        [int]$Global:OsMinorVersion = $_.Minor
        [int]$Global:OsBuild        = $_.Build
      }

      $Global:OsSpMajorVersion  = [Environment]::OSVersion.ServicePack
    } #end Try-Catch
  } #end Process
  End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting OS build."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
  } #end End
} #end Function
