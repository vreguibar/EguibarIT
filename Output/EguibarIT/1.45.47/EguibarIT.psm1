### --- PUBLIC FUNCTIONS --- ### 
#Region - ConvertTo-IPv4MaskBit.ps1
function ConvertTo-IPv4MaskBit {
    <#
        .SYNOPSIS
            Returns the number of bits (0-32) in a network mask string (e.g., "255.255.255.0").

        .DESCRIPTION
            Returns the number of bits (0-32) in a network mask string (e.g., "255.255.255.0").

        .PARAMETER MaskString
            Specifies the IPv4 network mask string (e.g., "255.255.255.0").
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([System.Int32])]
    Param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
        Position = 1)]
        [ValidateScript({Test-IPv4MaskString $_})]
        [String] $MaskString
    )
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
        $mask = ([IPAddress] $MaskString).Address
        for ( $bitCount = 0; $mask -ne 0; $bitCount++ ) {
            $mask = $mask -band ($mask - 1)
        }
        $bitCount
    }
    End {
        Write-Verbose -Message ('Function {0} finished.' -f $MyInvocation.InvocationName)
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function ConvertTo-IPv4MaskBit
#EndRegion - ConvertTo-IPv4MaskBit.ps1
#Region - ConvertTo-IPv4MaskString.ps1
function ConvertTo-IPv4MaskString {
    <#
        .SYNOPSIS
            Converts a number of bits (0-32) to an IPv4 network mask string (e.g., "255.255.255.0").

        .DESCRIPTION
            Converts a number of bits (0-32) to an IPv4 network mask string (e.g., "255.255.255.0").

        .PARAMETER MaskBits
            Specifies the number of bits in the mask.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
        Position = 1)]
        [ValidateRange(0,32)]
        [Int] $MaskBits
    )
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
        $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
        $bytes = [BitConverter]::GetBytes([UInt32] $mask)
        (($bytes.Count - 1)..0 | ForEach-Object { [String] $bytes[$_] }) -join "."
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function ConvertTo-IPv4MaskString
#EndRegion - ConvertTo-IPv4MaskString.ps1
#Region - ConvertTo-WmiFilter.ps1
function ConvertTo-WmiFilter
{
    <#
        .Synopsis
        .DESCRIPTION
        .EXAMPLE
            ConvertTo-WmiFilter
        .INPUTS
        .NOTES
            Version:         1.0
            DateModified:    25/Mar/2014
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param (
        [Microsoft.ActiveDirectory.Management.ADObject[]] $ADObject
    )

    Begin  {
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
        # The concept of this function has been taken directly from the GPWmiFilter.psm1 module
        # written by Bin Yi from Microsoft. I have modified it to allow for the challenges of
        # Active Directory replication. It will return the WMI filter as an object of type
        # "Microsoft.GroupPolicy.WmiFilter".
        $gpDomain = New-Object -TypeName Microsoft.GroupPolicy.GPDomain

        $ADObject | ForEach-Object {
            $path = 'MSFT_SomFilter.Domain="' + $gpDomain.DomainName + '",ID="' + $_.Name + '"'
            $filter = $null
            try {
                $filter = $gpDomain.GetWmiFilter($path)
            }
            catch {
                Write-Error -Message 'The WMI filter could not be found.'
            }
            if ($filter) {
                [Guid]$Guid = $_.Name.Substring(1, $_.Name.Length - 2)
                $filter |
                    Add-Member -MemberType NoteProperty -Name Guid -Value $Guid -PassThru |
                    Add-Member -MemberType NoteProperty -Name Content -Value $_.'msWMI-Parm2' -PassThru
            } else {
                Write-Warning -Message 'Waiting 5 seconds for Active Directory replication to complete.'
                Start-Sleep -Seconds 5
                Write-Warning -Message 'Trying again to retrieve the WMI filter.'
                ConvertTo-WmiFilter $ADObject
            }
        }
    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished converting the WMI filter."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function ConvertTo-WmiFilter
#EndRegion - ConvertTo-WmiFilter.ps1
#Region - Get-AdSite.ps1
function Get-AdSite {
    <#
        .Synopsis
            Get AD Sites from current Forest
        .DESCRIPTION
            Reads all Sites from the current Forest and store those on an array.
        .EXAMPLE
            Get-AdSites
        .INPUTS
            No input needed.
        .NOTES
            Version:         1.0
            DateModified:    31/Mar/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([array])]
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


        Import-Module -name ServerManager   -Verbose:$false
        Import-Module -name ActiveDirectory -Verbose:$false
    }
    Process {
        Write-Verbose -Message "Get AD Site List `r"
        [array] $ADSites = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
    }
    End  {

        Return $ADSites
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting AD Sites."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Get-AdSite
#EndRegion - Get-AdSite.ps1
#Region - Get-AllAdSiteLink.ps1
function Get-AllAdSiteLink {
    <#
        .Synopsis
            Get AD Site Links from current Forest
        .DESCRIPTION
            Reads all Site Links from the current Forest and store those on an array.
        .EXAMPLE
            Get-AdSiteLinks
        .INPUTS
            No input needed.
        .NOTES
            Version:         1.0
            DateModified:    31/Mar/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
        #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([array])]
    Param ()

    Begin
    {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Import-Module -name ServerManager   -Verbose:$false
        Import-Module -name ActiveDirectory -Verbose:$false

        $ADSiteDN      = 'CN=Sites,{0}' -f ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()
        #$SubnetsDN     = 'CN=Subnets,{0}' -f $ADSiteDN
        #$ADSiteLinksDN = 'CN=IP,CN=Inter-Site Transports,{0}' -f $ADSiteDN
    }
    Process
    {
        Write-Verbose -Message "Get List of AD Site Links `r"

        [array] $ADSiteLinks = Get-ADObject -Filter { ObjectClass -eq 'sitelink' } -SearchBase $ADSiteDN -Properties *

        $ADSiteLinksCount = $ADSiteLinks.Count

        Write-Output -InputObject ("There are {0} AD Site Links in {1} `r" -f $ADSiteLinksCount, $env:USERDNSDOMAIN)
  }
  End {

    Return $ADSiteLinks
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting SiteLinks."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
  }
}
Export-ModuleMember -Function Get-AllAdSiteLink
#EndRegion - Get-AllAdSiteLink.ps1
#Region - Get-AllAdSubnet.ps1
function Get-AllAdSubnet {
    <#
        .Synopsis
            Get AD subnets from current Forest
        .DESCRIPTION
            Reads all Subnets from the current Forest and store those on an array.
        .EXAMPLE
            Get-AdSubnets
        .INPUTS
            No input needed.
        .NOTES
            Version:         1.0
            DateModified:    31/Mar/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([array])]
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


        Import-Module -name ServerManager   -Verbose:$false
        Import-Module -name ActiveDirectory -Verbose:$false
    }
    Process {
        #Get a reference to the RootDSE of the current domain
        $ADConfigurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext

        [array] $ADSubnets = Get-ADObject -Filter {
            objectclass -eq 'subnet'
        } -SearchBase $ADConfigurationNamingContext -Properties *
    }
    End {

        Return $ADSubnets
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting AD Subnets."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Get-AllAdSubnet
#EndRegion - Get-AllAdSubnet.ps1
#Region - Get-OsBuild.ps1
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
Export-ModuleMember -Function Get-OsBuild
#EndRegion - Get-OsBuild.ps1
#Region - Grant-NTFSPermissions.ps1
function Grant-NTFSPermissions
{
    <#
        .Synopsis
            Function to Add NTFS permissions to a folder
        .DESCRIPTION
            Function to Add NTFS permissions to a folder
        .EXAMPLE
            Grant-NTFSPermissions path object permission
        .INPUTS
            Param1 path:......... The path to the folder
            Param2 object:....... the identity which will get the permissions
            Param3 permission:... the permissions to be modified
        .NOTES
            Version:         1.1
            DateModified:    03/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param (
        # Param1 path to the resource|folder
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Absolute path to the object',
        Position = 0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $path,

        # Param2 object or SecurityPrincipal
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the object',
        Position = 1)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $object,

        # Param3 permission
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Permission of the object',
        Position = 2)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $permission
    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        # Possible values for FileSystemRights are:
        # ReadAndExecute, AppendData, CreateFiles, read, write, Modify, FullControl
        $FileSystemRights  = [Security.AccessControl.FileSystemRights]$PSBoundParameters['permission']

        $InheritanceFlag   = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
        $PropagationFlag   = [Security.AccessControl.PropagationFlags]::None
        $AccessControlType = [Security.AccessControl.AccessControlType]::Allow
    }
    Process {
        Try {
            $Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList $PSBoundParameters['object']

            $FileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)

            $DirectorySecurity = Get-Acl -Path $PSBoundParameters['path']

            $DirectorySecurity.AddAccessRule($FileSystemAccessRule)

            Set-Acl -Path $PSBoundParameters['path'] -AclObject $DirectorySecurity
        } catch { throw }
    }
    End
    {
        Write-Verbose -Message ('The User/Group {0} was given {1} to folder {2}.' -f $PSBoundParameters['object'], $PSBoundParameters['permission'], $PSBoundParameters['path'])
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Grant-NTFSPermissions
#EndRegion - Grant-NTFSPermissions.ps1
#Region - Import-MyModule.ps1
Function Import-MyModule
{
    <#
        .Synopsis
            Function to Import Modules with error handling
        .DESCRIPTION
            Function to Import Modules as with Import-Module Cmdlet but
            with error handling on it.
        .INPUTS
            Param1 name:........String representing Module Name
        .EXAMPLE
            Import-MyModule ActiveDirectory
        .NOTES
            Version:         1.0
            DateModified:    19/Feb/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        # Param1 STRING for the Module Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the module to be imported',
        Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $name
    )
    Begin{
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"
    }
    Process
    {
        if(-not(Get-Module -Name $PSBoundParameters['name']))
        {
            if(Get-Module -ListAvailable -Name $PSBoundParameters['name'])
            {
                Import-Module -Name $PSBoundParameters['name'] -Force

                Write-Verbose -Message ('Imported module {0}' -f $PSBoundParameters['name'])
            }
            else
            {
                Throw ('Module {0} is not installed. Exiting...' -f $PSBoundParameters['name'])
                Write-Verbose -Message ('The module {0} is not installed.' -f $PSBoundParameters['name'])
            }
        }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished importing module."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Import-MyModule
#EndRegion - Import-MyModule.ps1
#Region - New-AdDelegatedGroup.ps1
function New-AdDelegatedGroup {
    <#
    .SYNOPSIS
        Same as New-AdGroup but with error handling, Security changes and loging
    .DESCRIPTION
        Native New-AdGroup throws an error exception when the group already exists. This error is handeled
        as a "correct" within this function due the fact that group might already exist and operation
        should continue after writting a log.
    .EXAMPLE
        New-AdDelegatedGroup -Name "Poor Admins" -GroupCategory Security -GroupScope DomainLocal -DisplayName "Poor Admins" -Path 'OU=Groups,OU=Admin,DC=EguibarIT,DC=local' -Description 'New Admin Group'
    .PARAMS
        PARAM1........: [STRING] Name
        PARAM2........: [ValidateSet] GroupCategory
        PARAM3........: [ValidateSet] GroupScope
        PARAM4........: [STRING] DisplayName
        PARAM5........: [STRING] Path
        PARAM6........: [STRING] Description
        PARAM7........: [SWITCH] ProtectFromAccidentalDeletion
        PARAM8........: [SWITCH] RemoveAccountOperators
        PARAM9........: [SWITCH] RemoveEveryone
        PARAM10.......: [SWITCH] RemoveAuthUsers
        PARAM11.......: [SWITCH] RemovePreWin2000
    .NOTES
        Version:         1.1
        DateModified:    15/Feb/2017
        LasModifiedBy:   Vicente Rodriguez Eguibar
            vicente@eguibar.com
            Eguibar Information Technology S.L.
            http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([Microsoft.ActiveDirectory.Management.AdGroup])]
    Param
    (
        # Param1 Group which membership is to be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Name of the group to be created. SamAccountName',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Name,

        # Param2 Group category, either Security or Distribution
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Group category, either Security or Distribution',
            Position = 1)]
        [ValidateSet('Security','Distribution')]
        $GroupCategory,

        # Param3 Group Scope, either DomainLocal, Global or Universal
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Group Scope, either DomainLocal, Global or Universal',
            Position = 2)]
        [ValidateSet('DomainLocal','Global','Universal')]
        $GroupScope,

        # Param4 Display Name of the group to be created
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Display Name of the group to be created',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        $DisplayName,

        # Param5 DistinguishedName of the container where the group will be created.
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'DistinguishedName of the container where the group will be created.',
            Position = 4)]
        [ValidateNotNullOrEmpty()]
        $path,

        # Param6 Description of the group.
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Description of the group.',
            Position = 5)]
        [ValidateNotNullOrEmpty()]
        $Description,

        # Param7 Protect from accidental deletion.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Protect from accidental deletion.',
            Position = 6)]
        [Switch]
        $ProtectFromAccidentalDeletion,

        # Param8 Remove Account Operators Built-In group.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Account Operators Built-In group',
            Position = 7)]
        [Switch]
        $RemoveAccountOperators,

        # Param9 Remove Everyone Built-In group.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Everyone Built-In group',
            Position = 8)]
        [Switch]
        $RemoveEveryone,

        # Param10 Remove Authenticated Users Built-In group.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Authenticated Users Built-In group',
            Position = 9)]
        [Switch]
        $RemoveAuthUsers,

        # Param11 Remove Pre-Windows 2000 Built-In group.
        [Parameter(Mandatory = $False,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Remove Pre-Windows 2000 Built-In group',
            Position = 10)]
        [Switch]
        $RemovePreWin2000

    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Import-Module -name ActiveDirectory      -Verbose:$false
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        $parameters = $null
        $newGroup   = $null
    }

    Process {
        try {
            # Get the group and store it on variable.
            $newGroup = Get-AdGroup -Filter { SamAccountName -eq $Name }

            ### Using $PSBoundParameters['Name'] throws an Error. Using variable instead.
            If(-not($newGroup)) {
                $parameters = @{
                    Name           = $PSBoundParameters['Name']
                    SamAccountName = $PSBoundParameters['Name']
                    GroupCategory  = $PSBoundParameters['GroupCategory']
                    GroupScope     = $PSBoundParameters['GroupScope']
                    DisplayName    = $PSBoundParameters['DisplayName']
                    Path           = $PSBoundParameters['path']
                    Description    = $PSBoundParameters['Description']
                }
                New-ADGroup @parameters
            } else {
                Write-Warning -Message ('Groups {0} already exists. Modifying the group!' -f $PSBoundParameters['Name'])

                $newGroup | Set-AdObject -ProtectedFromAccidentalDeletion $False

                Try {
                    $parameters = @{
                        Identity      = $PSBoundParameters['Name']
                        Description   = $PSBoundParameters['Description']
                        DisplayName   = $PSBoundParameters['DisplayName']
                        GroupCategory = $PSBoundParameters['GroupCategory']
                        GroupScope    = $PSBoundParameters['GroupScope']
                    }
                    Set-AdGroup @parameters

                    If(-not($newGroup.DistinguishedName -ccontains $PSBoundParameters['path']))
                    {
                        # Move object to the corresponding OU
                        Move-ADObject -Identity $newGroup -TargetPath $PSBoundParameters['path']
                    }

                }
                catch { throw }
            }

            # Get the group again and store it on variable.
            $newGroup = Get-AdGroup -Filter { SamAccountName -eq $Name }


            # Protect From Accidental Deletion
            If($PSBoundParameters['ProtectFromAccidentalDeletion']) {
                $newGroup | Set-ADObject -ProtectedFromAccidentalDeletion $true
            }

            # Remove Account Operators Built-In group
            If($PSBoundParameters['RemoveAccountOperators']) {
                Remove-AccountOperator -LDAPPath $newGroup.DistinguishedName
            }

            # Remove Everyone Built-In group
            If($PSBoundParameters['RemoveEveryone']) {
                Remove-Everyone -LDAPPath $newGroup.DistinguishedName
            }

            # Remove Authenticated Users Built-In group
            If($PSBoundParameters['RemoveAuthUsers']) {
                Remove-AuthUser -LDAPPath $newGroup.DistinguishedName
            }

            # Remove Pre-Windows 2000 Built-In group
            If($PSBoundParameters['RemovePreWin2000']) {
                Remove-PreWin2000 -LDAPPath $newGroup.DistinguishedName
            }
        }
        catch {
            throw
            Write-Warning -Message ('An unhandeled error was thrown when creating Groups {0}' -f $PSBoundParameters['Name'])
        }
    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating Delegated Group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        #Return the group object.
        return $newGroup
    }
}
Export-ModuleMember -Function New-AdDelegatedGroup
#EndRegion - New-AdDelegatedGroup.ps1
#Region - New-AGPMobjects.ps1
Function New-AGPMObjects
{
    <#
        .Synopsis
            Create Advanced Group Policy Management Objects and Delegations
        .DESCRIPTION
            Create the AGPM Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-AGPMObjects
        .INPUTS

        .NOTES
            Version:         1.3
            DateModified:    05/Feb/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param(
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        # Param2 Location of all scripts & files
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 1)]
        [string]
        $DMscripts = "C:\PsScripts\"
    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        ################################################################################
        # Initialisations
        Import-Module -name ActiveDirectory      -Verbose:$false
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        ################################################################################
        #region Declarations


        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        catch { throw }



        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0

        # Organizational Units Distinguished Names

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $AdDn

        # It Admin ServiceAccount OU Distinguished Name
        $ItServiceAccountsOu = $confXML.n.Admin.OUs.ItServiceAccountsOU.name
        # It Admin ServiceAccount OU Distinguished Name
        $ItServiceAccountsOuDn = 'OU={0},{1}' -f $ItServiceAccountsOu, $ItAdminOuDn

        # It Admin Rights OU
        $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

        $parameters = $null

        #endregion Declarations
        ################################################################################
    }
    Process {
        ###############################################################################
        #region Creating Service account

        # Create the new Temporary Service Account with special values
        # This TEMP SA will be used for AGMP Server setup. Afterwards will be replaced by a MSA
        $parameters = @{
            Path                  = $ItServiceAccountsOuDn
            Name                  = 'SA_AGPM_Temp'
            AccountPassword       = (ConvertTo-SecureString -String $confXML.n.DefaultPassword -AsPlainText -Force)
            ChangePasswordAtLogon = $false
            Enabled               = $true
            UserPrincipalName     = ('AGPM@{0}' -f $env:USERDNSDOMAIN)
            SamAccountName        = 'SA_AGPM_Temp'
            DisplayName           = 'SA_AGPM_Temp'
            Description           = 'Service account used for Advanced Group Policy Management service'
            employeeId            = '0123456'
            TrustedForDelegation  = $false
            AccountNotDelegated   = $true
            Company               = $confXML.n.RegisteredOrg
            Country               = 'MX'
            Department            = 'IT Operations and Architecture'
            State                 = 'Puebla'
            EmailAddress          = ('AGPM@{0}' -f $env:USERDNSDOMAIN)
            OtherAttributes       = @{
                'employeeType'                  = 'ServiceAccount'
                'msNpAllowDialin'               = $false
                'msDS-SupportedEncryptionTypes' = '24'
        }
        }
        New-AdUser @parameters

        $SA_AGPM = Get-AdUser -Filter { samAccountName -eq 'SA_AGPM_Temp' }

        #http://blogs.msdn.com/b/openspecification/archive/2011/05/31/windows-configurations-for-kerberos-supported-encryption-type.aspx
        # 'msDS-SupportedEncryptionTypes'= Kerberos DES Encryption = 2, Kerberos AES 128 = 8, Kerberos AES 256 = 16

        # Make it member of Tier 0 ServiceAccount groups
        Add-AdGroupNesting -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name) -Members $SA_AGPM

        # http://blogs.msdn.com/b/muaddib/archive/2013/12/30/how-to-modify-security-inheritance-on-active-directory-objects.aspx

        # Remove Everyone group from Admin-User & Administrator
        Remove-Everyone -LDAPPath $SA_AGPM.DistinguishedName

        # Remove AUTHENTICATED USERS group from Admin-User & Administrator
        #Remove-AuthUser -LDAPPath $SA_AGPM.DistinguishedName

        # Remove Pre-Windows 2000 Compatible Access group from Admin-User & Administrator
        Remove-PreWin2000 -LDAPPath $SA_AGPM.DistinguishedName


        If ($Global:OsBuild -ge 9200) {
            $Splat = @{
                Name                   = $confXML.n.Admin.gMSA.AGPM.Name
                SamAccountName         = $confXML.n.Admin.gMSA.AGPM.Name
                DNSHostName            = ('{0}.{1}' -f $confXML.n.Admin.gMSA.AGPM.Name, $env:USERDNSDOMAIN)
                AccountNotDelegated    = $true
                Description            = $confXML.n.Admin.gMSA.AGPM.Description
                DisplayName            = $confXML.n.Admin.gMSA.AGPM.DisplayName
                KerberosEncryptionType = 'AES128,AES256'
                Path                   = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $ItServiceAccountsOuDn
                enabled                = $True
                TrustedForDelegation   = $false
            }

            $ReplaceParams = @{
                Replace = @{
                    'c'="MX"
                    'co'="Mexico"
                    'company'=$confXML.n.RegisteredOrg
                    'department'="IT"
                    'employeeID'='T0'
                    'employeeType'="ServiceAccount"
                    'info'=$confXML.n.Admin.gMSA.AGPM.Description
                    'l'="Puebla"
                    'title'=$confXML.n.Admin.gMSA.AGPM.DisplayName
                    'userPrincipalName'='{0}@{1}' -f $confXML.n.Admin.gMSA.AGPM.Name, $env:USERDNSDOMAIN
                }
            }

            try {
                New-ADServiceAccount @Splat | Set-ADServiceAccount @ReplaceParams
            }
            catch { throw }
        } else {
            $Splat = @{
                name        = $confXML.n.Admin.gMSA.AGPM.Name
                Description = $confXML.n.Admin.gMSA.AGPM.Description
                Path        = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $ItServiceAccountsOuDn
                enabled     = $True
            }
            New-ADServiceAccount @Splat
        }


        #endregion
        ###############################################################################

        ###############################################################################
        #region Create AGPM groups

        # AdminRights group is created by default on CentralItOU procedure. Is the default delegated Admin for OUs

        #New-ADGroup -Name "SG_AllSiteAdmins"      -SamAccountName SG_AllSiteAdmins      -GroupCategory Security -GroupScope Global      -DisplayName "All Sites Admins"        -Path $ItPGOuDn -Description "Members of this group are Site Administrators of all sites"

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.GpoApproverRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.GpoApproverRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.GpoApproverRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_GpoApproverRight = New-AdDelegatedGroup @parameters

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.GpoEditorRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.GpoEditorRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.GpoEditorRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_GpoEditorRight = New-AdDelegatedGroup @parameters

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.GpoReviewerRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.GpoReviewerRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.GpoReviewerRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_GpoReviewerRight = New-AdDelegatedGroup @parameters

        #endregion
        ###############################################################################

        # Apply the PSO to the corresponding Groups
        Add-ADFineGrainedPasswordPolicySubject -Identity $confXML.n.Admin.PSOs.ItAdminsPSO.Name -Subjects $SL_GpoApproverRight, $SL_GpoEditorRight, $SL_GpoReviewerRight


        ###############################################################################
        # Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Add-AdGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SL_GpoApproverRight, $SL_GpoEditorRight, $SL_GpoReviewerRight


        ###############################################################################
        #region Nest Groups - Delegate Rights through Builtin groups
        # http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx

        Add-AdGroupNesting -Identity 'Backup Operators' -Members $SA_AGPM

        Add-AdGroupNesting -Identity 'Group Policy Creator Owners' -Members $SA_AGPM

        #endregion

        ###############################################################################
        # Nest Groups - Extend Rights through delegation model groups

        # No nesting needed here

        ###############################################################################
        # START Delegation to

        # No delegation requiered because:
        #
        # 1.- Privileged groups are empty
        # 2.- AGPM will control all GPOs
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) created objects and Delegations successfully."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
  }
}
Export-ModuleMember -Function New-AGPMobjects
#EndRegion - New-AGPMobjects.ps1
#Region - New-AreaShareNTFS.ps1
function New-AreaShareNTFS
{
    <#
        .Synopsis
            Function to create a new Area folder share
        .DESCRIPTION
            Function to create a new Area folder share
        .EXAMPLE
            New-AreaShareNTFS -ShareName 'Acounting' -ReadGroup 'SL_Accounting_Read' -ChangeGroup 'SL_Accounting_write' -SiteAdminGroup 'SG_Accounting_MNGT' -SitePath 'C:\Shares\Areas\Accounting'
        .INPUTS
            Param1...: ShareName
            Param2...: ReadGroup
            Param3...: ChangeGroup
            Param4...: SiteAdminGroup
            Param5...: SitePath
        .NOTES
            Version:         1.1
            DateModified:    03/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([String])]
    Param (
        # Param1 Sharename
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the share to be created',
        Position = 0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ShareName,

        # Param2 Read group
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the group with Read-Only permissions',
        Position = 1)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $readGroup,

        # Param3 Change Group
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the group with Change permissions',
        Position = 2)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $changeGroup,

        # Param4 All Site Admins group
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the group with Full permissions',
        Position = 3)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $SG_SiteAdminsGroup,

        # Param5 Path to the site
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'DistinguishedName where the new Groups will be created.',
        Position = 4)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $sitePath,

        # Param6
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Absolute path to the root Share folder (e.g. "C:\Shares\")',
        Position = 5)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ShareLocation,

        # Param7
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'The root share name for general areas.',
        Position = 6)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $AreasName
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        #------------------------------------------------------------------------------
        # Define the variables

        # Create Full Share Name
        $FullShareName = '{0}\{1}\{2}' -f $PSBoundParameters['ShareLocation'], $PSBoundParameters['AreasName'], $PSBoundParameters['ShareName']

        $parameters = $null

        # END variables
        #---------------------
    }

    Process {
        If(-not(test-path -Path $FullShareName)) {
            # Create the new Directory
            New-Item -Path $FullShareName -ItemType Directory
        }

        # Create the associated READ group
        $parameters = @{
            Name                          = $PSBoundParameters['readGroup']
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $PSBoundParameters['readGroup']
            Path                          = $PSBoundParameters['sitePath']
            Description                   = 'Read Access to Share {0}' -f $PSBoundParameters['ShareName']
        }
        New-AdDelegatedGroup @parameters

        # Create the associated Modify group
        $parameters = @{
            Name                          = $PSBoundParameters['changeGroup']
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $PSBoundParameters['changeGroup']
            Path                          = $PSBoundParameters['sitePath']
            Description                   = 'Read Access to Share {0}' -f $PSBoundParameters['ShareName']
        }
        New-AdDelegatedGroup @parameters

        Start-Sleep -Seconds 2

        Grant-NTFSPermissions -path $FullShareName -object $PSBoundParameters['readGroup'] -permission 'ReadAndExecute, ChangePermissions'
        Grant-NTFSPermissions -path $FullShareName -object $PSBoundParameters['changeGroup'] -permission 'Modify, ChangePermissions'
        Grant-NTFSPermissions -path $FullShareName -object $PSBoundParameters['SG_SiteAdminsGroup'] -permission 'FullControl, ChangePermissions'

        #& "$env:windir\system32\net.exe" share $ShareName=$FullShareName '/GRANT:Everyone,FULL'

        New-SmbShare -Name $PSBoundParameters['ShareName'] -Path $FullShareName -FullAccess Everyone

        if ($error.count -eq 0) {
            Write-Verbose -Message ('The folder {0} was shared correctly.' -f $ShareName)
        }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating the share."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-AreaShareNTFS
#EndRegion - New-AreaShareNTFS.ps1
#Region - New-CaObjects.ps1
Function New-CaObjects
{
    <#
        .Synopsis
            Create Certificate Authority Objects and Delegations
        .DESCRIPTION
            Create the Certificate Authority Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-CaObjects
        .INPUTS

        .NOTES
            Version:         1.3
            DateModified:    01/Feb/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param(
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        # Param2 Location of all scripts & files
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 1)]
        [string]
        $DMscripts = "C:\PsScripts\"
    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        ################################################################################
        # Initialisations
        Import-Module -name EguibarIT.Delegation -Verbose:$false


        #Get the OS Instalation Type
        $OsInstalationType = Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' | Select-Object -ExpandProperty InstallationType


        ################################################################################
        #region Declarations


        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        catch { throw }



        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0

        # Organizational Units Distinguished Names

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $AdDn

        # It Admin Groups OU
        # $ItGroupsOu = $confXML.n.Admin.OUs.ItAdminGroupsOU.name
        # It Admin Groups OU Distinguished Name
        # $ItGroupsOuDn = 'OU={0},{1}' -f $ItGroupsOu, $ItAdminOuDn

        # It Privileged Groups OU
        $ItPGOu = $confXML.n.Admin.OUs.ItPrivGroupsOU.name
        # It Privileged Groups OU Distinguished Name
        $ItPGOuDn = 'OU={0},{1}' -f $ItPGOu, $ItAdminOuDn

        # It Admin Rights OU
        $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

        $parameters = $null

        #endregion Declarations
        ################################################################################
    }
    Process {
        # Check if AD module is installed
        If(-not((Get-WindowsFeature -Name RSAT-AD-PowerShell).Installed)) {
            Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature
        }
        Import-Module -name ActiveDirectory      -Verbose:$false

        # AD CS Step by Step Guide: Two Tier PKI Hierarchy Deployment
        # https://social.technet.microsoft.com/wiki/contents/articles/15037.ad-cs-step-by-step-guide-two-tier-pki-hierarchy-deployment.aspx

        # Deploy a PKI on Windows Server 2016
        # https://timothygruber.com/pki/deploy-a-pki-on-windows-server-2016-part-2/


        try {
            # Check if feature is installed, if not then proceed to install it.
            If(-not((Get-WindowsFeature -Name ADCS-Cert-Authority).Installed)) {
                Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeAllSubFeature

                Install-WindowsFeature -Name ADCS-web-enrollment

                Install-WindowsFeature -Name ADCS-Online-Cert

                If($OsInstalationType -ne 'Server Core') {
                    Install-WindowsFeature -Name RSAT-ADCS -IncludeAllSubFeature
                }

                # https://www.pkisolutions.com/tools/pspki/
                # Install PSPKI module for managing Certification Authority
                Install-PackageProvider -Name NuGet -Force
                Install-Module -Name PSPKI -Force
                Import-Module PSPKI

                #Define PKI Cname
                $PkiServer = ('pki.{0}' -f $env:USERDNSDOMAIN)

                # Create CAPolicy.inf for Enterprise Root CA
                $CaPolicy = @"
[Version]
Signature="$Windows NT$"
[PolicyStatementExtension]
Policies=AllIssuancePolicy
Critical=False
[AllIssuancePolicy]
OID=2.5.29.32.0
URL=http://$PkiServer/certdata/cps.txt
[Certsrv_Server]
RenewalKeyLength=$($confXML.n.CA.CAKeyLength)
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=$($confXML.n.CA.CACertValidity)
CRLPeriod=$($confXML.n.CA.CACRLPeriod)
CRLPeriodUnits=$($confXML.n.CA.CACRLPeriodUnits)
CRLDeltaPeriod=$($confXML.n.CA.CACRLDeltaPeriod)
CRLDeltaPeriodUnits=$($confXML.n.CA.CACRLDeltaPeriodUnits)
LoadDefaultTemplates=0
"@
                # Set the content into the file
                Set-Content -Path C:\Windows\CaPolicy.ini -Value $CaPolicy -Force

                # Create Folder where to store CA Database
                $CaConfig = ('{0}\CaConfig\' -f $env:SystemDrive)

                if(-not(Test-Path $CaConfig)) {
                    New-Item -ItemType Directory -Force -Path $CaConfig
                }

                $Splat = @{
                    CAType                    = $confXML.n.CA.CAType
                    CryptoProviderName        = $confXML.n.CA.CACryptoProvider
                    KeyLength                 = $confXML.n.CA.CAKeyLength
                    HashAlgorithmName         = $confXML.n.CA.CAHashAlgorithm
                    ValidityPeriod            = 'Years'
                    ValidityPeriodUnits       = $confXML.n.CA.CACertValidity
                    CACommonName              = '{0}-CA' -f ($AdDn.Split(",")[0]).split("=")[1]
                    CADistinguishedNameSuffix = $AdDn
                    DatabaseDirectory         = $CaConfig
                    LogDirectory              = '{0}LOGs' -f $CaConfig
                    Force                     = $true
                    Confirm                   = $false
                }
                # Configure the new CA
                Install-AdcsCertificationAuthority @Splat

                # configure the web enrollment role service
                Install-ADCSwebenrollment -Confirm
            } # End If
        } # End Try
        catch { throw } # End Try-Catch
        finally {

            # Remove all distribution points
            foreach ($crl in Get-CACrlDistributionPoint) {
                Remove-CACrlDistributionPoint $crl.uri -Force
            }

            # Add CDP local path
            Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8%9.crl -PublishToServer -PublishDeltaToServer -Force

            # Add CDP url
            Add-CACRLDistributionPoint -Uri http://$PkiServer/CertEnroll/%3%8%9.crl -AddToCertificateCDP -AddToFreshestCrl -Force

            Get-CAAuthorityInformationAccess | Where-Object {$_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*'} | Remove-CAAuthorityInformationAccess -Force

            # Add AIA url
            Add-CAAuthorityInformationAccess -AddToCertificateAia http://$PkiServer/CertEnroll/%1_%3%4.crt -Force


            # Configure CRL and DeltaCRL
            [String]$cmd = "Certutil -setreg CA\CRLPeriodUnits $($confXML.n.CA.CACRLPeriodUnits)"
            Invoke-Expression -Command $cmd
            [String]$cmd = "Certutil -setreg CA\CRLPeriod $($confXML.n.CA.CACRLPeriod)"
            Invoke-Expression -Command $cmd
            [String]$cmd = "Certutil -setreg CA\CRLDeltaPeriodUnits $($confXML.n.CA.CACRLDeltaPeriodUnits)"
            Invoke-Expression -Command $cmd
            [String]$cmd = "Certutil -setreg CA\CRLDeltaPeriod $($confXML.n.CA.CACRLDeltaPeriod)"
            Invoke-Expression -Command $cmd

            <##TODO
            Failing next 2
            #>

            [String]$cmd = "Certutil -setreg CA\CRLOverlapPeriodUnits $($confXML.n.CA.CACRLOverlapPeriodUnits)"
            Invoke-Expression -Command $cmd
            [String]$cmd = "Certutil -setreg CA\CRLOverlapPeriod $($confXML.n.CA.CACRLOverlapPeriod)"
            Invoke-Expression -Command $cmd


            # Create A record for PKI
            Add-DnsServerResourceRecordCName -Name "pki" -HostNameAlias ('{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN) -ZoneName $env:USERDNSDOMAIN


            # Configure CA auditing
            [String]$cmd = "Certutil -setreg CA\AuditFilter 127"
            Invoke-Expression -Command $cmd

            # Configure the AIA
            [String]$Locations = '"1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt\n2:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11\n2:http://{0}/CertEnroll/%1_%3%4.crt"' -f $PkiServer
            [String]$cmd = "certutil -setreg CA\CACertPublicationURLs $($Locations)"
            Invoke-Expression -Command $cmd

            # Configure the CDP
            [String]$Locations = '"65:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl\n79:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10\n6:http://{0}/CertEnroll/%3%8%9.crl\n65:\\{1}\CertEnroll\%3%8%9.crl"' -f  $PkiServer, ('{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN)
            [String]$cmd = "certutil -setreg CA\CRLPublicationURLs $($Locations)"
            Invoke-Expression -Command $cmd

            # Configure Online Responder
            #Configure and Publish the OCSP Response Signing Certificate
            Get-CertificateTemplate -Name 'OCSPResponseSigning' | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -Identity ('{0}$' -f $env:computername) -AccessType Allow -AccessMask Read, Enroll | Set-CertificateTemplateAcl
            Get-CertificationAuthority | Get-CATemplate | Add-CATemplate -DisplayName 'OCSP Response Signing'

            Restart-Service certsvc

        } # End Try-Catch-Finally

<#
        ###############################################################################
        #Install Edge
        $ProgressPreference='SilentlyContinue' #for faster download
        Invoke-WebRequest -Uri "http://dl.delivery.mp.microsoft.com/filestreamingservice/files/07367ab9-ceee-4409-a22f-c50d77a8ae06/MicrosoftEdgeEnterpriseX64.msi" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"

        #start install
        Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"

        #start Edge
        start-sleep 5
        & "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
#>

        ###############################################################################
        # Create OU Admin groups
        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.PkiAdmins.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.AdminXtra.GG.PkiAdmins.DisplayName
            Path                          = $ItPGOuDn
            Description                   = $confXML.n.AdminXtra.GG.PkiAdmins.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SG_PkiAdmins = New-AdDelegatedGroup @parameters

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.PkiTemplateAdmins.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.AdminXtra.GG.PkiTemplateAdmins.DisplayName
            Path                          = $ItPGOuDn
            Description                   = $confXML.n.AdminXtra.GG.PkiTemplateAdmins.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SG_PkiTemplAdmins = New-AdDelegatedGroup @parameters

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.PkiRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.PkiRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.PkiRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_PkiRight = New-AdDelegatedGroup @parameters

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.PkiTemplateRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.PkiTemplateRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.PkiTemplateRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_PkiTemplRight = New-AdDelegatedGroup @parameters

        # Apply the PSO to the corresponding Groups
        Add-ADFineGrainedPasswordPolicySubject -Identity $confXML.n.Admin.PSOs.ItAdminsPSO.Name -Subjects $SG_PkiAdmins, $SG_PkiTemplAdmins, $SL_PkiRight, $SL_PkiTemplRight


        ###############################################################################
        # Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Add-AdGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SG_PkiAdmins, $SG_PkiTemplAdmins, $SL_PkiRight, $SL_PkiTemplRight


        ###############################################################################
        # Nest Groups - Extend Rights through delegation model groups

        Add-AdGroupNesting -Identity $SG_PkiAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.InfraAdmins.Name)

        Add-AdGroupNesting -Identity $SG_PkiTemplAdmins -Members $SG_PkiAdmins

        Add-AdGroupNesting -Identity $SL_PkiRight -Members $SG_PkiAdmins

        Add-AdGroupNesting -Identity $SL_PkiTemplRight -Members $SG_PkiTemplAdmins

        Add-AdGroupNesting -Identity 'Cryptographic Operators' -Members $SG_PkiAdmins

        ###############################################################################
        # START Delegation to SL_InfraRights group on ADMIN area

        #
        Set-AdAclPkiAdmin -Group $SL_PkiRight.SamAccountName -ItRightsOuDN $ItRightsOuDn

        #
        Set-AdAclPkiTemplateAdmin -Group $SL_PkiTemplRight.SamAccountName

        ###############################################################################
        # START Create new Templates

        #https://github.com/GoateePFE/ADCSTemplate
        # Export-ADCSTemplate -Server DC1 -DisplayName WAC > .\WAC.json

        #
        #Windows Admin Center and Enterprise CA
        #https://github.com/microsoft/WSLab/tree/master/Scenarios/Windows%20Admin%20Center%20and%20Enterprise%20CA


        $DisplayName="RemoteDesktopAuthentication"
        $TemplateOtherAttributes = @{
            'Name'                                 = [System.String]$DisplayName
            'ObjectClass'                          = [System.String]'pKICertificateTemplate'
            'flags'                                = [System.Int32]'131680'
            'revision'                             = [System.Int32]'100'
            'msPKI-Cert-Template-OID'              = '1.3.6.1.4.1.311.21.8.2144245.16492515.9915066.5498192.1427428.109.8434507.13944343'
            'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.4.1.311.54.1.2')
            'msPKI-Certificate-Name-Flag'          = [System.Int32]'1249902592'
            'msPKI-Enrollment-Flag'                = [System.Int32]'40'
            'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
            'msPKI-Private-Key-Flag'               = [System.Int32]'101056768'
            'msPKI-RA-Signature'                   = [System.Int32]'0'
            'msPKI-Template-Minor-Revision'        = [System.Int32]'3'
            'msPKI-Template-Schema-Version'        = [System.Int32]'4'
            'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
            'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft RSA SChannel Cryptographic Provider')
            'pKIDefaultKeySpec'                    = [System.Int32]'1'
            'pKIExpirationPeriod'                  = [System.Byte[]]@('0','128','114','14','93','194','253','255')
            'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.4.1.311.54.1.2')
            'pKIKeyUsage'                          = [System.Byte[]]@('160','0')
            'pKIMaxIssuingDepth'                   = [System.Int32]'0'
            'pKIOverlapPeriod'                     = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        }
        New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

        #Publish  Template
        PublishCert -CertDisplayName  $DisplayName

        $DisplayName="WindowsAdminCenter"
        $TemplateOtherAttributes = @{
            'Name'                                 = [System.String]$DisplayName
            'ObjectClass'                          = [System.String]'pKICertificateTemplate'
            'flags'                                = [System.Int32]'131649'
            'revision'                             = [System.Int32]'101'
            "msPKI-Cert-Template-OID"              = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.4.1.311.21.8.2144245.16492515.9915066.5498192.1427428.109.11631727.2421588')
            'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
            'msPKI-Certificate-Name-Flag'          = [System.Int32]'1249902592'
            'msPKI-Enrollment-Flag'                = [System.Int32]'40'
            'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
            'msPKI-Private-Key-Flag'               = [System.Int32]'101056768'
            'msPKI-RA-Application-Policies'        = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA512`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168')
            'msPKI-RA-Signature'                   = [System.Int32]'0'
            'msPKI-Template-Minor-Revision'        = [System.Int32]'1'
            'msPKI-Template-Schema-Version'        = [System.Int32]'4'
            'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
            'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft RSA SChannel Cryptographic Provider','2,Microsoft DH SChannel Cryptographic Provider')
            'pKIDefaultKeySpec'                    = [System.Int32]'1'
            'pKIExpirationPeriod'                  = [System.Byte[]]@('0','128','114','14','93','194','253','255')
            'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
            'pKIKeyUsage'                          = [System.Byte[]]@('160','0')
            'pKIMaxIssuingDepth'                   = [System.Int32]'0'
            'pKIOverlapPeriod'                     = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        }
        New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

        #Publish  Template
        PublishCert -CertDisplayName  $DisplayName

        $DisplayName="WinRM"
        $TemplateOtherAttributes = @{
            'Name'                                 = [System.String]$DisplayName
            'ObjectClass'                          = [System.String]'pKICertificateTemplate'
            'flags'                                = [System.Int32]'131649'
            'revision'                             = [System.Int32]'100'
            "msPKI-Cert-Template-OID"              = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.4.1.311.21.8.2144245.16492515.9915066.5498192.1427428.109.16552861.1454492')
            'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2','1.3.6.1.5.5.7.3.1')
            'msPKI-Certificate-Name-Flag'          = [System.Int32]'1249902592'
            'msPKI-Enrollment-Flag'                = [System.Int32]'32'
            'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
            'msPKI-Private-Key-Flag'               = [System.Int32]'101056512'
            'msPKI-RA-Application-Policies'        = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@("msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA256`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168")
            'msPKI-RA-Signature'                   = [System.Int32]'0'
            'msPKI-Template-Minor-Revision'        = [System.Int32]'2'
            'msPKI-Template-Schema-Version'        = [System.Int32]'4'
            'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
            'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft RSA SChannel Cryptographic Provider','2,Microsoft DH SChannel Cryptographic Provider')
            'pKIDefaultKeySpec'                    = [System.Int32]'1'
            'pKIExpirationPeriod'                  = [System.Byte[]]@('0','128','114','14','93','194','253','255')
            'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1','1.3.6.1.5.5.7.3.2')
            'pKIKeyUsage'                          = [System.Byte[]]@('160','0')
            'pKIMaxIssuingDepth'                   = [System.Int32]'0'
            'pKIOverlapPeriod'                     = [System.Byte[]]@('0','128','166','10','255','222','255','255')
        }
        New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

        #Publish  Template
        PublishCert -CertDisplayName  $DisplayName



<#

$GatewayServerName="Wac1"
$TemplateName = "WindowsAdminCenter"

# Install PSPKI module for managing Certification Authority
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSPKI -Force
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force
Import-Module PSPKI

#Set Cert Template permission
Get-CertificateTemplate -Name $TemplateName | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "$GatewayServerName$" -AccessType Allow -AccessMask Read, Enroll,AutoEnroll | Set-CertificateTemplateAcl

#Configure AutoEnrollment policy and enroll cert on WACGW
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {
    Set-CertificateAutoEnrollmentPolicy -StoreName MY -PolicyState Enabled -ExpirationPercentage 10 -EnableTemplateCheck -EnableMyStoreManagement -context Machine
    certutil -pulse
}

#>


    }
    End {
        Write-Verbose -Message ('Function {0} created Certificate Authority objects and Delegations successfully.' -f $MyInvocation.InvocationName)
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-CaObjects
#EndRegion - New-CaObjects.ps1
#Region - New-CentralItOU.ps1
function New-CentralItOu
{
    <#
        .Synopsis
            Create Central OU and aditional Tier 0 infrastructure OUs
        .DESCRIPTION
            Create Central OU including sub-OUs, secure them accordingly, move built-in objects
            and secure them, create needed groups and secure them, make nesting and delegations
            and finaly create PSO and delegate accordingly.
        .EXAMPLE
            New-CentralItOu
        .PARAMETER
            Param1 ConfigXFileFile:..[STRING] Full path to the configuration.xml file
            Param2 CreateExchange:...[SWITCH] If present It will create all needed Exchange objects, containers and delegations
            Param3 CreateDfs:........[SWITCH] If present It will create all needed DFS objects, containers and delegations
            Param4 CreateCa:.........[SWITCH] If present It will create all needed Certificate Authority (PKI) objects, containers and delegations
            Param5 CreateAGPM:.......[SWITCH] If present It will create all needed AGPM objects, containers and delegations
            Param6 CreateLAPS:.......[SWITCH] If present It will create all needed LAPS objects, containers and delegations
            Param7 CreateDHCP:.......[SWITCH] If present It will create all needed DHCP objects, containers and delegations
            Param8 DMscripts:........[String] Full path to the Delegation Model Scripts Directory

            This function relies on Config.xml file.

        .NOTES
            Version:         1.2
            DateModified:    28/Oct/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([String])]

    Param (
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        # Param2 If present It will create all needed Exchange objects, containers and delegations
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects, containers and delegations.',
        Position = 1)]
        [switch]
        $CreateExchange,

        # Param3 Create DFS Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed DFS objects, containers and delegations.',
        Position = 2)]
        [switch]
        $CreateDfs,

        # Param4 Create CA (PKI) Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Certificate Authority (PKI) objects, containers and delegations.',
        Position = 3)]
        [switch]
        $CreateCa,

        # Param5 Create AGPM Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed AGPM objects, containers and delegations.',
        Position = 4)]
        [switch]
        $CreateAGPM,

        # Param6 Create LAPS Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed LAPS objects, containers and delegations.',
        Position = 5)]
        [switch]
        $CreateLAPS,

        # Param7 Create DHCP Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed DHCP objects, containers and delegations.',
        Position = 6)]
        [switch]
        $CreateDHCP,

        # Param8 Location of all scripts & files
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 7)]
        [string]
        $DMscripts = "C:\PsScripts\"
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        ################################################################################
        # Initialisations
        Import-Module -name ServerManager        -Verbose:$false
        Import-Module -name ActiveDirectory      -Verbose:$false
        Import-Module -name GroupPolicy          -Verbose:$false
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        ################################################################################
        #region Declarations

        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        } catch { throw } # End Try

        # Read the value from parsed SWITCH parameters.
        try {
            # Check if CreateExchange parameter is parsed.
            If($PSBoundParameters['CreateExchange']) {
                # If parameter is parsed, then make variable TRUE
                $CreateExchange = $True
            } else {
                # Otherwise variable is FALSE
                $CreateExchange = $False
            }

            # Check if CreateDfs parameter is parsed.
            If($PSBoundParameters['CreateDfs']) {
                # If parameter is parsed, then make variable TRUE
                $CreateDfs = $True
            } else {
                # Otherwise variable is FALSE
                $CreateDfs = $False
            }

            # Check if CreateCa parameter is parsed.
            If($PSBoundParameters['CreateCa']) {
                # If parameter is parsed, then make variable TRUE
                $CreateCa = $True
            } else {
                # Otherwise variable is FALSE
                $CreateCa = $False
            }

            # Check if CreateAGPM  parameter is parsed.
            If($PSBoundParameters['CreateAGPM']) {
                # If parameter is parsed, then make variable TRUE
                $CreateAGPM = $True
            } else {
                # Otherwise variable is FALSE
                $CreateAGPM = $False
            }

            # Check if CreateLAPS  parameter is parsed.
            If($PSBoundParameters['CreateLAPS']) {
                # If parameter is parsed, then make variable TRUE
                $CreateLAPS = $True
            } else {
                # Otherwise variable is FALSE
                $CreateLAPS = $False
            }
        } catch { throw } # End Try

        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0





        # Global Groups
        Foreach($node in $confXML.n.Admin.GG.ChildNodes) {
            $param = @{
                Name        = "$('sg{0}{1}' -f $NC['Delim'], $Node.LocalName)"
                Value       = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.Name
                Description = $Node.Description
                Option      = 'RreadOnly'
                Force       = $true
            }
            # Create variable for each defined ADMIN GlobalGroup name, Appending SG prefix
            New-Variable @Param
        }

        New-Variable -Name "SG_Operations" -Value ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.Operations.Name) -Force
        New-Variable -Name "SG_ServerAdmins" -Value ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name) -Force





        # Domain Local Groups
        Foreach($node in $confXML.n.Admin.LG.ChildNodes) {
            $param = @{
                Name        = "$('sl{0}{1}' -f $NC['Delim'], $Node.LocalName)"
                Value       = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.Name
                Description = $Node.Description
                Option      = 'RreadOnly'
                Force       = $true
            }
            # Create variable for each defined ADMIN LocalGroup name using the XML name, Appending SL prefix
            New-Variable @Param

        }

        New-Variable -Name "SL_SvrAdmRight" -Value ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name) -Force
        New-Variable -Name "SL_SvrOpsRight" -Value ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.Name) -Force





        # Users
        $AdminName    = $confXML.n.Admin.users.Admin.Name
        $newAdminName = $confXML.n.Admin.users.NEWAdmin.Name





        # Organizational Units Names
        # Iterate all OUs within Admin
        Foreach($node in $confXML.n.Admin.OUs.ChildNodes) {
            $param = @{
                Name        = "$($Node.LocalName)"
                Value       = $Node.Name
                Description = $Node.Description
                Option      = 'RreadOnly'
                Force       = $true
            }
            # Create variable for current OUs name, Using the XML LocalName of the node for the variable
            New-Variable @Param
        }

        # Organizational Units Distinguished Names
        # Admin Area

        # IT Admin OU Distinguished Name
        New-Variable -Name 'ItAdminOuDn' -Value ('OU={0},{1}' -f $ItAdminOu, $AdDn) -Option ReadOnly -Force

        # It Admin Users OU Distinguished Name
        $ItAdminAccountsOuDn = 'OU={0},{1}' -f $ItAdminAccountsOu, $ItAdminOuDn

        # It Admin Groups OU Distinguished Name
        $ItAdminGroupsOuDn = 'OU={0},{1}' -f $ItAdminGroupsOu, $ItAdminOuDn

        # It Privileged Groups OU Distinguished Name
        $ItPrivGroupsOUDn = 'OU={0},{1}' -f $ItPrivGroupsOU, $ItAdminOuDn

        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

        # It Admin ServiceAccount OU Distinguished Name
        $ItServiceAccountsOuDn = 'OU={0},{1}' -f $ItServiceAccountsOu, $ItAdminOuDn

            # It Admin T0SA OU Distinguished Name
            $ItSAT0OuDn = 'OU={0},{1}' -f $ItSAT0Ou, $ItServiceAccountsOuDn

            # It Admin T0SA OU Distinguished Name
            $ItSAT1OuDn = 'OU={0},{1}' -f $ItSAT1Ou, $ItServiceAccountsOuDn

            # It Admin T0SA OU Distinguished Name
            $ItSAT2OuDn = 'OU={0},{1}' -f $ItSAT2Ou, $ItServiceAccountsOuDn

        # It PAW OU Distinguished Name
        $ItPawOuDn = 'OU={0},{1}' -f $ItPawOu, $ItAdminOuDn

            # It PAW T0 OU Distinguished Name
            $ItPawT0OuDn = 'OU={0},{1}' -f $ItPawT0Ou, $ItPawOuDn

            # It PAW T1 OU Distinguished Name
            $ItPawT1OuDn = 'OU={0},{1}' -f $ItPawT1Ou, $ItPawOuDn

            # It PAW T2 OU Distinguished Name
            $ItPawT2OuDn = 'OU={0},{1}' -f $ItPawT2Ou, $ItPawOuDn

            # It PAW Staging OU Distinguished Name
            $ItPawStagingOuDn = 'OU={0},{1}' -f $ItPawStagingOu, $ItPawOuDn

        # It Infrastructure Servers OU Distinguished Name
        $ItInfraOuDn = 'OU={0},{1}' -f $ItInfraOu, $ItAdminOuDn

            # It Infrastructure Servers T0 OU Distinguished Name
            $ItInfraT0OuDn = 'OU={0},{1}' -f $ItInfraT0Ou, $ItInfraOuDn

            # It Infrastructure Servers T1 OU Distinguished Name
            $ItInfraT1OuDn = 'OU={0},{1}' -f $ItInfraT1Ou, $ItInfraOuDn

            # It Infrastructure Servers T2 OU Distinguished Name
            $ItInfraT2OuDn = 'OU={0},{1}' -f $ItInfraT2Ou, $ItInfraOuDn

            # It Infrastructure Servers Staging OU Distinguished Name
            $ItInfraStagingOuDn = 'OU={0},{1}' -f $ItInfraStagingOu, $ItInfraOuDn

        # It HOUSEKEEPING OU Distinguished Name
        $ItHousekeepingOuDn = 'OU={0},{1}' -f $ItHousekeepingOu, $ItAdminOuDn



        # Servers Area

        # Servers OU
        New-Variable -Name 'ServersOu' -Value $confXML.n.Servers.OUs.ServersOU.Name -Option ReadOnly -Force
        # Servers OU Distinguished Name
        $ServersOuDn = 'OU={0},{1}' -f $ServersOu, $AdDn



        # Sites Area

        # Sites OU
        New-Variable -Name 'SitesOu' -Value $confXML.n.Sites.OUs.SitesOU.name -Option ReadOnly -Force
        # Sites OU Distinguished Name
        $SitesOuDn = 'OU={0},{1}' -f $SitesOu, $AdDn

            # Sites GLOBAL OU
            $SitesGlobalOu = $confXML.n.Sites.OUs.OuSiteGlobal.name
            # Sites GLOBAL OU Distinguished Name
            $SitesGlobalOuDn = 'OU={0},{1}' -f $SitesGlobalOu, $SitesOuDn

                # Sites GLOBAL GROUPS OU
                $SitesGlobalGroupOu = $confXML.n.Sites.OUs.OuSiteGlobalGroups.name
                # Sites GLOBAL GROUPS OU Distinguished Name
                $SitesGlobalGroupOuDn = 'OU={0},{1}' -f $SitesGlobalGroupOu, $SitesGlobalOuDn

                # Sites GLOBAL APPACCUSERS OU
                $SitesGlobalAppAccUserOu = $confXML.n.Sites.OUs.OuSiteGlobalAppAccessUsers.name
                # Sites GLOBAL APPACCUSERS OU Distinguished Name
                $SitesGlobalAppAccUserOuDn = 'OU={0},{1}' -f $SitesGlobalAppAccUserOu, $SitesGlobalOuDn




        # Quarantine OU
        New-Variable -Name 'ItQuarantineOu' -Value $confXML.n.Admin.OUs.ItNewComputersOU.name -Option ReadOnly -Force
        # Quarantine OU Distinguished Name
        $ItQuarantineOuDn = 'OU={0},{1}' -f $ItQuarantineOu, $AdDn

        # parameters variable for splatting CMDlets
        $parameters = $null


        #endregion Declarations
        ################################################################################
    }
    Process {
        ###############################################################################
        # Create IT Admin and Sub OUs
        Write-Verbose -Message 'Create Admin Area and related structure...'
        New-DelegateAdOU -ouName $ItAdminOu -ouPath $AdDn -ouDescription $confXML.n.Admin.OUs.ItAdminOU.description

        # Remove Inheritance and copy the ACE
        Set-AdInheritance -LDAPPath $ItAdminOuDn -RemoveInheritance $true -RemovePermissions $true
        <#
        # Remove AUTHENTICATED USERS group from OU
        #
        # CHECK... This one should not "LIST" but must be on ACL
        Remove-AuthUser -LDAPPath $ItAdminOuDn

        # Clean Ou
        Start-AdCleanOU -LDAPPath $ItAdminOuDn  -RemoveUnknownSIDs

        # Remove Pre-Windows 2000 Access group from OU
        Remove-PreWin2000FromOU -LDAPPath $ItAdminOuDn

        # Remove ACCOUNT OPERATORS 2000 Access group from OU
        Remove-AccountOperator -LDAPPath $ItAdminOuDn

        # Remove PRINT OPERATORS 2000 Access group from OU
        Remove-PrintOperator -LDAPPath $ItAdminOuDn
        #>

        # Computer objects within this ares MUST have read access, otherwise GPO will not apply - TO BE DONE

        ###############################################################################
        #region Create Sub-OUs for admin

        $Splat = @{
            ouPath = $ItAdminOuDn
            CleanACL =$True
        }
        New-DelegateAdOU -ouName $ItAdminAccountsOu   -ouDescription $confXML.n.Admin.OUs.ItAdminAccountsOU.description   @Splat
        New-DelegateAdOU -ouName $ItAdminGroupsOU     -ouDescription $confXML.n.Admin.OUs.ItAdminGroupsOU.description     @Splat
        New-DelegateAdOU -ouName $ItPrivGroupsOU      -ouDescription $confXML.n.Admin.OUs.ItPrivGroupsOU.description      @Splat
        New-DelegateAdOU -ouName $ItPawOu             -ouDescription $confXML.n.Admin.OUs.ItPawOU.description             @Splat
        New-DelegateAdOU -ouName $ItRightsOu          -ouDescription $confXML.n.Admin.OUs.ItRightsOU.description          @Splat
        New-DelegateAdOU -ouName $ItServiceAccountsOu -ouDescription $confXML.n.Admin.OUs.ItServiceAccountsOU.description @Splat
        New-DelegateAdOU -ouName $ItHousekeepingOu    -ouDescription $confXML.n.Admin.OUs.ItHousekeepingOU.description    @Splat
        New-DelegateAdOU -ouName $ItInfraOu           -ouDescription $confXML.n.Admin.OUs.ItInfraOU.description           @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPPath $ItAdminAccountsOuDn   @Splat
        Set-AdInheritance -LDAPPath $ItAdminGroupsOUDn     @Splat
        Set-AdInheritance -LDAPPath $ItPrivGroupsOUDn      @Splat
        Set-AdInheritance -LDAPPath $ItPawOuDn             @Splat
        Set-AdInheritance -LDAPPath $ItRightsOuDn          @Splat
        Set-AdInheritance -LDAPPath $ItServiceAccountsOuDn @Splat
        Set-AdInheritance -LDAPPath $ItHousekeepingOuDn    @Splat
        Set-AdInheritance -LDAPPath $ItInfraOuDn           @Splat

        # PAW Sub-OUs
        $Splat = @{
            ouPath = $ItPawOuDn
            CleanACL =$True
        }
        New-DelegateAdOU -ouName $ItPawT0Ou      -ouDescription $confXML.n.Admin.OUs.ItPawT0OU.description      @Splat
        New-DelegateAdOU -ouName $ItPawT1Ou      -ouDescription $confXML.n.Admin.OUs.ItPawT1OU.description      @Splat
        New-DelegateAdOU -ouName $ItPawT2Ou      -ouDescription $confXML.n.Admin.OUs.ItPawT2OU.description      @Splat
        New-DelegateAdOU -ouName $ItPawStagingOu -ouDescription $confXML.n.Admin.OUs.ItPawStagingOU.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPPath $ItPawT0OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItPawT1OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItPawT2OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItPawStagingOuDn @Splat

        # Service Accounts Sub-OUs
        $Splat = @{
            ouPath = $ItServiceAccountsOuDn
            CleanACL =$True
        }
        New-DelegateAdOU -ouName $ItSAT0OU -ouDescription $confXML.n.Admin.OUs.ItSAT0OU.description @Splat
        New-DelegateAdOU -ouName $ItSAT1OU -ouDescription $confXML.n.Admin.OUs.ItSAT1OU.description @Splat
        New-DelegateAdOU -ouName $ItSAT2OU -ouDescription $confXML.n.Admin.OUs.ItSAT2OU.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPPath $ItSAT0OuDn @Splat
        Set-AdInheritance -LDAPPath $ItSAT1OuDn @Splat
        Set-AdInheritance -LDAPPath $ItSAT2OuDn @Splat

        # Infrastructure Servers Sub-OUs
        $Splat = @{
            ouPath = $ItInfraOuDn
            CleanACL =$True
        }
        New-DelegateAdOU -ouName $ItInfraT0Ou      -ouDescription $confXML.n.Admin.OUs.ItInfraT0.description        @Splat
        New-DelegateAdOU -ouName $ItInfraT1Ou      -ouDescription $confXML.n.Admin.OUs.ItInfraT1.description        @Splat
        New-DelegateAdOU -ouName $ItInfraT2Ou      -ouDescription $confXML.n.Admin.OUs.ItInfraT2.description        @Splat
        New-DelegateAdOU -ouName $ItInfraStagingOu -ouDescription $confXML.n.Admin.OUs.ItInfraStagingOU.description @Splat

        # Ensure inheritance is enabled for child Admin OUs
        $Splat = @{
            RemoveInheritance = $false
            RemovePermissions = $True
        }
        Set-AdInheritance -LDAPPath $ItInfraT0OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItInfraT1OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItInfraT2OuDn      @Splat
        Set-AdInheritance -LDAPPath $ItInfraStagingOuDn @Splat

        #endregion

        ###############################################################################
        #region  Move Built-In Admin user & Groups (Builtin OU groups can't be moved)

        Write-Verbose -Message 'Moving objects...'

        Get-ADUser -Identity $AdminName |                                 Move-ADObject -TargetPath $ItAdminAccountsOuDn
        Get-ADUser -Identity $confXML.n.Admin.users.Guest.Name |          Move-ADObject -TargetPath $ItAdminAccountsOuDn
        Get-ADUser -Identity krbtgt |                                     Move-ADObject -TargetPath $ItAdminAccountsOuDn

        Get-ADGroup -Identity 'Domain Admins' |                           Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Enterprise Admins' |                       Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Schema Admins' |                           Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Domain Controllers' |                      Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Group Policy Creator Owners' |             Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Read-only Domain Controllers' |            Move-ADObject -TargetPath $ItPrivGroupsOUDn
        Get-ADGroup -Identity 'Enterprise Read-only Domain Controllers' | Move-ADObject -TargetPath $ItPrivGroupsOUDn

        Get-ADGroup -Identity 'DnsUpdateProxy' |                          Move-ADObject -TargetPath $ItAdminGroupsOuDn
        Get-ADGroup -Identity 'Domain Users' |                            Move-ADObject -TargetPath $ItAdminGroupsOuDn
        Get-ADGroup -Identity 'Domain Computers' |                        Move-ADObject -TargetPath $ItAdminGroupsOuDn
        Get-ADGroup -Identity 'Domain Guests' |                           Move-ADObject -TargetPath $ItAdminGroupsOuDn

        Get-ADGroup -Identity 'Allowed RODC Password Replication Group' | Move-ADObject -TargetPath $ItRightsOuDn
        Get-ADGroup -Identity 'RAS and IAS Servers' |                     Move-ADObject -TargetPath $ItRightsOuDn
        Get-ADGroup -Identity 'DNSAdmins' |                               Move-ADObject -TargetPath $ItRightsOuDn
        Get-ADGroup -Identity 'Cert Publishers' |                         Move-ADObject -TargetPath $ItRightsOuDn
        Get-ADGroup -Identity 'Denied RODC Password Replication Group' |  Move-ADObject -TargetPath $ItRightsOuDn

        # Following groups only exist on Win 2012
        If ($Global:OsBuild -ge 9200) {
            Get-ADGroup -Identity 'Protected Users' |              Move-ADObject -TargetPath $ItPrivGroupsOUDn
            Get-ADGroup -Identity 'Cloneable Domain Controllers' | Move-ADObject -TargetPath $ItPrivGroupsOUDn

            Get-ADGroup -Identity 'Access-Denied Assistance Users' | Move-ADObject -TargetPath $ItPrivGroupsOUDn
            Get-ADGroup -Filter { SamAccountName -like "WinRMRemoteWMIUsers*" } |           Move-ADObject -TargetPath $ItPrivGroupsOUDn
        }

        # Following groups only exist on Win 2019
        If ($Global:OsBuild -ge 17763) {
            Get-ADGroup -Identity 'Enterprise Key Admins'               | Move-ADObject -TargetPath $ItPrivGroupsOUDn
            Get-ADGroup -Identity 'Key Admins'                          | Move-ADObject -TargetPath $ItPrivGroupsOUDn
            #Get-ADGroup -Identity 'Windows Admin Center CredSSP Admins' | Move-ADObject -TargetPath $ItPrivGroupsOUDn
        }

        # Get-ADGroup "Administrators" |                          Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Account Operators" |                       Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Backup Operators" |                        Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Certificate Service DCOM Access" |         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Cryptographic Operators" |                 Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Server Operators" |                        Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Remote Desktop Users" |                    Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Distributed COM Users" |                   Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Event Log Readers" |                       Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Guests" |                                  Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "IIS_IUSRS" |                               Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Incoming Forest Trust Builders" |          Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Network Configuration Operators" |         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Performance Log Users" |                   Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Performance Monitor Users" |               Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Pre-Windows 2000 Compatible Access" |      Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Print Operators" |                         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Replicator" |                              Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Terminal Server License Servers" |         Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Users" |                                   Move-ADObject -TargetPath $ItRightsOuDn
        # Get-ADGroup "Windows Authorization Access Group" |      Move-ADObject -TargetPath $ItRightsOuDn

        #endregion
        ###############################################################################

        ###############################################################################
        #region Creating Secured Admin accounts

        Write-Verbose -Message 'Creating and securing Admin accounts...'

        try {

            # Try to get the new Admin
            $NewAdminExists = Get-AdUser -Filter { SamAccountName -eq $newAdminName }

            # Check if the new Admin account already exist. If not, then create it.
            If($NewAdminExists) {
                #The user was found. Proceed to modify it accordingly.
                $parameters = @{
                    Enabled               = $true
                    UserPrincipalName     = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                    SamAccountName        = $newAdminName
                    DisplayName           = $newAdminName
                    Description           = $confXML.n.Admin.users.NEWAdmin.description
                    employeeId            = '0123456'
                    TrustedForDelegation  = $false
                    AccountNotDelegated   = $true
                    Company               = $confXML.n.RegisteredOrg
                    Country               = 'MX'
                    Department            = $confXML.n.Admin.users.NEWAdmin.department
                    State                 = 'Puebla'
                    EmailAddress          = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                    Replace               = @{
                        'employeeType'                  = $confXML.n.NC.AdminAccSufix0
                        'msNpAllowDialin'               = $false
                        'msDS-SupportedEncryptionTypes' = '24'
                    }
                }
                If(Test-Path -Path ('{0}\Pic\{1}.jpg' -f $DMscripts, $newAdminName)) {
                    # Read the path and file name of JPG picture
                    $PhotoFile = '{0}\Pic\{1}.jpg' -f $DMscripts, $newAdminName
                    # Get the content of the JPG file
                    $photo = [byte[]](Get-Content -Path $PhotoFile -Encoding byte)

                    # Only if photo exists, add it to splatting
                    $parameters.Replace.Add('thumbnailPhoto',$photo)
                } else {
                    If(Test-Path -Path ('{0}\Pic\Default.jpg' -f $DMscripts)) {
                        # Read the path and file name of JPG picture
                        $PhotoFile = '{0}\Pic\Default.jpg' -f $DMscripts
                        # Get the content of the JPG file
                        $photo = [byte[]](Get-Content -Path $PhotoFile -Encoding byte)
    
                        # Only if photo exists, add it to splatting
                        $parameters.Replace.Add('thumbnailPhoto',$photo)
                    }
                }

                Set-AdUser -Identity $NewAdminExists
            } #end if -user exists
            Else {
                # User was not Found! create new.
                $parameters = @{
                    Path                  = $ItAdminAccountsOuDn
                    Name                  = $newAdminName
                    AccountPassword       = (ConvertTo-SecureString -String $confXML.n.DefaultPassword -AsPlainText -Force)
                    ChangePasswordAtLogon = $false
                    Enabled               = $true
                    UserPrincipalName     = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                    SamAccountName        = $newAdminName
                    DisplayName           = $newAdminName
                    Description           = $confXML.n.Admin.users.NEWAdmin.description
                    employeeId            = '0123456'
                    TrustedForDelegation  = $false
                    AccountNotDelegated   = $true
                    Company               = $confXML.n.RegisteredOrg
                    Country               = 'MX'
                    Department            = $confXML.n.Admin.users.NEWAdmin.department
                    State                 = 'Puebla'
                    EmailAddress          = ('{0}@{1}' -f $newAdminName, $env:USERDNSDOMAIN)
                    OtherAttributes       = @{
                        'employeeType'                  = $confXML.n.NC.AdminAccSufix0
                        'msNpAllowDialin'               = $false
                        'msDS-SupportedEncryptionTypes' = '24'
                    }
                }

                If(Test-Path -Path ('{0}\Pic\{1}.jpg' -f $DMscripts, $newAdminName)) {
                    # Read the path and file name of JPG picture
                    $PhotoFile = '{0}\Pic\{1}.jpg' -f $DMscripts, $newAdminName
                    # Get the content of the JPG file
                    $photo = [byte[]](Get-Content -Path $PhotoFile -Encoding byte)

                    # Only if photo exists, add it to splatting
                    $parameters.OtherAttributes.Add('thumbnailPhoto',$photo)
                } else {
                    If(Test-Path -Path ('{0}\Pic\Default.jpg' -f $DMscripts)) {
                        # Read the path and file name of JPG picture
                        $PhotoFile = '{0}\Pic\Default.jpg' -f $DMscripts
                        # Get the content of the JPG file
                        $photo = [byte[]](Get-Content -Path $PhotoFile -Encoding byte)
    
                        # Only if photo exists, add it to splatting
                        $parameters.Replace.Add('thumbnailPhoto',$photo)
                    }
                }

                # Create the new Admin with special values
                New-AdUser @parameters
                $NewAdminExists = Get-AdUser -Identity $newAdminName

                #http://blogs.msdn.com/b/openspecification/archive/2011/05/31/windows-configurations-for-kerberos-supported-encryption-type.aspx
                # 'msDS-SupportedEncryptionTypes'= Kerberos DES Encryption = 2, Kerberos AES 128 = 8, Kerberos AES 256 = 16
            } #end esle-if new user created

            # Set the Protect against accidental deletions attribute
            Get-AdUser -Identity $AdminName | Set-ADObject -ProtectedFromAccidentalDeletion $true
            $NewAdminExists                 | Set-ADObject -ProtectedFromAccidentalDeletion $true

            # Make it member of administrative groups
            Add-AdGroupNesting -Identity 'Domain Admins'                          -Members $NewAdminExists
            Add-AdGroupNesting -Identity 'Enterprise Admins'                      -Members $NewAdminExists
            Add-AdGroupNesting -Identity 'Group Policy Creator Owners'            -Members $NewAdminExists
            Add-AdGroupNesting -Identity 'Denied RODC Password Replication Group' -Members $NewAdminExists

            # http://blogs.msdn.com/b/muaddib/archive/2013/12/30/how-to-modify-security-inheritance-on-active-directory-objects.aspx

            ####
            # Remove Everyone group from Admin-User & Administrator
            Remove-Everyone -LDAPPath $NewAdminExists.DistinguishedName
            Remove-Everyone -LDAPPath ('CN={0},{1}' -f $AdminName, $ItAdminAccountsOuDn)

            ####
            # Remove AUTHENTICATED USERS group from Admin-User & Administrator
            #Remove-AuthUser -LDAPPath $NewAdminExists.DistinguishedName
            #Remove-AuthUser -LDAPPath ('CN={0},{1}' -f $AdminName, $ItAdminAccountsOuDn)

            ####
            # Remove Pre-Windows 2000 Compatible Access group from Admin-User & Administrator
            Remove-PreWin2000 -LDAPPath $NewAdminExists.DistinguishedName
            Remove-PreWin2000 -LDAPPath ('CN={0},{1}' -f $AdminName, $ItAdminAccountsOuDn)

            ###
            # Configure TheGood account

            # Read the path and file name of JPG picture
            $PhotoFile = '{0}\Pic\{1}.jpg' -f $DMscripts, $AdminName
            # Get the content of the JPG file
            $photo = [byte[]](Get-Content -Path $PhotoFile -Encoding byte)

            Get-ADUser -Identity $AdminName | Set-AdUser -TrustedForDelegation $false -AccountNotDelegated $true -Add @{
                'employeeType'                = $confXML.n.NC.AdminAccSufix0
                'msNpAllowDialin'             = $false
                'msDS-SupportedEncryptionTypes' = '24'
                'thumbnailPhoto'              = $photo
            }
        } # end try
        catch { throw }
        finally { Write-Verbose -Message 'Admin accounts created and secured.' }

        #endregion Creating Secured Admin accounts
        ###############################################################################

        ###############################################################################
        #region Create Admin groups

        # Iterate through all Admin-LocalGroups child nodes
        Foreach($Node in $confXML.n.Admin.LG.ChildNodes) {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $Node.Name))
            $parameters = @{
                Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $Node.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = $Node.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = $Node.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $varparam = @{
                Name  = "$('SL{0}{1}' -f $NC['Delim'], $Node.LocalName)"
                Value = New-AdDelegatedGroup @parameters
                Force = $true
            }
            New-Variable @varparam
        } # End ForEach

        # Iterate through all Admin-GlobalGroups child nodes
        Foreach($Node in $confXML.n.Admin.GG.ChildNodes) {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.localname))
            $parameters = @{
                Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = $Node.DisplayName
                Path                          = $ItAdminGroupsOuDn
                Description                   = $Node.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $varparam = @{
                Name  = "$('SG{0}{1}' -f $NC['Delim'], $Node.LocalName)"
                Value = New-AdDelegatedGroup @parameters
                Force = $true
            }
            New-Variable @varparam
        } # End ForEach


        # Create Servers Area / Tier1 Domain Local & Global Groups
        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.Operations.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.Servers.GG.Operations.DisplayName
            Path                          = $ItAdminGroupsOuDn
            Description                   = $confXML.n.Servers.GG.Operations.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        New-Variable -Name "$('SG{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.Operations.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.Servers.GG.ServerAdmins.DisplayName
            Path                          = $ItAdminGroupsOuDn
            Description                   = $confXML.n.Servers.GG.ServerAdmins.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        New-Variable -Name "$('SG{0}{1}' -f $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.Servers.LG.SvrOpsRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.Servers.LG.SvrOpsRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        New-Variable -Name "$('SL{0}{1}' -f $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.Servers.LG.SvrAdmRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.Servers.LG.SvrAdmRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        New-Variable -Name "$('SL{0}{1}' -f $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.LocalName)" -Value (New-AdDelegatedGroup @parameters) -Force



        # Get all Privileged groups into an array
        $AllGroups = @(
            $SG_InfraAdmins,
            $SG_AdAdmins,
            $SG_T0SA,
            $SG_T1SA,
            $SG_T2SA,
            $SG_GpoAdmins,
            $SG_Tier0Admins,
            $SG_Tier1Admins,
            $SG_Tier2Admins,
            $SG_AllSiteAdmins,
            $SG_AllGALAdmins
        )

        # Move the groups to PG OU
        foreach($item in $AllGroups) {
            # Remove the ProtectedFromAccidentalDeletion, otherwise throws error when moving
            $item | Set-ADObject -ProtectedFromAccidentalDeletion $false

            # Move objects to PG OU
            $item | Move-ADObject -TargetPath $ItPrivGroupsOUDn

            # Set back again the ProtectedFromAccidentalDeletion flag.
            #The group has to be fetch again because of the previus move
            Get-ADGroup -Identity $item.SamAccountName | Set-ADObject -ProtectedFromAccidentalDeletion $true
        }

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create Group Managed Service Account

        # Get the current OS build
        Get-OsBuild

        If ($Global:OsBuild -ge 9200) {
            # Create the KDS Root Key (only once per domain).  This is used by the KDS service on DCs (along with other information) to generate passwords
            # http://blogs.technet.com/b/askpfeplat/archive/2012/12/17/windows-server-2012-group-managed-service-accounts.aspx
            # If working in a test environment with a minimal number of DCs and the ability to guarantee immediate replication, please use:
            #    Add-KdsRootKey â€“EffectiveTime ((get-date).addhours(-10))
            Add-KdsRootKey -EffectiveTime ((get-date).addhours(-10))
        }


        If ($Global:OsBuild -ge 9200) {

            $Splat = @{
                Name                   = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                SamAccountName         = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                DNSHostName            = ('{0}.{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN)
                AccountNotDelegated    = $true
                Description            = $confXML.n.Admin.gMSA.AdTaskScheduler.Description
                DisplayName            = $confXML.n.Admin.gMSA.AdTaskScheduler.DisplayName
                KerberosEncryptionType = 'AES128,AES256'
                Path                   = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $ItServiceAccountsOuDn
                enabled                = $True
                TrustedForDelegation   = $false
                ServicePrincipalName   = ('HOST/{0}.{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN)
            }

            $ReplaceParams = @{
                Replace = @{
                    'c'="MX"
                    'co'="Mexico"
                    'company'=$confXML.n.RegisteredOrg
                    'department'="IT"
                    'employeeID'='T0'
                    'employeeType'="ServiceAccount"
                    'info'=$confXML.n.Admin.gMSA.AdTaskScheduler.Description
                    'l'="Puebla"
                    'title'=$confXML.n.Admin.gMSA.AdTaskScheduler.DisplayName
                    'userPrincipalName'='{0}@{1}' -f $confXML.n.Admin.gMSA.AdTaskScheduler.Name, $env:USERDNSDOMAIN
                }
            }

            try {
                New-ADServiceAccount @Splat | Set-ADServiceAccount @ReplaceParams
            }
            catch { throw }
        }
        else {
            $Splat = @{
                name        = $confXML.n.Admin.gMSA.AdTaskScheduler.Name
                Description = $confXML.n.Admin.gMSA.AdTaskScheduler.Description
                Path        = 'OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.name, $ItServiceAccountsOuDn
                enabled     = $True
            }

            New-ADServiceAccount @Splat
        }

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create a New Fine Grained Password Policy for Admins Accounts

        $PSOexists = $null

        $PsoName = $confXML.n.Admin.PSOs.ItAdminsPSO.Name

        $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { cn -eq $PsoName }

        if(-not($PSOexists)) {
            $parameters = @{
              Name                        = $confXML.n.Admin.PSOs.ItAdminsPSO.Name
              Precedence                  = $confXML.n.Admin.PSOs.ItAdminsPSO.Precedence
              ComplexityEnabled           = [System.Boolean]$confXML.n.Admin.PSOs.ItAdminsPSO.ComplexityEnabled
              Description                 = $confXML.n.Admin.PSOs.ItAdminsPSO.Description
              DisplayName                 = $confXML.n.Admin.PSOs.ItAdminsPSO.DisplayName
              LockoutDuration             = $confXML.n.Admin.PSOs.ItAdminsPSO.LockoutDuration
              LockoutObservationWindow    = $confXML.n.Admin.PSOs.ItAdminsPSO.LockoutObservationWindow
              LockoutThreshold            = $confXML.n.Admin.PSOs.ItAdminsPSO.LockoutThreshold
              MaxPasswordAge              = $confXML.n.Admin.PSOs.ItAdminsPSO.MaxPasswordAge
              MinPasswordAge              = $confXML.n.Admin.PSOs.ItAdminsPSO.MinPasswordAge
              MinPasswordLength           = $confXML.n.Admin.PSOs.ItAdminsPSO.MinPasswordLength
              PasswordHistoryCount        = $confXML.n.Admin.PSOs.ItAdminsPSO.PasswordHistoryCount
              ReversibleEncryptionEnabled = [System.Boolean]$confXML.n.Admin.PSOs.ItAdminsPSO.ReversibleEncryptionEnabled
            }

            New-ADFineGrainedPasswordPolicy @parameters

            [String]$PsoName = $confXML.n.Admin.PSOs.ItAdminsPSO.Name

            $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { cn -eq $PsoName }
        } # End If PSO exists


        # Apply the PSO to the corresponding accounts and groups
        $parameters = @( $AdminName,
                         $newAdminName,
                         'Domain Admins',
                         'Enterprise Admins',
                         $SG_InfraAdmins.SamAccountName,
                         $SG_AdAdmins.SamAccountName,
                         $SG_GpoAdmins.SamAccountName,
                         $SG_Tier0Admins.SamAccountName,
                         $SG_Tier1Admins.SamAccountName,
                         $SG_Tier2Admins.SamAccountName,
                         $SG_Operations.SamAccountName,
                         $SG_ServerAdmins.SamAccountName,
                         $SG_AllSiteAdmins.SamAccountName,
                         $SG_AllGALAdmins.SamAccountName,
                         $SG_GlobalUserAdmins.SamAccountName,
                         $SG_GlobalPcAdmins.SamAccountName,
                         $SG_GlobalGroupAdmins.SamAccountName,
                         $SG_ServiceDesk.SamAccountName,
                         $SL_InfraRight.SamAccountName,
                         $SL_AdRight.SamAccountName,
                         $SL_UM.SamAccountName,
                         $SL_GM.SamAccountName,
                         $SL_PUM.SamAccountName,
                         $SL_PGM.SamAccountName,
                         $SL_GpoAdminRight.SamAccountName,
                         $SL_DirReplRight.SamAccountName,
                         $SL_PISM.SamAccountName,
                         $SL_PAWM.SamAccountName,
                         $SL_PSAM.SamAccountName,
                         $SL_SvrAdmRight.SamAccountName,
                         $SL_SvrOpsRight.SamAccountName,
                         $SL_GlobalGroupRight.SamAccountName,
                         $SL_GlobalAppAccUserRight.SamAccountName
        )
        Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $parameters


        #endregion
        ###############################################################################

        ###############################################################################
        #region Create a New Fine Grained Password Policy for Service Accounts

        $PSOexists = $null


        $PsoName = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Name

        $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { cn -eq $PsoName }

        if(-not($PSOexists)) {
            $parameters = @{
              Name                        = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Name
              Precedence                  = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Precedence
              ComplexityEnabled           = [System.Boolean]$confXML.n.Admin.PSOs.ServiceAccountsPSO.ComplexityEnabled
              Description                 = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Description
              DisplayName                 = $confXML.n.Admin.PSOs.ServiceAccountsPSO.DisplayName
              LockoutDuration             = $confXML.n.Admin.PSOs.ServiceAccountsPSO.LockoutDuration
              LockoutObservationWindow    = $confXML.n.Admin.PSOs.ServiceAccountsPSO.LockoutObservationWindow
              LockoutThreshold            = $confXML.n.Admin.PSOs.ServiceAccountsPSO.LockoutThreshold
              MaxPasswordAge              = $confXML.n.Admin.PSOs.ServiceAccountsPSO.MaxPasswordAge
              MinPasswordAge              = $confXML.n.Admin.PSOs.ServiceAccountsPSO.MinPasswordAge
              MinPasswordLength           = $confXML.n.Admin.PSOs.ServiceAccountsPSO.MinPasswordLength
              PasswordHistoryCount        = $confXML.n.Admin.PSOs.ServiceAccountsPSO.PasswordHistoryCount
              ReversibleEncryptionEnabled = [System.Boolean]$confXML.n.Admin.PSOs.ServiceAccountsPSO.ReversibleEncryptionEnabled
            }

            New-ADFineGrainedPasswordPolicy @parameters

            $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { cn -eq $PsoName }
        }

        # Apply the PSO to all Tier Service Accounts
        $parameters = @( $SG_T0SA.SamAccountName,
                         $SG_T1SA.SamAccountName,
                         $SG_T2SA.SamAccountName
                        )
        Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $parameters

        #endregion
        ###############################################################################

        ###############################################################################
        #region Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Write-Verbose -Message 'Nesting groups...'

        $parameters = @( $AdminName,
                         $newAdminName,
                         'Domain Admins',
                         'Enterprise Admins',
                         $SG_InfraAdmins,
                         $SG_AdAdmins,
                         $SG_GpoAdmins,
                         $SG_Tier0Admins,
                         $SG_Tier1Admins,
                         $SG_Tier2Admins,
                         $SG_T0SA,
                         $SG_T1SA,
                         $SG_T2SA,
                         $SG_Operations,
                         $SG_ServerAdmins,
                         $SG_AllSiteAdmins,
                         $SG_AllGALAdmins,
                         $SG_GlobalUserAdmins,
                         $SG_GlobalPcAdmins,
                         $SG_GlobalGroupAdmins,
                         $SG_ServiceDesk,
                         $SL_InfraRight,
                         $SL_AdRight,
                         $SL_UM,
                         $SL_GM,
                         $SL_PUM,
                         $SL_PGM,
                         $SL_GpoAdminRight,
                         $SL_DirReplRight,
                         $SL_PISM,
                         $SL_PAWM,
                         $SL_PSAM,
                         $SL_SvrAdmRight,
                         $SL_SvrOpsRight,
                         $SL_GlobalGroupRight,
                         $SL_GlobalAppAccUserRight
        )
        Add-AdGroupNesting -Identity 'Denied RODC Password Replication Group' -Members $parameters

        #endregion
        ###############################################################################

        ###############################################################################
        #region Enabling Management Accounts to Modify the Membership of Protected Groups

        # Enable PUM to manage Privileged Accounts (Reset PWD, enable/disable Administrator built-in account)
        Set-AdAclMngPrivilegedAccounts -Group $SL_PUM.SamAccountName

        # Enable PGM to manage Privileged Groups (Administrators, Domain Admins...)
        Set-AdAclMngPrivilegedGroups -Group $SL_PGM.SamAccountName

        #endregion
        ###############################################################################

        ###############################################################################
        #region Nest Groups - Delegate Rights through Builtin groups
        # http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/

        Add-AdGroupNesting -Identity 'Cryptographic Operators' -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity 'Network Configuration Operators' -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity DnsAdmins -Members $SG_AdAdmins

        Add-AdGroupNesting -Identity 'Event Log Readers' -Members $SG_AdAdmins, $SG_Operations

        Add-AdGroupNesting -Identity 'Performance Log Users' -Members $SG_AdAdmins, $SG_Operations

        Add-AdGroupNesting -Identity 'Performance Monitor Users' -Members $SG_AdAdmins, $SG_Operations

        Add-AdGroupNesting -Identity 'Remote Desktop Users' -Members $SG_AdAdmins

        # https://technet.microsoft.com/en-us/library/dn466518(v=ws.11).aspx
        $parameters = @($AdminName,
                        $NewAdminName,
                        $SG_InfraAdmins,
                        $SG_AdAdmins,
                        $SG_GpoAdmins,
                        $SG_Tier0Admins,
                        $SG_Tier1Admins,
                        $SG_Tier2Admins,
                        $SG_Operations,
                        $SG_ServerAdmins,
                        $SG_AllSiteAdmins,
                        $SG_AllGALAdmins,
                        $SG_GlobalUserAdmins,
                        $SG_GlobalPcAdmins,
                        $SG_GlobalGroupAdmins,
                        $SG_ServiceDesk
        )
        Add-AdGroupNesting -Identity 'Protected Users' -Members $parameters


        #endregion
        ###############################################################################

        ###############################################################################
        #region Nest Groups - Extend Rights through delegation model groups
        # http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/

        # InfraAdmins as member of InfraRight
        $parameters = @{
            Identity = $SL_InfraRight
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PUM
        $parameters = @{
            Identity = $SL_PUM
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PGM
        $parameters = @{
            Identity = $SL_PGM
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PISM
        $parameters = @{
            Identity = $SL_PISM
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PAWM
        $parameters = @{
            Identity = $SL_PAWM
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of PSAM
        $parameters = @{
            Identity = $SL_PSAM
            Members  = $SG_InfraAdmins.SamAccountName
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of Tier0Admins
        $parameters = @{
            Identity = $SG_Tier0Admins.SamAccountName
            Members  = $SG_InfraAdmins.SamAccountName
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of DirReplRight
        $parameters = @{
            Identity = $SL_DirReplRight.SamAccountName
            Members  = $SG_InfraAdmins.SamAccountName
        }
        Add-AdGroupNesting @parameters

        # InfraAdmins as member of AdAdmins
        $parameters = @{
            Identity = $SG_AdAdmins
            Members  = $SG_InfraAdmins
        }
        Add-AdGroupNesting @parameters



        # AdAdmins as member of AdRight
        $parameters = @{
            Identity = $SL_AdRight
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of UM
        $parameters = @{
            Identity = $SL_UM
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of GM
        $parameters = @{
            Identity = $SL_GM
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of GpoAdmins
        $parameters = @{
            Identity = $SG_GpoAdmins
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of AllSiteAdmins
        $parameters = @{
            Identity = $SG_AllSiteAdmins
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters

        # AdAdmins as member of ServerAdmins
        $parameters = @{
            Identity = $SG_ServerAdmins
            Members  = $SG_AdAdmins
        }
        Add-AdGroupNesting @parameters



        # GpoAdmins as member of GpoAdminRight
        $parameters = @{
            Identity = $SL_GpoAdminRight
            Members  = $SG_GpoAdmins
        }
        Add-AdGroupNesting @parameters



        # AllSiteAdmins as member of AllGalAdmins
        $parameters = @{
            Identity = $SG_AllGALAdmins
            Members  = $SG_AllSiteAdmins
        }
        Add-AdGroupNesting @parameters

        # AllGalAdmins as member of ServiceDesk
        $parameters = @{
            Identity = $SG_ServiceDesk
            Members  = $SG_AllGALAdmins
        }
        Add-AdGroupNesting @parameters



        # ServerAdmins as member of SvrAdmRight
        $parameters = @{
            Identity = $SL_SvrAdmRight
            Members  = $SG_ServerAdmins
        }
        Add-AdGroupNesting @parameters

        # Operations as member of SvrOpsRight
        $parameters = @{
            Identity = $SL_SvrOpsRight
            Members  = $SG_Operations
        }
        Add-AdGroupNesting @parameters

        # ServerAdmins as member of Operations
        $parameters = @{
            Identity = $SG_Operations
            Members  = $SG_ServerAdmins
        }
        Add-AdGroupNesting @parameters


        #endregion
        ###############################################################################

        ###############################################################################
        #region redirect Users & Computers containers

        New-DelegateAdOU -ouName $ItQuarantineOu                        -ouPath $AdDn -ouDescription $confXML.n.Admin.OUs.ItNewComputersOU.description -RemoveAuthenticatedUsers
        New-DelegateAdOU -ouName $confXML.n.Admin.OUs.ItNewUsersOU.Name -ouPath $AdDn -ouDescription $confXML.n.Admin.OUs.ItNewUsersOU.description     -RemoveAuthenticatedUsers

        # START Remove Delegation to BuiltIn groups BEFORE REDIRECTION

        $parameters = @{
            Group      = 'Account Operators'
            LDAPPath   = 'CN=Computers,{0}' -f $AdDn
            RemoveRule = $True
        }
        ### COMPUTERS
        # Remove the Account Operators group from ACL to Create/Delete Users
        Set-AdAclCreateDeleteUser @parameters

        # Remove the Account Operators group from ACL to Create/Delete Computers
        Set-AdAclCreateDeleteComputer @parameters

        # Remove the Account Operators group from ACL to Create/Delete Groups
        Set-AdAclCreateDeleteGroup @parameters

        # Remove the Account Operators group from ACL to Create/Delete Contacts
        Set-AdAclCreateDeleteContact @parameters

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-CreateDeleteInetOrgPerson @parameters

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-AdAclCreateDeletePrintQueue @parameters

        $parameters = @{
            Group      = 'Account Operators'
            LDAPPath   = 'CN=Users,{0}' -f $AdDn
            RemoveRule = $True
        }
        ### USERS
        # Remove the Account Operators group from ACL to Create/Delete Users
        Set-AdAclCreateDeleteUser @parameters

        # Remove the Account Operators group from ACL to Create/Delete Computers
        Set-AdAclCreateDeleteComputer @parameters

        # Remove the Account Operators group from ACL to Create/Delete Groups
        Set-AdAclCreateDeleteGroup @parameters

        # Remove the Account Operators group from ACL to Create/Delete Contacts
        Set-AdAclCreateDeleteContact @parameters

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-CreateDeleteInetOrgPerson @parameters

        # Remove the Print Operators group from ACL to Create/Delete PrintQueues
        Set-AdAclCreateDeletePrintQueue @parameters

        ###############################################################################
        # Redirect Default USER & COMPUTERS Containers
        redircmp.exe ('OU={0},{1}' -f $ItQuarantineOu, $AdDn)
        redirusr.exe ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItNewUsersOU.Name, $AdDn)

        #endregion
        ###############################################################################

        ###############################################################################
        #region Delegation to ADMIN area (Tier 0)

        Write-Verbose -Message 'Delegate Admin Area...'

        # Computer objects within this ares MUST have read access, otherwise GPO will not apply

        # UM - Semi-Privileged User Management
        Set-AdAclDelegateUserAdmin -Group $SL_UM.SamAccountName -LDAPpath $ItAdminAccountsOuDn
        Set-AdAclDelegateGalAdmin  -Group $SL_UM.SamAccountName -LDAPpath $ItAdminAccountsOuDn





        # GM - Semi-Privileged Group Management
        Set-AdAclCreateDeleteGroup -Group $SL_GM.SamAccountName -LDAPPath $ItGroupsOuDn
        Set-AdAclChangeGroup       -Group $SL_GM.SamAccountName -LDAPPath $ItGroupsOuDn





        # PUM - Privileged User Management
        Set-AdAclDelegateUserAdmin -Group $SL_PUM.SamAccountName -LDAPpath $ItAdminAccountsOuDn
        Set-AdAclDelegateGalAdmin  -Group $SL_PUM.SamAccountName -LDAPpath $ItAdminAccountsOuDn





        # PGM - Privileged Group Management
        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_PGM.SamAccountName -LDAPPath $ItPrivGroupsOUDn
        Set-AdAclCreateDeleteGroup -Group $SL_PGM.SamAccountName -LDAPPath $ItRightsOuDn
        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_PGM.SamAccountName -LDAPPath $ItPrivGroupsOUDn
        Set-AdAclChangeGroup -Group $SL_PGM.SamAccountName -LDAPPath $ItRightsOuDn





        # PISM - Privileged Infrastructure Services Management
        # Create/Delete Computers
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM.SamAccountName -LDAPPath $ItInfraT0OuDn      -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM.SamAccountName -LDAPPath $ItInfraT1OuDn      -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM.SamAccountName -LDAPPath $ItInfraT2OuDn      -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PISM.SamAccountName -LDAPPath $ItInfraStagingOuDn -QuarantineDN $ItQuarantineOuDn





        # PAWM - Privileged Access Workstation Management
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM.SamAccountName -LDAPPath $ItPawT0OuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM.SamAccountName -LDAPPath $ItPawT1OuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM.SamAccountName -LDAPPath $ItPawT2OuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_PAWM.SamAccountName -LDAPPath $ItPawStagingOuDn -QuarantineDN $ItQuarantineOuDn






        # PSAM - Privileged Service Account Management - Create/Delete Managed Service Accounts & Standard user service accounts
        # Managed Service Accounts "Default Container"
        $parameters = @{
            Group    = $SL_PSAM.SamAccountName
            LDAPPath = ('CN=Managed Service Accounts,{0}' -f $AdDn)
        }
        Set-AdAclCreateDeleteGMSA       @parameters
        Set-AdAclCreateDeleteMSA        @parameters

        # TIER 0
        $parameters = @{
            Group    = $SL_PSAM.SamAccountName
            LDAPPath = $ItT0SAOuDn
        }
        Set-AdAclCreateDeleteGMSA       @parameters
        Set-AdAclCreateDeleteMSA        @parameters
        Set-AdAclCreateDeleteUser       @parameters
        Set-AdAclResetUserPassword      @parameters
        Set-AdAclChangeUserPassword     @parameters
        Set-AdAclUserGroupMembership    @parameters
        Set-AdAclUserAccountRestriction @parameters
        Set-AdAclUserLogonInfo          @parameters

        # TIER 1
        $parameters = @{
            Group    = $SL_PSAM.SamAccountName
            LDAPPath = $ItT1SAOuDn
        }
        Set-AdAclCreateDeleteGMSA       @parameters
        Set-AdAclCreateDeleteMSA        @parameters
        Set-AdAclCreateDeleteUser       @parameters
        Set-AdAclResetUserPassword      @parameters
        Set-AdAclChangeUserPassword     @parameters
        Set-AdAclUserGroupMembership    @parameters
        Set-AdAclUserAccountRestriction @parameters
        Set-AdAclUserLogonInfo          @parameters

        # TIER 2
       $parameters = @{
            Group    = $SL_PSAM.SamAccountName
            LDAPPath = $ItT0SAOuDn
        }
        Set-AdAclCreateDeleteGMSA       @parameters
        Set-AdAclCreateDeleteMSA        @parameters
        Set-AdAclCreateDeleteUser       @parameters
        Set-AdAclResetUserPassword      @parameters
        Set-AdAclChangeUserPassword     @parameters
        Set-AdAclUserGroupMembership    @parameters
        Set-AdAclUserAccountRestriction @parameters
        Set-AdAclUserLogonInfo          @parameters





        # GPO Admins
        # Create/Delete GPOs
        Set-AdAclCreateDeleteGPO -Group $SL_GpoAdminRight.SamAccountName
        # Link existing GPOs to OUs
        Set-AdAclLinkGPO -Group $SL_GpoAdminRight.SamAccountName
        # Change GPO options
        Set-AdAclGPoption -Group $SL_GpoAdminRight.SamAccountName





        # Delegate Directory Replication Rights
        Set-AdDirectoryReplication -Group $SL_DirReplRight.SamAccountName





        # Infrastructure Admins
        # Organizational Units at domain level
        Set-AdAclCreateDeleteOU      -Group $SL_InfraRight.SamAccountName -LDAPPath $AdDn
        # Organizational Units at Admin area
        Set-AdAclCreateDeleteOU      -Group $SL_InfraRight.SamAccountName -LDAPPath $ItAdminOuDn
        # Subnet Configuration Container
        # Create/Delete Subnet
        Set-AdAclCreateDeleteSubnet  -Group $SL_InfraRight.SamAccountName
        # Site Configuration Container
        # Create/Delete Sites
        Set-AdAclCreateDeleteSite    -Group $SL_InfraRight.SamAccountName
        # Site-Link Configuration Container
        # Create/Delete Site-Link
        Set-AdAclCreateDeleteSiteLink -Group $SL_InfraRight.SamAccountName





        # AD Admins
        # Delete computers from default container
        Set-DeleteOnlyComputer -Group $SL_AdRight.SamAccountName -LDAPPath $ItQuarantineOuDn
        # Subnet Configuration Container|
        # Change Subnet
        Set-AdAclChangeSubnet   -Group $SL_AdRight.SamAccountName
        # Site Configuration Container
        # Change Site
        Set-AdAclChangeSite     -Group $SL_AdRight.SamAccountName
        # Site-Link Configuration Container
        # Change SiteLink
        Set-AdAclChangeSiteLink -Group $SL_AdRight.SamAccountName

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create Baseline GPO

        Write-Verbose -Message 'Creating Baseline GPOs and configure them accordingly...'

        # Domain
        New-DelegateAdGpo -gpoDescription Baseline -gpoScope C -gpoLinkPath $AdDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription Baseline -gpoScope U -gpoLinkPath $AdDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # Domain Controllers
        New-DelegateAdGpo -gpoDescription DomainControllers-Baseline -gpoScope C -gpoLinkPath ('OU=Domain Controllers,{0}' -f $AdDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # Admin Area
        New-DelegateAdGpo -gpoDescription ItAdmin-Baseline -gpoScope C -gpoLinkPath $ItAdminOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ItAdmin-Baseline -gpoScope U -gpoLinkPath $ItAdminOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItAdminOU.Name) -gpoScope U -gpoLinkPath $ItAdminAccountsOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # Service Accounts
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItServiceAccountsOU.Name) -gpoScope U -gpoLinkPath $ItServiceAccountsOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT0OU.Name) -gpoScope U -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT0OU.Name, $ItServiceAccountsOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT1OU.Name) -gpoScope U -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT1OU.Name, $ItServiceAccountsOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItSAT2OU.Name) -gpoScope U -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItSAT2OU.Name, $ItServiceAccountsOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # PAWs
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawOU.Name)   -gpoScope C -gpoLinkPath $ItPawOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT0OU.Name, $ItPawOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT1OU.Name, $ItPawOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawT2OU.Name, $ItPawOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name, $ItPawOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # Infrastructure Servers
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraOU.Name) -gpoScope C -gpoLinkPath $ItInfraOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT0.Name, $ItInfraOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT1.Name, $ItInfraOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraT2.Name, $ItInfraOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name, $ItInfraOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # redirected containers (X-Computers & X-Users)
        New-DelegateAdGpo -gpoDescription ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItNewComputersOU.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItNewComputersOU.Name, $AdDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItNewUsersOU.Name)     -gpoScope U -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Admin.OUs.ItNewUsersOU.Name, $AdDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # Housekeeping
        New-DelegateAdGpo -gpoDescription ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItHousekeepingOU.Name) -gpoScope U -gpoLinkPath $ItHousekeepingOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-LOCKDOWN' -f $confXML.n.Admin.OUs.ItHousekeepingOU.Name) -gpoScope C -gpoLinkPath $ItHousekeepingOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)


        ###############################################################################
        # Import GPO from Archive

        #Import the Default Domain Policy
        Import-GPO -BackupId $confXML.n.Admin.GPOs.DefaultDomain.backupID -TargetName $confXML.n.Admin.GPOs.DefaultDomain.Name -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)

        # Configure Default Domain Controllers GPO
        Import-GPO -BackupId $confXML.n.Admin.GPOs.DefaultDomainControllers.backupID -TargetName $confXML.n.Admin.GPOs.DefaultDomainControllers.Name -path (Join-Path $DMscripts SecTmpl)

        # C-DomainControllers-Baseline
        Import-GPO -BackupId $confXML.n.Admin.GPOs.DCBaseline.backupID -TargetName ('{0}-{1}-Baseline' -f $confXML.n.Admin.GPOs.DCBaseline.Scope, $confXML.n.Admin.GPOs.DCBaseline.Name) -path (Join-Path $DMscripts SecTmpl)

        # C-Baseline
        Import-GPO -BackupId $confXML.n.Admin.GPOs.PCbaseline.backupID -TargetName 'C-Baseline' -path (Join-Path $DMscripts SecTmpl)

        # U-Baseline
        Import-GPO -BackupId $confXML.n.Admin.GPOs.Userbaseline.backupID -TargetName 'U-Baseline' -path (Join-Path $DMscripts SecTmpl)







        ###############################################################################
        # Configure GPO Restrictions based on Tier Model

        # Domain
        $Splat = @(
            'ALL SERVICES',
            'ANONYMOUS LOGON',
            'NT AUTHORITY\Local Account',
            'NT AUTHORITY\Local Account and member of administrators group'
            )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -DenyNetworkLogon $Splat

        $parameters = @(
            $SG_T0SA.SamAccountName,
            $SG_T1SA.SamAccountName,
            $SG_T2SA.SamAccountName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -DenyInteractiveLogon $parameters

        $parameters = @(
            $SG_T0SA.SamAccountName,
            $SG_T1SA.SamAccountName,
            $SG_T2SA.SamAccountName,
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -DenyRemoteInteractiveLogon $parameters

        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -DenyBatchLogon $parameters -DenyServiceLogon $parameters

        $parameters = @(
            'Network Service',
            'NT SERVICE\All Services'
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Baseline' -ServiceLogon $parameters

        # Domain Controllers
        $parameters = @(
            $SG_T1SA.SamAccountName,
            $SG_T2SA.SamAccountName,
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-DomainControllers-Baseline' -DenyBatchLogon $parameters -DenyServiceLogon $parameters

        Set-GpoPrivilegeRights -GpoToModify 'C-DomainControllers-Baseline' -BatchLogon $SG_T0SA.SamAccountName -ServiceLogon $SG_T0SA.SamAccountName, 'Network Service'

        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-DomainControllers-Baseline' -InteractiveLogon $parameters -RemoteInteractiveLogon $parameters

        $parameters = @(
            $SG_T1SA.SamAccountName,
            $SG_T2SA.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Account Operators',
            'Backup Operators',
            'Print Operators'
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-DomainControllers-Baseline' -DenyInteractiveLogon $parameters

        # Admin Area
        $parameters = @(
            $SG_T1SA.SamAccountName,
            $SG_T2SA.SamAccountName,
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-ItAdmin-Baseline' -DenyBatchLogon $parameters -DenyServiceLogon $parameters

        $parameters = @(
            $SG_T0SA.SamAccountName
            'Network Service',
            'NT SERVICE\All Services'
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-ItAdmin-Baseline' -BatchLogon $SG_T0SA.SamAccountName -ServiceLogon $parameters

        # Admin Area = HOUSEKEEPING
        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            'Domain Admins',
            'Administrators'
        )
        Set-GpoPrivilegeRights -GpoToModify 'C-Housekeeping-LOCKDOWN' -NetworkLogon $parameters -InteractiveLogon $parameters

        # Admin Area = Infrastructure

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0.Name) -InteractiveLogon $SL_PISM.SamAccountName, 'Domain Admins', Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0.Name) -RemoteInteractiveLogon $SL_PISM.SamAccountName
        $parameters = @(
            $SG_T0SA.SamAccountName
            'Network Service',
            'NT SERVICE\All Services'
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT0.Name) -BatchLogon $SG_T0SA.SamAccountName -ServiceLogon $parameters

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1.Name) -InteractiveLogon $SG_Tier1Admins.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1.Name) -RemoteInteractiveLogon $SG_Tier1Admins.SamAccountName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1.Name) -BatchLogon $SG_T1SA.SamAccountName -ServiceLogon $SG_T1SA.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2.Name) -InteractiveLogon $SG_Tier2Admins.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT1.Name) -RemoteInteractiveLogon $SG_Tier2Admins.SamAccountName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraT2.Name) -BatchLogon $SG_T2SA.SamAccountName -ServiceLogon $SG_T2SA.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name) -InteractiveLogon $SL_PISM.SamAccountName, 'Domain Admins', Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItInfraStagingOU.Name) -RemoteInteractiveLogon $SL_PISM.SamAccountName

        # Admin Area = PAWs

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name) -InteractiveLogon $SL_PAWM.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawStagingOU.Name) -RemoteInteractiveLogon $SL_PAWM.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name) -InteractiveLogon $SL_PAWM.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name) -RemoteInteractiveLogon $SL_PAWM.SamAccountName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT0OU.Name) -BatchLogon $SG_T0SA.SamAccountName -ServiceLogon $SG_T0SA.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name) -InteractiveLogon $SG_Tier1Admins.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name) -RemoteInteractiveLogon $SG_Tier1Admins.SamAccountName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT1OU.Name) -BatchLogon $SG_T1SA.SamAccountName -ServiceLogon $SG_T1SA.SamAccountName

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name) -InteractiveLogon $SG_Tier2Admins.SamAccountName, Administrators
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name) -RemoteInteractiveLogon $SG_Tier2Admins.SamAccountName
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $confXML.n.Admin.OUs.ItPawT2OU.Name) -BatchLogon $SG_T2SA.SamAccountName -ServiceLogon $SG_T2SA.SamAccountName


        #endregion
        ###############################################################################

        ###############################################################################
        #region SERVERS OU (area)

        Write-Verbose -Message 'Creating Servers Area...'

        ###############################################################################
        # Create Servers and Sub OUs
        New-DelegateAdOU -ouName $ServersOu -ouPath $AdDn -ouDescription $confXML.n.Servers.OUs.ServersOU.Description

        # Create Sub-OUs for Servers
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.SqlOU.Name           -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.SqlOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.WebOU.Name           -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.WebOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.FileOU.Name          -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.FileOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.ApplicationOU.Name   -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.ApplicationOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.HypervOU.Name        -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.HypervOU.Description
        New-DelegateAdOU -ouName $confXML.n.Servers.OUs.RemoteDesktopOU.Name -ouPath $ServersOuDn -ouDescription $confXML.n.Servers.OUs.RemoteDesktopOU.Description





        # Create basic GPO for Servers
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $ServersOu) -gpoScope C -gpoLinkPath $ServersOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # Create basic GPOs for different types under Servers
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.ApplicationOU.Name)   -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.ApplicationOU.Name, $ServersOuDn)   -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.FileOU.Name)          -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.FileOU.Name, $ServersOuDn)          -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.HypervOU.Name)        -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.HypervOU.Name, $ServersOuDn)        -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.RemoteDesktopOU.Name) -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.RemoteDesktopOU.Name, $ServersOuDn) -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.SqlOU.Name)           -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.SqlOU.Name, $ServersOuDn)           -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $confXML.n.Servers.OUs.WebOU.Name)           -gpoScope C -gpoLinkPath ('OU={0},{1}' -f $confXML.n.Servers.OUs.WebOU.Name, $ServersOuDn)           -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # Import the security templates to the corresponding GPOs under Servers

        # Configure Default Servers Baseline
        Import-GPO -BackupId $confXML.n.Servers.GPOs.Servers.backupID       -TargetName ('C-{0}-Baseline' -f $ServersOu)       -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)
        # Configure File Server GPO
        Import-GPO -BackupId $confXML.n.Servers.GPOs.FileSrv.backupID       -TargetName ('C-{0}-Baseline' -f $confXML.n.Servers.OUs.FileOU.Name)          -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)
        # Configure Hyper-V GPO
        Import-GPO -BackupId $confXML.n.Servers.GPOs.HyperV.backupID        -TargetName ('C-{0}-Baseline' -f $confXML.n.Servers.OUs.HypervOU.Name)        -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)
        # Configure RemoteDesktop GPO
        Import-GPO -BackupId $confXML.n.Servers.GPOs.RemoteDesktop.backupID -TargetName ('C-{0}-Baseline' -f $confXML.n.Servers.OUs.RemoteDesktopOU.Name) -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)
        # Configure Web GPO
        Import-GPO -BackupId $confXML.n.Servers.GPOs.WebSrv.backupID        -TargetName ('C-{0}-Baseline' -f $confXML.n.Servers.OUs.WebOU.Name)           -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)

        # Tier Restrictions
        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier2Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Guests',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $ServersOu) -DenyInteractiveLogon $parameters -DenyRemoteInteractiveLogon $parameters

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $ServersOu) -BatchLogon $SG_T1SA.SamAccountName -ServiceLogon $SG_T1SA.SamAccountName -InteractiveLogon $SG_Tier1Admins.SamAccountName -RemoteInteractiveLogon $SG_Tier0Admins.SamAccountName


        ###############################################################################
        #region Delegation to SL_SvrAdmRight and SL_SvrOpsRight groups to SERVERS area


        # Get the DN of 1st level OU underneath SERVERS area
        $AllSubOu = Get-AdOrganizationalUnit -Filter * -SearchBase $ServersOuDn -SearchScope OneLevel | Select-Object -ExpandProperty DistinguishedName

        # Iterate through each sub OU and invoke delegation
        Foreach ($Item in $AllSubOu) {
            ###############################################################################
            # Delegation to SL_SvrAdmRight group to SERVERS area

            Set-AdAclDelegateComputerAdmin -Group $SL_SvrAdmRight.SamAccountName -LDAPPath $Item -QuarantineDN $ItQuarantineOuDn

            ###############################################################################
            # Delegation to SL_SvrOpsRight group on SERVERS area

            # Change Public Info
            Set-AdAclComputerPublicInfo   -Group $SL_SvrOpsRight.SamAccountName -LDAPPath $Item

            # Change Personal Info
            Set-AdAclComputerPersonalInfo -Group $SL_SvrOpsRight.SamAccountName -LDAPPath $Item

        }#end foreach

        # Create/Delete OUs within Servers
        Set-AdAclCreateDeleteOU -Group $SL_InfraRight.SamAccountName -LDAPPath $ServersOuDn

        # Change OUs within Servers
        Set-AdAclChangeOU -Group $SL_AdRight.SamAccountName -LDAPPath $ServersOuDn

        #endregion
        ###############################################################################

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create Sites OUs (Area)

        Write-Verbose -Message 'Creating Sites Area...'

        New-DelegateAdOU -ouName $SitesOu -ouPath $AdDn -ouDescription $confXML.n.Sites.OUs.SitesOU.Description

        # Create basic GPO for Users and Computers
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $SitesOu) -gpoScope C -gpoLinkPath $SitesOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $SitesOu) -gpoScope U -gpoLinkPath $SitesOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        # Tier Restrictions
        $parameters = @(
            $SG_Tier0Admins.SamAccountName,
            $SG_Tier1Admins.SamAccountName,
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Guests',
            $AdminName,
            $newAdminName
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $SitesOu) -DenyInteractiveLogon $parameters -DenyRemoteInteractiveLogon $parameters

        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-Baseline' -f $SitesOu) -BatchLogon $SG_T2SA.SamAccountName -ServiceLogon $SG_T2SA.SamAccountName -InteractiveLogon $SG_Tier2Admins.SamAccountName -RemoteInteractiveLogon $SG_Tier2Admins.SamAccountName

        # Create Global OU within SITES area
        New-DelegateAdOU -ouName $SitesGlobalOu           -ouPath $SitesOuDn       -ouDescription $confXML.n.Sites.OUs.OuSiteGlobal.Description
        New-DelegateAdOU -ouName $SitesGlobalGroupOu      -ouPath $SitesGlobalOuDn -ouDescription $confXML.n.Sites.OUs.OuSiteGlobalGroups.Description
        New-DelegateAdOU -ouName $SitesGlobalAppAccUserOu -ouPath $SitesGlobalOuDn -ouDescription $confXML.n.Sites.OUs.OuSiteGlobalAppAccessUsers.Description


        # Sites OU
        # Create/Delete OUs within Sites
        Set-AdAclCreateDeleteOU  -Group $SL_InfraRight.SamAccountName -LDAPPath $SitesOuDn

        # Sites OU
        # Change OUs
        Set-AdAclChangeOU        -Group $SL_AdRight.SamAccountName -LDAPPath $SitesOuDn


        Write-Verbose -Message 'START APPLICATION ACCESS USER Global Delegation'
        ###############################################################################
        #region USER Site Administrator Delegation
        $parameters = @{
            Group    = $SL_GlobalAppAccUserRight.SamAccountName
            LDAPPath = $SitesGlobalAppAccUserOuDn
        }
        Set-AdAclDelegateUserAdmin @parameters

        #### GAL
        Set-AdAclDelegateGalAdmin @parameters

        Add-AdGroupNesting -Identity $SL_GlobalAppAccUserRight.SamAccountName -Members $SG_GlobalUserAdmins.SamAccountName

        #endregion USER Site Delegation
        ###############################################################################

        Write-Verbose -Message 'START GROUP Global Delegation'
        ###############################################################################
        #region GROUP Site Admin Delegation

        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_GlobalGroupRight.SamAccountName -LDAPPath $SitesGlobalGroupOuDn

        # Nest groups
        Add-AdGroupNesting -Identity $SL_GlobalGroupRight.SamAccountName -Members $SG_GlobalGroupAdmins.SamAccountName

        #### GAL

        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_GlobalGroupRight.SamAccountName -LDAPPath $SitesGlobalGroupOuDn

        #endregion GROUP Site Delegation
        ###############################################################################

        Write-Verbose 'Sites area was delegated correctly to the corresponding groups.'

        #endregion
        ###############################################################################


        ###############################################################################
        # Check if Exchange objects have to be created. Proccess if TRUE
        if($CreateExchange) {

            # Get the Config.xml file
            $param = @{
                ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve
                verbose = $true
            }

            New-ExchangeObjects @param
        }

        ###############################################################################
        # Check if DFS objects have to be created. Proccess if TRUE
        if($CreateDfs) {
            # Get the Config.xml file
            $param = @{
                ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve
                verbose = $true
            }

            New-DfsObjects @param
        }

        ###############################################################################
        # Check if Certificate Authority (PKI) objects have to be created. Proccess if TRUE
        if($CreateCa) {
            New-CaObjects -ConfigXMLFile $ConfXML
        }

        ###############################################################################
        # Check if Advanced Group Policy Management (AGPM) objects have to be created. Proccess if TRUE
        if($CreateAGPM) {
            New-AGPMObjects -ConfigXMLFile $ConfXML
        }

        ###############################################################################
        # Check if MS Local Administrator Password Service (LAPS) is to be used. Proccess if TRUE
        if($CreateLAPS) {
            #To-Do
            #New-LAPSobjects -PawOuDn $ItPawOuDn -ServersOuDn $ServersOuDn -SitesOuDn $SitesOuDn
            New-LAPSobjects -ConfigXMLFile $ConfXML
        }

        ###############################################################################
        # Check if DHCP is to be used. Proccess if TRUE
        if($CreateDHCP) {
            #
            New-DHCPobjects -ConfigXMLFile $ConfXML
        }

    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating central OU."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-CentralItOU
#EndRegion - New-CentralItOU.ps1
#Region - New-DelegateAdGpo.ps1
function New-DelegateAdGpo
{
    <#
        .Synopsis
            Creates and Links new GPO

        .DESCRIPTION
            Create new custom delegated GPO, Delegate rights to an existing group and links it to the given OU

        .EXAMPLE
            New-DelegateAdGpo MyNewGPO C "OU=Servers,OU=eguibarit,OU=local" "SL_GpoRight"
        .EXAMPLE
            New-DelegateAdGpo -gpoDescription MyNewGPO -gpoScope C -gpoLinkPath "OU=Servers,OU=eguibarit,OU=local" -GpoAdmin "SL_GpoRight"

        .PARAMETER gpoDescription
            [STRING] Description of the GPO. Used to build the name. Only Characters a-z A-Z
        .PARAMETER gpoScope
            [STRING] Scope of the GPO. U for Users and C for Computers DEFAULT is U. The non-used part of the GPO will get disabled
        .PARAMETER gpoLinkPath
            [STRING] Where to link the newly created GPO
        .PARAMETER GpoAdmin
            [STRING] Domain Local Group with GPO Rights to be assigned

            No Config.xml needed for this function.

        .INPUTS
            None

        .OUTPUTS
            Microsoft.GroupPolicy.Gpo

        .LINKS
            http://www.eguibarit.com

        .NOTES
            Version:         1.2
            DateModified:    22/Jan/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([Microsoft.GroupPolicy.Gpo])]
    Param (
        # Param1 GPO description, used to generate name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Description of the GPO. Used to build the name.',
        Position = 0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $gpoDescription,

        # Param2 GPO scope. U = Users, C = Computers
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Scope of the GPO. U for Users and C for Computers DEFAULT is U. The non-used part of the GPO will get disabled',
        Position = 1)]
        [ValidateSet('U', 'C', ignorecase = $false)]
        [string]
        $gpoScope,

        # Param3 GPO Link to OU
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Where to link the newly created GPO',
        Position = 2)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $gpoLinkPath,

        # Param4 Domain Local Group with GPO Rights to be assigned
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Domain Local Group with GPO Rights to be assigned',
        Position = 3)]
        [string]
        $GpoAdmin

    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Import-Module -name ActiveDirectory -Verbose:$false
        Import-Module -name GroupPolicy     -Verbose:$false

        try {
            # Active Directory Domain Distinguished Name
            If(-not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }
        }
        catch { throw }


        $gpoAlreadyExist = $null
        $gpoName = '{0}-{1}' -f $PSBoundParameters['gpoScope'], $PSBoundParameters['gpoDescription']
        #$adGroupName = Get-ADGroup -Identity $GpoAdmin
        $dcServer = (Get-ADDomaincontroller).HostName
    }
    Process {
        # Check if the GPO already exist
        $gpoAlreadyExist = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        # Clean the error if object does not exist. No need to log.
        $error.clear()

        if (-not $gpoAlreadyExist) {
          Write-Verbose -Message ('Policy: Create policy {0}' -f $gpoName)
          $parameters = @{
            Name        = $gpoName
            Comment     = $gpoName
            Server      = $dcServer
            ErrorAction = 'SilentlyContinue'
            Verbose     = $true
          }
          $CurrentNewGPO = New-GPO @parameters


          Write-Verbose -Message '1 second pause to give AD a chance to catch up'
          Start-Sleep -Seconds 1

          #Write-Host "Remove Authenticated Users from GPO Security Filtering"
          #Set-GPPermissions -Name $gpoName -PermissionLevel None -TargetName "Authenticated Users" -TargetType Group -Server $dcServer

          # Give Rights to SL_AdRights
          Write-Verbose -Message ('Add Administrators to {0}' -f $gpoName)
          $parameters = @{
            GUID            = $CurrentNewGPO.Id
            PermissionLevel = 'GpoEditDeleteModifySecurity'
            TargetName      = $GpoAdmin
            TargetType      = 'group'
            Server          = $dcServer
            ErrorAction     = 'SilentlyContinue'
            Verbose     = $true
          }
          Set-GPPermissions @parameters


          #Write-Host "Add Editors to GPO"
          #Set-GPPermissions -Name $gpoName -PermissionLevel GpoEdit -TargetName $gpoEditors -TargetType group -Server $dcServer

          #Write-Host "Add AD-Group to Security Filtering on GPO"
          #Set-GPPermissions -Name $gpoName -PermissionLevel GpoApply -TargetName "$($adGroupName)" -TargetType Group -Server $dcServer
          If ($gpoScope -eq 'C') {
            Write-Verbose -Message 'Disable Policy User Settings'
            $CurrentNewGPO.GpoStatus = 'UserSettingsDisabled'
          } else {
            Write-Verbose -Message 'Disable Policy Computer Settings'
            $CurrentNewGPO.GpoStatus = 'ComputerSettingsDisabled'
          }

          Write-Verbose -Message 'Add GPO-link to corresponding OU'
          $parameters = @{
            GUID        = $CurrentNewGPO.Id
            Target      = $PSBoundParameters['gpoLinkPath']
            LinkEnabled = 'Yes'
            Server      = $dcServer
          }
          New-GPLink @parameters

          # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

          # Adding settings
          #Write-Host "Setting Screen saver timeout to 15 minutes"
          #Set-GPRegistryValue -Name $gpoName -key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName ScreenSaveTimeOut -Type String -value 900

          #Write-Host "Enable Screen Saver"
          #Set-GPRegistryValue -Name $gpoName -key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName ScreenSaveActive -Type String -value 1

          #Write-Host "Disable Desktop Cleanup Wizzard"
          #Set-GPRegistryValue -Name $gpoName -key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName NoDesktopCleanupWizard -Type Dword -value 1

          #Write-Host "Remove MyMusic from Start Menu"
          #Set-GPRegistryValue -Name $gpoName -key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName NoStartMenuMymusic -Type Dword -value 1
        } else {
          Write-Verbose -Message ('{0} Policy already exist. Skipping.' -f $gpoName)
        }
    }
    End {
        Write-Verbose -Message ('Function New-DelegateAdGpo Finished creating {0} GPO' -f $gpoName)
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

        return $CurrentNewGPO
    }
}
Export-ModuleMember -Function New-DelegateAdGpo
#EndRegion - New-DelegateAdGpo.ps1
#Region - New-DelegatedAdOU.ps1
function New-DelegateAdOU
{
    <#
        .Synopsis
            Create New custom delegated AD OU
        .DESCRIPTION
            Create New custom delegated AD OU, and remove
            some groups as Account Operators and Print Operators
        .EXAMPLE
            New-DelegateAdOU OuName OuPath OuDescription ...
        .INPUTS
            Param1  OuName:............ [STRING] Name of the OU
            Param2  OuPath:............ [STRING] LDAP path where this ou will be created
            Param3  OuDescrition:...... [STRING] Full description of the OU
            Param4  OuCity:............ [STRING]
            Param5  OuCountry:......... [STRING]
            Param6  OuStreetAddress:... [STRING]
            Param7  OuState:........... [STRING]
            Param8  OuZipCode:......... [STRING]
            Param9  strOuDisplayName:.. [STRING]
            Param10 RemoveAuthenticatedUsers:.. [Switch] Remove Authenticated Users
            Param11 CleanACL:.......... [Switch] Remove Authenticated Users

            No Config.xml needed for this function.

        .NOTES
            Version:         1.2
            DateModified:    01/Feb/2017
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]

    # https://docs.microsoft.com/en-us/dotnet/api/microsoft.activedirectory.management?view=activedirectory-management-10.0
    [OutputType([Microsoft.ActiveDirectory.Management.ADOrganizationalUnit])]

    Param (
        # Param1 Site Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the OU',
            Position = 0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(2,50)]
        [string]
        $ouName,

        # Param2 OU DistinguishedName (Path)
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'LDAP path where this ou will be created',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ouPath,

        # Param3 OU Description
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            Position = 2)]
        [string]
        $ouDescription,

        # Param4 OU City
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            Position = 3)]
        [string]
        $ouCity,

        # Param5 OU Country
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            Position = 4)]
        [string]
        $ouCountry,

        # Param6 OU Street Address
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            Position = 5)]
        [string]
        $ouStreetAddress,

        # Param7 OU State
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            Position = 6)]
        [string]
        $ouState,

        # Param8 OU Postal Code
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            Position = 7)]
        [string]
        $ouZIPCode,

        # Param9 OU Display Name
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 8)]
        [string]
        $strOuDisplayName,

        #PARAM10 Remove Authenticated Users
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Remove Authenticated Users. CAUTION! This might affect applying GPO to objects.',
        Position = 9)]
        [switch]
        $RemoveAuthenticatedUsers,

        #PARAM11 Remove Specific Non-Inherited ACE and enable inheritance
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = ' Remove Specific Non-Inherited ACE and enable inheritance.',
        Position = 10)]
        [switch]
        $CleanACL

  )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Import-Module -name EguibarIT.Delegation -Verbose:$false

        #------------------------------------------------------------------------------
        # Define the variables

        try {
          # Active Directory Domain Distinguished Name
          If(-not (Test-Path -Path variable:AdDn)) {
            New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
          }

          # Sites OU Distinguished Name
          $ouNameDN = 'OU={0},{1}' -f $PSBoundParameters['ouName'], $PSBoundParameters['ouPath']
        }
        Catch { throw }

        #$Return = $null

        # END variables
        #------------------------------------------------------------------------------
    }

      Process {
        #
        if (-not $strOuDisplayName) {
          $strOuDisplayName = $PSBoundParameters['ouName']
        }

        try {
          # Try to get Ou
          $OUexists = Get-AdOrganizationalUnit -Filter { distinguishedName -eq $ouNameDN } -SearchBase $AdDn

          # Check if OU exists
          If($OUexists) {
            # OU it does exists
            Write-Warning -Message ('Organizational Unit {0} already exists.' -f $ouNameDN)
          } else {
            Write-Verbose -Message ('Creating the {0} Organizational Unit' -f $PSBoundParameters['ouName'])
            # Create OU
            $parameters = @{
              Name                            = $PSBoundParameters['ouName']
              Path                            = $PSBoundParameters['ouPath']
              City                            = $PSBoundParameters['ouCity']
              Country                         = $PSBoundParameters['ouCountry']
              Description                     = $PSBoundParameters['ouDescription']
              DisplayName                     = $PSBoundParameters['strOuDisplayName']
              PostalCode                      = $PSBoundParameters['ouZIPCode']
              ProtectedFromAccidentalDeletion = $true
              StreetAddress                   = $PSBoundParameters['ouStreetAddress']
              State                           = $PSBoundParameters['ouState']
            }
            $OUexists = New-ADOrganizationalUnit @parameters
          }
        } catch { throw }

        # Remove "Account Operators" and "Print Operators" built-in groups from OU. Any unknown/UnResolvable SID will be removed.
        Start-AdCleanOU -LDAPPath $ouNameDN -RemoveUnknownSIDs

        if($PSBoundParameters['CleanACL']) {
            Remove-SpecificACLandEnableInheritance -LDAPpath $ouNameDN
        }
      }

    End {

        Write-Verbose -Message ('Function New-DelegateAdOU finished {0}' -f $ouNameDN)
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
        return $OUexists
    }
}
Export-ModuleMember -Function New-DelegatedAdOU
#EndRegion - New-DelegatedAdOU.ps1
#Region - New-DelegateSiteOU.ps1
function New-DelegateSiteOU
{
    <#
        .Synopsis
            Create New delegated Site OU
        .DESCRIPTION
            Create the new OU representing the SITE root on the pre-defined
            container (Sites, Country, etc.), then adding additional OU structure
            below to host different object types, create the corresponding managing groups and
            GPOs and finally delegating right to those objects.
        .EXAMPLE
            New-DelegateSiteOU -ouName "Mexico" -ouDescription "Mexico Site root" -ConfigXMLFile "C:\PsScripts\Config.xml"
        .INPUTS
            Param1 ouName:...............[String] Name of the OU corresponding to the SITE root
            Param2 ouDescription:........[String] Description of the OU
            Param3 ouCity:...............[String]
            Param4 ouCountry:............[String]
            Param5 ouStreetAddress:......[String]
            Param6 ouState:..............[String]
            Param7 ouZIPCode:............[String]
            Param8 CreateExchange:.......[switch] If present It will create all needed Exchange objects and containers.
            Param9 CreateLAPS............[switch] If present It will create all needed LAPS objects, containers and delegations.
            Param10 ConfigXMLFile:.......[String] Full path to the configuration.xml file

            This function relies on Config.xml file.

        .NOTES
            Version:         1.2
            DateModified:    11/Feb/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([String])]
    Param
    (
        # Param1 Site Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the OU corresponding to the SITE root',
        Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ouName,

        # Param2 OU Description
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Description of the OU',
        Position = 1)]
        [string]
        $ouDescription,

        # Param3 OU City
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 2)]
        [string]
        $ouCity,

        # Param4 OU Country
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 3)]
        [ValidatePattern('[a-zA-Z]*')]
        [ValidateLength(2,2)]
        [string]
        $ouCountry,

        # Param5 OU Street Address
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 4)]
        [string]
        $ouStreetAddress,

        # Param6 OU State
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 5)]
        [string]
        $ouState,

        # Param7 OU Postal Code
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
        Position = 6)]
        [string]
        $ouZIPCode,

        # Param8 Create Exchange Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects and containers.',
        Position = 7)]
        [switch]
        $CreateExchange,

        # Param9 Create LAPS Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed LAPS objects, containers and delegations.',
        Position = 8)]
        [switch]
        $CreateLAPS,

        # PARAM10 full path to the configuration.xml file
        [Parameter(Mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage='Full path to the configuration.xml file',
            Position=9)]
        [string]
        $ConfigXMLFile

    )

    Begin
    {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Import-Module -name ServerManager        -Verbose:$false
        Import-Module -name ActiveDirectory      -Verbose:$false
        Import-Module -name GroupPolicy          -Verbose:$false
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        #------------------------------------------------------------------------------
        # Define the variables

        try
        {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn))
            {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML))
            {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile'])
                {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        Catch { throw }


        ####################
        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0

        ####################
        # Users

        ####################
        # Groups
        $SG_AllSiteAdmins = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllSiteAdmins.Name)
        $SG_AllGALAdmins  = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllGALAdmins.Name)


        ####################
        # OU DistinguishedNames

        # Admin Area

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $AdDn

        # It Admin Groups OU
        $ItGroupsOu = $confXML.n.Admin.OUs.ItAdminGroupsOU.name
        # It Admin Groups OU Distinguished Name
        $ItGroupsOuDn = 'OU={0},{1}' -f $ItGroupsOu, $ItAdminOuDn

        # It Privileged Groups OU
        #$ItPGOu = $confXML.n.Admin.OUs.ItPrivGroupsOU.name
        # It Privileged Groups OU Distinguished Name
        #$ItPGOuDn = 'OU={0},{1}' -f $ItPGOu, $ItAdminOuDn

        # It Admin Rights OU
        $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn





        # Sites Area

        # Sites OU
        $SitesOu = $confXML.n.Sites.OUs.SitesOU.name
        # Sites OU Distinguished Name
        $SitesOuDn = 'OU={0},{1}' -f $SitesOu, $AdDn

            # Sites GLOBAL OU
            #$SitesGlobalOu = $confXML.n.Sites.OUs.OuSiteGlobal.name
            # Sites GLOBAL OU Distinguished Name
            #$SitesGlobalOuDn = 'OU={0},{1}' -f $SitesGlobalOu, $SitesOuDn

                # Sites GLOBAL GROUPS OU
                #$SitesGlobalGroupOu = $confXML.n.Sites.OUs.OuSiteGlobalGroups.name
                # Sites GLOBAL GROUPS OU Distinguished Name
                #$SitesGlobalGroupOuDn = 'OU={0},{1}' -f $SitesGlobalGroupOu, $SitesGlobalOuDn

                # Sites GLOBAL APPACCUSERS OU
                #$SitesGlobalAppAccUserOu = $confXML.n.Sites.OUs.OuSiteGlobalAppAccessUsers.name
                # Sites GLOBAL APPACCUSERS OU Distinguished Name
                #$SitesGlobalAppAccUserOuDn = 'OU={0},{1}' -f $SitesGlobalAppAccUserOu, $SitesGlobalOuDn





        # Quarantine OU
        $ItQuarantineOu = $confXML.n.Admin.OUs.ItNewComputersOU.name
        # Quarantine OU Distinguished Name
        $ItQuarantineOuDn = 'OU={0},{1}' -f $ItQuarantineOu, $AdDn



        # Current OU DistinguishedName
        $ouNameDN = 'OU={0},{1}' -f $ouName, $SitesOuDn


        # parameters variable for splatting the CMDlets
        $splat = $null


        # END variables
        #------------------------------------------------------------------------------
    }
    Process
    {
        # Checking if the OU exist is done prior calling this function.

        Write-Verbose -Message ('Create Site root OU {0}' -f $PSBoundParameters['ouName'])

        # Check if the Site OU exists
        If(-not(Get-AdOrganizationalUnit -Filter { distinguishedName -eq $ouNameDN } -SearchBase $AdDn))
        {
            $splat = @{
                ouName           = $PSBoundParameters['ouName']
                ouPath           = $SitesOuDn
                ouDescription    = $PSBoundParameters['ouDescription']
                ouCity           = $PSBoundParameters['ouCity']
                ouCountry        = $PSBoundParameters['ouCountry']
                ouStreetAddress  = $PSBoundParameters['ouStreetAddress']
                ouState          = $PSBoundParameters['ouState']
                ouZIPCode        = $PSBoundParameters['ouZIPCode']
                strOuDisplayName = $PSBoundParameters['ouName']
            }
            # If does not exist, create it.
            New-DelegateAdOU @splat
        }
        else
        {
            Write-Warning -Message ('Site {0} already exist. Continue to cleanup.' -f $PSBoundParameters['ouName'])
            # If OU already exist, clean it.
            Start-AdCleanOU -LDAPPath $ouNameDN  -RemoveUnknownSIDs
        }

        Write-Verbose -Message 'Create SITE Sub-OU'
        ###############################################################################
        #region Create SITE Sub-OU

        # --- USER CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteUser.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteUser.description
        }
        New-DelegateAdOU @splat

        # --- COMPUTER CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteComputer.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.description
        }
        New-DelegateAdOU @splat
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteLaptop.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.description
        }
        New-DelegateAdOU @splat

        # --- GROUP CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteGroup.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteGroup.description
        }
        New-DelegateAdOU @splat

        # --- VOLUME CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSiteShares.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteShares.description
        }
        New-DelegateAdOU @splat

        # --- PRINTQUEUE CLASS ---
        $splat = @{
            ouName        = $confXML.n.Sites.OUs.OuSitePrintQueue.Name
            ouPath        = $ouNameDN
            ouDescription = '{0} {1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSitePrintQueue.description
        }
        New-DelegateAdOU @splat

        #endregion END
        ###############################################################################



        Write-Verbose -Message ('Create requiered groups for the site {0}' -f $PSBoundParameters['ouName'])

        ###############################################################################
        #region Create the required Right's Local Domain groups

        # Iterate through all Site-LocalGroups child nodes
        Foreach($node in $confXML.n.Sites.LG.ChildNodes)
        {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']))
            $parameters = @{
                Name                          = '{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = '{0} {1}' -f $PSBoundParameters['ouName'], $node.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = '{0} {1}' -f $PSBoundParameters['ouName'], $node.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }

            New-Variable -Name "$('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $node.Name)" -Value (New-AdDelegatedGroup @parameters) -Force
        }

        #endregion
        ###############################################################################

        ###############################################################################
        #region Create the required Admin Global groups


        # Iterate through all Site-GlobalGroups child nodes
        Foreach($node in $confXML.n.Sites.GG.ChildNodes)
        {
            Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']))
            $parameters = @{
                Name                          = '{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = '{0} {1}' -f $PSBoundParameters['ouName'], $node.DisplayName
                Path                          = $ItGroupsOuDn
                Description                   = '{0} {1}' -f $PSBoundParameters['ouName'], $node.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            New-Variable -Name "$('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $node.Name)" -Value (New-AdDelegatedGroup @parameters) -Force
        }

        #endregion
        ###############################################################################




        Write-Verbose -Message 'Add group membership & nesting'
        ###############################################################################
        #region Add group membership & nesting

        #region NESTING Global groups into Domain Local Groups -> order Less privileged to more privileged

        Add-AdGroupNesting -Identity $SL_PwdRight -Members $SG_PwdAdmins, $SG_GALAdmins, $SG_SiteAdmins

        if($PSBoundParameters['CreateSrvContainer'])
        {
            Add-AdGroupNesting -Identity $SL_LocalServerRight -Members $SG_LocalServerAdmins
        }

        Add-AdGroupNesting -Identity $SL_PcRight -Members $SG_ComputerAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_GroupRight -Members $SG_GroupAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_CreateUserRight -Members $SG_UserAdmins, $SG_SiteAdmins

        Add-AdGroupNesting -Identity $SL_GALRight -Members $SG_GALAdmins, $SG_SiteAdmins

        <# VIOLATES Tiering model  Add-AdGroupNesting -Identity $SL_LocalServerRight -Members $SG_SiteAdmins #>

        Add-AdGroupNesting -Identity $SL_SiteRight -Members $SG_SiteAdmins

        #endregion

        #region NESTING Global groups into Global Groups -> order Less privileged to more privileged

        Add-AdGroupNesting -Identity $SG_PwdAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.ServiceDesk.Name)

        if($PSBoundParameters['CreateSrvContainer'])
        {
            Add-AdGroupNesting -Identity $SG_LocalServerAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name)
        }

        Add-AdGroupNesting -Identity $SG_ComputerAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalPcAdmins.Name)

        Add-AdGroupNesting -Identity $SG_GroupAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalGroupAdmins.Name)

        Add-AdGroupNesting -Identity $SG_UserAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalUserAdmins.Name)

        Add-AdGroupNesting -Identity $SG_GALAdmins -Members $SG_AllGALAdmins

        Add-AdGroupNesting -Identity $SG_SiteAdmins -Members $SG_AllSiteAdmins

        #endregion

        #endregion
        ###############################################################################

        <#Write-Verbose -Message 'Nesting to Built-In groups'
        ###############################################################################
        #region Nest Groups - Delegate Rights through Builtin groups
        # http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx

        Add-AdGroupNesting -Identity 'Remote Desktop Users' -Members $SG_SiteAdmins

        #endregion
        ###############################################################################
        #>

        Write-Verbose -Message 'Create basic GPO'
        ###############################################################################
        #region Create basic GPO

        # Create Desktop Baseline
        $splat = @{
            gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteComputer.Name
            gpoScope       = 'C'
            gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.Name, $ouNameDN
            GpoAdmin       = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        }
        New-DelegateAdGpo @splat

        # Create Laptop-Baseline Baseline
        $splat = @{
            gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLaptop.Name
            gpoScope       = 'C'
            gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Name, $ouNameDN
            GpoAdmin       = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        }
        New-DelegateAdGpo @splat

        # Create Users Baseline
        $splat = @{
            gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteUser.Name
            gpoScope       = 'U'
            gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteUser.Name, $ouNameDN
            GpoAdmin       = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        }
        New-DelegateAdGpo @splat

        #endregion Create basic GPO
        ###############################################################################

        Write-Verbose -Message 'Configure GPO'
        ###############################################################################
        #region Configure GPO

        # Configure Users
        $splat = @{
            BackupId   = $confXML.n.Sites.OUs.OuSiteUser.backupID
            TargetName = 'U-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteUser.Name
            path       = Join-Path -Path $DMscripts -ChildPath SecTmpl
        }
        Import-GPO @splat

        if($PSBoundParameters['CreateSrvContainer'])
        {
            # Configure File-Print Server Baseline GPO
            $splat = @{
                BackupId   = $confXML.n.Sites.OUs.OuSiteFilePrint.backupID
                TargetName = 'C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteFilePrint.Name
                path       = Join-Path -Path $DMscripts -ChildPath SecTmpl
            }
            Import-GPO @splat

            # File-Print Baseline Tiering Restrictions
            $splat = @(
                'Schema Admins',
                'Enterprise Admins',
                'Domain Admins',
                $confXML.n.Admin.users.Admin.name,
                $confXML.n.Admin.users.newAdmin.name,
                'Guests'
            )
            Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteFilePrint.Name) -DenyNetworkLogon $splat

            $splat = @(
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
                'Guests'
            )
            Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteFilePrint.Name) -DenyInteractiveLogon $splat -DenyRemoteInteractiveLogon $splat

            $splat = @(
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
                'Schema Admins',
                'Enterprise Admins',
                'Domain Admins',
                'Administrators',
                'Account Operators',
                'Backup Operators',
                'Print Operators',
                'Server Operators',
                'Guests',
                $confXML.n.Admin.users.Admin.name,
                $confXML.n.Admin.users.newAdmin.name
            )
            Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteFilePrint.Name) -DenyBatchLogon $splat -DenyServiceLogon $splat

            $splat = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name)
            Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteFilePrint.Name) -BatchLogon $splat -ServiceLogon $splat




            # Configure Local Servers Baseline
            $splat = @{
                BackupId   = $confXML.n.Sites.OUs.OuSiteLocalServer.backupID
                TargetName = 'C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLocalServer.Name
                path       = Join-Path -Path $DMscripts -ChildPath SecTmpl
            }
            Import-GPO @splat

            # Local Servers Baseline Tiering Restrictions
            $splat = @(
                'Schema Admins',
                'Enterprise Admins',
                'Domain Admins',
                'Guests',
                $confXML.n.Admin.users.Admin.name,
                $confXML.n.Admin.users.newAdmin.name
            )
            Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLocalServer.Name) -DenyNetworkLogon $splat

            $splat = @(
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
                'Guests'
            )
            Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLocalServer.Name) -DenyInteractiveLogon $splat -DenyRemoteInteractiveLogon $splat

            $splat = @(
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
                ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
                'Schema Admins',
                'Enterprise Admins',
                'Domain Admins',
                'Administrators',
                'Account Operators',
                'Backup Operators',
                'Print Operators',
                'Server Operators',
                'Guests',
                $confXML.n.Admin.users.Admin.name,
                $confXML.n.Admin.users.newAdmin.name
            )
            Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLocalServer.Name) -DenyBatchLogon $splat -DenyServiceLogon $splat

            $splat = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name
            Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLocalServer.Name) -BatchLogon $splat -ServiceLogon $splat

        }




        # Configure Desktop Baseline
        $splat = @{
            BackupId   = $confXML.n.Sites.OUs.OuSiteComputer.backupID
            TargetName = 'C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name
            path       = Join-Path -Path $DMscripts -ChildPath SecTmpl
        }
        Import-GPO @splat

        # Desktop Baseline Tiering Restrictions
        $splat = @(
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Guests',
            $confXML.n.Admin.users.Admin.name,
            $confXML.n.Admin.users.newAdmin.name
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name) -DenyNetworkLogon $splat

        $splat = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            'Guests'
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name) -DenyInteractiveLogon $splat -DenyRemoteInteractiveLogon $splat

        $splat = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Guests',
            $confXML.n.Admin.users.Admin.name,
            $confXML.n.Admin.users.newAdmin.name
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteComputer.Name) -DenyBatchLogon $splat -DenyServiceLogon $splat

        $splat = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteComputer.Name) -BatchLogon $splat -ServiceLogon $splat







        # Configure Laptop Baseline
        $splat = @{
            BackupId   = $confXML.n.Sites.OUs.OuSiteLaptop.backupID
            TargetName = 'C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name
            path       = Join-Path -Path $DMscripts -ChildPath SecTmpl
        }
        Import-GPO @splat

        # Laptop Baseline Tiering Restrictions
        $splat = @(
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Guests',
            $confXML.n.Admin.users.Admin.name,
            $confXML.n.Admin.users.newAdmin.name
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name) -DenyNetworkLogon $splat

        $splat = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            'Guests'
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name) -DenyInteractiveLogon $splat -DenyRemoteInteractiveLogon $splat

        $splat = @(
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name),
            ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name),
            'Schema Admins',
            'Enterprise Admins',
            'Domain Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Print Operators',
            'Server Operators',
            'Guests',
            $confXML.n.Admin.users.Admin.name,
            $confXML.n.Admin.users.newAdmin.name
        )
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLaptop.Name) -DenyBatchLogon $splat -DenyServiceLogon $splat

        $splat = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name
        Set-GpoPrivilegeRights -GpoToModify ('C-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteLaptop.Name) -BatchLogon $splat -ServiceLogon $splat





        #endregion Configure GPO
        ###############################################################################

        Write-Verbose -Message 'Delegate GPO'
        ###############################################################################
        #region Delegate GPO

        if($PSBoundParameters['CreateSrvContainer'])
        {
            Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteFilePrint.Name)
            $splat = @{
                Name            = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteFilePrint.Name)
                PermissionLevel = 'GpoEdit'
                TargetName      = $SG_SiteAdmins.SamAccountName
                TargetType      = 'group'
                ErrorAction     = 'SilentlyContinue'
                Verbose         = $true
            }
            Set-GPPermissions @splat

            Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLocalServer.Name)
            $splat = @{
                Name            = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLocalServer.Name)
                PermissionLevel = 'GpoEdit'
                TargetName      = $SG_SiteAdmins.SamAccountName
                TargetType      = 'group'
                ErrorAction     = 'SilentlyContinue'
                Verbose         = $true
            }
            Set-GPPermissions @splat
        }

        # Give Rights to SG_SiteAdmin_XXXX to $ouName + -Desktop
        Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name)
        $splat = @{
            Name            = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteComputer.Name)
            PermissionLevel = 'GpoEdit'
            TargetName      = $SG_SiteAdmins.SamAccountName
            TargetType      = 'group'
            ErrorAction     = 'SilentlyContinue'
            Verbose         = $true
        }
        Set-GPPermissions @splat

        Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name)
        $splat = @{
            Name            = ('C-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteLaptop.Name)
            PermissionLevel = 'GpoEdit'
            TargetName      = $SG_SiteAdmins.SamAccountName
            TargetType      = 'group'
            ErrorAction     = 'SilentlyContinue'
            Verbose         = $true
        }
        Set-GPPermissions @splat




        Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteUser.Name)
        $splat = @{
            Name            = ('U-{0}-{1}' -f $PSBoundParameters['ouName'], $confXML.n.Sites.OUs.OuSiteUser.Name)
            PermissionLevel = 'GpoEdit'
            TargetName      = $SG_SiteAdmins.SamAccountName
            TargetType      = 'group'
            ErrorAction     = 'SilentlyContinue'
            Verbose         = $true
        }
        Set-GPPermissions @splat


        #endregion Delegate GPO
        ###############################################################################

        Write-Verbose -Message 'Rights delegation'

        # --- Exchange Related
        ###############################################################################
        If($PSBoundParameters['CreateExchange'])
        {
            Start-AdDelegateSite -ConfigXMLFile $ConfigXMLFile -ouName $ouName -QuarantineDN $ItQuarantineOuDn -CreateExchange

            #create Sub-OUs
            # --- USER CLASS ---
            New-DelegateAdOU -ouName $confXML.n.Sites.OUs.OuSiteMailbox.Name   -ouPath $ouNameDN -ouDescription ('{0} {1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Description)

            # --- GROUP CLASS ---
            New-DelegateAdOU -ouName $confXML.n.Sites.OUs.OuSiteDistGroup.Name -ouPath $ouNameDN -ouDescription ('{0} {1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteDistGroup.Description)

            # --- CONTACT CLASS ---
            New-DelegateAdOU -ouName $confXML.n.Sites.OUs.OuSiteContact.Name   -ouPath $ouNameDN -ouDescription ('{0} {1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteContact.Description)

            #create Basic Gpo
            # Create Mailboxes Baseline
            $splat = @{
                gpoDescription = '{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Name
                gpoScope       = 'U'
                gpoLinkPath    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteMailbox.Name, $ouNameDN
                GpoAdmin       = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
            }
            New-DelegateAdGpo @splat

            # Delegate GPO
            Write-Verbose -Message ('Add Local Admin to new {0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Name)
            $splat = @{
                Name            = ('U-{0}-{1}' -f $ouName, $confXML.n.Sites.OUs.OuSiteMailbox.Name)
                PermissionLevel = 'GpoEdit'
                TargetName      = $SG_SiteAdmins.SamAccountName
                TargetType      = 'group'
                ErrorAction     = 'SilentlyContinue'
            }
            Set-GPPermissions @splat
        }# end if CreateExchange
        else
        {
            Start-AdDelegateSite -ConfigXMLFile $ConfigXMLFile -ouName $ouName -QuarantineDN $ItQuarantineOuDn
        }

        # --- LAPS Related
        ###############################################################################
        If($PSBoundParameters['CreateLAPS'])
        {
            # Desktop LAPS delegation
            Set-AdAclLaps -ResetGroup $SL_PwdRight.SamAccountName -ReadGroup $SL_PwdRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.Name, $ouNameDN)

            # Laptop LAPS delegation
            Set-AdAclLaps -ResetGroup $SL_PwdRight.SamAccountName -ReadGroup $SL_PwdRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Name, $ouNameDN)

            If($PsBoundParameters['CreateSrvContainer'])
            {
                # File-Print LAPS delegation
                Set-AdAclLaps -ResetGroup $SL_LocalServerRight.SamAccountName -ReadGroup $SL_LocalServerRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteFilePrint.Name, $ouNameDN)

                # Local Server LAPS delegation
                Set-AdAclLaps -ResetGroup $SL_LocalServerRight.SamAccountName -ReadGroup $SL_LocalServerRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLocalServer.Name, $ouNameDN)
            }
        }
    }
    End
    {
        Write-Verbose -Message ("Function $($MyInvocation.InvocationName) finished creating creating Site {0}" -f $PSBoundParameters['ouName'])
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-DelegateSiteOU
#EndRegion - New-DelegateSiteOU.ps1
#Region - New-DfsObjects.ps1
Function New-DfsObjects
{
    <#
        .Synopsis
            Create DFS Objects and Delegations
        .DESCRIPTION
            Create the DFS Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-DfsObjects
        .INPUTS

        .NOTES
            Version:         1.3
            DateModified:    01/Feb/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param(
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        # Param2 Location of all scripts & files
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 1)]
        [string]
        $DMscripts = "C:\PsScripts\"
    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        ################################################################################
        # Initialisations
        Import-Module -name ActiveDirectory      -Verbose:$false
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        ################################################################################
        #region Declarations


        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile'])
                {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        catch { throw }



        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0


        # Organizational Units Distinguished Names

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $AdDn

        # It Privileged Groups OU
        $ItPGOu = $confXML.n.Admin.OUs.ItPrivGroupsOU.name
        # It Privileged Groups OU Distinguished Name
        $ItPGOuDn = 'OU={0},{1}' -f $ItPGOu, $ItAdminOuDn

        # It Admin Rights OU
        $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

        $parameters = $null

        #endregion Declarations
        ################################################################################
    }
    Process {
        # Check if feature is installed, if not then proceed to install it.
        If(-not((Get-WindowsFeature -Name FS-DFS-Namespace).Installed)) {
            Install-WindowsFeature -Name FS-DFS-Namespace -IncludeAllSubFeature
        }
        If(-not((Get-WindowsFeature -Name FS-DFS-Replication).Installed)) {
            Install-WindowsFeature -Name FS-DFS-Replication -IncludeAllSubFeature
        }

        ###############################################################################
        # Create OU Admin groups
        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.DfsAdmins.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.AdminXtra.GG.DfsAdmins.DisplayName
            Path                          = $ItPGOuDn
            Description                   = $confXML.n.AdminXtra.GG.DfsAdmins.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SG_DfsAdmins = New-AdDelegatedGroup @parameters

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.DfsRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.DfsRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.DfsRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_DfsRight = New-AdDelegatedGroup @parameters

        # Apply the PSO to the SL_DfsRights and SG_DfsAdmin Group
        Add-ADFineGrainedPasswordPolicySubject -Identity $confXML.n.Admin.PSOs.ItAdminsPSO.Name -Subjects $SG_DfsAdmins, $SL_DfsRight


        ###############################################################################
        # Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Add-AdGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SG_DfsAdmins, $SL_DfsRight


        ###############################################################################
        # Nest Groups - Extend Rights through delegation model groups

        Add-AdGroupNesting -Identity $SL_DfsRight -Members $SG_DfsAdmins

        Add-AdGroupNesting -Identity $SG_DfsAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AdAdmins.Name)

        ###############################################################################
        # START Delegation to SL_InfraRights group on ADMIN area

        # Distributed File System
        # Full control over DFS-Configuration & DFSR-GlobalSettings
        Set-AdAclFullControlDFS -Group $SL_DfsRight.SamAccountName
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) created DFS objects and Delegations successfully."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-DfsObjects
#EndRegion - New-DfsObjects.ps1
#Region - New-DhcpObjects.ps1
Function New-DHCPobjects
{
    <#
        .Synopsis
            Create DHCP Objects and Delegations
        .DESCRIPTION
            Create the DHCP Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-DHCPobjects
        .INPUTS
            Param1 ConfigXMLFile:..[STRING] Full path to the configuration.xml file
            Param2 DMscripts:......[String] Full path to the Delegation Model Scripts Directory
        .NOTES
            Version:         1.0
            DateModified:    29/Oct/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        # Param2 Location of all scripts & files
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 1)]
        [string]
        $DMscripts = "C:\PsScripts\"

    )

    Begin  {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        ################################################################################
        # Initialisations
        Import-Module ActiveDirectory      -Verbose:$false
        Import-Module EguibarIT.Delegation -Verbose:$false

        ################################################################################
        #region Declarations

        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        catch { throw }

        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0

        $parameters = $null


        # Organizational Units Distinguished Names

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $AdDn

        # It Privileged Groups OU
        $ItPGOu = $confXML.n.Admin.OUs.ItPrivGroupsOU.name
        # It Privileged Groups OU Distinguished Name
        $ItPGOuDn = 'OU={0},{1}' -f $ItPGOu, $ItAdminOuDn

        # It Admin Rights OU
        $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

        #endregion Declarations
        ################################################################################


    }

    Process {
        ###############################################################################
        # Create OU Admin groups
        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.DHCPAdmins.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.AdminXtra.GG.DHCPAdmins.DisplayName
            Path                          = $ItPGOuDn
            Description                   = $confXML.n.AdminXtra.GG.DHCPAdmins.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SG_DHCPAdmins = New-AdDelegatedGroup @parameters

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.DHCPRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.DHCPRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.DHCPRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_DHCPRight = New-AdDelegatedGroup @parameters

        # Apply the PSO to the SL_DfsRights and SG_DfsAdmin Group
        Add-ADFineGrainedPasswordPolicySubject -Identity $confXML.n.Admin.PSOs.ItAdminsPSO.Name -Subjects $SG_DHCPAdmins, $SL_DHCPRight


        ###############################################################################
        # Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Add-AdGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SG_DHCPAdmins, $SL_DHCPRight


        ###############################################################################
        # Nest Groups - Extend Rights through delegation model groups

        Add-AdGroupNesting -Identity $SL_DHCPRight -Members $SG_DHCPAdmins

        Add-AdGroupNesting -Identity $SG_DHCPAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AdAdmins.Name)


        ###############################################################################
        # START Delegation to SL_DHCPRight

        # Dynamic Host Configuration Protocol (DHCP)
        Set-AdAclFullControlDHCP -Group $SL_DHCPRight.SamAccountName

    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) created DHCP objects and Delegations successfully."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-DhcpObjects
#EndRegion - New-DhcpObjects.ps1
#Region - New-EitAdSite.ps1
function New-EitAdSite
{
    <#
        .Synopsis
            Create new AD Site
        .DESCRIPTION
            Create new AD Site
        .EXAMPLE
            New-EitAdSite -NewSiteName $SiteName
        .INPUTS
            Param1 NewSiteName - Name for the new site.
        .NOTES
            Version:         1.0
            DateModified:    31/Mar/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([string])]
    Param
    (
        # Param1 New Site name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Add help message for user',
        Position = 0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $NewSiteName
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Import-Module -name ServerManager   -Verbose:$false
        Import-Module -name ActiveDirectory -Verbose:$false

        #Get a reference to the RootDSE of the current domain
        Write-Verbose -Message 'Get the Root DSE of the forest'
        $ADConfigurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()

        # Get the Sites container
        $ADSiteDN      = "CN=Sites,$ADConfigurationNamingContext"

        Write-Verbose -Message "Set necessary site variables `r "
        $NewADSiteDN = 'CN={0},{1}' -f $PSBoundParameters['NewSiteName'], $ADSiteDN
    }
    Process {
        If (Test-Path -Path AD:$NewADSiteDN) {
            Write-Warning -Message ('The site {0} already exist. Please review the name and try again' -f $PSBoundParameters['NewSiteName'])
        } else {
            Write-Verbose -Message 'Create New Site Object `r '
            TRY {
                New-ADObject -Name $PSBoundParameters['NewSiteName'] -Path $ADSiteDN -Type Site
            }
            CATCH {
                Write-Warning -Message ('An error occured while attempting to create the new site {0} in the AD Site Path: {1} `r ' -f $PSBoundParameters['NewSiteName'], $ADSiteDN)
            }

            $SiteCreationCheck = Test-Path -Path AD:$NewADSiteDN

            IF ($SiteCreationCheck -eq $false) {
                Write-Warning -Message ('Failed to create the new site {0} `r ' -f $PSBoundParameters['NewSiteName'])
            } ELSE {
                ## OPEN ELSE Site Object created successfully
                Write-Verbose -Message 'Create New Site Object Child Objects (NTDS Site Settings & Servers Container) `r '

                TRY {
                    ## OPEN TRY Create New Site Object Child Objects (NTDS Site Settings & Servers Container)
                    New-ADObject -Name 'NTDS Site Settings' -Path $NewADSiteDN -Type NTDSSiteSettings
                    New-ADObject -Name 'Servers' -Path $NewADSiteDN -Type serversContainer

                    Write-Verbose -Message 'Get New AD Site as variable `r '
                    $NewADSiteInfo = Get-ADObject $NewADSiteDN
                }  ## CLOSE TRY Create New Site Object Child Objects (NTDS Site Settings & Servers Container)
                CATCH {
                    Write-Warning -Message ('An error occured while attempting to create site {0} child objects in the AD Site Path: {1} `r ' -f $PSBoundParameters['NewSiteName'], $NewADSiteDN)
                }
            }#end elseIf
        }#end elseIf
    }
  End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating new AD Site."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-EitAdSite
#EndRegion - New-EitAdSite.ps1
#Region - New-ExchangeObjects.ps1
Function New-ExchangeObjects {
  <#
      .Synopsis
      Create Exchange Objects and Containers
      .DESCRIPTION
      Create the Exchange OU structure and objects used to manage
      this organization by following the defined Delegation Model.
      .EXAMPLE
      New-ExchangeObjects
      .INPUTS

      .NOTES
      Version:         1.0
      DateModified:    19/Apr/2016
      LasModifiedBy:   Vicente Rodriguez Eguibar
      vicente@eguibar.com
      Eguibar Information Technology S.L.
      http://www.eguibarit.com
  #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param(
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        # Param2 Location of all scripts & files
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 1)]
        [string]
        $DMscripts = "C:\PsScripts\"
    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

        ################################################################################
        # Initialisations
        Import-Module -name ServerManager        -Verbose:$false
        Import-Module -name ActiveDirectory      -Verbose:$false
        Import-Module -name GroupPolicy          -Verbose:$false
        Import-Module -name EguibarIT.Delegation -Verbose:$false

        ################################################################################
        #region Declarations


        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile'])
                {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        catch { throw }



        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0


        # Organizational Units Distinguished Names

        # IT Admin OU
        New-Variable -Name 'ItAdminOu' -Value $confXML.n.Admin.OUs.ItAdminOU.name -Option ReadOnly -Force
        # IT Admin OU Distinguished Name
        New-Variable -Name 'ItAdminOuDn' -Value ('OU={0},{1}' -f $ItAdminOu, $AdDn) -Option ReadOnly -Force

            # It Admin Groups OU
            #$ItGroupsOu = $confXML.n.Admin.OUs.ItAdminGroupsOU.name
            # It Admin Groups OU Distinguished Name
            #$ItGroupsOuDn = 'OU={0},{1}' -f $ItGroupsOu, $ItAdminOuDn

            # It Privileged Groups OU
            $ItPGOu = $confXML.n.Admin.OUs.ItPrivGroupsOU.name
            # It Privileged Groups OU Distinguished Name
            $ItPGOuDn = 'OU={0},{1}' -f $ItPGOu, $ItAdminOuDn

            # It Admin Rights OU
            $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
            # It Admin Rights OU Distinguished Name
            $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

            # It Admin Exchange OU
            $ItExchangeOu = $confXML.n.AdminXtra.OUs.ItExchangeOU.name
            # It Admin Exchange OU Distinguished Name
            $ItExchangeOuDn = 'OU={0},{1}' -f $ItExchangeOu, $ItAdminOuDn

                # It Admin Exchange Distribution Groups OU
                $ItExDistGroupsOu = $confXML.n.AdminXtra.OUs.ItExDistGroups.name
                # It Admin Exchange Distribution Groups OU Distinguished Name
                $ItExDistGroupsOuDn = 'OU={0},{1}' -f $ItExDistGroupsOu, $ItExchangeOuDn

                # It Admin Exchange External Contacts OU
                #$ItExExternalContactOu = $confXML.n.AdminXtra.OUs.ItExExternalContact.name
                # It Admin Exchange External Contacts OU Distinguished Name
                #$ItExExternalContactOuDn = 'OU={0},{1}' -f $ItExExternalContactOu, $ItExchangeOuDn

                # It Admin Exchange Resource OU
                #$ItExResourceOu = $confXML.n.AdminXtra.OUs.ItExResource.name
                # It Admin Exchange Resource OU Distinguished Name
                #$ItExResourceOuDn = 'OU={0},{1}' -f $ItExResourceOu, $ItExchangeOuDn

                # It Admin Exchange Shared OU
                #$ItExSharedOu = $confXML.n.AdminXtra.OUs.ItExShared.name
                # It Admin Exchange Shared OU Distinguished Name
                #$ItExSharedOuDn = 'OU={0},{1}' -f $ItExSharedOu, $ItExchangeOuDn

                # It Admin Exchange Equipment OU
                #$ItExEquipOu = $confXML.n.AdminXtra.OUs.ItExEquip.name
                # It Admin Exchange Equipment OU Distinguished Name
                #$ItExEquipOuDn = 'OU={0},{1}' -f $ItExEquipOu, $ItExchangeOuDn

        # Servers OU
        $ServersOu = $confXML.n.Servers.OUs.ServersOU.name
        # Servers OU Distinguished Name
        $ServersOuDn = 'OU={0},{1}' -f $ServersOu, $AdDn

            # Exchange Servers
            $ExServersOu = $confXML.n.Servers.OUs.ExchangeOU.Name
            # Exchange Servers Distinguished Name
            $ExServersOuDn = 'OU={0},{1}' -f $ExServersOu, $ServersOuDn

                # Exchange CAS Servers
                $ExCasOu = $confXML.n.Servers.OUs.ExCasOU.Name
                # Exchange CAS Servers Distinguished Name
                $ExCasOuDn = 'OU={0},{1}' -f $ExCasOu, $ExServersOuDn

                # Exchange HUB Servers
                $ExHubOu = $confXML.n.Servers.OUs.ExHubOU.Name
                # Exchange HUB Servers Distinguished Name
                $ExHubOuDn = 'OU={0},{1}' -f $ExHubOu, $ExServersOuDn

                # Exchange EDGE Servers
                $ExEdgeOu = $confXML.n.Servers.OUs.ExEdgeOU.Name
                # Exchange EDGE Servers Distinguished Name
                $ExEdgeOuDn = 'OU={0},{1}' -f $ExEdgeOu, $ExServersOuDn

                # Exchange MAILBOX Servers
                $ExMailboxOu = $confXML.n.Servers.OUs.ExMailboxOU.Name
                # Exchange MAILBOX Servers Distinguished Name
                $ExMailboxOuDn = 'OU={0},{1}' -f $ExMailboxOu, $ExServersOuDn

                # Exchange MIXED ROLE Servers
                $ExMixedOu = $confXML.n.Servers.OUs.ExMixedRolOU.Name
                # Exchange MIXED ROLE Servers Distinguished Name
                $ExMixedOuDn = 'OU={0},{1}' -f $ExMixedOu, $ExServersOuDn

        # Quarantine OU
        $ItQuarantineOu = $confXML.n.Admin.OUs.ItNewComputersOU.name
        # Quarantine OU Distinguished Name
        $ItQuarantineOuDn = 'OU={0},{1}' -f $ItQuarantineOu, $AdDn

        #endregion Declarations
        ################################################################################
    }
    Process {
        ###############################################################################
        # Create Sub-OUs for admin

        New-DelegateAdOU -ouName $ItExchangeOu -ouPath $ItAdminOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExchangeOU.Description

        ###############################################################################
        # Create Sub-Sub-OUs
        New-DelegateAdOU -ouName $ItExDistGroupsOu      -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExDistGroups.Description
        New-DelegateAdOU -ouName $ItExExternalContactOu -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExExternalContact.Description
        New-DelegateAdOU -ouName $ItExResourceOu        -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExResource.Description
        New-DelegateAdOU -ouName $ItExSharedOu          -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExShared.Description
        New-DelegateAdOU -ouName $ItExEquipOu           -ouPath $ItExchangeOuDn -ouDescription $confXML.n.AdminXtra.OUs.ItExEquip.Description

        ###############################################################################
        # Create OU Admin groups
        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.ExAdmins.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'Global'
            DisplayName                   = $confXML.n.AdminXtra.GG.ExAdmins.DisplayName
            Path                          = $ItPGOuDn
            Description                   = $confXML.n.AdminXtra.GG.ExAdmins.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SG_ExAdmins = New-AdDelegatedGroup @parameters

        $parameters = @{
            Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.ExRight.Name
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $confXML.n.AdminXtra.LG.ExRight.DisplayName
            Path                          = $ItRightsOuDn
            Description                   = $confXML.n.AdminXtra.LG.ExRight.Description
            ProtectFromAccidentalDeletion = $True
            RemoveAccountOperators        = $True
            RemoveEveryone                = $True
            RemovePreWin2000              = $True
        }
        $SL_ExRight = New-AdDelegatedGroup @parameters

        ###############################################################################
        # Create a New Fine Grained Password Policy for Admins Accounts
        #  and apply the PSO to the account ()
        Add-ADFineGrainedPasswordPolicySubject -Identity $confXML.n.Admin.PSOs.ItAdminsPSO.Name -Subjects $SG_ExAdmins.SamAccountName, $SL_ExRight.SamAccountName

        ###############################################################################
        # Nest Groups - Security for RODC
        # Avoid having privileged or semi-privileged groups copy to RODC

        Add-AdGroupMember -Identity 'Denied RODC Password Replication Group' -Members $SG_ExAdmins, $SL_ExRight


        ###############################################################################
        # Nest Groups - Extend  Rights

        Add-AdGroupNesting -Identity $SG_ExAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.InfraAdmins.Name)
        Add-AdGroupNesting -Identity $SL_ExRight -Members $SG_ExAdmins

        ###############################################################################
        # START Delegation to SL_InfraRights group on ADMIN area

        $SL_InfraRight = (Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraRight.Name)).SamAccountName
        $SL_AdRight     = (Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.AdRight.Name)).SamAccountName
        $SL_PGM         = (Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PGM.Name)).SamAccountName

        # Administration OU
        Set-AdAclCreateDeleteGroup -Group $SL_InfraRight             -LDAPPath $ItExDistGroupsOuDn
        Set-AdAclCreateDeleteGroup -Group $SL_PGM                    -LDAPPath $ItExDistGroupsOuDn
        Set-AdAclCreateDeleteGroup -Group $SL_ExRight.SamAccountName -LDAPPath $ItExDistGroupsOuDn

        ###############################################################################
        # START Delegation to SL_AdRights group on ADMIN area

        $SL_AdRights = (Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.AdRight.Name)).SamAccountName

        # Administration OU
        Set-AdAclChangeGroup     -Group $SL_AdRights.SamAccountName -LDAPPath $ItExDistGroupsOuDn
        Set-AdAclChangeGroup     -Group $SL_PGM                     -LDAPPath $ItExDistGroupsOuDn
        Set-AdAclChangeGroup     -Group $SL_ExRight.SamAccountName  -LDAPPath $ItExDistGroupsOuDn

        ###############################################################################
        # Create Servers and Sub OUs
        # Create Sub-Sub-OUs for Exchange
        New-DelegateAdOU -ouName $ExServersOu -ouPath $ServersOuDn   -ouDescription $confXML.n.Servers.OUs.ExchangeOU.Description
        New-DelegateAdOU -ouName $ExCasOu     -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExCasOU.Description
        New-DelegateAdOU -ouName $ExHubOu     -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExHubOU.Description
        New-DelegateAdOU -ouName $ExEdgeOu    -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExEdgeOU.Description
        New-DelegateAdOU -ouName $ExMailboxOu -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExMailboxOU.Description
        New-DelegateAdOU -ouName $ExMixedOu   -ouPath $ExServersOuDn -ouDescription $confXML.n.Servers.OUs.ExMixedRolOU.Description

        ###############################################################################
        # START Delegation to SL_InfraRights group on SERVERS area

        # Servers OU
        # Create/Delete Computers
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExServersOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExCasOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExHubOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExEdgeOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExMailboxOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_InfraRight.SamAccountName -LDAPPath $ExMixedOuDn -QuarantineDN $ItQuarantineOuDn

        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExServersOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExCasOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExHubOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExEdgeOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExMailboxOuDn -QuarantineDN $ItQuarantineOuDn
        Set-AdAclDelegateComputerAdmin -Group $SL_ExRight.SamAccountName -LDAPPath $ExMixedOuDn -QuarantineDN $ItQuarantineOuDn

        ###############################################################################
        # START Delegation to SL_AdRights group

        # Servers OU
        # Change Public Info
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight -LDAPPath $ExServersOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight -LDAPPath $ExCasOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight -LDAPPath $ExHubOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight -LDAPPath $ExEdgeOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight -LDAPPath $ExMailboxOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_AdRight -LDAPPath $ExMixedOuDn

        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExServersOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExCasOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExHubOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExEdgeOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExMailboxOuDn
        Set-AdAclComputerPublicInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExMixedOuDn

        # Change Personal Info
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight -LDAPPath $ExServersOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight -LDAPPath $ExCasOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight -LDAPPath $ExHubOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight -LDAPPath $ExEdgeOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight -LDAPPath $ExMailboxOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_AdRight -LDAPPath $ExMixedOuDn

        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExServersOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExCasOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExHubOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExEdgeOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExMailboxOuDn
        Set-AdAclComputerPersonalInfo   -Group $SL_ExRight.SamAccountName -LDAPPath $ExMixedOuDn

        ###############################################################################
        # Create basic GPOs for different types under Servers
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $ExCasOu)     -gpoScope C -gpoLinkPath $ExCasOuDn     -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $ExHubOu)     -gpoScope C -gpoLinkPath $ExHubOuDn     -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $ExMailboxOu) -gpoScope C -gpoLinkPath $ExMailboxOuDn -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
        New-DelegateAdGpo -gpoDescription ('{0}-Baseline' -f $ExEdgeOuDn)  -gpoScope C -gpoLinkPath $ExEdgeOuDn    -GpoAdmin ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)

        ###############################################################################
        # Import the security templates to the corresponding GPOs under Servers

        # Configure Exchange ClientAccess GPO
        #Import-GPO -BackupId $confXML.n.AdminXtra.GPOs.ExCas.backupID     -TargetName ('C-{0}-Baseline' -f $ExCasOu) -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)

        # Configure Exchange Hub GPO
        #Import-GPO -BackupId $confXML.n.AdminXtra.GPOs.ExHub.backupID     -TargetName ('C-{0}-Baseline' -f $ExHubOu) -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)

        # Configure Mailbox GPO
        #Import-GPO -BackupId $confXML.n.AdminXtra.GPOs.ExMailbox.backupID -TargetName ('C-{0}-Baseline' -f $ExMailboxOu) -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)

        # Configure EDGE GPO
        #Import-GPO -BackupId $confXML.n.AdminXtra.GPOs.ExEdge.backupID    -TargetName ('C-{0}-Baseline' -f $ExEdgeOuDn) -path (Join-Path -Path $DMscripts -ChildPath SecTmpl)
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating Exchange containers and objects."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-ExchangeObjects
#EndRegion - New-ExchangeObjects.ps1
#Region - New-LapsObjects.ps1
Function New-LAPSobjects
{
    <#
        .Synopsis
            Create Local Administration Password Services (LAPS) Objects and Delegations
        .DESCRIPTION
            Create the LAPS Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-LAPSobjects -PawOuDn "OU=PAW,OU=Admin,DC=EguibarIT,DC=local" -ServersOuDn "OU=Servers,DC=EguibarIT,DC=local" -SitesOuDn "OU=Sites,DC=EguibarIT,DC=local"
        .INPUTS
            Param1 PawOuDn:......[String] Distinguished Name of the IT PrivilegedAccess Workstations OU
            Param2 ServersOuDn:..[String] Distinguished Name of the Servers OU
            Param3 SitesOuDn:....[String] Distinguished Name of the Sites OU
        .NOTES
            Version:         1.1
            DateModified:    11/Feb/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        # Param2 Location of all scripts & files
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 1)]
        [string]
        $DMscripts = "C:\PsScripts\"

    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        ################################################################################
        # Initialisations
        Import-Module ActiveDirectory      -Verbose:$false
        Import-Module EguibarIT.Delegation -Verbose:$false
        Import-Module AdmPwd.PS            -Verbose:$false

        ################################################################################
        #region Declarations

        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        catch { throw }

        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0

        $SL_InfraRight = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraRight.Name)
        $SL_PISM = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PISM.Name)
        $SL_PAWM = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PAWM.Name)
        # $SL_AdRight = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.AdRight.Name)
        $SL_SvrAdmRight = Get-ADGroup -Identity ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name)

        $guidmap = $null
        $guidmap = @{}
        $guidmap = Get-AttributeSchemaHashTable
        #$parameters = $null


        # Organizational Units Distinguished Names

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $AdDn

        # Servers OU
        $ServersOu = $confXML.n.Servers.OUs.ServersOU.name
        # Servers OU Distinguished Name
        $ServersOuDn = 'OU={0},{1}' -f $ServersOu, $AdDn

        # It InfraServers OU
        $ItInfraServersOu = $confXML.n.Admin.OUs.ItInfraOU.name
        # It PAW OU Distinguished Name
        $ItInfraServersOuDn = 'OU={0},{1}' -f $ItInfraServersOu, $ItAdminOuDn

        # It InfraServers Tier0 OU
        $ItInfraT0OU = $confXML.n.Admin.OUs.ItInfraT0.name
        #  It InfraServers Tier0 OU Distinguished Name
        $ItInfraT0OUDN = 'OU={0},{1}' -f $ItInfraT0OU, $ItInfraServersOuDn

        # It InfraServers Tier1 OU
        $ItInfraT1OU = $confXML.n.Admin.OUs.ItInfraT1.name
        #  It InfraServers Tier1 OU Distinguished Name
        $ItInfraT1OUDN = 'OU={0},{1}' -f $ItInfraT1OU, $ItInfraServersOuDn

        # It InfraServers Tier2 OU
        $ItInfraT2OU = $confXML.n.Admin.OUs.ItInfraT2.name
        #  It InfraServers Tier2 OU Distinguished Name
        $ItInfraT2OUDN = 'OU={0},{1}' -f $ItInfraT2OU, $ItInfraServersOuDn

        # It InfraServers Staging Tier0 OU
        $ItInfraStagingOU = $confXML.n.Admin.OUs.ItInfraStagingOU.name
        #  It InfraServers Staging Tier0 OU Distinguished Name
        $ItInfraStagingOUDN = 'OU={0},{1}' -f $ItInfraStagingOU, $ItInfraServersOuDn

        # It PAW OU
        $ItPawOu = $confXML.n.Admin.OUs.ItPawOU.name
        # It PAW OU Distinguished Name
        $ItPawOuDn = 'OU={0},{1}' -f $ItPawOu, $ItAdminOuDn

        # It PAW Tier0 OU
        $ItPawT0OU = $confXML.n.Admin.OUs.ItPawT0OU.name
        #  It PAW Tier0 OU Distinguished Name
        $ItPawT0OUDN = 'OU={0},{1}' -f $ItPawT0OU, $ItPawOuDn

        # It PAW Tier1 OU
        $ItPawT1OU = $confXML.n.Admin.OUs.ItPawT1OU.name
        #  It PAW Tier1 OU Distinguished Name
        $ItPawT1OUDN = 'OU={0},{1}' -f $ItPawT1OU, $ItPawOuDn

        # It PAW Tier2 OU
        $ItPawT2OU = $confXML.n.Admin.OUs.ItPawT2OU.name
        #  It PAW Tier2 OU Distinguished Name
        $ItPawT2OUDN = 'OU={0},{1}' -f $ItPawT2OU, $ItPawOuDn

        # It PAW Staging Tier0 OU
        $ItPawStagingOU = $confXML.n.Admin.OUs.ItPawStagingOU.name
        #  It PAW Tier2 OU Distinguished Name
        $ItPawStagingOUDN = 'OU={0},{1}' -f $ItPawStagingOU, $ItPawOuDn

        # Sites OU
        $SitesOu = $confXML.n.Sites.OUs.SitesOU.name
        # Sites OU Distinguished Name
        $SitesOuDn = 'OU={0},{1}' -f $SitesOu, $AdDn

        #endregion Declarations
        ################################################################################

        # Check if schema is extended for LAPS. Extend it if not.
        Try {
            if($null -eq $guidmap["ms-Mcs-AdmPwd"]) {
                Write-Verbose -Message 'LAPS is NOT supported on this environment. Proceeding to configure it by extending the Schema.'

                # Check if user can change schema
                if (-not ((Get-ADUser $env:UserName -Properties memberof).memberof -like "CN=Schema Admins*")) {
                    Write-Verbose -Message 'Member is not a Schema Admin... adding it.'
                    Add-ADGroupMember -Identity 'Schema Admins' -Members $env:username

                    # Modify Schema
                    try {
                        Write-Verbose -Message 'Modify the schema...!'
                        Update-AdmPwdADSchema  -Verbose
                    }
                    catch { throw }
                    finally {
                        # If Schema extension OK, remove user from Schema Admin
                        Remove-ADGroupMember -Identity 'Schema Admins' -Members $env:username -Confirm:$false
                    }
                }#end if
            }#end if
        }#end try
        catch { throw }
        Finally {
            Write-Verbose -Message 'Schema was extended succesfully for LAPS.'
        }#end finally
    }

    Process {
        # Make Infrastructure Servers modifications
        Set-AdAclLaps -ResetGroup $SL_PISM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPPath $ItInfraT0OUDN
        Set-AdAclLaps -ResetGroup $SL_PISM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPPath $ItInfraT1OUDN
        Set-AdAclLaps -ResetGroup $SL_PISM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPPath $ItInfraT2OUDN
        Set-AdAclLaps -ResetGroup $SL_PISM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPPath $ItInfraStagingOUDN

        # Make PAW modifications
        Set-AdAclLaps -ResetGroup $SL_PAWM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPPath $ItPawT0OUDN
        Set-AdAclLaps -ResetGroup $SL_PAWM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPPath $ItPawT1OUDN
        Set-AdAclLaps -ResetGroup $SL_PAWM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPPath $ItPawT2OUDN
        Set-AdAclLaps -ResetGroup $SL_PAWM.SamAccountName -ReadGroup $SL_InfraRight.SamAccountName -LDAPPath $ItPawStagingOUDN

        # Make Servers Modifications
        Set-AdAclLaps -ResetGroup $SL_SvrAdmRight.SamAccountName -ReadGroup $SL_SvrAdmRight.SamAccountName -LDAPPath $ServersOuDn

        # Make Sites Modifications
        # Get the DN of 1st level OU underneath SERVERS area
        $AllSubOu = Get-AdOrganizationalUnit -Filter * -SearchBase $SitesOuDn -SearchScope OneLevel | Select-Object -ExpandProperty DistinguishedName

        # Iterate through each sub OU and invoke delegation
        Foreach ($Item in $AllSubOu) {
            # Exclude _Global OU from delegation
            If(-not($item.Split(',')[0].Substring(3) -eq $confXML.n.Sites.OUs.OuSiteGlobal.name)) {
                # Get group who manages Desktops and Laptops
                $CurrentGroup = (Get-ADGroup -Identity ('{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $confXML.n.Sites.LG.PcRight.Name, ($item.Split(',')[0].Substring(3)))).SamAccountName

                # Desktops
                $CurrentLDAPPath = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.Name, $Item
                Set-AdAclLaps -ResetGroup $CurrentGroup.SamAccountName -ReadGroup $CurrentGroup.SamAccountName -LDAPPath $CurrentLDAPPath

                # Laptop
                $CurrentLDAPPath = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.Name, $Item
                Set-AdAclLaps -ResetGroup $CurrentGroup.SamAccountName -ReadGroup $CurrentGroup.SamAccountName -LDAPPath $CurrentLDAPPath

                # Get group who manages Local Servers & File-Print
                $CurrentGroup = (Get-ADGroup -Identity ('{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $confXML.n.Sites.LG.LocalServerRight.Name, ($item.Split(',')[0].Substring(3)))).SamAccountName

                # File-Print
                $CurrentLDAPPath = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteFilePrint.Name, $Item
                Set-AdAclLaps -ResetGroup $CurrentGroup.SamAccountName -ReadGroup $CurrentGroup.SamAccountName -LDAPPath $CurrentLDAPPath

                # Local Server
                $CurrentLDAPPath = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLocalServer.Name, $Item
                Set-AdAclLaps -ResetGroup $CurrentGroup.SamAccountName -ReadGroup $CurrentGroup.SamAccountName -LDAPPath $CurrentLDAPPath
            }
        }#end foreach
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) created LAPS and Delegations successfully."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-LapsObjects
#EndRegion - New-LapsObjects.ps1
#Region - New-LocalLogonTask.ps1
function New-LocalLogonTask
{
<#
    .SYNOPSIS
        Generates a New Local Logon task
    .DESCRIPTION
        Generates a New Local Logon task
    .EXAMPLE
        New-LocalLogonTask -Name -Description -Author -Command -CommandArguments -Hiden
    .NOTES
        Version:         1.0
        DateModified:    31/Mar/2015
        LasModifiedBy:   Vicente Rodriguez Eguibar
            vicente@eguibar.com
            Eguibar Information Technology S.L.
            http://www.eguibarit.com
#>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
  Param
  (
    # Param1 help description
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]
    $name,

    # Param2 help description
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Description,

    # Param3 help description
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 2)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Author,

    # Param4 help description
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 3)]
    [ValidateNotNullOrEmpty()]
    [string]
    $Command,

    # Param5 help description
    [Parameter(Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 4)]
    [string]
    $CommandArguments,

    # Param6 help description
    [Parameter(Mandatory = $false,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 5)]
    [switch]
    $Hidden
  )

  Begin
  {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

  }
  Process
  {
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa383607(v=vs.85).aspx
    try
    {
      # Create the TaskService object
      $service = New-Object -ComObject('Schedule.Service')
      # Connect to the server's Task Service Scheduler
      $service.Connect($Env:computername)

      $rootFolder = $service.GetFolder('\')

      $taskDefinition = $service.NewTask(0)

      # Define information about the task.
      # Set the registration info for the task by creating the RegistrationInfo object.
      $regInfo = $taskDefinition.RegistrationInfo
      $regInfo.Description = $Description
      $regInfo.Author = $Author

      # Set the task setting info for the Task Scheduler by creating a TaskSettings object.
      $settings = $taskDefinition.Settings
      $settings.Enabled = $true
      $settings.StartWhenAvailable = $true
      $settings.Hidden = $Hidden

      # Create a logon trigger
      $triggers = $taskDefinition.Triggers
      # TriggerTypeLogon is 9
      $trigger = $triggers.Create(9)

      # Trigger variables that define when the trigger is active
      $trigger.StartBoundary = '2014-10-0T22:00:00'
      #$trigger.DaysInterval = 1
      $trigger.Id = 'LogonTriggerId'
      $trigger.Enabled = $true

      # Create the action for the task to execute. Add an action to the task
      $Action = $taskDefinition.Actions.Create(0)
      $Action.Path = $Command
      $Action.Arguments = $CommandArguments

      # Register (create -> 6 ) the task
      $rootFolder.RegisterTaskDefinition( $name, $taskDefinition, 6, $null , $null , 0)
    }
    catch
    {
      throw $error
    }
  }
  End
    {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating new task."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-LocalLogonTask
#EndRegion - New-LocalLogonTask.ps1
#Region - New-TimePolicyGPO.ps1
Function New-TimePolicyGPO
{
    <#
        .Synopsis

        .DESCRIPTION

        .EXAMPLE
            New-TimePolicyGPO
        .INPUTS

        .NOTES
            Version:         1.0
            DateModified:    25/Mar/2014
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        # Param1 GPO Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the GPO to be created',
        Position = 0)]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [string]
        $gpoName,

        # Param2 NTP servers
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'NTP Servers to be used for time sync',
        Position = 1)]
        [string]
        $NtpServer,

        # Param3 AnnounceFlags for reliable time server
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'AnnounceFlags for reliable time server',
        Position = 2)]
        [ValidateNotNullOrEmpty()]
        [int]
        $AnnounceFlags,

        # Param4 Type of Sync
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Type of sync to be used',
        Position = 3)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('NoSync', 'NTP', 'NT5DS', 'AllSync', ignorecase = $false)]
        [string]
        $Type,

        # Param5 WMIFilter to be created and used
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'WMIFilter to be created and used',
        Position = 3)]
        [ValidateNotNullOrEmpty()]
        $WMIFilter,

        # Param6 Disable Virtual Machine time sync clock
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Disable Virtual Machine time sync clock',
        Position = 4)]
        [switch]
        $DisableVMTimeSync
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"



        $msWMIAuthor = (Get-ADUser -Identity $env:USERNAME).Name

        # Create WMI Filter
        $WMIGUID = [string]'{'+([Guid]::NewGuid())+'}'
        $WMIDN = 'CN='+$WMIGUID+',CN=SOM,CN=WMIPolicy,CN=System,{0}' -f ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString()
        $WMICN = $WMIGUID
        $WMIdistinguishedname = $WMIDN
        $WMIID = $WMIGUID

        $now = (Get-Date).ToUniversalTime()
        $msWMICreationDate = ($now.Year).ToString('0000') + ($now.Month).ToString('00') + ($now.Day).ToString('00') + ($now.Hour).ToString('00') + ($now.Minute).ToString('00') + ($now.Second).ToString('00') + '.' + ($now.Millisecond * 1000).ToString('000000') + '-000'
        $msWMIName = $WMIFilter[0]
        $msWMIParm1 = $WMIFilter[1] + ' '
        $msWMIParm2 = '1;3;10;' + $WMIFilter[3].Length.ToString() + ';WQL;' + $WMIFilter[2] + ';' + $WMIFilter[3] + ';'

        # msWMI-Name: The friendly name of the WMI filter
        # msWMI-Parm1: The description of the WMI filter
        # msWMI-Parm2: The query and other related data of the WMI filter
        $Attr = @{
            'msWMI-Name'           = $msWMIName
            'msWMI-Parm1'          = $msWMIParm1
            'msWMI-Parm2'          = $msWMIParm2
            'msWMI-Author'         = $msWMIAuthor
            'msWMI-ID'             = $WMIID
            'instanceType'         = 4
            'showInAdvancedViewOnly' = 'TRUE'
            'distinguishedname'    = $WMIdistinguishedname
            'msWMI-ChangeDate'     = $msWMICreationDate
            'msWMI-CreationDate'   = $msWMICreationDate
        }

        $WMIPath = ('CN=SOM,CN=WMIPolicy,CN=System,{0}' -f ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString())

        $ExistingWMIFilters = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2'
        $array = @()
    }

    Process {
        If ($null -ne $ExistingWMIFilters) {
            foreach ($ExistingWMIFilter in $ExistingWMIFilters)
            {
                $array += $ExistingWMIFilter.'msWMI-Name'
            }
        } Else {
            $array += 'no filters'
        }

        if ($array -notcontains $msWMIName) {
            Write-Output ('Creating the {0} WMI Filter...' -f $msWMIName)
            $WMIFilterADObject = New-ADObject -name $WMICN -type 'msWMI-Som' -Path $WMIPath -OtherAttributes $Attr
        } Else {
            Write-Warning -Message ('The {0} WMI Filter already exists.' -f $msWMIName)
        }

        $WMIFilterADObject = $null

        # Get WMI filter
        $WMIFilterADObject = Get-ADObject -Filter 'objectClass -eq "msWMI-Som"' -Properties 'msWMI-Name', 'msWMI-Parm1', 'msWMI-Parm2' |
        Where-Object {
            $_.'msWMI-Name' -eq "$msWMIName"
        }

        $ExistingGPO = get-gpo -Name $PSBoundParameters['gpoName'] -ErrorAction 'SilentlyContinue'

        If ($null -eq $ExistingGPO) {
            Write-Output ('Creating the {0} Group Policy Object...' -f $PSBoundParameters['gpoName'])

            # Create new GPO shell
            $GPO = New-GPO -Name $PSBoundParameters['gpoName']

            # Disable User Settings
            $GPO.GpoStatus = 'UserSettingsDisabled'

            # Add the WMI Filter
            $GPO.WmiFilter = ConvertTo-WmiFilter $WMIFilterADObject

            # Set the three registry keys in the Preferences section of the new GPO
            $null = Set-GPPrefRegistryValue -Name $PSBoundParameters['gpoName'] -Action Update -Context Computer `
                -Key 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config' `
                -Type DWord -ValueName 'AnnounceFlags' -Value $PSBoundParameters['AnnounceFlags']

            $null = Set-GPPrefRegistryValue -Name $PSBoundParameters['gpoName'] -Action Update -Context Computer `
                -Key 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' `
                -Type String -ValueName 'NtpServer' -Value "$PSBoundParameters['NtpServer']"

            $null = Set-GPPrefRegistryValue -Name $PSBoundParameters['gpoName'] -Action Update -Context Computer `
                -Key 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' `
                -Type String -ValueName 'Type' -Value "$PSBoundParameters['Type']"

            If ($PSBoundParameters['DisableVMTimeSync']) {
                # Disable the Hyper-V time synchronization integration service.
                $null = Set-GPPrefRegistryValue -Name $PSBoundParameters['gpoName'] -Action Update -Context Computer `
                    -Key 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters' `
                -Type DWord -ValueName 'Enabled' -Value 0

                # Used to control how often the time service synchronizes to 15 minutes
                $null = Set-GPPrefRegistryValue -Name $PSBoundParameters['gpoName'] -Action Update -Context Computer `
                    -Key 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\NtpClient' `
                    -Type DWord -ValueName 'SpecialPollInterval' -Value 900

                # Set the three registry keys in the Preferences section of the new GPO
                $null = Set-GPPrefRegistryValue -Name $PSBoundParameters['gpoName'] -Action Update -Context Computer `
                    -Key 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config' `
                    -Type DWord -ValueName 'MaxPosPhaseCorrection' -Value 3600

                # Set the three registry keys in the Preferences section of the new GPO
                    $null = Set-GPPrefRegistryValue -Name $PSBoundParameters['gpoName'] -Action Update -Context Computer `
                    -Key 'HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Config' `
                    -Type DWord -ValueName 'MaxNegPhaseCorrection' -Value 3600
            }#end if

            # Link the new GPO to the Domain Controllers OU
            Write-Output ('Linking the {0} Group Policy Object to the OU=Domain Controllers,{1} ...' -f $PSBoundParameters['gpoName'], ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString())
            $null = New-GPLink -Name $PSBoundParameters['gpoName'] -Target ('OU=Domain Controllers,{0}' -f ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString())
        } Else {
            Write-Warning -Message ('The {0} Group Policy Object already exists.' -f $PSBoundParameters['gpoName'])
            Write-Output ('Adding the {0} WMI Filter...' -f $msWMIName)
            $ExistingGPO.WmiFilter = ConvertTo-WmiFilter $WMIFilterADObject
        }
    }

    End {
        Write-Output "Completed.`n"
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating the Time Policy GPO."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function New-TimePolicyGPO
#EndRegion - New-TimePolicyGPO.ps1
#Region - New-WsusObjects.ps1
Function New-WsusObjects {
    <#
        .Synopsis
            Create WSUS Objects and Delegations
        .DESCRIPTION
            Create the WSUS Objects used to manage
            this organization by following the defined Delegation Model.
        .EXAMPLE
            New-WsusObjects
        .INPUTS
        .NOTES
            Version:         1.1
            DateModified:    22/Apr/2021
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param ( )

    Begin {

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        ################################################################################
        # Initialisations
        Import-Module ActiveDirectory      -Verbose:$false

        #Get the OS Instalation Type
        $OsInstalationType = Get-ItemProperty -Path 'HKLM:Software\Microsoft\Windows NT\CurrentVersion' | Select-Object -ExpandProperty InstallationType

    } # End Bigin

    Process {

        # Check if AD module is installed
        If(-not((Get-WindowsFeature -Name RSAT-AD-PowerShell).Installed)) {
            Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature
        }

        # Check if feature is installed, if not then proceed to install it.
        If(-not((Get-WindowsFeature -Name UpdateServices-Services).Installed)) {

            Install-WindowsFeature -Name UpdateServices, UpdateServices-Services, UpdateServices-WidDB -Restart

        }

        If($OsInstalationType -ne 'Server Core') {
            Install-WindowsFeature -Name UpdateServices-RSAT -IncludeAllSubFeature
        }

        # Configure Download Location

        #Create WSUS folder
        # Create Folder where to store all Delegation Model scripts & files
        $WsusFolder = ('{0}\WSUS\' -f $env:SystemDrive)

        if(-not(Test-Path $WsusFolder)) {
            New-Item -ItemType Directory -Force -Path $WsusFolder
        }

        # Create a new Windows Script Shell
        $sh = New-Object -comobject 'Wscript.Shell'

        [String]$cmd = '"C:\Program Files\Update Services\Tools\WsusUtil.exe" PostInstall CONTENT_DIR=C:\WSUS'
        $sh.Run($cmd,1,'true')

        # Download Microsoft System CLR Types for SQL Server 2014
        #$URL = 'https://download.microsoft.com/download/1/3/0/13089488-91FC-4E22-AD68-5BE58BD5C014/ENU/x64/SQLSysClrTypes.msi'

        # Download Microsoft System CLR Types for SQL Server 2012
        $URL = 'http://download.microsoft.com/download/F/E/D/FEDB200F-DE2A-46D8-B661-D019DFE9D470/ENU/x64/SQLSysClrTypes.msi'
        Start-BitsTransfer -Source $URL -Destination $env:TEMP -Priority High -TransferType Download -RetryInterval 60 -RetryTimeout 180 -ErrorVariable err
        if ($err) {
            write-Error -Message 'Microsoft Microsoft System CLR Types for SQL Server 2014 could not be downloaded!. Please download and install it manually to use WSUS Reports.'
        }

        # Download MICROSOFT� REPORT VIEWER 2015 RUNTIME
        #$URL = 'https://download.microsoft.com/download/A/1/2/A129F694-233C-4C7C-860F-F73139CF2E01/ENU/x86/ReportViewer.msi'

        # Download MICROSOFT� REPORT VIEWER 2012 RUNTIME
        $URL = 'https://download.microsoft.com/download/F/B/7/FB728406-A1EE-4AB5-9C56-74EB8BDDF2FF/ReportViewer.msi'
        Start-BitsTransfer -Source $URL -Destination $env:TEMP -Priority High -TransferType Download -RetryInterval 60 -RetryTimeout 180 -ErrorVariable err
        if ($err) {
            write-Error -Message 'Microsoft REPORT VIEWER 2015 RUNTIME could not be downloaded!. Please download and install it manually to use WSUS Reports.'
        }



        # Install Microsoft System CLR Types for SQL Server 2014
        $Arguments = '/i "{0}\SQLSysClrTypes.msi" /qn /quiet /norestart' -f $env:TEMP
        $setup = Start-Process -FilePath 'msiexec.exe' -Verb RunAs -ArgumentList $Arguments -Wait -PassThru -Verbose
        $setup.WaitForExit()
        if ($setup.exitcode -eq 0) {
            write-verbose -Message 'Microsoft System CLR Types for SQL Server 2017 Successfully installed'
        }  else {
            write-error -Message 'Microsoft System CLR Types for SQL Server 2017 did not install correctly. Please download and install it manually to use WSUS Reports.'
        }


        # Install REPORT VIEWER 2015 RUNTIME
        $Arguments = '/i "{0}\ReportViewer.msi" /qn /quiet /norestart' -f $env:TEMP
        $setup = Start-Process -FilePath 'msiexec.exe' -Verb RunAs -ArgumentList $Arguments -Wait -PassThru -Verbose
        $setup.WaitForExit()
        if ($setup.exitcode -eq 0) {
            write-verbose -Message 'Microsoft REPORT VIEWER 2015 RUNTIME Successfully installed'
        } else {
            write-error -Message 'Microsoft REPORT VIEWER 2015 RUNTIME did not install correctly. Please download and install it manually to use WSUS Reports.'
        }




        # Cannot be imported in the bigin section due features installation
        Import-Module -Name WebAdministration -Force -Verbose:$false





        # Set Application Pool Maximum Private memory
        #Clear-ItemProperty IIS:\AppPools\WsusPool -Name Recycling.periodicRestart.privatememory
        #[int32] $PrivMemMax = 4GB
        #[int32] $PrivMemMax = 8GB
        [int32] $PrivMemMax = 0
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name Recycling.periodicRestart.privateMemory -Value $PrivMemMax

		# ( C:\Program Files\Update Services\WebServices\ClientWebService\web.config ) for WSUS: Replace <httpRuntime maxRequestLength="4096" /> with <httpRuntime maxRequestLength="204800" executionTimeout="7200"/>

        <#
        This one are failing
        Set-WebConfiguration -Filter "/system.applicationHost/applicationPools/add[@name='WsusPool']/recycling/periodicRestart/@privateMemory" -Value 0
        Set-WebConfiguration -Filter "/system.applicationHost/applicationPools/add[@name='WsusPool']/processModel/@maxProcesses" -Value 0
        #>

        # Other "Unexpected error" hacks
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name queueLength -Value 25000
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name cpu.resetInterval -Value "00.00:15:00"
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name failure.loadBalancerCapabilities -Value "TcpLevel"
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name failure.rapidFailProtectionInterval -Value "00.00:30:00"
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name failure.rapidFailProtectionMaxCrashes -Value 60
        Set-ItemProperty -Path IIS:\AppPools\WsusPool -Name ProcessModel.MaxProcesses -Value 0


        # Get WSUS Server Object
        $wsus = Get-WSUSServer

        # Connect to WSUS server configuration
        $wsusConfig = $wsus.GetConfiguration()

        ### Remove WSUS configuration pop-up when opening WSUS Management Console
        $wsusConfig.OobeInitialized = $true
        $wsusConfig.Save()


        #Check WSUS services. Mark those as automatic
        Set-Service WSusCertServer -StartupType Automatic
        Set-Service WsusService -StartupType Automatic
        Set-Service wuauserv -StartupType Automatic

        #Start Services
        Start-Service WSusCertServer, WsusService, wuauserv -Verbose


        # Get a new certificate from CA1 using WebServerV2 template
        $Splat = @{
            Template          = 'WebServerV2'
            DnsName           = ('{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN).ToLower()
            Url               = 'ldap:'
            CertStoreLocation = 'cert:\LocalMachine\My'
            SubjectName       = ('CN={0}' -f $env:COMPUTERNAME).ToLower()
        }
        $WsusCert = Get-Certificate @Splat

        # Get the binding as object
        $bind = Get-WebBinding -Name 'WSUS Administration' -Protocol https

        # Merge the 2 objects
        $bind.AddSslCertificate($WsusCert.Certificate.Thumbprint, "My")

        # Set all corresponding virtual directories to use SSL
        $Splat = @{
            PSPath = 'MACHINE/WEBROOT/APPHOST'
            Filter = "system.webServer/Security/access"
            Name   = "sslFlags"
            Value  ="Ssl"
        }
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/ApiRemoting30'
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/ClientWebService'
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/DSSAuthWebService'
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/ServerSyncWebService'
        Set-WebConfigurationProperty @Splat -Location 'WSUS Administration/SimpleAuthWebService'

        # Final SSL configuration
        [String]$cmd = '"C:\Program Files\Update Services\Tools\WsusUtil.exe" configuressl {0}' -f ('{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN).ToLower()
        $sh.Run($cmd,1,'true')



        # Get WSUS Server Object
        $wsus = Get-WSUSServer
        # Refresh WSUS server configuration
        $wsusConfig = $wsus.GetConfiguration()

        # Set to download updates from Microsoft Updates
        Set-WsusServerSynchronization -SyncFromMU

        # Set Update Languages to English and save configuration settings
        $wsusConfig.AllUpdateLanguagesEnabled = $false
        $wsusConfig.SetEnabledUpdateLanguages('en')
        $wsusConfig.GetContentFromMU = $True
        $wsusConfig.AutoApproveWsusInfrastructureUpdates = $True
        $wsusConfig.AutoRefreshUpdateApprovals = $True
        $wsusConfig.AutoRefreshUpdateApprovalsDeclineExpired = $True
        $wsusConfig.HostBinariesOnMicrosoftUpdate = $True
        $wsusConfig.Save()

        # Get WSUS Subscription and perform initial synchronization to get latest categories
        $subscription = $wsus.GetSubscription()
        $subscription.StartSynchronizationForCategoryOnly()

        while ($subscription.GetSynchronizationProgress().ProcessedItems -ne $subscription.GetSynchronizationProgress().TotalItems) {
            Write-Progress -PercentComplete ( $subscription.GetSynchronizationProgress().ProcessedItems*100/($subscription.GetSynchronizationProgress().TotalItems) ) -Activity "WSUS Sync Progress"
        }


        # Disable all previously selected products
        Get-WsusProduct | Set-WsusProduct -Disable

        # Configure the Platforms that we want WSUS to receive updates
        Get-WsusProduct | where-Object {
            $_.Product.Title -in (
            'Active Directory',
            'Developer Tools, Runtimes, and Redistributables',
            'Forefront Client Security',
            'Forefront Identity Manager 2010 R2',
            'Forefront Identity Manager 2010',
            'Forefront Protection Category',
            'Forefront Server Security Category',
            'Forefront Threat Management Gateway, Definition Updates for HTTP Malware Inspection',
            'Forefront TMG MBE',
            'Forefront TMG',
            'Forefront',
            'Microsoft Advanced Threat Analytics',
            'Microsoft BitLocker Administration and Monitoring v1',
            'Microsoft BitLocker Administration and Monitoring',
            'Microsoft Edge',
            'Microsoft Security Essentials',
            'MS Security Essentials',
            'Report Viewer 2005',
            'Report Viewer 2008',
            'Report Viewer 2010',
            'Security Essentials',
            'Visual Studio 2015',
            'Visual Studio 2017',
            'Windows 10, version 1809 and later, Upgrade & Servicing Drivers',
            'Windows 10',
            'Windows Admin Center',
            'Windows Defender',
            'Windows Dictionary Updates',
            'Windows Server 2016 and Later Servicing Drivers',
            'Windows Server 2016',
            'Windows Server 2019 and later, Servicing Drivers',
            'Windows Server 2019 and later, Upgrade & Servicing Drivers',
            'Windows Server 2019',
            'Windows Server Drivers',
            'Windows Server Solutions Best Practices Analyzer 1.0',
            'Windows Server, version 1903 and later'
            )
        } | Set-WsusProduct



        # Configure the Classifications
        write-Output 'Setting WSUS Classifications'
        Get-WsusClassification | Where-Object {
            $_.Classification.Title -in (
            'Critical Updates',
            'Definition Updates',
            'Feature Packs',
            'Security Updates',
            'Service Packs',
            'Update Rollups',
            'Updates')
        } | Set-WsusClassification



        # Configure Default Approval Rule
        [void][reflection.assembly]::LoadWithPartialName('Microsoft.UpdateServices.Administration')

        $rule = $wsus.GetInstallApprovalRules() | Where-Object { $_.Name -eq 'Default Automatic Approval Rule' }

        $class = $wsus.GetUpdateClassifications() | Where-Object {$_.Title -In (
            'Critical Updates',
            'Definition Updates',
            'Security Updates',
            'Service Packs',
            'Update Rollups',
            'Updates')
        }

        $class_coll = New-Object Microsoft.UpdateServices.Administration.UpdateClassificationCollection

        $class_coll.AddRange($class)
        $rule.SetUpdateClassifications($class_coll)
        $rule.Enabled = $True
        $rule.Save()


        # Configure Synchronizations
        write-Output 'Enabling WSUS Automatic Synchronisation'
        $subscription.SynchronizeAutomatically=$true

        # Set synchronization scheduled for midnight each night
        $subscription.SynchronizeAutomaticallyTimeOfDay= (New-TimeSpan -Hours 0)
        $subscription.NumberOfSynchronizationsPerDay=1
        $subscription.Save()

        # Kick off a synchronization
        $subscription.StartSynchronization()


        ### Create computer target group
        $wsus.CreateComputerTargetGroup("DCs")
        $wsus.CreateComputerTargetGroup("PAWs")
        $wsus.CreateComputerTargetGroup("Infrastructure Servers")
        $wsus.CreateComputerTargetGroup("Tier1")
        $wsus.CreateComputerTargetGroup("Tier2")

    } # End Process

    End {

        Write-Verbose -Message ('Function {0} created Wsus objects and Delegations successfully.' -f $MyInvocation.InvocationName)
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''

    } # End end
} # end function New-WsusObjects
Export-ModuleMember -Function New-WsusObjects
#EndRegion - New-WsusObjects.ps1
#Region - Revoke-Inheritance.ps1
function Revoke-Inheritance
{
<#
    .Synopsis
    Function to remove NTFS inheritance of a folder
    .DESCRIPTION
    Function to remove NTFS inheritance of a folder
    .EXAMPLE
    Revoke-Inheritance path
    .INPUTS
    Param1 path = The path to the folder
    .NOTES
    Version:         1.0
    DateModified:    31/Mar/2015
    LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com
#>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
  [OutputType([String])]
  Param
  (
    # Param1 path to the resource|folder
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
        HelpMessage = 'Add help message for user',
    Position = 0)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]
    $path
  )
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
      $isProtected = $true
      $preserveInheritance = $true
      $DirectorySecurity = Get-Acl -Path $path
      # SetAccessRuleProtection, which is a method to control whether inheritance from the parent folder should
      # be blocked ($True means no Inheritance) and if the previously inherited access rules should
      # be preserved ($False means remove previously inherited permissions).
      $DirectorySecurity.SetAccessRuleProtection($isProtected, $preserveInheritance)
      Set-Acl -Path $path -AclObject $DirectorySecurity
    }
    Catch { Throw }
  }
  End {
        Write-Verbose -Message ('The folder {0} was removed inheritance.' -f $path)
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
  }
}
Export-ModuleMember -Function Revoke-Inheritance
#EndRegion - Revoke-Inheritance.ps1
#Region - Revoke-NTFSPermissions.ps1
function Revoke-NTFSPermissions
{
<#
    .Synopsis
    Function to remove NTFS permissions to a folder
    .DESCRIPTION
    Function to remove NTFS permissions to a folder
    .EXAMPLE
    Revoke-NTFSPermissions path object permission
    .INPUTS
    Param1 path = The path to the folder
    Param2 object = the identity which will get the permissions
    Param3 permission = the permissions to be modified
    .NOTES
    Version:         1.0
    DateModified:    31/Mar/2015
    LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com
#>
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
  Param
  (
    # Param1 path to the resource|folder
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 0)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]
    $path,

    # Param2 object or SecurityPrincipal
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 1)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]
    $object,

    # Param3 permission
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 2)]
    [ValidateNotNull()]
    [ValidateNotNullOrEmpty()]
    [string]
    $permission
  )
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
            $FileSystemRights = [Security.AccessControl.FileSystemRights]$permission
            $InheritanceFlag = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
            $PropagationFlag = [Security.AccessControl.PropagationFlags]'None'
            $AccessControlType = [Security.AccessControl.AccessControlType]::Allow
            $Account = New-Object -TypeName System.Security.Principal.NTAccount -ArgumentList ($object)
            $FileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList ($Account, $FileSystemRights, $InheritanceFlag, $PropagationFlag, $AccessControlType)
            $DirectorySecurity = Get-Acl -Path $path
            $DirectorySecurity.RemoveAccessRuleAll($FileSystemAccessRule)
            Set-Acl -Path $path -AclObject $DirectorySecurity
        }
        Catch { Throw }
    }
    End {
        Write-Verbose -Message ('The User/Group {0} was removed {1} from folder {2}.' -f $object, $permission, $path)
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Revoke-NTFSPermissions
#EndRegion - Revoke-NTFSPermissions.ps1
#Region - Set-AdAclDelegateComputerAdmin.ps1
# Group together all COMPUTER admin delegations
function Set-AdAclDelegateComputerAdmin
{
    <#
        .Synopsis
            The function will consolidate all rights used for Computer object container.
        .DESCRIPTION

        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .INPUTS
            Param1 Group:........[STRING] for the Delegated Group Name
            Param2 LDAPPath:.....[STRING] Distinguished Name of the OU where given group will fully manage a computer object.
            Param3 RemoveRule:...[SWITCH] If present, the access rule will be removed
        .NOTES
            Version:         1.0
            DateModified:    19/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a computer object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM3 Distinguished Name of the quarantine OU
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the quarantine OU',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String]
        $QuarantineDN,

        # PARAM4 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule

    )
    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        $parameters = $null

        # Active Directory Domain Distinguished Name
        If(-Not (Test-Path -Path variable:AdDn)) {
            New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
        }
    }
    Process {
        try {
            $parameters = @{
                Group    = $PSBoundParameters['Group']
                LDAPPath = $PSBoundParameters['LDAPpath']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }

            # Create/Delete Computers
            Set-AdAclCreateDeleteComputer @parameters

            # Reset Computer Password
            Set-AdAclResetComputerPassword @parameters

            # Change Computer Password
            Set-AdAclChangeComputerPassword @parameters

            # Validated write to DNS host name
            Set-AdAclValidateWriteDnsHostName @parameters

            # Validated write to SPN
            Set-AdAclValidateWriteSPN @parameters

            # Change Computer Account Restriction
            Set-AdAclComputerAccountRestriction @parameters

            # Change DNS Hostname Info
            Set-AdAclDnsInfo @parameters

            # Change MS TerminalServices info
            Set-AdAclMsTsGatewayInfo @parameters

            # Access to BitLocker & TMP info
            Set-AdAclBitLockerTPM @parameters

            # Grant the right to delete computers from default container. Move Computers
            Set-DeleteOnlyComputer -Group $PSBoundParameters['Group'] -LDAPPath $PSBoundParameters['QuarantineDN']

            # Set LAPS
            Set-AdAclLaps -ResetGroup $PSBoundParameters['Group'] -ReadGroup $PSBoundParameters['Group'] -LDAPPath $PSBoundParameters['LDAPpath']

        }
        catch { throw }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Computer Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Set-AdAclDelegateComputerAdmin
#EndRegion - Set-AdAclDelegateComputerAdmin.ps1
#Region - Set-AdAclDelegateGalAdmin.ps1
# Group together all USER admin delegations
function Set-AdAclDelegateGalAdmin
{
    <#
        .Synopsis
            The function will consolidate all rights used for GAL admin.
        .DESCRIPTION

        .EXAMPLE
            Set-AdAclDelegateGalAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            Set-AdAclDelegateGalAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .INPUTS
            Param1 Group:........[STRING] for the Delegated Group Name
            Param2 LDAPPath:.....[STRING] Distinguished Name of the OU where given group will manage a User GAL.
            Param3 RemoveRule:...[SWITCH] If present, the access rule will be removed
        .NOTES
            Version:         1.1
            DateModified:    12/Feb/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group will manage a User GAL.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will manage a User GAL.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )
    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        $parameters = $null
    }
    Process {
        try {
            $parameters = @{
                Group    = $PSBoundParameters['Group']
                LDAPPath = $PSBoundParameters['LDAPpath']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }

            # Change Group Membership
            Set-AdAclUserGroupMembership @parameters

            # Change Personal Information
            Set-AdAclUserPersonalInfo @parameters

            # Change Public Information
            Set-AdAclUserPublicInfo @parameters

            # Change General Information
            Set-AdAclUserGeneralInfo @parameters

            # Change Web Info
            Set-AdAclUserWebInfo @parameters

            # Change Email Info
            Set-AdAclUserEmailInfo @parameters
        }
        catch { throw }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating GAL Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Set-AdAclDelegateGalAdmin
#EndRegion - Set-AdAclDelegateGalAdmin.ps1
#Region - Set-AdAclDelegateUserAdmin.ps1
# Group together all USER admin delegations
function Set-AdAclDelegateUserAdmin
{
    <#
        .Synopsis
            The function will consolidate all rights used for USER object container.
        .DESCRIPTION

        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .INPUTS
            Param1 Group:........[STRING] for the Delegated Group Name
            Param2 LDAPPath:.....[STRING] Distinguished Name of the OU where given group will fully manage a User object.
            Param3 RemoveRule:...[SWITCH] If present, the access rule will be removed
        .NOTES
            Version:         1.1
            DateModified:    12/Feb/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group can read the User password
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a User object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM3 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )
    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

        $parameters = $null
    }
    Process {
        try {
            $parameters = @{
                Group    = $PSBoundParameters['Group']
                LDAPPath = $PSBoundParameters['LDAPpath']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }

            # Create/Delete Users
            Set-AdAclCreateDeleteUser @parameters

            # Reset User Password
            Set-AdAclResetUserPassword @parameters

            # Change User Password
            Set-AdAclChangeUserPassword @parameters

            # Enable and/or Disable user right
            Set-AdAclEnableDisableUser @parameters

            # Unlock user account
            Set-AdAclUnlockUser @parameters

            # Change User Restrictions
            Set-AdAclUserAccountRestriction @parameters

            # Change User Account Logon Info
            Set-AdAclUserLogonInfo @parameters
        }
        catch { throw }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating User Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Set-AdAclDelegateUserAdmin
#EndRegion - Set-AdAclDelegateUserAdmin.ps1
#Region - Set-AdAclLaps.ps1
# Delegate Local Administration Password Service (LAPS)
function Set-AdAclLaps
{
    <#
        .Synopsis
            The function will consolidate all rights used for LAPS on a given container.
        .DESCRIPTION

        .EXAMPLE
            Set-AdAclLaps -ResetGroup "SG_SiteAdmins_XXXX" -ReadGroup "SG_GalAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            Set-AdAclLaps -ResetGroup "SG_SiteAdmins_XXXX" -ReadGroup "SG_GalAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .INPUTS
            Param1 ReadGroup:....[STRING] Identity of the group getting being able to READ the password
            Param2 ResetGroup:...[STRING] Identity of the group getting being able to RESET the password
            Param3 LDAPPath:.....[STRING] Distinguished Name of the OU where LAPS will apply to computer object.
            Param4 RemoveRule:...[SWITCH] If present, the access rule will be removed
        .NOTES
            Version:         1.0
            DateModified:    19/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting being able to READ the password.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ReadGroup,

        # PARAM2 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting being able to RESET the password.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ResetGroup,

        # PARAM3 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where LAPS will apply to computer object',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM4 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule
    )
    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"



        Import-Module -Name 'AdmPwd.PS' -Verbose:$false

        $guidmap = $null
        $guidmap = @{}
        $guidmap = Get-AttributeSchemaHashTable
    }
    Process {
        if(-not($null -eq $guidmap["ms-Mcs-AdmPwdExpirationTime"])) {
            Write-Verbose -Message "LAPS is supported on this environment. We can proceed to configure it."

            Set-AdmPwdComputerSelfPermission -Identity $LDAPpath

            Set-AdmPwdReadPasswordPermission -AllowedPrincipals $ReadGroup -Identity $LDAPpath

            Set-AdmPwdResetPasswordPermission -AllowedPrincipals $ResetGroup -Identity $LDAPpath
        } else {
            Write-Error -Message "Not Implemented. Schema does not contains the requiered attributes."
        }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating LAPS Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Set-AdAclLaps
#EndRegion - Set-AdAclLaps.ps1
#Region - Start-AdAclDelegateComputerAdmin.ps1
# Group together all COMPUTER admin delegations
function Set-AdAclDelegateComputerAdmin
{
    <#
        .Synopsis
            The function will consolidate all rights used for Computer object container.
        .DESCRIPTION

        .EXAMPLE
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
            Set-AdAclDelegateComputerAdmin -Group "SG_SiteAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
        .INPUTS
            Param1 Group:........[STRING] for the Delegated Group Name
            Param2 LDAPPath:.....[STRING] Distinguished Name of the OU where given group will fully manage a computer object.
            Param3 RemoveRule:...[SWITCH] If present, the access rule will be removed
        .NOTES
            Version:         1.0
            DateModified:    19/Oct/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param
    (
        # PARAM1 STRING for the Delegated Group Name
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Identity of the group getting the delegation, usually a DomainLocal group.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Group,

        # PARAM2 Distinguished Name of the OU where given group can read the computer password
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the OU where given group will fully manage a computer object',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        # PARAM3 Distinguished Name of the quarantine OU
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished Name of the quarantine OU',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String]
        $QuarantineDN,

        # PARAM4 SWITCH If present, the access rule will be removed.
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'If present, the access rule will be removed.',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [Switch]
        $RemoveRule

    )
    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        $parameters = $null

        # Active Directory Domain Distinguished Name
        If(-Not (Test-Path -Path variable:AdDn))
        {
            New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
        }
    }
    Process {
        try {
            $parameters = @{
                Group    = $PSBoundParameters['Group']
                LDAPPath = $PSBoundParameters['LDAPpath']
            }
            # Check if RemoveRule switch is present.
            If($PSBoundParameters['RemoveRule']) {
                # Add the parameter to remove the rule
                $parameters.Add('RemoveRule', $true)
            }

            # Create/Delete Computers
            Set-AdAclCreateDeleteComputer @parameters

            # Reset Computer Password
            Set-AdAclResetComputerPassword @parameters

            # Change Computer Password
            Set-AdAclChangeComputerPassword @parameters

            # Validated write to DNS host name
            Set-AdAclValidateWriteDnsHostName @parameters

            # Validated write to SPN
            Set-AdAclValidateWriteSPN @parameters

            # Change Computer Account Restriction
            Set-AdAclComputerAccountRestriction @parameters

            # Change DNS Hostname Info
            Set-AdAclDnsInfo @parameters

            # Change MS TerminalServices info
            Set-AdAclMsTsGatewayInfo @parameters

            # Access to BitLocker & TMP info
            Set-AdAclBitLockerTPM @parameters

            # Grant the right to delete computers from default container. Move Computers
            Set-DeleteOnlyComputer -Group $PSBoundParameters['Group'] -LDAPPath $PSBoundParameters['QuarantineDN']

            # Set LAPS
            Set-AdAclLaps -ResetGroup $PSBoundParameters['Group'] -ReadGroup $PSBoundParameters['Group'] -LDAPPath $PSBoundParameters['LDAPpath']

        }
        catch { throw }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished delegating Computer Admin."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Start-AdAclDelegateComputerAdmin
#EndRegion - Start-AdAclDelegateComputerAdmin.ps1
#Region - Start-AdCleanOU.ps1
# Clean OU from default BuiltIn groups
function Start-AdCleanOU
{
    <#
        .Synopsis
            The function will remove some of the default premission on
            the provided OU. It will remove the "Account Operators" and
            "Print Operators" built-in groups.
        .DESCRIPTION
            Long description
        .EXAMPLE
            Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
        .INPUTS
            Param1 LDAPPath:................... [STRING] Distinguished name of the OU to be cleaned.
            Param2 RemoveAuthenticatedUsers:... [SWITCH] Remove Authenticated Users.
            Param3 RemoveUnknownSIDs:.......... [SWITCH] Remove Unknown SIDs.
        .NOTES
            Version:         1.2
            DateModified:    19/Dec/2017
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    param
    (
        #PARAM1 Distinguished name of the OU to be cleaned
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Distinguished name of the OU to be cleaned.',
        Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $LDAPpath,

        #PARAM2 Remove Authenticated Users
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remove Authenticated Users.',
        Position = 1)]
        [switch]
        $RemoveAuthenticatedUsers,

        #PARAM3 Remove Unknown SIDs
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Remove Unknown SIDs.',
        Position = 2)]
        [switch]
        $RemoveUnknownSIDs

    )
    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

        Write-Verbose -Message 'Removing Account Operators and Print Operators'

        $Parameters = $null
    }
    process {
        $parameters = @{
            Group      = 'Account Operators'
            LDAPPath   = $PSBoundParameters['LDAPPath']
            RemoveRule = $true
        }
        # Remove the Account Operators group from ACL to Create/Delete Users
        Set-AdAclCreateDeleteUser @parameters

        # Remove the Account Operators group from ACL to Create/Delete Computers
        Set-AdAclCreateDeleteComputer @parameters

        # Remove the Account Operators group from ACL to Create/Delete Groups
        Set-AdAclCreateDeleteGroup @parameters

        # Remove the Account Operators group from ACL to Create/Delete Contacts
        Set-AdAclCreateDeleteContact @parameters

        # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
        Set-CreateDeleteInetOrgPerson @parameters

        # Remove the Print Operators group from ACL to Create/Delete PrintQueues
        Set-AdAclCreateDeletePrintQueue @parameters

        # Remove Pre-Windows 2000 Compatible Access group from Admin-User
        Remove-PreWin2000 -LDAPPath $PSBoundParameters['LDAPPath']

        # Remove Pre-Windows 2000 Access group from OU
        Remove-PreWin2000FromOU -LDAPPath $PSBoundParameters['LDAPPath']

        # Remove ACCOUNT OPERATORS 2000 Access group from OU
        Remove-AccountOperator -LDAPPath $PSBoundParameters['LDAPPath']

        # Remove PRINT OPERATORS 2000 Access group from OU
        Remove-PrintOperator -LDAPPath $PSBoundParameters['LDAPPath']

        If($PsBoundParameters['RemoveAuthenticatedUsers']) {
            # Remove AUTHENTICATED USERS group from OU
            Remove-AuthUser -LDAPPath $PSBoundParameters['LDAPPath']

            Write-Verbose -Message 'Removing Authenticated Users'
        }

        If($PsBoundParameters['$RemoveUnknownSIDs']) {
            # Remove Un-Resolvable SID from a given object
            Remove-UnknownSID -LDAPPath $PSBoundParameters['LDAPPath'] -RemoveSID

            Write-Verbose -Message 'Remove Un-Resolvable / Unknown SIDs'
        }

    }
    end {
        Write-Verbose -Message('Builtin groups were removed correctly from object {0}.' -f $PSBoundParameters['LDAPPath'])
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Start-AdCleanOU
#EndRegion - Start-AdCleanOU.ps1
#Region - Start-AdDelegatedSite.ps1
# Delegate Rights to SITE groups
function Start-AdDelegateSite
{
    <#
        .Synopsis
            The function will create
        .DESCRIPTION
            Long description
        .EXAMPLE
            Start-AdDelegateSite -ConfigXMLFile "C:\PsScripts\Config.xml" -ouName "GOOD" -QuarantineDN "Quarantine" -CreateExchange -DMscripts "C:\PsScripts\"
        .INPUTS
            Param1 ConfigXMLFile:....[String] Full path to the Configuration.XML file
            Param1 ouName:...........[String] Enter the Name of the Site OU
            Param2 QuarantineDN:.....[String] Enter the Name new redirected OU for computers
            Param3 CreateExchange:...[String] If present It will create all needed Exchange objects and containers.
            Param4 DMscripts:........[String] Path to all the scripts and files needed by this function
        .NOTES
            Version:         1.3
            DateModified:    12/Feb/2019
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium', DefaultParameterSetName = 'ParamOptions')]
    param
    (
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory=$true, ValueFromPipeline=$True, ValueFromPipelineByPropertyName=$True, ValueFromRemainingArguments=$false,
            HelpMessage='Full path to the configuration.xml file',
            Position=0)]
        [string]
        $ConfigXMLFile,

        #PARAM2
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            ParameterSetName = 'ParamOptions',
            HelpMessage = 'Enter the Name of the Site OU',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ouName,

        #PARAM3
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            ParameterSetName = 'ParamOptions',
            HelpMessage = 'Enter the Name new redirected OU for computers',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [String]
        $QuarantineDN,

        # Param4 Create Exchange Objects
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'If present It will create all needed Exchange objects and containers.',
            Position = 3)]
        [switch]
        $CreateExchange,

        # Param5 Location of all scripts & files
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
        Position = 4)]
        [string]
        $DMscripts = "C:\PsScripts\",

        # PARAM6 Switch indicating if local server containers has to be created. Not recommended due TIer segregation
        [Parameter(Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, ValueFromRemainingArguments = $false,
            HelpMessage='Switch indicating if local server containers has to be created. Not recommended due TIer segregation',
            Position=5)]
        [switch]
        $CreateSrvContainer

    )
    begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Write-Verbose -Message 'Delegate Rights Site Groups'

        ################################################################################
        #region Declarations

        try {
            # Active Directory Domain Distinguished Name
            If(-Not (Test-Path -Path variable:AdDn)) {
                New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
            }

            # Check if Config.xml file is loaded. If not, proceed to load it.
            If(-Not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                If(Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        }
        catch { throw }


        # Naming conventions hashtable
        $NC = @{'sl'    = $confXML.n.NC.LocalDomainGroupPreffix;
                'sg'    = $confXML.n.NC.GlobalGroupPreffix;
                'su'    = $confXML.n.NC.UniversalGroupPreffix;
                'Delim' = $confXML.n.NC.Delimiter;
                'T0'    = $confXML.n.NC.AdminAccSufix0;
                'T1'    = $confXML.n.NC.AdminAccSufix1;
                'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0


        ###############################################################################
        #region Get all newly created Groups and store on variable

        # Iterate through all Site-DomainLocalGroups child nodes
        Foreach($node in $confXML.n.Sites.LG.ChildNodes) {

            $TempName = '{0}{1}{2}{1}{3}' -f $NC['sl'], $NC['Delim'], $node.Name, $PSBoundParameters['ouName']

            Write-Verbose -Message ('Get group {0}' -f $TempName)

            New-Variable -Name "$($TempName)" -Value (Get-AdGroup $TempName) -Force
        }

        #endregion
        ###############################################################################


        # Sites OU Distinguished Name
        If(-Not (Test-Path -Path variable:ouNameDN)) {
            $ouNameDN = 'OU={0},OU={1},{2}' -f $ouName, $confXML.n.Sites.OUs.SitesOU.name, $AdDn
        }

        $OuSiteDefComputer    = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteComputer.name, $ouNameDN
        $OuSiteDefLaptop      = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLaptop.name, $ouNameDN

        if($PSBoundParameters['CreateSrvContainer']) {
            $OuSiteDefLocalServer = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteLocalServer.name, $ouNameDN
            $OuSiteDefFilePrint   = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteFilePrint.name, $ouNameDN
        }

        $OuSiteDefMailbox   = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteMailbox.name, $ouNameDN
        $OuSiteDefDistGroup = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteDistGroup.name, $ouNameDN
        $OuSiteDefContact   = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteContact.name, $ouNameDN

        # parameters variable for splatting CMDlets
        $parameters = $null

        #endregion
        ###############################################################################
    }
    process {
        Write-Verbose -Message 'START USER Site Delegation'
        ###############################################################################
        #region USER Site Administrator Delegation

        $OuSiteDefUser = 'OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteUser.name, $ouNameDN

        $parameters = @{
            Group    = $SL_PwdRight.SamAccountName
            LDAPPath = $OuSiteDefUser
        }

        # Reset User Password
        Set-AdAclResetUserPassword @parameters
        #Set-AdAclResetUserPassword -Group $SL_CreateUserRight.SamAccountName -LDAPPath $OuSiteDefUser

        # Change User Password
        Set-AdAclChangeUserPassword @parameters

        # Unlock user account
        Set-AdAclUnlockUser @parameters


        $parameters = @{
            Group    = $SL_CreateUserRight.SamAccountName
            LDAPPath = $OuSiteDefUser
        }

        # Create/Delete Users
        Set-AdAclCreateDeleteUser @parameters

        # Enable and/or Disable user right
        Set-AdAclEnableDisableUser @parameters

        # Change User Restrictions
        Set-AdAclUserAccountRestriction @parameters

        # Change User Account Logon Info
        Set-AdAclUserLogonInfo @parameters


        #### GAL

        $parameters = @{
            Group    = $SL_GALRight.SamAccountName
            LDAPPath = $OuSiteDefUser
        }

        # Change Group Membership
        Set-AdAclUserGroupMembership @parameters

        # Change Personal Information
        Set-AdAclUserPersonalInfo @parameters

        # Change Public Information
        Set-AdAclUserPublicInfo @parameters

        # Change General Information
        Set-AdAclUserGeneralInfo @parameters

        # Change Web Info
        Set-AdAclUserWebInfo @parameters

        # Change Email Info
        Set-AdAclUserEmailInfo @parameters

        #endregion USER Site Delegation
        ###############################################################################

        Write-Verbose -Message 'START COMPUTER Site Delegation'
        ###############################################################################
        #region COMPUTER Site Admin Delegation

        # Create/Delete Computers
        Set-AdAclDelegateComputerAdmin -Group $SL_PcRight.SamAccountName          -LDAPPath $OuSiteDefComputer    -QuarantineDN $PSBoundParameters['QuarantineDN']
        Set-AdAclDelegateComputerAdmin -Group $SL_PcRight.SamAccountName          -LDAPPath $OuSiteDefLaptop      -QuarantineDN $PSBoundParameters['QuarantineDN']

        # Grant the right to delete computers from default container. Move Computers
        Set-DeleteOnlyComputer -Group $SL_PcRight.SamAccountName          -LDAPPath $PSBoundParameters['QuarantineDN']

        #### GAL

        # Change Personal Info
        Set-AdAclComputerPersonalInfo -Group $SL_GALRight.SamAccountName         -LDAPPath $OuSiteDefComputer
        Set-AdAclComputerPersonalInfo -Group $SL_GALRight.SamAccountName         -LDAPPath $OuSiteDefLaptop

        # Change Public Info
        Set-AdAclComputerPublicInfo -Group $SL_GALRight.SamAccountName         -LDAPPath $OuSiteDefComputer
        Set-AdAclComputerPublicInfo -Group $SL_GALRight.SamAccountName         -LDAPPath $OuSiteDefLaptop


        if($PSBoundParameters['CreateSrvContainer']) {
            # Create/Delete Computers
            Set-AdAclDelegateComputerAdmin -Group $SL_LocalServerRight.SamAccountName -LDAPPath $OuSiteDefFilePrint   -QuarantineDN $PSBoundParameters['QuarantineDN']
            Set-AdAclDelegateComputerAdmin -Group $SL_LocalServerRight.SamAccountName -LDAPPath $OuSiteDefLocalServer -QuarantineDN $PSBoundParameters['QuarantineDN']

            # Grant the right to delete computers from default container. Move Computers
            Set-DeleteOnlyComputer -Group $SL_LocalServerRight.SamAccountName -LDAPPath $PSBoundParameters['QuarantineDN']

            #### GAL

            # Change Personal Info
            Set-AdAclComputerPersonalInfo -Group $SL_LocalServerRight.SamAccountName -LDAPPath $OuSiteDefFilePrint
            Set-AdAclComputerPersonalInfo -Group $SL_LocalServerRight.SamAccountName -LDAPPath $OuSiteDefLocalServer

            # Change Public Info
            Set-AdAclComputerPublicInfo -Group $SL_LocalServerRight.SamAccountName -LDAPPath $OuSiteDefFilePrint
            Set-AdAclComputerPublicInfo -Group $SL_LocalServerRight.SamAccountName -LDAPPath $OuSiteDefLocalServer
        }




        #endregion COMPUTER Site Delegation
        ###############################################################################

        Write-Verbose -Message 'START GROUP Site Delegation'
        ###############################################################################
        #region GROUP Site Admin Delegation

        # Create/Delete Groups
        Set-AdAclCreateDeleteGroup -Group $SL_GroupRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteGroup.name, $ouNameDN)

        #### GAL

        # Change Group Properties
        Set-AdAclChangeGroup -Group $SL_GroupRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteGroup.name, $ouNameDN)

        #endregion GROUP Site Delegation
        ###############################################################################

        Write-Verbose -Message 'START PRINTQUEUE Site Admin Delegation'
        ###############################################################################
        #region PRINTQUEUE Site Admin Delegation

        # Create/Delete Print Queue
        Set-AdAclCreateDeletePrintQueue -Group $SL_SiteRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSitePrintQueue.name, $ouNameDN)

        #endregion PRINTQUEUE Site Admin Delegation
        ###############################################################################

        Write-Verbose -Message 'START PRINTQUEUE Site GAL Delegation'
        ###############################################################################
        #region PRINTQUEUE Site GAL Delegation

        Set-AdAclChangePrintQueue -Group $SL_GALRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSitePrintQueue.name, $ouNameDN)

        #endregion PRINTQUEUE Site GAL Delegation
        ###############################################################################

        Write-Verbose -Message 'START VOLUME Site Admin Delegation'
        ###############################################################################
        #region VOLUME Site Admin Delegation

        # Create/Delete Volume
        Set-AdAclCreateDeleteVolume -Group $SL_SiteRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteShares.name, $ouNameDN)

        #endregion VOLUME Site Admin Delegation
        ###############################################################################

        Write-Verbose -Message 'START VOLUME Site GAL Delegation'
        ###############################################################################
        #region VOLUME Site GAL Delegation

        # Change Volume Properties
        Set-AdAclChangeVolume -Group $SL_GALRight.SamAccountName -LDAPPath ('OU={0},{1}' -f $confXML.n.Sites.OUs.OuSiteShares.name, $ouNameDN)

        #endregion VOLUME Site GAL Delegation
        ###############################################################################

        Write-Verbose -Message 'START Exchange Related delegation'
        ###############################################################################
        #region Exchange Related delegation
        ###############################################################################
        If($PSBoundParameters['CreateExchange']) {
            # USER class
            # Create/Delete Users
            Set-AdAclCreateDeleteUser -Group $SL_CreateUserRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Reset User Password
            Set-AdAclResetUserPassword -Group $SL_PwdRight.SamAccountName -LDAPPath $OuSiteDefMailbox
            #Set-AdAclResetUserPassword -Group $SL_CreateUserRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change User Password
            Set-AdAclChangeUserPassword -Group $SL_PwdRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change User Restrictions
            Set-AdAclUserAccountRestriction -Group $SL_SiteRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change User Account Logon Info
            Set-AdAclUserLogonInfo -Group $SL_SiteRight.SamAccountName -LDAPPath $OuSiteDefMailbox
            #--------------------------------------------------
            # Change Group Membership
            Set-AdAclUserGroupMembership     -Group $SL_SiteRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change Personal Information
            Set-AdAclUserPersonalInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change Public Information
            Set-AdAclUserPublicInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change General Information
            Set-AdAclUserGeneralInfo  -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change Web Info
            Set-AdAclUserWebInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # Change Email Info
            Set-AdAclUserEmailInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefMailbox

            # GROUP Class
            # Create/Delete Groups
            Set-AdAclCreateDeleteGroup -Group $SL_GroupRight.SamAccountName -LDAPPath $OuSiteDefDistGroup
            #--------------------------------------------------
            # Change Group Properties
            Set-AdAclChangeGroup -Group $SL_GroupRight.SamAccountName -LDAPPath $OuSiteDefDistGroup

            # CONTACT Class
            # Create/Delete Contacts
            Set-AdAclCreateDeleteContact -Group $SL_SiteRight.SamAccountName -LDAPPath $OuSiteDefContact
            #--------------------------------------------------
            # Change Personal Info
            Set-AdAclContactPersonalInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefContact

            # Change Web Info
            Set-AdAclContactWebInfo -Group $SL_GALRight.SamAccountName -LDAPPath $OuSiteDefContact
        }
        #endregion Exchange Related delegation
        ###############################################################################
    }
    end {
        Write-Verbose -Message ('Site delegation was completed succesfully to {0}' -f $PSBoundParameters['ouName'])
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Start-AdDelegatedSite
#EndRegion - Start-AdDelegatedSite.ps1
#Region - Test-IPv4MaskString.ps1
function Test-IPv4MaskString {
    <#
        .SYNOPSIS
            Tests whether an IPv4 network mask string (e.g., "255.255.255.0") is valid.

        .DESCRIPTION
            Tests whether an IPv4 network mask string (e.g., "255.255.255.0") is valid.

        .PARAMETER MaskString
            Specifies the IPv4 network mask string (e.g., "255.255.255.0").

        .EXAMPLE
            Test-IPv4MaskString -MaskString "255.255.255.0"

        .INPUTS
            Param1  MaskString:............ [STRING] Specifies the IPv4 network mask string
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param
    (
        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = "Specifies the IPv4 network mask string (e.g., 255.255.255.0)",
        Position = 1)]
        [String] $MaskString
    )
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
        $validBytes = '0|128|192|224|240|248|252|254|255'
        $maskPattern = ('^((({0})\.0\.0\.0)|'      -f $validBytes) +
             ('(255\.({0})\.0\.0)|'      -f $validBytes) +
             ('(255\.255\.({0})\.0)|'    -f $validBytes) +
             ('(255\.255\.255\.({0})))$' -f $validBytes)
        $MaskString -match $maskPattern
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Test-IPv4MaskString
#EndRegion - Test-IPv4MaskString.ps1
#Region - Test-RegistryValue.ps1
function Test-RegistryValue
{
    <#
        .Synopsis
            Function to Test Registry Values
        .DESCRIPTION

        .INPUTS
            Param1 Path:...[STRING] Registry path to be tested
            Param2 Value:..[STRING] Registry value to be tested
        .EXAMPLE
            Test-RegistryValue -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value "AutoAdminLogon"
            Test-RegistryValue "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
        .NOTES
            Version:         1.0
            DateModified:    16/Ene/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
  #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([Bool])]
    Param (
        [parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Registry path to be tested',
        Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Registry value to be tested',
        Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Value
    )
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
        try {
            Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            return $false
        }
    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished testing registry."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
Export-ModuleMember -Function Test-RegistryValue
#EndRegion - Test-RegistryValue.ps1
### --- PRIVATE FUNCTIONS --- ###
#Region - Add-AdGroupNesting.ps1

# http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx
# http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/
function Add-AdGroupNesting
{
    <#
        .SYNOPSIS
            Same as Add-AdGroupMember but with error handling and loging
        .DESCRIPTION
            Same as Add-AdGroupMember but with error handling and loging
        .EXAMPLE
            Add-AdGroupNesting -Identity "Domain Admins" -Members TheUgly
        .NOTES
            Version:         1.0
            DateModified:    22/Jun/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param
    (
        # Param1 Group which membership is to be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Group which membership is to be changed',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Identity,

        # Param2 ID of New Member of the group
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'ID of New Member of the group. Can be a single string or array.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        $Members
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Import-Module -name ActiveDirectory -Verbose:$false

        # Active Directory Domain Distinguished Name
        If(-Not (Test-Path -Path variable:AdDn))
        {
            New-Variable -Name 'AdDn' -Value ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString() -Option ReadOnly -Force
        }

        # Define an empty array
        $CurrentMembers = @()
        $NewMembers     = @()
        $parameters     = $null

        If($identity.GetType() -eq [Microsoft.ActiveDirectory.Management.AdGroup])
        {
            $Group = Get-AdGroup -Identity $Identity.ObjectGUID
        }

        If($identity.GetType() -eq [System.String])
        {
            If($identity -ccontains $AdDn)
            {
                $Group = Get-AdGroup -Filter { distinguishedName -eq $Identity }
            }
            ELSE
            {
                $Group = Get-AdGroup -Filter { samAccountName -eq $Identity }
            }
        }
    }
    Process {
        # Get group members
        Get-AdGroupMember -Identity $Group.SID | Select-Object -ExpandProperty sAMAccountName | ForEach-Object { $CurrentMembers += $_ }

        try
        {
            Write-Verbose -Message ('Adding members to group..: {0}' -f $Group.SamAccountName)

            Foreach ($item in $Members)
            {
                If($CurrentMembers -notcontains $item) {
                    $NewMembers += $item
                }
                else
                {
                     Write-Verbose -Message ('{0} is already member of {1} group' -f $item.SamAccountName, $Group.SamAccountName)
                }
            }
            If($NewMembers.Count -gt 0)
            {
                $parameters = @{
                    Identity = $Group
                    Members  = $NewMembers
                }
                Add-AdGroupMember @parameters
            }
            #Add-AdGroupMember @parameters

            Write-Verbose -Message ('Member {0} was added correctly to group {1}' -f $Members, $Group.sAMAccountName)
        }
        catch { throw }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
#EndRegion - Add-AdGroupNesting.ps1
#Region - Get-AdObjectType.ps1
function Get-AdObjectType
{
  [CmdletBinding(ConfirmImpact = 'Medium')]
  Param
  (
    # Param1
    [Parameter(Mandatory = $true,HelpMessage = 'Add help message for user',
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ValueFromRemainingArguments = $false,
    Position = 0)]
    [ValidateNotNullOrEmpty()]
    $Identity
  )
  Begin
  {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

        $ReturnValue = $null
  }
  Process
  {
    If($Identity -is [Microsoft.ActiveDirectory.Management.ADAccount])
    {
      Write-Verbose -Message 'AD User Object'
      return [Microsoft.ActiveDirectory.Management.ADAccount]$ReturnValue = $Identity
    }

    If($Identity -is [Microsoft.ActiveDirectory.Management.ADComputer])
    {
      Write-Verbose -Message 'AD Computer Object'
      return [Microsoft.ActiveDirectory.Management.ADComputer]$ReturnValue = $Identity
    }

    If($Identity -is [Microsoft.ActiveDirectory.Management.AdGroup])
    {
      Write-Verbose -Message 'AD Group Object'
      return [Microsoft.ActiveDirectory.Management.AdGroup]$ReturnValue = $Identity
    }

    If($Identity -is [String])
    {
      Write-Verbose -Message 'Simple String'
      $newObject = get-AdObject -filter {
        SamAccountName -eq $Identity
      }
      Switch ($newObject.ObjectClass)
      {
        'user'
        {
          Write-Verbose -Message 'AD User Object from STRING'
          return [Microsoft.ActiveDirectory.Management.ADAccount]$ReturnValue = Get-AdUser -Identity $Identity
        }
        'group'
        {
          Write-Verbose -Message 'AD Group Object from STRING'
          return [Microsoft.ActiveDirectory.Management.AdGroup]$ReturnValue   = Get-ADGroup -Identity $Identity
        }
        'computer'
        {
          Write-Verbose -Message 'AD Computer Object from STRING'
          return [Microsoft.ActiveDirectory.Management.AdGroup]$ReturnValue   = Get-AdComputer -Identity $Identity
        }
      }
    }
  }
  End {
      Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting AD object type."
      Write-Verbose -Message ''
      Write-Verbose -Message '-------------------------------------------------------------------------------'
      Write-Verbose -Message ''
  }
}
#EndRegion - Get-AdObjectType.ps1
#Region - Get-IniContent.ps1
function Get-IniContent
{
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

  [CmdletBinding(ConfirmImpact = 'Medium')]
  [OutputType([System.Collections.Hashtable])]
  Param(
    [ValidateNotNullOrEmpty()]
    [Parameter(ValueFromPipeline = $true,HelpMessage = 'Path and Filename to the ini file to be read',Mandatory = $true)]
    [string]$FilePath
  )

    Begin
    {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"
    }

  Process
  {
    Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Processing file: $PSBoundParameters['FilePath']"

    $ini = @{}
    switch -regex -file $PSBoundParameters['FilePath']
    {
      '^\[(.+)\]$' # Section
      {
        $section = $matches[1]
        $ini[$section] = @{}
        $CommentCount = 0
      }
      '^(;.*)$' # Comment
      {
        if (!($section))
        {
          $section = 'No-Section'
          $ini[$section] = @{}
        }
        $value = $matches[1]
        $CommentCount = $CommentCount + 1
        $name = 'Comment' + $CommentCount
        $ini[$section][$name] = $value
      }
      '(.+?)\s*=\s*(.*)' # Key
      {
        if (!($section))
        {
          $section = 'No-Section'
          $ini[$section] = @{}
        }
        $name, $value = $matches[1..2]
        $ini[$section][$name] = $value
      }
    }
    Write-Verbose -Message "$($myInvocation.MyCommand.Name):: Finished Processing file: $PSBoundParameters['FilePath']"
    Return $ini
  }

    End
    {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished reading content from $PSBoundParameters['FilePath'] file."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
#EndRegion - Get-IniContent.ps1
#Region - Get-RandomHex.ps1
Function Get-RandomHex {
param ([int]$Length)
    $Hex = '0123456789ABCDEF'
    [string]$Return = $null
    For ($i=1;$i -le $length;$i++) {
        $Return += $Hex.Substring((Get-Random -Minimum 0 -Maximum 16),1)
    }
    Return $Return
}
#EndRegion - Get-RandomHex.ps1
#Region - IsUniqueOID.ps1
Function IsUniqueOID {
    [CmdletBinding(ConfirmImpact = 'low')]
    [OutputType([System.Boolean])]
    param (
        $cn,
        $TemplateOID,
        $Server,
        $ConfigNC
    )
    $Search = Get-ADObject -Server $Server `
        -SearchBase "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
        -Filter {cn -eq $cn -and msPKI-Cert-Template-OID -eq $TemplateOID}
    If ($Search) {$False} Else {$True}
}
#EndRegion - IsUniqueOID.ps1
#Region - New-Template.ps1
Function New-Template {
    [CmdletBinding(ConfirmImpact = 'Medium')]
    Param(
        $DisplayName,
        $TemplateOtherAttributes
    )

    #grab DC
    $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
    #grab Naming Context
    $ConfigNC = (Get-ADRootDSE -Server $Server).configurationNamingContext
    #Create OID
        $OID = New-TemplateOID -Server $Server -ConfigNC $ConfigNC
        $TemplateOIDPath = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
        $OIDOtherAttributes = @{
                'DisplayName' = $DisplayName
                'flags' = [System.Int32]'1'
                'msPKI-Cert-Template-OID' = $OID.TemplateOID
        }
        New-ADObject -Path $TemplateOIDPath -OtherAttributes $OIDOtherAttributes -Name $OID.TemplateName -Type 'msPKI-Enterprise-Oid' -Server $Server
    #Create Template itself
        $TemplateOtherAttributes+= @{
            'msPKI-Cert-Template-OID' = $OID.TemplateOID
        }
        $TemplatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
        New-ADObject -Path $TemplatePath -OtherAttributes $TemplateOtherAttributes -Name $DisplayName -DisplayName $DisplayName -Type pKICertificateTemplate -Server $Server
}
#EndRegion - New-Template.ps1
#Region - New-TemplateOID.ps1
Function New-TemplateOID {
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([System.Collections.Hashtable])]
    Param(
        $Server,
        $ConfigNC
    )
    <#
    OID CN/Name                    [10000000-99999999].[32 hex characters]
    OID msPKI-Cert-Template-OID    [Forest base OID].[1000000-99999999].[10000000-99999999]  <--- second number same as first number in OID name
    #>
    do {
        $OID_Part_1 = Get-Random -Minimum 1000000  -Maximum 99999999
        $OID_Part_2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $OID_Part_3 = Get-RandomHex -Length 32
        $OID_Forest = Get-ADObject -Server $Server `
            -Identity "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC" `
            -Properties msPKI-Cert-Template-OID |
            Select-Object -ExpandProperty msPKI-Cert-Template-OID
        $msPKICertTemplateOID = "$OID_Forest.$OID_Part_1.$OID_Part_2"
        $Name = "$OID_Part_2.$OID_Part_3"
    } until (IsUniqueOID -cn $Name -TemplateOID $msPKICertTemplateOID -Server $Server -ConfigNC $ConfigNC)
    Return @{
        TemplateOID  = $msPKICertTemplateOID
        TemplateName = $Name
    }
}
#EndRegion - New-TemplateOID.ps1
#Region - Out-IniFile.ps1
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

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"
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
#EndRegion - Out-IniFile.ps1
#Region - PublishCert.ps1
Function PublishCert {
    Param (
        $CertDisplayName
    )
    #Publish  Template
    #grab DC
    $Server = (Get-ADDomainController -Discover -ForceDiscover -Writable).HostName[0]
    #grab Naming Context
    $ConfigNC = (Get-ADRootDSE -Server $Server).configurationNamingContext

    ### WARNING: Issues on all available CAs. Test in your environment.
    $EnrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"
    $CAs = Get-ADObject -SearchBase $EnrollmentPath -SearchScope OneLevel -Filter * -Server $Server
    ForEach ($CA in $CAs) {
        Set-ADObject -Identity $CA.DistinguishedName -Add @{certificateTemplates=$CertDisplayName.Replace(' ','')} -Server $Server
    }
}
#EndRegion - PublishCert.ps1
