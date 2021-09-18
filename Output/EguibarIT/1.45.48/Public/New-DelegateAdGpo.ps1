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