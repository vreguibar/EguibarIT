function New-AreaShareNTFS {
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
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        # Create Full Share Name
        $FullShareName = '{0}\{1}\{2}' -f $PSBoundParameters['ShareLocation'], $PSBoundParameters['AreasName'], $PSBoundParameters['ShareName']

        $Splat    = [Hashtable]::New()
    } #end Begin

    Process {
        If(-not(test-path -Path $FullShareName)) {
            # Create the new Directory
            New-Item -Path $FullShareName -ItemType Directory
        } #end If

        # Create the associated READ group
        $Splat = @{
            Name                          = $PSBoundParameters['readGroup']
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $PSBoundParameters['readGroup']
            Path                          = $PSBoundParameters['sitePath']
            Description                   = 'Read Access to Share {0}' -f $PSBoundParameters['ShareName']
        }
        New-AdDelegatedGroup @Splat

        # Create the associated Modify group
        $Splat = @{
            Name                          = $PSBoundParameters['changeGroup']
            GroupCategory                 = 'Security'
            GroupScope                    = 'DomainLocal'
            DisplayName                   = $PSBoundParameters['changeGroup']
            Path                          = $PSBoundParameters['sitePath']
            Description                   = 'Read Access to Share {0}' -f $PSBoundParameters['ShareName']
        }
        New-AdDelegatedGroup @Splat

        Start-Sleep -Seconds 2

        Grant-NTFSPermission -path $FullShareName -object $PSBoundParameters['readGroup'] -permission 'ReadAndExecute, ChangePermissions'
        Grant-NTFSPermission -path $FullShareName -object $PSBoundParameters['changeGroup'] -permission 'Modify, ChangePermissions'
        Grant-NTFSPermission -path $FullShareName -object $PSBoundParameters['SG_SiteAdminsGroup'] -permission 'FullControl, ChangePermissions'

        #& "$env:windir\system32\net.exe" share $ShareName=$FullShareName '/GRANT:Everyone,FULL'

        New-SmbShare -Name $PSBoundParameters['ShareName'] -Path $FullShareName -FullAccess Everyone

        if ($error.count -eq 0) {
            Write-Verbose -Message ('The folder {0} was shared correctly.' -f $ShareName)
        } #end If
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating the share."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End

} #end Function
