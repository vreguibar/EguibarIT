function New-AreaShareNTFS {
    <#
        .SYNOPSIS
            Creates a new NTFS-secured area folder share with role-based access groups.

        .DESCRIPTION
            Creates a new NTFS-secured area folder share with three role-based access groups:
            - ReadGroup: Read-only access
            - ChangeGroup: Modify access
            - SiteAdminGroup: Full control

        .PARAMETER ShareName
            [String] Name of the share to be created.

        .PARAMETER readGroup
            [String] Name of the group with Read-Only permissions.

        .PARAMETER changeGroup
            [String] Name of the group with Change (Modify) permissions.

        .PARAMETER SG_SiteAdminsGroup
            [String] Name of the group with Full Control permissions.

        .PARAMETER sitePath
            [String] File system path where the area share will be created.

        .EXAMPLE
            New-AreaShareNTFS -ShareName 'Accounting' -ReadGroup 'SL_Accounting_Read' -ChangeGroup 'SL_Accounting_Write' -SiteAdminGroup 'SG_Accounting_MNGT' -SitePath 'C:\Shares\Areas\Accounting'

            Creates a new area share with the specified groups.

        .EXAMPLE
            $Splat = @{
                ShareName        = 'Finance'
                ReadGroup        = 'SL_Finance_Read'
                ChangeGroup      = 'SL_Finance_Write'
                SG_SiteAdminsGroup = 'SG_Finance_MNGT'
                SitePath         = 'D:\Shares\Finance'
            }
            New-AreaShareNTFS @Splat

            Creates a Finance share using splatting.

        .EXAMPLE
            New-AreaShareNTFS -ShareName 'IT' -ReadGroup 'SL_IT_Read' -ChangeGroup 'SL_IT_Write' -SiteAdminGroup 'SG_IT_MNGT' -SitePath 'D:\Shares\IT' -WhatIf

            Shows what would happen when creating an IT area share.

        .INPUTS
            [System.String]
            You can pipe parameter values to this function.

        .OUTPUTS
            [System.String]
            Returns a status string indicating success or failure.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Grant-NTFSPermission                   ║ EguibarIT
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:    21/Sep/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/New-AreaShareNTFS.ps1

        .COMPONENT
            File System

        .ROLE
            Infrastructure Administration

        .FUNCTIONALITY
            NTFS Share Management
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([String])]

    param (
        # Param1 Share name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the share to be created',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ShareName,

        # Param2 Read group
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the group with Read-Only permissions',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $readGroup,

        # Param3 Change Group
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the group with Change permissions',
            Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]
        $changeGroup,

        # Param4 All Site Admins group
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name of the group with Full permissions',
            Position = 3)]
        [ValidateNotNullOrEmpty()]
        [string]
        $SG_SiteAdminsGroup,

        # Param5 Path to the site
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'DistinguishedName where the new Groups will be created.',
            Position = 4)]
        [ValidateNotNullOrEmpty()]
        [string]
        $sitePath,

        # Param6
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Absolute path to the root Share folder (e.g. "C:\Shares\")',
            Position = 5)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ShareLocation,

        # Param7
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'The root share name for general areas.',
            Position = 6)]
        [ValidateNotNullOrEmpty()]
        [string]
        $AreasName
    )

    begin {
        Set-StrictMode -Version Latest

        # Initialize logging
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end If

        ##############################
        # Module imports

        ##############################
        # Variables Definition

        # Create Full Share Name
        $FullShareName = '{0}\{1}\{2}' -f $PSBoundParameters['ShareLocation'], $PSBoundParameters['AreasName'], $PSBoundParameters['ShareName']

        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
    } #end Begin

    process {
        if ($PSCmdlet.ShouldProcess($PSBoundParameters['ShareName'], 'Create shared folder with NTFS permissions')) {
            if (-not(Test-Path -Path $FullShareName)) {
                # Create the new Directory
                New-Item -Path $FullShareName -ItemType Directory
            } #end If

            # Create the associated READ group
            $Splat = @{
                Name          = $PSBoundParameters['readGroup']
                GroupCategory = 'Security'
                GroupScope    = 'DomainLocal'
                DisplayName   = $PSBoundParameters['readGroup']
                Path          = $PSBoundParameters['sitePath']
                Description   = 'Read Access to Share {0}' -f $PSBoundParameters['ShareName']
            }
            New-AdDelegatedGroup @Splat

            # Create the associated Modify group
            $Splat = @{
                Name          = $PSBoundParameters['changeGroup']
                GroupCategory = 'Security'
                GroupScope    = 'DomainLocal'
                DisplayName   = $PSBoundParameters['changeGroup']
                Path          = $PSBoundParameters['sitePath']
                Description   = 'Read Access to Share {0}' -f $PSBoundParameters['ShareName']
            }
            New-AdDelegatedGroup @Splat

            Start-Sleep -Seconds 2

            Grant-NTFSPermission -path $FullShareName -object $PSBoundParameters['readGroup'] -permission 'ReadAndExecute'
            Grant-NTFSPermission -path $FullShareName -object $PSBoundParameters['changeGroup'] -permission 'Modify'
            Grant-NTFSPermission -path $FullShareName -object $PSBoundParameters['SG_SiteAdminsGroup'] -permission 'FullControl'

            #& "$env:windir\system32\net.exe" share $ShareName=$FullShareName '/GRANT:Everyone,FULL'

            New-SmbShare -Name $PSBoundParameters['ShareName'] -Path $FullShareName -FullAccess Everyone

            if ($error.count -eq 0) {
                Write-Verbose -Message ('The folder {0} was shared correctly.' -f $ShareName)
            } #end If
        } #end If ShouldProcess
    } #end Process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'creating shares.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
