function New-Tier0AdminGroup {

    <#
        .SYNOPSIS
            Creates Tier0 administrative groups in Active Directory following the tiered administration model.

        .DESCRIPTION
            This function creates all the necessary security groups needed for implementing a tiered administrative model.
            It creates both domain local and global security groups as defined in the configuration XML file.
            The groups are created in the appropriate OUs and are protected from accidental deletion.
            This follows Microsoft's recommended tiered administration model with separation of privilege.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            [System.String] Path to all the scripts and files needed by this function.
            Must contain a SecTmpl subfolder for security templates.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0AdminGroup -ConfigXMLFile C:\PsScripts\Config.xml
            Creates all Tier0 admin groups using the specified configuration file.

        .EXAMPLE
            New-Tier0AdminGroup -ConfigXMLFile C:\PsScripts\Config.xml -DMScripts C:\Scripts
            Creates Tier0 admin groups using the specified configuration file and scripts path.

        .INPUTS
            [System.IO.FileInfo]
            [System.String]

        .OUTPUTS
            [System.Void]

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Import-MyModule                            ║ EguibarIT
                Get-FunctionDisplay                        ║ EguibarIT
                New-AdDelegatedGroup                       ║ EguibarIT
                Set-ADObject                               ║ ActiveDirectory
                Move-ADObject                              ║ ActiveDirectory
                Get-ADGroup                                ║ ActiveDirectory

        .NOTES
            Version:         1.0
            DateModified:    29/Apr/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Active Directory

        .ROLE
            Administrator

        .FUNCTIONALITY
            Group Management, Security Hardening
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.Void])]

    param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0)]
        [ValidateScript({
                if (-Not ($_ | Test-Path -PathType Leaf) ) {
                    throw ('File not found: {0}' -f $_)
                }
                if ($_.Extension -ne '.xml') {
                    throw ('File must be XML: {0}' -f $_)
                }
                try {
                    [xml]$xml = Get-Content -Path $_ -ErrorAction Stop
                    # Verify required XML elements are present
                    if ($null -eq $xml.n.Admin -or
                        $null -eq $xml.n.Admin.OUs -or
                        $null -eq $xml.n.Admin.LG -or
                        $null -eq $xml.n.Admin.GG -or
                        $null -eq $xml.n.Servers.GG -or
                        $null -eq $xml.n.Servers.LG -or
                        $null -eq $xml.n.NC) {
                        throw 'XML file is missing required elements (Admin, OUs, LG, GG, Servers.GG, Servers.LG or NC section)'
                    }
                    return $true
                } catch {
                    throw ('Invalid XML file: {0}' -f $_.Exception.Message)
                }
            })]
        [PSDefaultValue(Help = 'Default Value is "C:\PsScripts\Config.xml"',
            Value = 'C:\PsScripts\Config.xml'
        )]
        [Alias('Config', 'XML', 'ConfigXml')]
        [System.IO.FileInfo]
        $ConfigXMLFile,

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Path to all the scripts and files needed by this function',
            Position = 1)]
        [PSDefaultValue(
            Help = 'Default Value is "C:\PsScripts\"',
            Value = 'C:\PsScripts\'
        )]
        [Alias('ScriptPath')]
        [string]
        $DMScripts = 'C:\PsScripts\',

        [Parameter(Mandatory = $false,
            ValueFromPipeline = $false,
            ValueFromPipelineByPropertyName = $false,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Start transcript logging to DMScripts path with function name',
            Position = 2)]
        [Alias('Transcript', 'Log')]
        [switch]
        $EnableTranscript

    )

    Begin {
        Set-StrictMode -Version Latest

        If (-not $PSBoundParameters.ContainsKey('ConfigXMLFile')) {
            $PSBoundParameters['ConfigXMLFile'] = 'C:\PsScripts\Config.xml'
        } #end If

        If (-not $PSBoundParameters.ContainsKey('DMScripts')) {
            $PSBoundParameters['DMScripts'] = 'C:\PsScripts\'
        } #end If

        # If EnableTranscript is specified, start a transcript
        if ($EnableTranscript) {
            # Ensure DMScripts directory exists
            if (-not (Test-Path -Path $DMScripts -PathType Container)) {
                try {
                    New-Item -Path $DMScripts -ItemType Directory -Force | Out-Null
                    Write-Verbose -Message ('Created transcript directory: {0}' -f $DMScripts)
                } catch {
                    Write-Warning -Message ('Failed to create transcript directory: {0}' -f $_.Exception.Message)
                } #end try-catch
            } #end if

            # Create transcript filename using function name and current date/time
            $TranscriptFile = Join-Path -Path $DMScripts -ChildPath ('{0}_{1}.LOG' -f $MyInvocation.MyCommand.Name, (Get-Date -Format 'yyyyMMdd_HHmmss'))

            try {
                Start-Transcript -Path $TranscriptFile -Force -ErrorAction Stop
                Write-Verbose -Message ('Transcript started: {0}' -f $TranscriptFile)
            } catch {
                Write-Warning -Message ('Failed to start transcript: {0}' -f $_.Exception.Message)
            } #end try-catch
        } #end if

        # Display function header
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

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # Parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Collection to store all groups for later processing
        [System.Collections.Generic.HashSet[object]]$AllGroups = [System.Collections.Generic.HashSet[object]]::New()

        # Load the XML configuration file
        try {
            [xml]$ConfXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        # Load naming conventions from XML
        [hashtable]$NC = @{
            'sl'    = $confXML.n.NC.LocalDomainGroupPreffix
            'sg'    = $confXML.n.NC.GlobalGroupPreffix
            'su'    = $confXML.n.NC.UniversalGroupPreffix
            'Delim' = $confXML.n.NC.Delimiter
            'T0'    = $confXML.n.NC.AdminAccSufix0
            'T1'    = $confXML.n.NC.AdminAccSufix1
            'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        # Generate DN paths for OUs
        [string]$ItAdminOu = $ConfXML.n.Admin.OUs.ItAdminOU.name
        [string]$ItAdminGroupsOu = $ConfXML.n.Admin.OUs.ItAdminGroupsOU.name
        [string]$ItRightsOu = $ConfXML.n.Admin.OUs.ItRightsOU.name
        [string]$ItPrivGroupsOu = $ConfXML.n.Admin.OUs.ItPrivGroupsOU.name

        # Build Distinguished Names
        [string]$ItAdminGroupsOuDn = ('OU={0},OU={1},{2}' -f $ItAdminGroupsOu, $ItAdminOu, $Variables.AdDn)
        [string]$ItRightsOuDn = ('OU={0},OU={1},{2}' -f $ItRightsOu, $ItAdminOu, $Variables.AdDn)
        [string]$ItPrivGroupsOuDn = ('OU={0},OU={1},{2}' -f $ItPrivGroupsOu, $ItAdminOu, $Variables.AdDn)

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Active Directory Privileged Groups', 'Create Tier0 Admin Groups')) {

            # Count total operations for progress tracking
            [int]$totalOperations = $confXML.n.Admin.LG.ChildNodes.Count +
            $confXML.n.Admin.GG.ChildNodes.Count +
            4 # Additional operations for server groups
            [int]$currentOperation = 0

            # Iterate through all Admin-LocalGroups child nodes
            Foreach ($Node in $confXML.n.Admin.LG.ChildNodes) {
                $currentOperation++

                # Update progress
                $progressParams = @{
                    Activity        = 'Creating Tier0 Admin Groups'
                    Status          = ('Creating group {0} ({1} of {2})' -f
                        ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $Node.Name),
                        $currentOperation, $totalOperations)
                    PercentComplete = ($currentOperation / $totalOperations * 100)
                }
                Write-Progress @progressParams

                Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $Node.LocalName))
                $Splat = @{
                    Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $Node.Name
                    GroupCategory                 = 'Security'
                    GroupScope                    = 'DomainLocal'
                    DisplayName                   = $Node.DisplayName
                    Path                          = $ItRightsOuDn
                    Description                   = $Node.Description
                    ProtectFromAccidentalDeletion = $true
                    RemoveAccountOperators        = $true
                    RemoveEveryone                = $true
                    RemovePreWin2000              = $true
                }
                $CreatedGroup = New-AdDelegatedGroup @Splat

                $VarParam = @{
                    Name  = 'SL{0}{1}' -f $NC['Delim'], $Node.LocalName
                    Value = $CreatedGroup
                    Scope = 'Global'
                    Force = $true
                }
                New-Variable @VarParam

                # Clear variable for next use
                $CreatedGroup = $null
            } #end ForEach

            # Iterate through all Admin-GlobalGroups child nodes
            Foreach ($Node in $confXML.n.Admin.GG.ChildNodes) {
                $currentOperation++

                # Update progress
                $progressParams = @{
                    Activity        = 'Creating Tier0 Admin Groups'
                    Status          = ('Creating group {0} ({1} of {2})' -f
                        ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.Name),
                        $currentOperation, $totalOperations)
                    PercentComplete = ($currentOperation / $totalOperations * 100)
                }
                Write-Progress @progressParams

                Write-Verbose -Message ('Create group {0}' -f ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.localname))
                $Splat = @{
                    Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $Node.Name
                    GroupCategory                 = 'Security'
                    GroupScope                    = 'Global'
                    DisplayName                   = $Node.DisplayName
                    Path                          = $ItAdminGroupsOuDn
                    Description                   = $Node.Description
                    ProtectFromAccidentalDeletion = $true
                    RemoveAccountOperators        = $true
                    RemoveEveryone                = $true
                    RemovePreWin2000              = $true
                }
                $CreatedGroup = New-AdDelegatedGroup @Splat

                $VarParam = @{
                    Name  = 'SG{0}{1}' -f $NC['Delim'], $Node.LocalName
                    Value = $CreatedGroup
                    Scope = 'Global'
                    Force = $true
                }
                New-Variable @VarParam

                # Clear variable for next use
                $CreatedGroup = $null
            } #end ForEach

            # Create Servers Area / Tier1 Domain Local & Global Groups
            # Operations group
            $currentOperation++
            # Update progress
            $progressParams = @{
                Activity        = 'Creating Tier0 Admin Groups'
                Status          = ('Creating Operations group ({0} of {1})' -f
                    $currentOperation, $totalOperations)
                PercentComplete = ($currentOperation / $totalOperations * 100)
            }
            Write-Progress @progressParams

            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $ConfXML.n.Servers.GG.Operations.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = $ConfXML.n.Servers.GG.Operations.DisplayName
                Path                          = $ItAdminGroupsOuDn
                Description                   = $ConfXML.n.Servers.GG.Operations.Description
                ProtectFromAccidentalDeletion = $true
                RemoveAccountOperators        = $true
                RemoveEveryone                = $true
                RemovePreWin2000              = $true
            }
            $CreatedGroup = New-AdDelegatedGroup @Splat
            $VariableName = 'SG{0}{1}' -f $NC['Delim'], $ConfXML.n.Servers.GG.Operations.LocalName
            New-Variable -Name $VariableName -Value $CreatedGroup -Scope Global -Force
            $CreatedGroup = $null

            # Server Admins group
            $currentOperation++
            # Update progress
            $progressParams = @{
                Activity        = 'Creating Tier0 Admin Groups'
                Status          = ('Creating Server Admins group ({0} of {1})' -f
                    $currentOperation, $totalOperations)
                PercentComplete = ($currentOperation / $totalOperations * 100)
            }
            Write-Progress @progressParams

            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $ConfXML.n.Servers.GG.ServerAdmins.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = $ConfXML.n.Servers.GG.ServerAdmins.DisplayName
                Path                          = $ItAdminGroupsOuDn
                Description                   = $ConfXML.n.Servers.GG.ServerAdmins.Description
                ProtectFromAccidentalDeletion = $true
                RemoveAccountOperators        = $true
                RemoveEveryone                = $true
                RemovePreWin2000              = $true
            }
            $CreatedGroup = New-AdDelegatedGroup @Splat
            $VariableName = 'SG{0}{1}' -f $NC['Delim'], $ConfXML.n.Servers.GG.ServerAdmins.LocalName
            New-Variable -Name $VariableName -Value $CreatedGroup -Scope Global -Force
            $CreatedGroup = $null

            # Server Ops Rights group
            $currentOperation++
            # Update progress
            $progressParams = @{
                Activity        = 'Creating Tier0 Admin Groups'
                Status          = ('Creating Server Ops Rights group ({0} of {1})' -f
                    $currentOperation, $totalOperations)
                PercentComplete = ($currentOperation / $totalOperations * 100)
            }
            Write-Progress @progressParams

            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $ConfXML.n.Servers.LG.SvrOpsRight.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = $ConfXML.n.Servers.LG.SvrOpsRight.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = $ConfXML.n.Servers.LG.SvrOpsRight.Description
                ProtectFromAccidentalDeletion = $true
                RemoveAccountOperators        = $true
                RemoveEveryone                = $true
                RemovePreWin2000              = $true
            }
            $CreatedGroup = New-AdDelegatedGroup @Splat
            $VariableName = 'SL{0}{1}' -f $NC['Delim'], $ConfXML.n.Servers.LG.SvrOpsRight.LocalName
            New-Variable -Name $VariableName -Value $CreatedGroup -Scope Global -Force
            $CreatedGroup = $null

            # Server Admin Rights group
            $currentOperation++
            # Update progress
            $progressParams = @{
                Activity        = 'Creating Tier0 Admin Groups'
                Status          = ('Creating Server Admin Rights group ({0} of {1})' -f
                    $currentOperation, $totalOperations)
                PercentComplete = ($currentOperation / $totalOperations * 100)
            }
            Write-Progress @progressParams

            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $ConfXML.n.Servers.LG.SvrAdmRight.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = $ConfXML.n.Servers.LG.SvrAdmRight.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = $ConfXML.n.Servers.LG.SvrAdmRight.Description
                ProtectFromAccidentalDeletion = $true
                RemoveAccountOperators        = $true
                RemoveEveryone                = $true
                RemovePreWin2000              = $true
            }
            $CreatedGroup = New-AdDelegatedGroup @Splat
            $VariableName = 'SL{0}{1}' -f $NC['Delim'], $ConfXML.n.Servers.LG.SvrAdmRight.LocalName
            New-Variable -Name $VariableName -Value $CreatedGroup -Scope Global -Force
            $CreatedGroup = $null

            # Complete the group creation progress
            Write-Progress -Activity 'Creating Tier0 Admin Groups' -Completed

            # Get all Privileged groups into an array $AllGroups
            # Note: For each group we check if it exists before adding to the collection
            if ($null -ne $SG_InfraAdmins) {
                [void]$AllGroups.Add($SG_InfraAdmins)
            }
            if ($null -ne $SG_AdAdmins) {
                [void]$AllGroups.Add($SG_AdAdmins)
            }
            if ($null -ne $SG_Tier0ServiceAccount) {
                [void]$AllGroups.Add($SG_Tier0ServiceAccount)
            }
            if ($null -ne $SG_Tier1ServiceAccount) {
                [void]$AllGroups.Add($SG_Tier1ServiceAccount)
            }
            if ($null -ne $SG_Tier2ServiceAccount) {
                [void]$AllGroups.Add($SG_Tier2ServiceAccount)
            }
            if ($null -ne $SG_GpoAdmins) {
                [void]$AllGroups.Add($SG_GpoAdmins)
            }
            if ($null -ne $SG_Tier0Admins) {
                [void]$AllGroups.Add($SG_Tier0Admins)
            }
            if ($null -ne $SG_Tier1Admins) {
                [void]$AllGroups.Add($SG_Tier1Admins)
            }
            if ($null -ne $SG_Tier2Admins) {
                [void]$AllGroups.Add($SG_Tier2Admins)
            }
            if ($null -ne $SG_AllSiteAdmins) {
                [void]$AllGroups.Add($SG_AllSiteAdmins)
            }
            if ($null -ne $SG_AllGALAdmins) {
                [void]$AllGroups.Add($SG_AllGALAdmins)
            }

            # Move the groups to PG OU
            $totalGroups = $AllGroups.Count
            $currentGroup = 0

            foreach ($Item in $AllGroups) {
                $currentGroup++

                # Update progress for moving groups
                $progressParams = @{
                    Activity        = 'Moving Privileged Groups to Protected OU'
                    Status          = ('Moving group {0} ({1} of {2})' -f
                        $Item.Name, $currentGroup, $totalGroups)
                    PercentComplete = ($currentGroup / $totalGroups * 100)
                }
                Write-Progress @progressParams

                try {
                    # Remove the ProtectedFromAccidentalDeletion, otherwise throws error when moving
                    Set-ADObject -Identity $Item.ObjectGUID -ProtectedFromAccidentalDeletion $false

                    # Move objects to PG OU
                    Move-ADObject -TargetPath $ItPrivGroupsOuDn -Identity $Item.ObjectGUID

                    # Set back again the ProtectedFromAccidentalDeletion flag.
                    # The group has to be fetched again because of the previous move
                    Set-ADObject -Identity $Item.ObjectGUID -ProtectedFromAccidentalDeletion $true

                    # Refresh the variable because DistinguishedName changed
                    Set-Variable -Name $Item.SamAccountName -Value (Get-ADGroup -Identity $Item.SID) -Scope Global -Force

                    # AD Object operations ONLY supports DN and GUID as identity
                    Write-Verbose -Message ('Protect and Move group {0} to Privileged Groups OU. Update Variable.' -f $Item.Name)

                } catch {

                    Write-Warning -Message (
                        'Failed to update variable or move group {0}: {1}' -f
                        $Item.Name, $_.Exception.Message
                    )

                } #end Try-Catch
            } #end foreach

            # Complete the group moving progress
            Write-Progress -Activity 'Moving Privileged Groups to Protected OU' -Completed

        } #end If ShouldProcess

    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Create Tier0 Admin Groups.'
            )
            Write-Verbose -Message $txt
        } #end If

        # Stop transcript if it was started
        if ($EnableTranscript) {
            try {
                Stop-Transcript -ErrorAction Stop
                Write-Verbose -Message 'Transcript stopped successfully'
            } catch {
                Write-Warning -Message ('Failed to stop transcript: {0}' -f $_.Exception.Message)
            } #end Try-Catch
        } #end If
    } #end End
} #end Function New-Tier0AdminGroup
