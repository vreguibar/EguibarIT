function New-Tier0FineGrainPasswordPolicy {

    <#
        .SYNOPSIS
            Creates and configures Fine Grained Password Policies (FGPP) for Tier 0 administrative accounts and service accounts.

        .DESCRIPTION
            Creates two different Fine Grained Password Policies (FGPPs):
            1. A policy for administrative accounts with stricter password requirements.
            2. A policy for service accounts with longer password age settings.

            These policies are then applied to the appropriate security groups and users according to
            the configuration specified in the XML configuration file.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            [System.String] Path to all the scripts and files needed by this function.
            Must contain a 'SecTmpl' subfolder.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0FineGrainPasswordPolicy -ConfigXMLFile C:\PsScripts\Config.xml -Verbose
            Creates Fine Grained Password Policies as defined in the Config.xml file and provides verbose output.

        .EXAMPLE
            New-Tier0FineGrainPasswordPolicy -ConfigXMLFile C:\PsScripts\Config.xml -DMScripts C:\Scripts\DMScripts\
            Creates Fine Grained Password Policies using the Config.xml file and scripts located in the specified path.

        .INPUTS
            System.IO.FileInfo
            System.String

        .OUTPUTS
            None. This function does not generate any output.

        .NOTES
            Used Functions:
                Name                                      ║ Module/Namespace
                ══════════════════════════════════════════╬══════════════════════════════
                Get-ADFineGrainedPasswordPolicy           ║ ActiveDirectory
                New-ADFineGrainedPasswordPolicy           ║ ActiveDirectory
                Add-ADFineGrainedPasswordPolicySubject    ║ ActiveDirectory
                Get-ADGroup                               ║ ActiveDirectory
                Get-Content                               ║ Microsoft.PowerShell.Management
                Test-Path                                 ║ Microsoft.PowerShell.Management
                Write-Verbose                             ║ Microsoft.PowerShell.Utility
                Write-Warning                             ║ Microsoft.PowerShell.Utility
                Write-Error                               ║ Microsoft.PowerShell.Utility
                Import-MyModule                           ║ EguibarIT
                Get-FunctionDisplay                       ║ EguibarIT

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                        vicente@eguibar.com
                        Eguibar IT
                        http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT

        .COMPONENT
            Active Directory

        .ROLE
            Security Administrator

        .FUNCTIONALITY
            Password Policy Management
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
                        $null -eq $xml.n.Admin.PSOs -or
                        $null -eq $xml.n.Admin.PSOs.ItAdminsPSO -or
                        $null -eq $xml.n.Admin.PSOs.ServiceAccountsPSO ) {
                        throw 'XML file is missing required elements (Admin, PSOs, ItAdminsPSO or ServiceAccountsPSO section)'
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

        # Display function header if variables exist
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
        #[System.Collections.ArrayList]$ArrayList = [System.Collections.ArrayList]::New()
        [System.Collections.Generic.List[object]]$ArrayList = [System.Collections.Generic.List[object]]::New()

        # Load the XML configuration file
        try {
            [xml]$confXML = [xml](Get-Content -Path $PSBoundParameters['ConfigXMLFile'] -ErrorAction Stop)
            Write-Debug -Message ('Successfully loaded configuration from {0}' -f $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        # Naming conventions hashtable
        $NC = @{
            'sl'    = $confXML.n.NC.LocalDomainGroupPreffix
            'sg'    = $confXML.n.NC.GlobalGroupPreffix
            'su'    = $confXML.n.NC.UniversalGroupPreffix
            'Delim' = $confXML.n.NC.Delimiter
            'T0'    = $confXML.n.NC.AdminAccSufix0
            'T1'    = $confXML.n.NC.AdminAccSufix1
            'T2'    = $confXML.n.NC.AdminAccSufix2
        }

        #region Users Variables
        $AdminName = Get-SafeVariable -Name 'AdminName' -CreateIfNotExist {
            try {
                Get-ADUser -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-500' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Administrator: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $NewAdminExists = Get-SafeVariable -Name 'NewAdminExists' -CreateIfNotExist {
            $newAdminName = $confXML.n.Admin.users.NEWAdmin.Name
            if (-not [string]::IsNullOrEmpty($newAdminName)) {
                Get-AdObjectType -Identity $newAdminName
            } else {
                $null
            }
        }
        #endregion Users Variables

        #region Well-Known groups Variables
        $DomainAdmins = Get-SafeVariable -Name 'DomainAdmins' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-512' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Domain Admins group: {0}' -f $_.Exception.Message)
                $null
            }
        }

        $EnterpriseAdmins = Get-SafeVariable -Name 'EnterpriseAdmins' -CreateIfNotExist {
            try {
                Get-ADGroup -Filter * | Where-Object { $_.SID -like 'S-1-5-21-*-519' }
            } catch {
                Write-Debug -Message ('Failed to retrieve Enterprise Admins group: {0}' -f $_.Exception.Message)
                $null
            }
        }
        #endregion Well-Known groups Variables

        #region Global groups Variables
        $SG_InfraAdmins = Get-SafeVariable -Name 'SG_InfraAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.InfraAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_AdAdmins = Get-SafeVariable -Name 'SG_AdAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AdAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_GpoAdmins = Get-SafeVariable -Name 'SG_GpoAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GpoAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_Tier0Admins = Get-SafeVariable -Name 'SG_Tier0Admins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0Admins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_Tier1Admins = Get-SafeVariable -Name 'SG_Tier1Admins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1Admins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_Tier2Admins = Get-SafeVariable -Name 'SG_Tier2Admins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2Admins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_Operations = Get-SafeVariable -Name 'SG_Operations' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.Operations.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_ServerAdmins = Get-SafeVariable -Name 'SG_ServerAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Servers.GG.ServerAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_AllSiteAdmins = Get-SafeVariable -Name 'SG_AllSiteAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllSiteAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_AllGALAdmins = Get-SafeVariable -Name 'SG_AllGALAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.AllGalAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_GlobalUserAdmins = Get-SafeVariable -Name 'SG_GlobalUserAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalUserAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_GlobalPcAdmins = Get-SafeVariable -Name 'SG_GlobalPcAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalPCAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_GlobalGroupAdmins = Get-SafeVariable -Name 'SG_GlobalGroupAdmins' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.GlobalGroupAdmins.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SG_ServiceDesk = Get-SafeVariable -Name 'SG_ServiceDesk' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.ServiceDesk.Name)
            Get-AdObjectType -Identity $groupName
        }

        # Tier Service Account Groups
        # ToDo: the GetSafeVariable is finding the variable, but variable has old DN. Interim fix filling the variable again
        $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier0ServiceAccount.Name)
        $SG_Tier0ServiceAccount = Get-AdObjectType -Identity $groupName


        # ToDo: the GetSafeVariable is finding the variable, but variable has old DN. Interim fix filling the variable again
        $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier1ServiceAccount.Name)
        $SG_Tier1ServiceAccount = Get-AdObjectType -Identity $groupName

        # ToDo: the GetSafeVariable is finding the variable, but variable has old DN. Interim fix filling the variable again
        $groupName = ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.Tier2ServiceAccount.Name)
        $SG_Tier2ServiceAccount = Get-AdObjectType -Identity $groupName
        #endregion Global groups Variables

        #region Local groups Variables
        $SL_AdRight = Get-SafeVariable -Name 'SL_AdRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.AdRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_InfraRight = Get-SafeVariable -Name 'SL_InfraRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.InfraRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_DnsAdminRight = Get-SafeVariable -Name 'SL_DnsAdminRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.DnsAdminRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GpoAdminRight = Get-SafeVariable -Name 'SL_GpoAdminRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GpoAdminRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PGM = Get-SafeVariable -Name 'SL_PGM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PGM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PUM = Get-SafeVariable -Name 'SL_PUM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PUM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GM = Get-SafeVariable -Name 'SL_GM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.GM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_UM = Get-SafeVariable -Name 'SL_UM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.UM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PSAM = Get-SafeVariable -Name 'SL_PSAM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PSAM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PAWM = Get-SafeVariable -Name 'SL_PAWM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PAWM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PISM = Get-SafeVariable -Name 'SL_PISM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PISM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_SAGM = Get-SafeVariable -Name 'SL_SAGM' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.SAGM.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_DcManagement = Get-SafeVariable -Name 'SL_DcManagement' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.DcManagement.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_TransferFSMOright = Get-SafeVariable -Name 'SL_TransferFSMOright' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.TransferFSMOright.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_PromoteDcRight = Get-SafeVariable -Name 'SL_PromoteDcRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.PromoteDcRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_DirReplRight = Get-SafeVariable -Name 'SL_DirReplRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Admin.LG.DirReplRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_SvrOpsRight = Get-SafeVariable -Name 'SL_SvrOpsRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrOpsRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_SvrAdmRight = Get-SafeVariable -Name 'SL_SvrAdmRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.SvrAdmRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GlobalGroupRight = Get-SafeVariable -Name 'SL_GlobalGroupRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.GlobalGroupRight.Name)
            Get-AdObjectType -Identity $groupName
        }

        $SL_GlobalAppAccUserRight = Get-SafeVariable -Name 'SL_GlobalAppAccUserRight' -CreateIfNotExist {
            $groupName = ('{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.Servers.LG.GlobalAppAccUserRight.Name)
            Get-AdObjectType -Identity $groupName
        }
        #endregion Local groups Variables

        # Create collection arrays for convenience
        [array]$AllGlobalGroupVariables = @(
            $DomainAdmins,
            $EnterpriseAdmins,
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

        [array]$AllLocalGroupVariables = @(
            $SL_AdRight,
            $SL_InfraRight,
            $SL_DnsAdminRight,
            $SL_GpoAdminRight,
            $SL_PGM,
            $SL_PUM,
            $SL_GM,
            $SL_UM,
            $SL_PSAM,
            $SL_PAWM,
            $SL_PISM,
            $SL_SAGM,
            $SL_DcManagement,
            $SL_TransferFSMOright,
            $SL_PromoteDcRight,
            $SL_DirReplRight,
            $SL_SvrOpsRight,
            $SL_SvrAdmRight,
            $SL_GlobalGroupRight,
            $SL_GlobalAppAccUserRight
        )

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Active Directory', 'Create Tier0 Fine Grain Password Policies')) {

            ###############################################################################
            #region Create a New Fine Grained Password Policy for Admins Accounts

            [string]$PsoName = $confXML.n.Admin.PSOs.ItAdminsPSO.Name
            Write-Verbose -Message ('Processing Admin PSO: {0}' -f $PsoName)

            # Check if the PSO already exists
            $Splat = @{
                Filter      = { name -like $PsoName }
                ErrorAction = 'SilentlyContinue'
            }
            $PSOexists = Get-ADFineGrainedPasswordPolicy @Splat

            if (-not($PSOexists)) {
                Write-Debug -Message ('Creating Admin PSO: {0}' -f $PsoName)

                $Splat = @{
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
                    Passthru                    = $true
                }

                try {

                    $PSOexists = New-ADFineGrainedPasswordPolicy @Splat -ErrorAction Stop
                    Write-Debug -Message ('Created PSO: {0}' -f $PsoName)
                } catch {

                    Write-Error -Message ('Failed to create PSO {0}: {1}' -f $PsoName, $_.Exception.Message)
                    # Refresh the PSOexists variable to get the latest object
                    $Splat = @{
                        Filter      = { name -like $PsoName }
                        ErrorAction = 'SilentlyContinue'
                    }
                    $PSOexists = Get-ADFineGrainedPasswordPolicy @Splat

                } #end Try-Catch

            } else {

                Write-Verbose -Message ('PSO already exists: {0}' -f $PsoName)

            } #end If PSO exists

            # Only proceed if PSO exists
            if ($null -ne $PSOexists) {

                Write-Debug -Message ('Applying PSO {0} to corresponding accounts and groups' -f $PsoName)

                # Allow Active Directory time to process the PSO creation
                Start-Sleep -Seconds 5

                # Apply the PSO to the corresponding accounts and groups
                $ArrayList.Clear()

                # Add Global Groups to ArrayList
                foreach ($Item in $AllGlobalGroupVariables) {
                    if ($null -ne $Item) {
                        [void]$ArrayList.Add($Item)
                    } #end If
                } #end ForEach

                # Add Local Groups to ArrayList
                foreach ($Item in $AllLocalGroupVariables) {
                    if ($null -ne $Item) {
                        [void]$ArrayList.Add($Item)
                    } #end If
                } #end ForEach

                # Only add subjects if there are any
                if ($ArrayList.Count -gt 0) {
                    try {
                        # Process each subject individually to handle errors gracefully
                        foreach ($Subject in $ArrayList) {
                            try {
                                Add-ADFineGrainedPasswordPolicySubject -Identity $PsoName -Subjects $Subject -ErrorAction Stop
                                Write-Debug -Message ('Added group {0} to PSO {1}' -f $Subject.Name, $PsoName)
                            } catch {
                                Write-Warning -Message ('Failed to add group {0} to PSO {1}: {2}' -f
                                    $Subject.Name, $PsoName, $_.Exception.Message)
                            }
                        }
                    } catch {
                        Write-Error -Message ('Failed to add groups to PSO {0}: {1}' -f $PsoName, $_.Exception.Message)
                    } #end Try-Catch
                } else {
                    Write-Debug -Message ('No groups found to add to PSO: {0}' -f $PsoName)
                } #end If ArrayList

                $ArrayList.Clear()

                if ($null -ne $AdminName) {
                    [void]$ArrayList.Add($AdminName)
                } #end if
                if ($null -ne $NewAdminExists) {
                    [void]$ArrayList.Add($NewAdminExists)
                } #end if

                # Only add subjects if there are any
                if ($ArrayList.Count -gt 0) {
                    try {
                        # Process each subject individually to handle errors gracefully
                        foreach ($Subject in $ArrayList) {
                            try {
                                Add-ADFineGrainedPasswordPolicySubject -Identity $PsoName -Subjects $Subject -ErrorAction Stop
                                Write-Debug -Message ('Added user {0} to PSO {1}' -f $Subject.Name, $PsoName)
                            } catch {
                                Write-Warning -Message ('Failed to add user {0} to PSO {1}: {2}' -f
                                    $Subject.Name, $PsoName, $_.Exception.Message)
                            }
                        }
                    } catch {

                        Write-Error -Message ('Failed to add users to PSO {0}: {1}' -f $PsoName, $_.Exception.Message)

                    } #end Try-Catch
                } else {

                    Write-Debug -Message ('No individual users found to add to PSO: {0}' -f $PsoName)

                } #end If ArrayList

            } else {

                Write-Warning -Message ('Could not find or create PSO: {0}' -f $PsoName)

            } #end If PSOexists

            #endregion
            ###############################################################################

            ###############################################################################
            #region Create a New Fine Grained Password Policy for Service Accounts

            [string]$PsoName = $confXML.n.Admin.PSOs.ServiceAccountsPSO.Name
            Write-Verbose -Message ('Processing Service Account PSO: {0}' -f $PsoName)

            # Check if the PSO already exists
            $Splat = @{
                Filter      = { name -like $PsoName }
                ErrorAction = 'SilentlyContinue'
            }
            $PSOexists = Get-ADFineGrainedPasswordPolicy @Splat

            if (-not($PSOexists)) {
                Write-Verbose -Message ('Creating Service Account PSO: {0}' -f $PsoName)

                $Splat = @{
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
                    ReversibleEncryptionEnabled =
                    [System.Boolean]$confXML.n.Admin.PSOs.ServiceAccountsPSO.ReversibleEncryptionEnabled
                    Passthru                    = $true
                }

                try {

                    $PSOexists = New-ADFineGrainedPasswordPolicy @Splat -ErrorAction Stop
                    Write-Debug -Message ('Created PSO: {0}' -f $PsoName)
                } catch {

                    Write-Error -Message ('Failed to create PSO {0}: {1}' -f $PsoName, $_.Exception.Message)
                    # Try to get the PSO if it was created despite the error
                    $Splat = @{
                        Filter      = { name -like $PsoName }
                        ErrorAction = 'SilentlyContinue'
                    }
                    $PSOexists = Get-ADFineGrainedPasswordPolicy @Splat

                } #end Try-Catch

            } else {

                Write-Debug -Message ('PSO already exists: {0}' -f $PsoName)

            } #end If PSO exists

            # Only proceed if PSO exists
            if ($null -ne $PSOexists) {

                Write-Debug -Message ('Applying PSO {0} to corresponding service accounts' -f $PsoName)

                # Allow Active Directory time to process the PSO creation
                Start-Sleep -Seconds 5

                # Apply the PSO to all Tier Service Accounts
                $ArrayList.Clear()
                if ($null -ne $SG_Tier0ServiceAccount) {
                    [void]$ArrayList.Add($SG_Tier0ServiceAccount)
                } #end if
                if ($null -ne $SG_Tier1ServiceAccount) {
                    [void]$ArrayList.Add($SG_Tier1ServiceAccount)
                } #end if
                if ($null -ne $SG_Tier2ServiceAccount) {
                    [void]$ArrayList.Add($SG_Tier2ServiceAccount)
                } #end if

                # Only add subjects if there are any
                if ($ArrayList.Count -gt 0) {
                    try {
                        # Process each subject individually to handle errors gracefully
                        foreach ($Subject in $ArrayList) {
                            try {
                                Add-ADFineGrainedPasswordPolicySubject -Identity $PsoName -Subjects $Subject -ErrorAction Stop
                                Write-Debug -Message ('Added {0} to PSO {1}' -f $Subject.Name, $PsoName)
                            } catch {
                                Write-Warning -Message ('Failed to add {0} to PSO {1}: {2}' -f
                                    $Subject.Name, $PsoName, $_.Exception.Message)
                            }
                        }
                    } catch {
                        Write-Error -Message ('Failed to add service accounts to PSO {0}: {1}' -f
                            $PsoName, $_.Exception.Message)
                    } #end Try-Catch

                } else {
                    Write-Debug -Message ('No service account groups found to add to PSO: {0}' -f $PsoName)
                } #end If ArrayList
            } #end If PSOexists

            #endregion
            ###############################################################################
        } #end If ShouldProcess
    } #end Process

    End {
        # Display function footer if variables exist
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Create Tier0 Fine Grain Password Policy.'
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
} #end Function New-Tier0FineGrainPasswordPolicy
