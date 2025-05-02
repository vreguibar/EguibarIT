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
        [ValidateScript({
                if (-not (Test-Path -Path $_ -PathType Container)) {
                    throw ('Directory not found: {0}' -f $_)
                }
                if (-not (Test-Path -Path (Join-Path -Path $_ -ChildPath 'SecTmpl'))) {
                    throw ('SecTmpl subfolder not found in: {0}' -f $_)
                }
                return $true
            })]
        [PSDefaultValue(
            Help = 'Default Value is "C:\PsScripts\"',
            Value = 'C:\PsScripts\'
        )]
        [Alias('ScriptPath')]
        [System.IO.DirectoryInfo]
        $DMScripts

    )

    Begin {
        Set-StrictMode -Version Latest

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

        Import-MyModule -Name 'ServerManager' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # Parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
        [System.Collections.ArrayList]$ArrayList = [System.Collections.ArrayList]::New()

        # Load the XML configuration file
        try {
            [xml]$confXML = [xml](Get-Content -Path $PSBoundParameters['ConfigXMLFile'] -ErrorAction Stop)
            Write-Verbose -Message ('Successfully loaded configuration from {0}' -f $PSBoundParameters['ConfigXMLFile'])
        } catch {
            Write-Error -Message ('Error reading XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        $AllGlobalGroupVariables = @(
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

        $AllLocalGroupVariables = @(
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
            $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -like $PsoName } -ErrorAction SilentlyContinue

            if (-not($PSOexists)) {
                Write-Verbose -Message ('Creating Admin PSO: {0}' -f $PsoName)

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
                    Write-Verbose -Message ('Successfully created PSO: {0}' -f $PsoName)
                } catch {
                    Write-Error -Message ('Failed to create PSO {0}: {1}' -f $PsoName, $_.Exception.Message)
                    # Refresh the PSOexists variable to get the latest object
                    $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -like $PsoName } -ErrorAction SilentlyContinue
                } #end Try-Catch
            } else {
                Write-Verbose -Message ('PSO already exists: {0}' -f $PsoName)
            } #end If PSO exists

            # Only proceed if PSO exists
            if ($null -ne $PSOexists) {
                Write-Verbose -Message ('Applying PSO {0} to corresponding accounts and groups' -f $PsoName)

                # Allow Active Directory time to process the PSO creation
                Start-Sleep -Seconds 5

                # Apply the PSO to the corresponding accounts and groups
                $ArrayList.Clear()

                foreach ($Item in @($AllGlobalGroupVariables, $AllLocalGroupVariables)) {
                    $GroupName = Get-AdObjectType -Identity $Item
                    if ($null -ne $Item) {
                        [void]$ArrayList.Add($GroupName)
                    } else {
                        Write-Error -Message ('Group not found: {0}' -f $Item)
                    } #end If GroupName
                } #end ForEach
                # Adding groups
                Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $ArrayList



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
                        Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $ArrayList -ErrorAction Stop
                        Write-Verbose -Message ('Successfully added {0} users to PSO {1}' -f $ArrayList.Count, $PsoName)
                    } catch {
                        Write-Error -Message ('Failed to add users to PSO {0}: {1}' -f $PsoName, $_.Exception.Message)
                    } #end Try-Catch
                } else {
                    Write-Verbose -Message ('No individual users found to add to PSO: {0}' -f $PsoName)
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
            $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -like $PsoName } -ErrorAction SilentlyContinue

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
                    ReversibleEncryptionEnabled = [System.Boolean]$confXML.n.Admin.PSOs.ServiceAccountsPSO.ReversibleEncryptionEnabled
                    Passthru                    = $true
                }

                try {
                    $PSOexists = New-ADFineGrainedPasswordPolicy @Splat -ErrorAction Stop
                    Write-Verbose -Message ('Successfully created PSO: {0}' -f $PsoName)
                } catch {
                    Write-Error -Message ('Failed to create PSO {0}: {1}' -f $PsoName, $_.Exception.Message)
                    # Try to get the PSO if it was created despite the error
                    $PSOexists = Get-ADFineGrainedPasswordPolicy -Filter { name -like $PsoName } -ErrorAction SilentlyContinue
                } #end Try-Catch

            } else {
                Write-Verbose -Message ('PSO already exists: {0}' -f $PsoName)
            } #end If PSO exists

            # Only proceed if PSO exists
            if ($null -ne $PSOexists) {

                Write-Verbose -Message ('Applying PSO {0} to corresponding service accounts' -f $PsoName)

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

                # todo: Fix error "The name reference is invalid."
                # Only add subjects if there are any
                if ($ArrayList.Count -gt 0) {
                    try {
                        Add-ADFineGrainedPasswordPolicySubject -Identity $PSOexists -Subjects $ArrayList -ErrorAction Stop
                        Write-Verbose -Message ('Successfully added {0} users to PSO {1}' -f $ArrayList.Count, $PsoName)
                    } catch {
                        Write-Error -Message ('Failed to add users to PSO {0}: {1}' -f $PsoName, $_.Exception.Message)
                    } #end Try-Catch
                } else {
                    Write-Verbose -Message ('No individual users found to add to PSO: {0}' -f $PsoName)
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
    } #end End
} #end Function New-Tier0FineGrainPasswordPolicy
