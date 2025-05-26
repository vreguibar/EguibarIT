function Test-KdsRootKeyPrerequisite {
    <#
        .SYNOPSIS
            Diagnoses KDS Root Key creation prerequisites and environment for gMSA support.

        .DESCRIPTION
            Checks forest/domain functional level, KdsSvc service, AD schema containers, KDS Root Key presence, and permissions.
            Outputs a diagnostic object and actionable recommendations for troubleshooting KDS Root Key creation issues.

            The function performs the following checks:
            - Forest and Domain functional levels
            - KdsSvc service status
            - Presence of required AD schema containers
            - Existence and validity of KDS Root Key
            - Required permissions for gMSA operations

        .EXAMPLE
            Test-KdsRootKeyPrerequisite -Verbose

            Runs all checks and outputs a detailed diagnostic report with verbose logging.

        .EXAMPLE
            $result = Test-KdsRootKeyPrerequisite
            $result.ForestMode

            Shows how to capture and examine specific aspects of the diagnostic report.

        .EXAMPLE
            Test-KdsRootKeyPrerequisite | Select-Object -ExpandProperty Recommendations

            Displays only the recommended actions based on the diagnostic results.

        .INPUTS
            None
            This function does not accept pipeline input.

        .OUTPUTS
            System.Management.Automation.PSCustomObject
            Returns a diagnostic report object containing:
            - Environment status (Forest/Domain modes)
            - Service status
            - Container existence
            - KDS Root Key status
            - Actionable recommendations

        .NOTES
            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Get-ADForest                               ║ ActiveDirectory
                Get-ADDomain                               ║ ActiveDirectory
                Get-Service                                ║ Microsoft.PowerShell.Management
                Get-KdsRootKey                            ║ ActiveDirectory
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Test-KdsRootKeyPrerequisite.ps1

        .COMPONENT
            Active Directory
            Key Distribution Service
            Group Managed Service Accounts

        .ROLE
            Infrastructure Administrator
            Domain Administrator

        .FUNCTIONALITY
            Diagnostics
            Security
            Prerequisite Validation
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    param ()

    Begin {
        Set-StrictMode -Version Latest
        if ($null -ne $Variables -and $null -ne $Variables.Header) {
            $txt = ($Variables.Header -f (Get-Date).ToString('dd/MMM/yyyy'), $MyInvocation.Mycommand, (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False))
            Write-Verbose -Message $txt
        } #end If
        ##############################
        # Module imports
        Import-Module -Name ActiveDirectory -ErrorAction Stop
        ##############################
        # Variables Definition
        [string]$ForestMode = ''
        [string]$DomainMode = ''
        [string]$KdsServiceStatus = ''
        [bool]$KdsContainerExists = $false
        [bool]$MasterRootKeysExists = $false
        [bool]$KdsRootKeyExists = $false
        [string]$KdsRootKeyId = ''
        [string]$PdcEmulator = ''
        [string]$CurrentComputer = $env:COMPUTERNAME
        [string]$ConfigNC = ''
        [string]$Recommendation = ''
        [string]$ErrorMessage = ''
    } #end Begin

    Process {
        try {
            # Check forest and domain functional level
            $Forest = Get-ADForest
            $Domain = Get-ADDomain
            $ForestMode = $Forest.ForestMode.ToString()
            $DomainMode = $Domain.DomainMode.ToString()
            $PdcEmulator = $Domain.PDCEmulator
            Write-Verbose -Message ('ForestMode: {0}, DomainMode: {1}' -f $ForestMode, $DomainMode)
            # Check KdsSvc service
            try {
                $KdsService = Get-Service -Name 'KdsSvc' -ErrorAction Stop
                $KdsServiceStatus = $KdsService.Status.ToString()
            } catch {
                $KdsServiceStatus = 'NotFound'
                Write-Warning -Message 'KdsSvc service not found.'
            }
            Write-Verbose -Message ('KdsSvc status: {0}' -f $KdsServiceStatus)
            # Check AD schema containers
            $ConfigNC = ([ADSI]'LDAP://RootDSE').configurationNamingContext
            $GkdsPath = 'LDAP://CN=Group Key Distribution Service,CN=Services,' + $ConfigNC
            $MrkPath = 'LDAP://CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,' + $ConfigNC
            try {
                $Gkds = [ADSI]$GkdsPath
                $null = $Gkds.distinguishedName
                $KdsContainerExists = $true
            } catch {
                $KdsContainerExists = $false
                Write-Warning -Message 'Group Key Distribution Service container missing.'
            }
            try {
                $Mrk = [ADSI]$MrkPath
                $null = $Mrk.distinguishedName
                $MasterRootKeysExists = $true
            } catch {
                $MasterRootKeysExists = $false
                Write-Warning -Message 'Master Root Keys container missing.'
            }
            # Check for KDS Root Key
            try {
                $KdsKey = Get-KdsRootKey -ErrorAction Stop
                if ($KdsKey) {
                    $KdsRootKeyExists = $true
                    $KdsRootKeyId = $KdsKey.KeyId.ToString()
                }
            } catch {
                $KdsRootKeyExists = $false
            }
        } catch {
            $ErrorMessage = $_.Exception.Message
            Write-Error -Message ('Error during KDS prerequisite check: {0}' -f $ErrorMessage)
        }
        # Recommendations
        if ($ForestMode -notlike '*2012*' -and $ForestMode -notlike '*2016*' -and $ForestMode -notlike '*2019*' -and $ForestMode -notlike '*2022*' -and $ForestMode -notlike '*2025*') {
            $Recommendation += 'Forest functional level must be at least Windows Server 2012. '
        }
        if ($DomainMode -notlike '*2012*' -and $DomainMode -notlike '*2016*' -and $DomainMode -notlike '*2019*' -and $DomainMode -notlike '*2022*' -and $DomainMode -notlike '*2025*') {
            $Recommendation += 'Domain functional level must be at least Windows Server 2012. '
        }
        if ($KdsServiceStatus -ne 'Running') {
            $Recommendation += 'KdsSvc service must be running. '
        }
        if (-not $KdsContainerExists) {
            $Recommendation += 'Group Key Distribution Service container missing in AD schema. '
        }
        if (-not $MasterRootKeysExists) {
            $Recommendation += 'Master Root Keys container missing in AD schema. '
        }
        if (-not $KdsRootKeyExists) {
            $Recommendation += 'No KDS Root Key found. Try creating with Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10)). '
        }
        if ($ErrorMessage) {
            $Recommendation += 'Error encountered: ' + $ErrorMessage
        }
        if ($Recommendation -eq '') {
            $Recommendation = 'All prerequisites appear satisfied. If Add-KdsRootKey still fails, check event logs and consider AD schema health.'
        }
        # Output diagnostic object
        [PSCustomObject]@{
            ForestMode           = $ForestMode
            DomainMode           = $DomainMode
            KdsServiceStatus     = $KdsServiceStatus
            KdsContainerExists   = $KdsContainerExists
            MasterRootKeysExists = $MasterRootKeysExists
            KdsRootKeyExists     = $KdsRootKeyExists
            KdsRootKeyId         = $KdsRootKeyId
            PdcEmulator          = $PdcEmulator
            CurrentComputer      = $CurrentComputer
            Recommendation       = $Recommendation
            ErrorMessage         = $ErrorMessage
        }
    } #end Process

    End {
        if ($null -ne $Variables -and $null -ne $Variables.Footer) {
            $txt = ($Variables.Footer -f $MyInvocation.InvocationName, 'KDS Root Key prerequisite diagnostics.')
            Write-Verbose -Message $txt
        } #end If
    } #end End
} #end Function Test-KdsRootKeyPrerequisites
