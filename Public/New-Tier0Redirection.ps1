function New-Tier0Redirection {

    <#
        .SYNOPSIS
            Redirects default Active Directory User and Computer container locations to secure quarantine OUs.

        .DESCRIPTION
            Redirects the default User and Computer containers to secure, quarantined organizational units.
            This function creates two new OUs with restricted permissions, removes dangerous delegations from
            the default containers, and redirects new user and computer objects to these secure OUs.

            This is a critical hardening measure for Tier 0 Active Directory environments to prevent
            privilege escalation via the default containers.

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the XML configuration file.
            Contains all naming conventions, OU structure, and security settings.
            Must be a valid XML file with required schema elements.
            Default: C:\PsScripts\Config.xml

        .PARAMETER DMScripts
            [System.String] Path to all the scripts and files needed by this function.
            Must contain a SecTmpl subfolder.
            Default: C:\PsScripts\

        .EXAMPLE
            New-Tier0Redirection -ConfigXMLFile "C:\PsScripts\Config.xml"

            Creates quarantine OUs, removes delegations from default containers, and redirects User/Computer creation.

        .EXAMPLE
            New-Tier0Redirection -ConfigXMLFile "C:\PsScripts\Config.xml" -DMScripts "D:\Scripts" -Verbose

            Creates quarantine OUs with verbose output, using scripts from the D:\Scripts location.

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
                New-DelegateAdOU                           ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteUser                  ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteComputer              ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteGroup                 ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeleteContact               ║ EguibarIT.DelegationPS
                Set-CreateDeleteInetOrgPerson              ║ EguibarIT.DelegationPS
                Set-AdAclCreateDeletePrintQueue            ║ EguibarIT.DelegationPS
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility

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
            Active Directory Tier 0 Hardening
    #>

    [CmdletBinding(
        SupportsShouldProcess = $true,
        ConfirmImpact = 'High'
    )]
    [OutputType([System.Void])]

    param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
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
                        $null -eq $xml.n.Admin.OUs) {
                        throw 'XML file is missing required elements (Admin or OUs section)'
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

        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false
        Import-MyModule -Name 'EguibarIT' -Verbose:$false
        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        # parameters variable for splatting CMDlets
        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Load the XML configuration file
        try {
            $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])

            # Extract OU names from the XML
            [string]$ItQuarantinePcOu = $confXML.n.Admin.OUs.ItNewComputersOU.name
            [string]$ItQuarantineUserOu = $confXML.n.Admin.OUs.ItNewUsersOU.name

            Write-Verbose -Message ('Extracted OU names: {0}, {1}' -f $ItQuarantinePcOu, $ItQuarantineUserOu)
        } catch {
            Write-Error -Message ('Error processing XML file: {0}' -f $_.Exception.Message)
            throw
        } #end Try-Catch

        $AccountOperators = Get-SafeVariable -Name 'AccountOperators' -CreateIfNotExist {
            try {
                Get-ADGroup -Identity 'S-1-5-32-548'
            } catch {
                Write-Debug -Message ('Failed to retrieve Account Operators group: {0}' -f $_.Exception.Message)
                $null
            }
        }

    } #end Begin

    Process {

        if ($PSCmdlet.ShouldProcess('Default User/Computer container redirection')) {

            $Splat = @{
                ouName                   = $ItQuarantinePcOu
                ouPath                   = $Variables.AdDn
                ouDescription            = $confXML.n.Admin.OUs.ItNewComputersOU.description
                RemoveAuthenticatedUsers = $true
            }
            New-DelegateAdOU @Splat

            $Splat = @{
                ouName                   = $ItQuarantineUserOu
                ouPath                   = $Variables.AdDn
                ouDescription            = $confXML.n.Admin.OUs.ItNewUsersOU.description
                RemoveAuthenticatedUsers = $true
            }
            New-DelegateAdOU @Splat

            # START Remove Delegation to BuiltIn groups BEFORE REDIRECTION
            $Splat = @{
                Group      = $AccountOperators
                LDAPPath   = 'CN=Computers,{0}' -f $Variables.AdDn
                RemoveRule = $True
            }
            ### COMPUTERS
            # Remove the Account Operators group from ACL to Create/Delete Users
            Set-AdAclCreateDeleteUser @Splat

            # Remove the Account Operators group from ACL to Create/Delete Computers
            Set-AdAclCreateDeleteComputer @Splat

            # Remove the Account Operators group from ACL to Create/Delete Groups
            Set-AdAclCreateDeleteGroup @Splat

            # Remove the Account Operators group from ACL to Create/Delete Contacts
            Set-AdAclCreateDeleteContact @Splat

            # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
            Set-CreateDeleteInetOrgPerson @Splat

            # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
            Set-AdAclCreateDeletePrintQueue @Splat

            $Splat = @{
                Group      = $AccountOperators
                LDAPPath   = 'CN=Users,{0}' -f $Variables.AdDn
                RemoveRule = $True
            }
            ### USERS
            # Remove the Account Operators group from ACL to Create/Delete Users
            Set-AdAclCreateDeleteUser @Splat

            # Remove the Account Operators group from ACL to Create/Delete Computers
            Set-AdAclCreateDeleteComputer @Splat

            # Remove the Account Operators group from ACL to Create/Delete Groups
            Set-AdAclCreateDeleteGroup @Splat

            # Remove the Account Operators group from ACL to Create/Delete Contacts
            Set-AdAclCreateDeleteContact @Splat

            # Remove the Account Operators group from ACL to Create/Delete inetOrgPerson
            Set-CreateDeleteInetOrgPerson @Splat

            # Remove the Print Operators group from ACL to Create/Delete PrintQueues
            Set-AdAclCreateDeletePrintQueue @Splat

            ###############################################################################
            # Redirect Default USER & COMPUTERS Containers
            redircmp.exe ('OU={0},{1}' -f $ItQuarantinePcOu, $Variables.AdDn)
            redirusr.exe ('OU={0},{1}' -f $ItQuarantineUserOu, $Variables.AdDn)

        } #end If ShouldProcess

    } #end Process

    End {
        if ($null -ne $Variables -and
            $null -ne $Variables.Footer) {

            $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
                'Default User/Computer container redirection.'
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
} #end Function New-Tier0Redirection
