﻿Function Initialize-ModuleVariable {
    <#
        .SYNOPSIS
            Initializes or reinitializes module-level variables for the module.

        .DESCRIPTION
            This function sets up the global $Variables variable used throughout the module.
            The $Variables variable is a hashtable that contains simple key-value pairs as well
            as nested hashtables (e.g. WellKnownSids). This function is automatically invoked on
            module import and can be called manually via Initialize-ModuleVariable to refresh or
            reinitialize the variables. The initialization logic is broken into smaller helper functions
            to simplify maintenance and testing.

        .PARAMETER Force
            When specified, forces reinitialization of variables even if they already exist.
            This is useful for troubleshooting or when you need to refresh the environment.

        .EXAMPLE
            Initialize-ModuleVariable
            # Reinitializes the module variables if required.

        .EXAMPLE
            Initialize-ModuleVariable -Force
            # Forces reinitialization even if $Variables is already set.

        .OUTPUTS
            VOID. The function sets global variables in the module.

        .NOTES
            Required Modules/Prerequisites:
            - None explicitly required; however, the module should export only Constants and Variables.
            - The function should be called at the end of the module script to ensure all variables are set.

            Used Functions:
                Name                                       ║ Module/Namespace
                ═══════════════════════════════════════════╬══════════════════════════════
                Write-Verbose                              ║ Microsoft.PowerShell.Utility
                Write-Warning                              ║ Microsoft.PowerShell.Utility
                Write-Error                                ║ Microsoft.PowerShell.Utility
                Set-StrictMode                             ║ Microsoft.PowerShell.Utility
                Get-AdObject                               ║ ActiveDirectory

        .NOTES
            Version:         1.1
            DateModified:    19/Mar/2025
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([void])]

    Param (
        [Parameter(Mandatory = $false,
            HelpMessage = 'Force reinitialization even if variables already exist.')]
        [switch]$Force
    )

    Begin {

        Set-StrictMode -Version Latest

        ##############################
        # Module imports

        # Check if ActiveDirectory module is available
        $adModuleAvailable = Get-Module -ListAvailable -Name 'ActiveDirectory'

        try {
            if ($adModuleAvailable) {

                Import-Module -Name 'ActiveDirectory' -Force -Verbose:$false | Out-Null

            } else {
                Write-Warning -Message 'ActiveDirectory module is not available. Skipping AD-related functionality.'
            } #end If-Else

        } catch {
            Write-Error -Message ('Failed to import ActiveDirectory module: {0}' -f $_ )
        } #end Try-Catch

        ##############################
        # Variables Definition

    } #end Begin

    Process {

        if ($adModuleAvailable) {
            try {

                # Active Directory DistinguishedName
                if ($Force -or $null -eq $Variables.AdDN) {
                    $Variables.AdDN = ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString()
                } #end If

                # Configuration Naming Context
                if ($Force -or $null -eq $Variables.configurationNamingContext) {
                    $Variables.configurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()
                } #end If

                # Active Directory DistinguishedName
                if ($Force -or $null -eq $Variables.defaultNamingContext) {
                    $Variables.defaultNamingContext = ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString()
                } #end If

                # Get current DNS domain name
                if ($Force -or $null -eq $Variables.DnsFqdn) {
                    $Variables.DnsFqdn = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
                } #end If

                # Naming Contexts
                if ($Force -or $null -eq $Variables.namingContexts) {
                    $Variables.namingContexts = ([ADSI]'LDAP://RootDSE').namingContexts
                } #end If

                # Partitions Container
                if ($Force -or $null -eq $Variables.PartitionsContainer) {
                    $Variables.PartitionsContainer = (([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString())
                } #end If

                # Root Domain Naming Context
                if ($Force -or $null -eq $Variables.rootDomainNamingContext) {
                    $Variables.rootDomainNamingContext = ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()
                } #end If

                # Schema Naming Context
                if ($Force -or $null -eq $Variables.SchemaNamingContext) {
                    $Variables.SchemaNamingContext = ([ADSI]'LDAP://RootDSE').SchemaNamingContext.ToString()
                } #end If

            } Catch {

                Write-Error -Message '
                    Something went wrong while trying to fill $Variables!
                        Ensure that:
                            * Machine is Domain Joined
                            * Active Directory is available and working
                            * Communication exist between this machine and AD'

            } #end Try-Catch


            # Well-Known SIDs
            # Following functions must be the last ones to be called, otherwise error is thrown.
            # Hashtable containing the mappings between ClassSchema/AttributeSchema and GUID's
            If ($Variables.GuidMap.Count -eq 0) {
                Try {
                    [hashtable]$TmpMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
                    [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

                    Write-Verbose -Message '
                        The GUID map is null, empty, zero, or false.
                        Getting the GUID value of each schema class and attribute'

                    #store the GUID value of each schema class and attribute
                    $Splat = @{
                        SearchBase = $Variables.SchemaNamingContext
                        LDAPFilter = '(schemaidguid=*)'
                        Properties = 'lDAPDisplayName', 'schemaIDGUID'
                    }
                    $AllSchema = Get-ADObject @Splat

                    Write-Verbose -Message 'Processing all schema class and attribute'
                    Foreach ($item in $AllSchema) {

                        # add current Guid to $TempMap
                        $TmpMap.Add($item.lDAPDisplayName, ([System.GUID]$item.schemaIDGUID).GUID)

                    } #end ForEach

                    # Include "ALL [nullGUID]"
                    $TmpMap.Add('All', $Constants.guidNull)

                    Write-Verbose -Message '$Variables.GuidMap was empty. Adding values to it!'
                    $Variables.GuidMap = $TmpMap

                } catch {

                    Write-Error -Message '
                        Something went wrong while trying to fill $Variables.GuidMap!
                            Ensure that:
                                * Machine is Domain Joined
                                * Active Directory is available and working
                                * Communication exist between this machine and AD'

                } #end Try-Catch
            } #end If

            # Hashtable containing the mappings between SchemaExtendedRights and GUID's
            If ($Variables.ExtendedRightsMap.Count -eq 0) {
                Try {
                    [hashtable]$TmpMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
                    [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

                    Write-Verbose -Message '
                        The Extended Rights map is null, empty, zero, or false.
                        Getting the GUID value of each Extended attribute'

                    # store the GUID value of each extended right in the forest
                    $Splat = @{
                        SearchBase = ('CN=Extended-Rights,{0}' -f $Variables.configurationNamingContext)
                        LDAPFilter = '(objectclass=controlAccessRight)'
                        Properties = 'DisplayName', 'rightsGuid'
                    }
                    $AllExtended = Get-ADObject @Splat

                    Write-Verbose -Message 'Processing all Extended attributes'
                    ForEach ($Item in $AllExtended) {

                        # add current Guid to $TempMap
                        $TmpMap.Add($Item.displayName, ([system.guid]$Item.rightsGuid).GUID)

                    } #end Foreach

                    # Include "ALL [nullGUID]"
                    $TmpMap.Add('All', $Constants.guidNull)

                    Write-Verbose -Message '$Variables.ExtendedRightsMap was empty. Adding values to it!'
                    $Variables.ExtendedRightsMap = $TmpMap

                } Catch {

                    Write-Error -Message '
                    Something went wrong while trying to fill $Variables.ExtendedRightsMap!
                        Ensure that:
                            * Machine is Domain Joined
                            * Active Directory is available and working
                            * Communication exist between this machine and AD'

                } #end Try-Catch
            } #end If
        } #end If


    } #end Process

    End {
    } #end End
} #end Function Initialize-ModuleVariable
