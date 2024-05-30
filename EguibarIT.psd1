#
# Module manifest for module 'EguibarIT'
#
# Generated by: Vicente Rodriguez Eguibar
#
# Generated on: 5/30/2024
#

@{

# Script module or binary module file associated with this manifest.
RootModule = 'EguibarIT.psm1'

# Version number of this module.
ModuleVersion = '1.56.113'

# Supported PSEditions
CompatiblePSEditions = 'Desktop', 'Core'

# ID used to uniquely identify this module
GUID = '73548059-dfed-487e-9e47-f1a95ff90118'

# Author of this module
Author = 'Vicente Rodriguez Eguibar'

# Company or vendor of this module
CompanyName = 'EguibarIT'

# Copyright statement for this module
Copyright = 'All rights reserved (c) 2022 - EguibarIT.'

# Description of the functionality provided by this module
Description = 'Functions used to implement the Delegation Model with Tiers on the given Active Directory.'

# Minimum version of the PowerShell engine required by this module
PowerShellVersion = '5.1'

# Name of the PowerShell host required by this module
# PowerShellHostName = ''

# Minimum version of the PowerShell host required by this module
# PowerShellHostVersion = ''

# Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# DotNetFrameworkVersion = ''

# Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
# ClrVersion = ''

# Processor architecture (None, X86, Amd64) required by this module
# ProcessorArchitecture = ''

# Modules that must be imported into the global environment prior to importing this module
# RequiredModules = @()

# Assemblies that must be loaded prior to importing this module
# RequiredAssemblies = @()

# Script files (.ps1) that are run in the caller's environment prior to importing this module.
# ScriptsToProcess = @()

# Type files (.ps1xml) to be loaded when importing this module
# TypesToProcess = @()

# Format files (.ps1xml) to be loaded when importing this module
# FormatsToProcess = @()

# Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
# NestedModules = @()

# Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
FunctionsToExport = 'Add-AdGroupNesting', 'ConvertTo-IntegerIPv4', 
               'ConvertTo-IPv4Integer', 'ConvertTo-IPv4MaskBit', 
               'ConvertTo-IPv4MaskString', 'ConvertTo-IPv4NetworkAddress', 
               'ConvertTo-WmiFilter', 'Get-AdSite', 'Get-AllAdSiteLink', 
               'Get-AllAdSubnet', 'Grant-NTFSPermission', 'Import-MyModule', 
               'New-AdDelegatedGroup', 'New-AGPMobject', 'New-AreaShareNTFS', 
               'New-CaObject', 'New-CentralItOU', 'New-DelegateAdGpo', 
               'New-DelegateAdOU', 'New-DelegateSiteOU', 'New-DfsObject', 
               'New-DhcpObject', 'New-EitAdSite', 'New-ExchangeObject', 
               'New-LapsObject', 'New-LocalLogonTask', 'New-TimePolicyGPO', 
               'New-WsusObjects', 'Revoke-Inheritance', 'Revoke-NTFSPermissions', 
               'Set-AdAclDelegateComputerAdmin', 'Set-AdAclDelegateGalAdmin', 
               'Set-AdAclDelegateUserAdmin', 'Set-AdAclLaps', 
               'Start-AdAclDelegateComputerAdmin', 'Start-AdCleanOU', 
               'Start-AdDelegatedSite', 'Test-IPv4MaskString', 'Test-RegistryValue'

# Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
CmdletsToExport = '*'

# Variables to export from this module
# VariablesToExport = @()

# Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
AliasesToExport = @()

# DSC resources to export from this module
# DscResourcesToExport = @()

# List of all modules packaged with this module
# ModuleList = @()

# List of all files packaged with this module
# FileList = @()

# Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{

    PSData = @{

        # Tags applied to this module. These help with module discovery in online galleries.
        Tags = 'Windows','ActiveDirectory','ActiveDirectory_Delegation','ActiveDirectory_Security','AD_Security','Security','Delegation','AD_Delegation','DelegationModel','TierModel','RBACmodel','RoleBasedAccessControl_model','DelegationModel','TierModel','RBACmodel','Infrastructure','Testing','Checks','Audits','Checklist','Validation','CredentialTheaf','Pass-the-Hash','Pass-the-Ticket','Golden_Ticket','Silver_Ticket'

        # A URL to the license for this module.
        # LicenseUri = ''

        # A URL to the main website for this project.
        ProjectUri = 'https://github.com/vreguibar/EguibarIT'

        # A URL to an icon representing this module.
        IconUri = 'https://EguibarIT.com/wp-content/uploads/2017/09/LOGO_FondoBlanco.png'

        # ReleaseNotes of this module
        # ReleaseNotes = ''

        # Prerelease string of this module
        # Prerelease = ''

        # Flag to indicate whether the module requires explicit user acceptance for install/update/save
        # RequireLicenseAcceptance = $false

        # External dependent modules of this module
        ExternalModuleDependencies = @('ActiveDirectory','GroupPolicy','ServerManager','EguibarIT.DelegationPS')

    } # End of PSData hashtable

 } # End of PrivateData hashtable

# HelpInfo URI of this module
HelpInfoURI = 'https://eguibarit.eu/powershell/delegation-model-powershell-scripts/eguibarit-powershell-module/'

# Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
# DefaultCommandPrefix = ''

}

