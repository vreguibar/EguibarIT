﻿$Variables = [ordered] @{

    # Active Directory DistinguishedName
    AdDN                       = $null

    # Configuration Naming Context
    configurationNamingContext = $null

    # Active Directory DistinguishedName
    defaultNamingContext       = $null

    # Get current DNS domain name
    DnsFqdn                    = $null

    # Hashtable containing the mappings between SchemaExtendedRights and GUID's
    ExtendedRightsMap          = $null

    # Hashtable containing the mappings between ClassSchema/AttributeSchema and GUID's
    GuidMap                    = $null

    # Naming Contexts
    namingContexts             = $null

    # Partitions Container
    PartitionsContainer        = $null

    # Root Domain Naming Context
    rootDomainNamingContext    = $null

    # Schema Naming Context
    SchemaNamingContext        = $null

    # Well-Known SIDs
    WellKnownSIDs              = $null
}

$Splat = @{
    Name        = 'Variables'
    Value       = $Variables
    Description = 'Define a Module variable, containing Schema GUIDs, Naming Contexts or Well Known SIDs'
    Scope       = 'Global'
    Force       = $true
}

# Check if the 'Variables' variable exists. Create it if not.
if (-not (Get-Variable -Name 'Variables' -Scope Global -ErrorAction SilentlyContinue)) {
    New-Variable @Splat
    Write-Verbose -Message ('Variables have been initialized: {0}' -f $Variables)
} else {
    Write-Verbose -Message 'Variables already exist.'
}
