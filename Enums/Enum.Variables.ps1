$Variables = @{

    # Active Directory DistinguishedName
    AdDN                       = $null

    # Configuration Naming Context
    configurationNamingContext = $null

    # Active Directory DistinguishedName
    defaultNamingContext       = $null

    # Get current DNS domain name
    DnsFqdn                    = $null

    # Hashtable containing the mappings between SchemaExtendedRights and GUID's
    ExtendedRightsMap          = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    # Hashtable containing the mappings between ClassSchema/AttributeSchema and GUID's
    GuidMap                    = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    # Naming Contexts
    namingContexts             = $null

    # Partitions Container
    PartitionsContainer        = $null

    # Root Domain Naming Context
    rootDomainNamingContext    = $null

    # Schema Naming Context
    SchemaNamingContext        = $null

    # Well-Known SIDs
    WellKnownSIDs              = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

    # Message header for new regions. Used on NewCentralItOu to easily identify regions on transcript
    NewRegionMessage           = @'

    ████████████████████████████████████████████████████████████████████████████████████████████████████
    █                                                                                                  █
    █             ╔══════════════════════════════════════════════════════════════════════╗             █
    █             ║                                                                      ║             █
    █             ║                        New Region Start                              ║             █
    █             ║                                                                      ║             █
    █             ╚══════════════════════════════════════════════════════════════════════╝             █
    █                                                                                                  █
    ████████████████████████████████████████████████████████████████████████████████████████████████████

        REGION: {0}

'@

    # Standard header used on each function on the Begin section
    Header                     = @'

    ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
    ┃                                        EguibarIT module                                          ┃
    ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
            Date:     {0}
            Starting: {1}

    Parameters used by the function... {2}

'@

    # Standard footer used on each function on the Begin section
    Footer                     = @'

        Function {0} finished {1}"

    ┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫

'@

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
