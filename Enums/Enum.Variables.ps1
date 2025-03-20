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

    # Module Logging Config
    LogConfig                  = @{
        LogName          = 'EguibarIT-Events'
        Source           = 'EguibarIT-PowerShellModule'
        MaximumKilobytes = 16384  # 16 MB default
        RetentionDays    = 30
    }
    EventLogInitialized        = $false

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


# Define the initial variable structure if it doesn't exist yet
if (-not (Get-Variable -Name 'Variables' -Scope Global -ErrorAction SilentlyContinue)) {

    New-Variable @Splat
    Write-Verbose -Message ('Variables have been initialized: {0}' -f $Variables)

} else {

    # If the variable exists, merge the new values with existing ones
    $existingVariables = Get-Variable -Name 'Variables' -Scope Global -ValueOnly

    # For each key in your new $Variables hashtable
    foreach ($key in $Variables.Keys) {

        if (-not $existingVariables.ContainsKey($key)) {

            # Add new keys that don't exist in the current Variables
            $existingVariables[$key] = $Variables[$key]
            Write-Verbose -Message ('Added new variable: {0}' -f $key)

        } elseif ($Variables[$key] -is [hashtable] -and
            $existingVariables[$key] -is [hashtable]) {

            # For nested hashtable, merge them
            foreach ($nestedKey in $Variables[$key].Keys) {

                if (-not $existingVariables[$key].ContainsKey($nestedKey)) {

                    $existingVariables[$key][$nestedKey] = $Variables[$key][$nestedKey]
                    Write-Verbose -Message ('Added new nested variable: {0}.{1}' -f $key, $nestedKey)

                } #end If

            } #end foreach
        } #end If-Else
        # For other types (non-hashtable), we don't overwrite by default
    } #end Foreach

    Write-Verbose -Message 'Variables already exist. Merged new values with existing ones.'
} #end If-Else
