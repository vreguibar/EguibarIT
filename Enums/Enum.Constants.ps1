$Constants = [ordered] @{

    # Null GUID which is considered as "All"
    #$guidNull  = New-Object -TypeName Guid -ArgumentList 00000000-0000-0000-0000-000000000000
    guidNull = [System.guid]::New('00000000-0000-0000-0000-000000000000')

    # Horizontal Tab
    HTab     = "`t"

    # New NewLine
    NL       = [System.Environment]::NewLine

    # Regular Expression (RegEx) for SIDs
    SidRegEx = [RegEx]::new('^S-1-(0|1|2|3|4|5|59)-\d+(-\d+)*$')
}

$Splat = @{
    Name        = 'Constants'
    Value       = $Constants
    Description = 'Contains the Constant values used on this module, like GUIDnull, Horizontal Tab or NewLine.'
    Scope       = 'Global'
    Option      = 'Constant'
    Force       = $true
}

# Check if the 'Constants' variable exists. Create it if not.
if (-not (Get-Variable -Name 'Constants' -Scope Global -ErrorAction SilentlyContinue)) {
    New-Variable @Splat
}

# Optional: Output the Constants for verification (verbose)
Write-Verbose -Message ('Constants have been initialized: {0}' -f $Constants)
