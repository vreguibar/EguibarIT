$Constants = [ordered] @{

    # Null GUID which is considered as "All"
    #$guidNull  = New-Object -TypeName Guid -ArgumentList 00000000-0000-0000-0000-000000000000
    guidNull   = [System.guid]::New('00000000-0000-0000-0000-000000000000')

    # Horizontal Tab
    HTab       = "`t"

    # New NewLine
    NL         = [System.Environment]::NewLine

    # Regular Expression (RegEx) for SIDs
    SidRegEx   = [RegEx]::new('^S-1-(0|1|2|3|4|5|16|59)-\d+(-\d+)*$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    # Regular Expression (RegEx) for DistinguishedName
    DnRegEx    = [RegEx]::new('^(?:(CN=(?<name>(?:[^,\\]|\\.)+),)*)?(OU=(?<ou>(?:[^,\\]|\\.)+),)*(DC=(?<dc1>(?:[^,\\]|\\.)+))(,DC=(?<dc2>(?:[^,\\]|\\.)+))+?$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    # Regular Expression (RegEx) for GUID
    <# Define GUID Regex
    Active Directory GUID is represented as a 128-bit number, typically displayed as a
    string of 32 hexadecimal characters, such as "550e8400-e29b-41d4-a716-446655440000"
        ^ asserts the start of the string.
        [0-9a-fA-F] matches any hexadecimal digit.
        {8} specifies that the preceding character class should appear exactly 8 times.
        - matches the hyphen character literally.
        {4} specifies that the preceding character class should appear exactly 4 times.
        {12} specifies that the preceding character class should appear exactly 12 times.
        $ asserts the end of the string.
    #>
    GuidRegEx  = [RegEx]::new('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    # Regular Expression (RegEx) for Email
    EmailRegEx = [RegEx]::new("^(?("")("".+?""@)|(([0-9a-zA-Z]((\.(?!\.))|[-!#\$%&'\*\+/=\?\^`\{\}\|~\w])*)(?<=[0-9a-zA-Z])@))(?(\[)(\[(\d{1,3}\.){3}\d{1,3}\])|(([0-9a-zA-Z][-\w]*[0-9a-zA-Z]\.)+[a-zA-Z]{2,6}))$", [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
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
