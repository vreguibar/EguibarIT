# Function to check if a class is already loaded
function Test-ClassExist {
    param(
        [string]$ClassName
    )

    # Try to get the type by its full name
    $type = [Type]::GetType($ClassName, $false, $false)

    # Return true if the type exists, otherwise false
    return [bool]$type
} #end Function

# Define the class only if it doesn't already exist
if ((-not (Test-ClassExist 'EventIdInfo')) -or
    (-not (Test-ClassExist 'EventIDs')) -or
    (-not (Test-ClassExist 'EventID')) -or
    (-not (Test-ClassExist 'EventSeverity')) -or
    (-not (Test-ClassExist 'EventCategory'))
) {
    Write-Verbose -Message 'Event Info class not loaded. Proceed to load...!'
    #$EventsFileCS = Get-Content -Path "$PSScriptRoot\Class.Events.cs" -Raw
    $EventsFileCS = [System.IO.File]::ReadAllText("$PSScriptRoot\Class.Events.cs")
    Add-Type -Language CSharp -TypeDefinition $EventsFileCS
} #end If
