# Get Enums
if (Test-Path -Path "$PSScriptRoot\Enums") {
    $Enums = @( Get-ChildItem -Path "$PSScriptRoot\Enums\" -Filter *.ps1 -ErrorAction SilentlyContinue -Recurse )

    # Import Enums
    foreach ($Item in $Enums) {
        Try {
            . $Item.FullName
            Write-Verbose -Message ('Enum Imported {0}' -f $($Item.BaseName))
        } Catch {
            Write-Error -Message "Could not load Enum [$($Item.Name)] : $($_.Message)"
            throw
        } #end Try-Catch
    } #end Foreach
} #end If

# Get Classes
if (Test-Path -Path "$PSScriptRoot\Classes") {
    $Classes = @( Get-ChildItem -Path "$PSScriptRoot\Classes\" -Filter *.ps1 -ErrorAction SilentlyContinue -Recurse )

    foreach ($Item in $Classes) {
        Try {
            . $Item.FullName
            Write-Verbose -Message ('Class Imported {0}' -f $($Item.BaseName))
        } Catch {
            Write-Error -Message "Could not load Class [$($Item.Name)] : $($_.Message)"
            throw
        } #end Try-Catch
    } #end Foreach
} #end If


# Load Private Functions
$Private = @( Get-ChildItem -Path "$PSScriptRoot\Private\" -Filter *.ps1 -ErrorAction SilentlyContinue -Recurse )
foreach ($Item in $Private) {
    Try {
        . $Item.Fullname
        Write-Verbose -Message ('Private Function Imported {0}' -f $($Item.BaseName))
    } Catch {
        Write-Error -Message "Failed to import private function from $($Item.Fullname): $($_.Exception.Message)"
        Throw
    } #end try-catch
} #end foreach

# Load Public Functions
$Public = @( Get-ChildItem -Path "$PSScriptRoot\Public\" -Filter *.ps1 -ErrorAction SilentlyContinue -Recurse )
foreach ($Item in $Public) {
    Try {
        . $Item.Fullname
        Write-Verbose -Message ('Public Function Imported {0}' -f $($Item.BaseName))
    } Catch {
        Write-Error -Message "Failed to import public function from $($Item.Fullname): $($_.Exception.Message)"
        Throw
    } #end try-catch
} #end foreach


Try {
    # Call function Initialize-ModuleVariable to fill-up $Variables
    Initialize-ModuleVariable
    return $true
} catch {
    Write-Error -Message ('Failed to update AD variables: {0}' -f $_)
    return $false
} #end try-catch

Export-ModuleMember -Function '*' -Alias '*' -Variable @('Constants', 'Variables') -Verbose:$false | Out-Null
