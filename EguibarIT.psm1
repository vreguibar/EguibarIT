# Get Enums
if (Test-Path -Path "$PSScriptRoot\Enums") {
    $Enums = @( Get-ChildItem -Path "$PSScriptRoot\Enums\" -Filter *.ps1 -ErrorAction SilentlyContinue -Recurse )

    # Import Enums
    foreach ($Item in $Enums) {
        Try {
            . $Item.FullName
            Write-Verbose -Message "Imported $($Item.BaseName)"
        } Catch {
            throw
            Write-Error -Message "Could not load Enum [$($Item.Name)] : $($_.Message)"
        } #end Try-Catch
    } #end Foreach
} #end If

# Get Classes
if (Test-Path -Path "$PSScriptRoot\Classes") {
    $Classes = @( Get-ChildItem -Path "$PSScriptRoot\Classes\" -Filter *.ps1 -ErrorAction SilentlyContinue -Recurse )

    foreach ($Item in $Classes) {
        Try {
            . $Item.FullName
            Write-Verbose -Message "Imported $($Item.BaseName)"
        } Catch {
            throw
            Write-Error -Message "Could not load Enum [$($Item.Name)] : $($_.Message)"
        } #end Try-Catch
    } #end Foreach
} #end If

#Get public and private function definition files.
$Private = @( Get-ChildItem -Path "$PSScriptRoot\Private\" -Filter *.ps1 -ErrorAction SilentlyContinue -Recurse )
$Public = @( Get-ChildItem -Path "$PSScriptRoot\Public\" -Filter *.ps1 -ErrorAction SilentlyContinue -Recurse )

#Dot source the files
Foreach ($Item in @($Private + $Public)) {
    Try {
        . $Item.fullname
        # Write-Warning $import.fullname
    } Catch {
        Write-Error -Message "Failed to import functions from $($Item.Fullname): $_"
    }
}

Export-ModuleMember -Function '*' -Alias '*'
