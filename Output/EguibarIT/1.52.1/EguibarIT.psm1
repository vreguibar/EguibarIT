#Get public and private function definition files.
$Classes = @( Get-ChildItem -Path $PSScriptRoot\Classes\*.ps1 -ErrorAction SilentlyContinue -Recurse )
$Enums = @( Get-ChildItem -Path $PSScriptRoot\Enums\*.ps1 -ErrorAction SilentlyContinue -Recurse )
$Private = @( Get-ChildItem -Path $PSScriptRoot\Private\*.ps1 -ErrorAction SilentlyContinue -Recurse )
$Public = @( Get-ChildItem -Path $PSScriptRoot\Public\*.ps1 -ErrorAction SilentlyContinue -Recurse )


#Dot source the files
Foreach ($import in @($Classes + $Enums + $Private + $Public)) {
    Try {
        . $import.fullname
        # Write-Warning $import.fullname
    } Catch {
        Write-Error -Message "Failed to import functions from $($import.Fullname): $_"
    }
}

Export-ModuleMember -Function '*' -Alias '*'
