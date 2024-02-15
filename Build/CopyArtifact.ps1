#
param (
    [Parameter(Mandatory = $true)]
    $ModuleName,
    [Parameter(Mandatory = $true)]
    $ModuleVersion
)

Function CopyArtifacts {
    <#
        .SYNOPSIS

        .DESCRIPTION

        .PARAMETER Length

        .EXAMPLE

        .NOTES
        Version:         0.0
            DateModified:    xx/Jun/2099
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $False)]

    param (

        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Name of the module being processed.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName,

        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Name of the module being processed.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleVersion

    )

    Begin {

        # Create Output folder
        if (Test-Path ".\Output\$($ModuleName)") {
            Write-Verbose -Message 'Output folder does exist, continuing build.'
        } else {
            Write-Verbose -Message 'Output folder does not exist. Creating it now'
            New-Item -Path ".\Output\$($ModuleName)" -ItemType Directory -Force
        } #end If-Else



        #Create Version folder
        if (Test-Path ".\Output\$($ModuleName)\$($ModuleVersion)") {
            Write-Warning -Message "Version: $($ModuleVersion) - folder was detected in .\Output\$($ModuleName). Removing old temp folder."
            Remove-Item ".\Output\$($ModuleName)\$($ModuleVersion)" -Recurse -Force
        } #end If

        Write-Verbose -Message "Creating new temp module version folder: .\Output\$($ModuleName)\$($ModuleVersion)."
        if (Test-Path ".\Output\$($ModuleName)") {
            Write-Verbose -Message 'Detected old folder, removing it from output folder'
            Remove-Item -Path ".\Output\$($ModuleName)" -Recurse -Force
        } #end If

        try {
            New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)" -ItemType Directory
        } catch {
            throw "Failed creating the new temp module folder: .\Output\$($ModuleName)\$($ModuleVersion)"
        } #end Try-Catch

    } #end Begin

    Process {

        Write-Verbose -Message 'Generating the Module Manifest for temp build and generating new Module File'
        try {
            Copy-Item -Path ".\$($ModuleName).psd1" -Destination ".\Output\$($ModuleName)\$ModuleVersion\"
            New-Item -Path ".\Output\$($ModuleName)\$ModuleVersion\$($ModuleName).psm1" -ItemType File
        } catch {
            throw "Failed copying Module Manifest from: .\$($ModuleName).psd1 to .\Output\$($ModuleName)\$ModuleVersion\ or Generating the new psm file."
        } #end Try-Catch



        Write-Verbose -Message 'Updating Module Manifest with Public Functions'
        try {
            Write-Verbose -Message 'Appending Public functions to the psm file'
            $functionsToExport = New-Object -TypeName System.Collections.ArrayList
            foreach ($function in $publicFunctions.Name) {
                Write-Verbose -Message "Exporting function: $(($function.split('.')[0]).ToString())"
                $functionsToExport.Add(($function.split('.')[0]).ToString())
            }
            Update-ModuleManifest -Path ".\Output\$($ModuleName)\$($ModuleVersion)\$($ModuleName).psd1" -FunctionsToExport $functionsToExport
        } catch {
            throw 'Failed updating Module manifest with public functions'
        } #end Try-Catch



        Write-Verbose -Message 'Copying Public .ps1 files'
        try {
            New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)\Public" -ItemType Directory -ErrorAction Continue
            Copy-Item -Path ".\$($ModuleName).psm1" -Destination ".\Output\$($ModuleName)\$ModuleVersion\"
            Copy-Item -Path '.\Public\*.ps1' -Destination ".\Output\$($ModuleName)\$ModuleVersion\Public\"
        } catch {
            throw "Failed copying Public functions from: .\$($ModuleName)\Public\ to .\Output\$($ModuleName)\$ModuleVersion\Public\"
        } #end Try-Catch



        Write-Verbose -Message 'Copying Private .ps1 functions'
        try {
            New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)\Private" -ItemType Directory -ErrorAction Continue
            Copy-Item -Path '.\Private\*.ps1' -Destination ".\Output\$($ModuleName)\$ModuleVersion\Private\"
        } catch {
            throw "Failed copying Private functions from: .\$($ModuleName)\Private\ to .\Output\$($ModuleName)\$ModuleVersion\Private\"
        } #end Try-Catch



        Write-Verbose -Message 'Copying Classes .ps1 functions'
        try {
            New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)\Classes" -ItemType Directory -ErrorAction Continue
            Copy-Item -Path '.\Classes\*.ps1' -Destination ".\Output\$($ModuleName)\$ModuleVersion\Classes\"
        } catch {
            throw "Failed copying Classes functions from: .\$($ModuleName)\Classes\ to .\Output\$($ModuleName)\$ModuleVersion\Classes\"
        } #end Try-Catch



        Write-Verbose -Message 'Copying Enums .ps1 functions'
        try {
            New-Item -Path ".\Output\$($ModuleName)\$($ModuleVersion)\Enums" -ItemType Directory -ErrorAction Continue
            Copy-Item -Path '.\Enums\*.ps1' -Destination ".\Output\$($ModuleName)\$ModuleVersion\Enums\"
        } catch {
            throw "Failed copying Enums functions from: .\$($ModuleName)\Enums\ to .\Output\$($ModuleName)\$ModuleVersion\Enums\"
        } #end Try-Catch



        Write-Verbose -Message 'Updating Module Manifest with root module'
        try {
            Write-Verbose -Message 'Updating the Module Manifest'
            Update-ModuleManifest -Path ".\Output\$($ModuleName)\$($ModuleVersion)\$($ModuleName).psd1" -RootModule "$($ModuleName).psm1"
        } catch {
            Write-Warning -Message 'Failed appinding the rootmodule to the Module Manifest'
        }

    } #end Process

    End {

    } #end End
} #end Function


# Call the function with parameters
CopyArtifacts -ModuleName $ModuleName -ModuleVersion $ModuleVersion
