param (
    [string] $preReleaseTag,
    [string] $apiKey
)

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition


$srcPath = "$scriptPath\src";
Write-Host "----------------------------------------------------"
Write-Host "Script Path $scriptPath"
Write-Host "----------------------------------------------------"
Write-Host "Source Path $srcPath"

$outFile = "srcPath\EguibarIT.psm1"
if (Test-Path $outFile) {
    Remove-Item $outFile
}

if (-Not(Test-Path "$scriptPath\src")) {
    New-Item "$scriptPath\src" -ItemType Directory
}

$ScriptFunctions = @( Get-ChildItem -Path $scriptPath\*.ps1 -ErrorAction SilentlyContinue -Recurse )
$ModulePSM = @( Get-ChildItem -Path $scriptPath\*.psm1 -ErrorAction SilentlyContinue -Recurse )


foreach ($FilePath in $ScriptFunctions) {
    $Results = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$null, [ref]$null)
    $Functions = $Results.EndBlock.Extent.Text
    $Functions | Add-Content -Path $outFile
}


foreach ($FilePath in $ModulePSM) {
    $Content = Get-Content $FilePath
    $Content | Add-Content -Path $outFile
}
"Export-ModuleMember -Function * -Cmdlet *" | Add-Content -Path $outFile

# Now replace version in psd1

$FileContent = Import-PowerShellDataFile -Path "$scriptPath\EguibarIT.psd1" -Verbose

[version]$Version = $FileContent.ModuleVersion

[version]$NewVersion = '{0}.{1}.{2}' -f $Version.Major, $Version.Minor, ($Version.Build + 1) 
Write-Host "New Version is: $NewVersion"
$Splat = @{
    Path          = "$srcPath\EguibarIT.psd1"
    ModuleVersion = $NewVersion
    Prerelease    = $preReleaseTag
    Verbose       = $true
}
Update-ModuleManifest @Splat

Publish-Module -Path $srcPath -NuGetApiKey $apiKey -Force -Verbose