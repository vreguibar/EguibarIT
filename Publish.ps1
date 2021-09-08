param (
    [string] $version,
    [string] $preReleaseTag,
    [string] $apiKey
)

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$srcPath = "$scriptPath\src";
Write-Host "Proceeding to publish all code found in $srcPath"

$outFile = "$scriptPath\EguibarIT\EguibarIT.psm1"
if (Test-Path $outFile) 
{
    Remove-Item $outFile
}

if (!(Test-Path "$scriptPath\EguibarIT")) 
{
    New-Item "$scriptPath\EguibarIT" -ItemType Directory
}

$ScriptFunctions = @( Get-ChildItem -Path $srcPath\*.ps1 -ErrorAction SilentlyContinue -Recurse )
$ModulePSM = @( Get-ChildItem -Path $srcPath\*.psm1 -ErrorAction SilentlyContinue -Recurse )
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

$fileContent = Get-Content "$scriptPath\src\EguibarIT.psd1.source"
$fileContent = $fileContent -replace '{{version}}', $version
$fileContent = $fileContent -replace '{{preReleaseTag}}', $preReleaseTag 
Set-Content "$scriptPath\EguibarIT\EguibarIT.psd1" -Value $fileContent  -Force

Publish-Module -Path $scriptPath\BuildUtils -NuGetApiKey $apiKey -Verbose -Force
