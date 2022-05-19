param (
    [string] $preReleaseTag,
    [string] $apiKey
)

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition

# Now replace version in psd1
#Read manifest
$FileContent = Import-PowerShellDataFile -Path "$scriptPath\EguibarIT.psd1" -Verbose
#Get current version
[version]$Version = $FileContent.ModuleVersion
#Increase Build version
[version]$NewVersion = '{0}.{1}.{2}' -f $Version.Major, $Version.Minor, ($Version.Build + 1) 

# Modify Manifest D:\a\EguibarIT\EguibarIT\EguibarIT.psd1
$Splat = @{
    Path          = "$scriptPath\EguibarIT.psd1"
    ModuleVersion = $NewVersion
    Prerelease    = $preReleaseTag
}
Update-ModuleManifest @Splat

$splat = @{
    Path = $scriptPath
    NuGetApiKey = $apiKey
    Tag         = 'Active Directory', 'Active-Directory', 'AD', 'Security', 'Delegation Model', 'Tiering', 'Tier Model', 'Credential Teaf', 'RBAC', 'RBAC Model'
    ProjectUri  = 'https://delegationmodel.com'
    Force       = $true
    Verbose     = $true
}
Publish-Module @Splat














<#
param (
    [string] $preReleaseTag,
    [string] $apiKey
)

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition


$srcPath = "$scriptPath\src";
Write-Host "----------------------------------------------------"
Write-Host "Script Path $scriptPath"
# Should be "Script Path D:\a\EguibarIT\EguibarIT"
Write-Host "----------------------------------------------------"
Write-Host "Source Path $srcPath"
# Should be "Script Path D:\a\EguibarIT\EguibarIT\src"

$outFile = "$srcPath\EguibarIT.psm1"
# Should be "D:\a\EguibarIT\EguibarIT\src\EguibarIT.psm1"

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
#Read manifest
$FileContent = Import-PowerShellDataFile -Path "$scriptPath\EguibarIT.psd1" -Verbose
#Get current version
[version]$Version = $FileContent.ModuleVersion
#Increase Build version
[version]$NewVersion = '{0}.{1}.{2}' -f $Version.Major, $Version.Minor, ($Version.Build + 1) 

$Dir1 = Get-ChildItem D:\a\EguibarIT\EguibarIT\src
Write-Host "Files in SRC directory: $Dir1"
Write-Host '-------------------------------------------------------------------------------------------------------'
$PSM1file = Get-Content $outFile
Write-Host "Content of EguibarIT.psm1: $PSM1file"
Write-Host '-------------------------------------------------------------------------------------------------------'

# Modify Manifest D:\a\EguibarIT\EguibarIT\EguibarIT.psd1
$Splat = @{
    Path          = "$scriptPath\EguibarIT.psd1"
    ModuleVersion = $NewVersion
    Prerelease    = $preReleaseTag
}
Update-ModuleManifest @Splat

Copy-Item -Path $scriptPath\EguibarIT.psd1 -Destination $srcPath -Verbose -force

Publish-Module -Path $srcPath -NuGetApiKey $apiKey -Force -Verbose
#>