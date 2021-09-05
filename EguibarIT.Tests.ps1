$PSVersionTable.PSVersion

$ModuleName = (Get-ChildItem $PSScriptRoot\*.psd1).BaseName
$RequiredModules = @(
    'Pester'
)
foreach ($_ in $RequiredModules) {
    if ($null -eq (Get-Module -ListAvailable $_)) {
        Write-Warning "$ModuleName - Downloading $_ from PSGallery"
        Install-Module -Name $_ -Repository PSGallery -Force -SkipPublisherCheck
    }
    Import-Module $_ -Force
}
Import-Module $PSScriptRoot\EguibarIT.psd1 -Force

$result = Invoke-Pester -Path $PSScriptRoot\Tests #-Output Detailed

if ($result.FailedCount -gt 0) {
    throw "$($result.FailedCount) tests failed."
}