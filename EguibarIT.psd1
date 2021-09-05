@{
    AliasesToExport      = @()
    Author               = 'Vicente Rodriguez Eguibar'
    CmdletsToExport      = @('*')
    CompanyName          = 'EguibarIT'
    CompatiblePSEditions = @('Desktop')
    Copyright            = 'All rights reserved (c) 2021 - Eguibar Information Technology S.L.'
    Description          = 'Functions used to implement the Delegation Model with Tiers on the given Active Directory'
    FunctionsToExport    = @('*')
    GUID                 = '73548059-dfed-487e-9e47-f1a95ff90118'
    ModuleVersion        = '1.0.2'
    PowerShellVersion    = '5.1'
    PrivateData          = @{
        PSData = @{
            Tags                       = @('Windows', 'ActiveDirectory', 'AD', 'Infrastructure', 'Testing', 'Checks', 'Audits', 'Checklist', 'Validation')
            ProjectUri                 = 'https://github.com/EguibarIT/EguibarIT'
            IconUri                    = 'https://EguibarIT.com//wp-content/uploads/2017/09/LOGO_FondoBlanco.png'
            ExternalModuleDependencies = @('ActiveDirectory', 'GroupPolicy', 'ServerManager')
        }
    }
    RequiredModules      = @( @{
            ModuleVersion = '1.2.7296.23723'
            ModuleName    = 'EguibarIT.Delegation'
            Guid          = '5953deff-85c3-4e58-b961-79da8c5f7573'
        }, 'ActiveDirectory', 'GroupPolicy', 'ServerManager')
    RootModule           = 'EguibarIT.psm1'
}