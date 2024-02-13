---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Get-ADCSTemplate

## SYNOPSIS
Returns the properties of either a single or all Active Directory Certificate Template(s).

## SYNTAX

```
Get-ADCSTemplate [[-DisplayName] <String>] [[-Server] <String>] [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
Returns the properties of either a single or list of Active Directory Certificate Template(s)
depending on whether a DisplayName parameter was passed.

## EXAMPLES

### EXAMPLE 1
```
Get-ADCSTemplate
```

### EXAMPLE 2
```
Get-ADCSTemplate -DisplayName PowerShellCMS
```

### EXAMPLE 3
```
Get-ADCSTemplate | Sort-Object Name | ft Name, Created, Modified
```

### EXAMPLE 4
```
###View template permissions
(Get-ADCSTemplate pscms).nTSecurityDescriptor
(Get-ADCSTemplate pscms).nTSecurityDescriptor.Sddl
(Get-ADCSTemplate pscms).nTSecurityDescriptor.Access
ConvertFrom-SddlString -Sddl (Get-ADCSTemplate pscms).nTSecurityDescriptor.sddl -Type ActiveDirectoryRights
```

## PARAMETERS

### -DisplayName
Name of an AD CS template to retrieve.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Server
FQDN of Active Directory Domain Controller to target for the operation.
When not specified it will search for the nearest Domain Controller.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ProgressAction
{{ Fill ProgressAction Description }}

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

## NOTES
https://www.powershellgallery.com/packages/ADCSTemplate/1.0.1.0/Content/ADCSTemplate.psm1

## RELATED LINKS
