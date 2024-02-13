---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Get-AdObjectType

## SYNOPSIS
This function retrieves the type of an Active Directory object based on the provided identity.

## SYNTAX

```
Get-AdObjectType [-Identity] <Object> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
The Get-AdObjectType function determines the type of an Active Directory object based on the given identity.
It supports various object types, including AD users, computers, and groups.
The function provides verbose output
and implements the -WhatIf parameter to simulate actions.

## EXAMPLES

### EXAMPLE 1
```
Get-AdObjectType -Identity "davader"
Retrieves the type of the Active Directory object with the SamAccountName "davader".
```

## PARAMETERS

### -Identity
Specifies the identity of the Active Directory object.
This parameter is mandatory.

```yaml
Type: Object
Parameter Sets: (All)
Aliases: ID, SamAccountName, DistinguishedName, DN, SID

Required: True
Position: 1
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

### String: Accepts a string representing the identity of the Active Directory object.
## OUTPUTS

### Microsoft.ActiveDirectory.Management.ADAccount or
### Microsoft.ActiveDirectory.Management.ADComputer or
### Microsoft.ActiveDirectory.Management.AdGroup
## NOTES
Version:         1.0
    DateModified:    08/Oct/2021
    LasModifiedBy:   Vicente Rodriguez Eguibar
        vicente@eguibar.com
        Eguibar Information Technology S.L.
        http://www.eguibarit.com

## RELATED LINKS
