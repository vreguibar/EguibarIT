---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Start-AdCleanOU

## SYNOPSIS
Clean default OU permissions.

## SYNTAX

```
Start-AdCleanOU [-LDAPpath] <String> [-RemoveAuthenticatedUsers] [-RemoveUnknownSIDs]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The function will remove some of the default premission on
the provided OU.
It will remove the "Account Operators" and
"Print Operators" built-in groups.

## EXAMPLES

### EXAMPLE 1
```
Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
```

### EXAMPLE 2
```
Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveAuthenticatedUsers
```

### EXAMPLE 3
```
Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveUnknownSIDs
```

### EXAMPLE 4
```
Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveAuthenticatedUsers -RemoveUnknownSIDs
```

## PARAMETERS

### -LDAPpath
Distinguished name of the OU to be cleaned.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -RemoveAuthenticatedUsers
If present, Remove Authenticated Users.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -RemoveUnknownSIDs
If present, Remove Unknown SIDs.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
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
Version:         1.2
DateModified:    19/Dec/2017
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
