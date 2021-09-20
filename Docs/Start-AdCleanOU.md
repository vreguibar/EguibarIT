---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Start-AdCleanOU

## SYNOPSIS
The function will remove some of the default premission on
the provided OU.
It will remove the "Account Operators" and
"Print Operators" built-in groups.

## SYNTAX

```
Start-AdCleanOU [-LDAPpath] <String> [-RemoveAuthenticatedUsers] [-RemoveUnknownSIDs] [<CommonParameters>]
```

## DESCRIPTION
Long description

## EXAMPLES

### EXAMPLE 1
```
Start-AdCleanOU -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
```

## PARAMETERS

### -LDAPpath
PARAM1 Distinguished name of the OU to be cleaned

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
PARAM2 Remove Authenticated Users

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
PARAM3 Remove Unknown SIDs

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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### Param1 LDAPPath:................... [STRING] Distinguished name of the OU to be cleaned.
### Param2 RemoveAuthenticatedUsers:... [SWITCH] Remove Authenticated Users.
### Param3 RemoveUnknownSIDs:.......... [SWITCH] Remove Unknown SIDs.
## OUTPUTS

## NOTES
Version:         1.2
DateModified:    19/Dec/2017
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
