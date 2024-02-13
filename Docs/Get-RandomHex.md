---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Get-RandomHex

## SYNOPSIS
Generates a random hexadecimal string of specified length.

## SYNTAX

```
Get-RandomHex [-Length] <Int32> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
This function generates a random hexadecimal string of the specified length.

## EXAMPLES

### EXAMPLE 1
```
Get-RandomHex -Length 8
Generates a random hexadecimal string of length 8.
```

## PARAMETERS

### -Length
The length of the hexadecimal string to generate.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: 0
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

### None
## OUTPUTS

### System.String
### A random hexadecimal string.
## NOTES
Version:         1.0
    DateModified:    22/Jun/2016
    LasModifiedBy:   Vicente Rodriguez Eguibar
        vicente@eguibar.com
        Eguibar Information Technology S.L.
        http://www.eguibarit.com

## RELATED LINKS
