---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# ConvertTo-IPv4MaskString

## SYNOPSIS
Converts a number of bits (0-32) to an IPv4 network mask string (e.g., "255.255.255.0").

## SYNTAX

```
ConvertTo-IPv4MaskString [-MaskBits] <Int32> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Converts a number of bits (0-32) to an IPv4 network mask string (e.g., "255.255.255.0").

## EXAMPLES

### EXAMPLE 1
```
ConvertTo-IPv4MaskString -MaskBits "24"
```

### EXAMPLE 2
```
ConvertTo-IPv4MaskString "24"
```

## PARAMETERS

### -MaskBits
Specifies the number of bits in the mask.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: 0
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
Version:         1.0
DateModified:    13/Apr/2022
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
