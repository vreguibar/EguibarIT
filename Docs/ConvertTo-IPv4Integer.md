---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# ConvertTo-IPv4Integer

## SYNOPSIS
Returns the integer representing the given IP Address

## SYNTAX

```
ConvertTo-IPv4Integer [-Ipv4Address] <String> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Returns the integer representing the given IP Address

## EXAMPLES

### EXAMPLE 1
```
ConvertTo-IPv4Integer -Ipv4Address "192.168.1.200"
```

### EXAMPLE 2
```
ConvertTo-IPv4Integer "192.168.1.200"
```

## PARAMETERS

### -Ipv4Address
Specifies the IPv4 Address as a string (e.g., "192.168.1.200")

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

### System.UInt32
## NOTES
Version:         1.0
DateModified:    13/Apr/2022
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
