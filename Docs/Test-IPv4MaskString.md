---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Test-IPv4MaskString

## SYNOPSIS
Tests whether an IPv4 network mask string (e.g., "255.255.255.0") is valid.

## SYNTAX

```
Test-IPv4MaskString [[-MaskString] <String>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
Tests whether an IPv4 network mask string (e.g., "255.255.255.0") is valid.

## EXAMPLES

### EXAMPLE 1
```
Test-IPv4MaskString -MaskString "255.255.255.0"
```

## PARAMETERS

### -MaskString
Specifies the IPv4 network mask string (e.g., "255.255.255.0").

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

## RELATED LINKS
