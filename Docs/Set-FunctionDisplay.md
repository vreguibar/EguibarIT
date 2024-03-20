---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Get-FunctionDisplay

## SYNOPSIS
Formats and displays the PsBoundParameters in a visually appealing way.

## SYNTAX

```
Get-FunctionDisplay [-HashTable] <Hashtable> [[-TabCount] <Int32>] [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
This advanced function formats and displays the contents of a hashtable, typically PsBoundParameters,
making it easier to read and understand in verbose output.
It supports customization of indentation.

## EXAMPLES

### EXAMPLE 1
```
Get-FunctionDisplay $PsBoundParameters
```

### EXAMPLE 2
```
Get-FunctionDisplay -HashTable $PsBoundParameters
```

## PARAMETERS

### -HashTable
The hashtable to format and display.
This is usually the $PsBoundParameters variable.

```yaml
Type: Hashtable
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -TabCount
The number of tabs to prepend to each line of output for indentation.
Defaults to 2 if not specified or less than 2.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
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

### System.Collections.Hashtable
## NOTES
Version:         1.1
DateModified:    13/Feb/2024
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar IT
    http://www.eguibarit.com

## RELATED LINKS
