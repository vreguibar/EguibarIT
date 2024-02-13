---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Test-IsValidSID

## SYNOPSIS
Cmdlet will check if the input string is a valid SID.

## SYNTAX

```
Test-IsValidSID [-ObjectSID] <String> [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
Cmdlet will check if the input string is a valid SID.

Cmdlet is intended as a dignostic tool for input validation

## EXAMPLES

### EXAMPLE 1
```
Test-IsValidDN -ObjectSID 'S-1-5-21-2562450185-1914323539-512974444-1234'
```

## PARAMETERS

### -ObjectSID
A string representing the object Security Identifier (SID).

```yaml
Type: String
Parameter Sets: (All)
Aliases: SID, SecurityIdentifier

Required: True
Position: 1
Default value: None
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

### System.Boolean
## NOTES
https://pscustomobject.github.io/powershell/howto/identity%20management/PowerShell-Check-If-String-Is-A-DN/
Version:         1.0
DateModified:    08/Oct/2021
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
