---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Start-AdDelegateSite

## SYNOPSIS
The function will create the corresponding Tier2 site

## SYNTAX

```
Start-AdDelegateSite [-ConfigXMLFile] <String> [-ouName] <String> [-QuarantineDN] <String> [-CreateExchange]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This function will create all needed objects and related delegations for the
given site.
This Tier2 site is intended to hold all related Tier2 objects, as Users, Computers, Groups, etc.
and provide all delegated rights and permissions according to the delegation model.

## EXAMPLES

### EXAMPLE 1
```
Start-AdDelegateSite -ConfigXMLFile "C:\PsScripts\Config.xml" -ouName "GOOD" -QuarantineDN "Quarantine" -CreateExchange
```

### EXAMPLE 2
```
$Splat = @{
    ConfigXMLFile  = "C:\PsScripts\Config.xml"
    ouName         = "GOOD"
    QuarantineDN   = "Quarantine"
    CreateExchange = $true
}
Start-AdDelegateSite @Splat
```

## PARAMETERS

### -ConfigXMLFile
Full path to the Configuration.XML file

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

### -ouName
Name of the Site OU

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -QuarantineDN
Name new redirected OU for computers

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -CreateExchange
If present It will create all needed Exchange objects and containers.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
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
Version:         1.3
DateModified:    12/Feb/2019
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
