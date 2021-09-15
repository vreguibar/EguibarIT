---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# New-DelegateSiteOU

## SYNOPSIS
Create New delegated Site OU

## SYNTAX

```
New-DelegateSiteOU [-ouName] <String> [[-ouDescription] <String>] [[-ouCity] <String>] [[-ouCountry] <String>]
 [[-ouStreetAddress] <String>] [[-ouState] <String>] [[-ouZIPCode] <String>] [-CreateExchange] [-CreateLAPS]
 [-ConfigXMLFile] <String> [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Create the new OU representing the SITE root on the pre-defined
container (Sites, Country, etc.), then adding additional OU structure
below to host different object types, create the corresponding managing groups and
GPOs and finally delegating right to those objects.

## EXAMPLES

### EXAMPLE 1
```
New-DelegateSiteOU -ouName "Mexico" -ouDescription "Mexico Site root" -ConfigXMLFile "C:\PsScripts\Config.xml"
```

## PARAMETERS

### -ouName
Param1 Site Name

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

### -ouDescription
Param2 OU Description

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

### -ouCity
Param3 OU City

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ouCountry
Param4 OU Country

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 4
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ouStreetAddress
Param5 OU Street Address

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ouState
Param6 OU State

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ouZIPCode
Param7 OU Postal Code

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -CreateExchange
Param8 Create Exchange Objects

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -CreateLAPS
Param9 Create LAPS Objects

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 9
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ConfigXMLFile
PARAM10 full path to the configuration.xml file

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 10
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

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### Param1 ouName:...............[String] Name of the OU corresponding to the SITE root
### Param2 ouDescription:........[String] Description of the OU
### Param3 ouCity:...............[String]
### Param4 ouCountry:............[String]
### Param5 ouStreetAddress:......[String]
### Param6 ouState:..............[String]
### Param7 ouZIPCode:............[String]
### Param8 CreateExchange:.......[switch] If present It will create all needed Exchange objects and containers.
### Param9 CreateLAPS............[switch] If present It will create all needed LAPS objects, containers and delegations.
### Param10 ConfigXMLFile:.......[String] Full path to the configuration.xml file
### This function relies on Config.xml file.
## OUTPUTS

### System.String
## NOTES
Version:         1.2
DateModified:    11/Feb/2019
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
