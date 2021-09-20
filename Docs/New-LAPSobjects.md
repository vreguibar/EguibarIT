---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# New-LAPSobjects

## SYNOPSIS
Create Local Administration Password Services (LAPS) Objects and Delegations

## SYNTAX

```
New-LAPSobjects [-ConfigXMLFile] <String> [[-DMscripts] <String>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Create the LAPS Objects used to manage
this organization by following the defined Delegation Model.

## EXAMPLES

### EXAMPLE 1
```
New-LAPSobjects -PawOuDn "OU=PAW,OU=Admin,DC=EguibarIT,DC=local" -ServersOuDn "OU=Servers,DC=EguibarIT,DC=local" -SitesOuDn "OU=Sites,DC=EguibarIT,DC=local"
```

## PARAMETERS

### -ConfigXMLFile
PARAM1 full path to the configuration.xml file

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

### -DMscripts
Param2 Location of all scripts & files

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: C:\PsScripts\
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

### Param1 PawOuDn:......[String] Distinguished Name of the IT PrivilegedAccess Workstations OU
### Param2 ServersOuDn:..[String] Distinguished Name of the Servers OU
### Param3 SitesOuDn:....[String] Distinguished Name of the Sites OU
## OUTPUTS

## NOTES
Version:         1.1
DateModified:    11/Feb/2019
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
