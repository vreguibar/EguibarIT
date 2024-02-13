---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# New-TemplateOID

## SYNOPSIS
Generates a new OID for certificate templates.

## SYNTAX

```
New-TemplateOID [-Server] <String> [-ConfigNC] <String> [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
This function generates a new OID (Object Identifier) for certificate templates within Active Directory.

## EXAMPLES

### EXAMPLE 1
```
$result = New-TemplateOID -Server "DC01" -ConfigNC "DC=example,DC=com"
$result.TemplateOID     # Output: ForestBaseOID.12345678.87654321
$result.TemplateName    # Output: 87654321.0123456789ABCDEF0123456789ABCDEF
```

## PARAMETERS

### -Server
FQDN of a Domain Controller.

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

### -ConfigNC
Configuration Naming Context of the domain.

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
Version:         1.4
DateModified:    08/Oct/2021
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
