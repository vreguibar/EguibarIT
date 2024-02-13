---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Test-IsUniqueOID

## SYNOPSIS
Checks if a given Certificate Template OID is unique within the specified context.

## SYNTAX

```
Test-IsUniqueOID [-cn] <String> [-TemplateOID] <String> [-Server] <String> [-ConfigNC] <String>
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
This function queries Active Directory to determine if a given Certificate Template OID
is already in use within the specified configuration context.
It returns $True if the OID
is unique and $False if it already exists.

## EXAMPLES

### EXAMPLE 1
```
Test-IsUniqueOID -cn "MyTemplate" -TemplateOID "1.2.3.4" -Server "ADServer01" -ConfigNC "DC=example,DC=com"
Checks if the Certificate Template with the specified OID is unique in the given context.
```

## PARAMETERS

### -cn
Specifies the Common Name (CN) of the Certificate Template.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TemplateOID
Specifies the OID (Object Identifier) of the Certificate Template.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
Specifies the Active Directory server to query.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ConfigNC
Specifies the Configuration Naming Context (ConfigNC) to search for the Certificate Template.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
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
### Returns $True if the Certificate Template OID is unique, and $False if it already exists.
## NOTES

## RELATED LINKS
