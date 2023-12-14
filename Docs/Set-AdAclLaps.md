---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Set-AdAclLaps

## SYNOPSIS
Wrapper for all rights used for LAPS on a given container.

## SYNTAX

```
Set-AdAclLaps [-ReadGroup] <String> [-ResetGroup] <String> [-LDAPpath] <String> [-RemoveRule]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
The function will consolidate all rights used for LAPS on a given container.

## EXAMPLES

### EXAMPLE 1
```
Set-AdAclLaps -ResetGroup "SG_SiteAdmins_XXXX" -ReadGroup "SG_GalAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local"
```

### EXAMPLE 2
```
Set-AdAclLaps -ResetGroup "SG_SiteAdmins_XXXX" -ReadGroup "SG_GalAdmins_XXXX" -LDAPPath "OU=Users,OU=XXXX,OU=Sites,DC=EguibarIT,DC=local" -RemoveRule
```

## PARAMETERS

### -ReadGroup
Identity of the group getting being able to READ the password

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

### -ResetGroup
Identity of the group getting being able to RESET the password

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

### -LDAPpath
Distinguished Name of the OU where LAPS will apply to computer object.

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

### -RemoveRule
If present, the access rule will be removed

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
DateModified:    19/Oct/2016
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
