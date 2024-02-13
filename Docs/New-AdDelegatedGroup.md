---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# New-AdDelegatedGroup

## SYNOPSIS
Same as New-AdGroup but with error handling, Security changes and loging

## SYNTAX

```
New-AdDelegatedGroup [-Name] <String> [-GroupCategory] <Object> [-GroupScope] <Object> [-DisplayName] <String>
 [-path] <String> [-Description] <String> [-ProtectFromAccidentalDeletion] [-RemoveAccountOperators]
 [-RemoveEveryone] [-RemoveAuthUsers] [-RemovePreWin2000] [-ProgressAction <ActionPreference>] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Native New-AdGroup throws an error exception when the group already exists.
This error is handeled
as a "correct" within this function due the fact that group might already exist and operation
should continue after writting a log.

## EXAMPLES

### EXAMPLE 1
```
New-AdDelegatedGroup -Name "Poor Admins" -GroupCategory Security -GroupScope DomainLocal -DisplayName "Poor Admins" -Path 'OU=Groups,OU=Admin,DC=EguibarIT,DC=local' -Description 'New Admin Group'
```

### EXAMPLE 2
```
$splat = @{
    Name                          = 'Poor Admins'
    GroupCategory                 = 'Security'
    GroupScope                    = 'DomainLocal'
    DisplayName                   = 'Poor Admins'
    Path                          = 'OU=Groups,OU=Admin,DC=EguibarIT,DC=local'
    Description                   = 'New Admin Group'
    ProtectFromAccidentalDeletion = $true
}
New-AdDelegatedGroup @Splat
```

## PARAMETERS

### -Name
\[STRING\] Name of the group to be created.
SamAccountName

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

### -GroupCategory
\[ValidateSet\] Group category, either Security or Distribution

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -GroupScope
\[ValidateSet\] Group Scope, either DomainLocal, Global or Universal

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 3
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -DisplayName
\[STRING\] Display Name of the group to be created

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 4
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -path
\[STRING\] DistinguishedName of the container where the group will be created.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 5
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Description
\[STRING\] Description of the group.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 6
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ProtectFromAccidentalDeletion
\[Switch\] Protect from accidental deletion.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 7
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -RemoveAccountOperators
\[Switch\] Remove Account Operators Built-In group

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

### -RemoveEveryone
\[Switch\] Remove Everyone Built-In group

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

### -RemoveAuthUsers
\[Switch\] Remove Authenticated Users Built-In group

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 10
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -RemovePreWin2000
\[Switch\] Remove Pre-Windows 2000 Built-In group

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 11
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

### Microsoft.ActiveDirectory.Management.ADGroup
## NOTES
Version:         1.1
DateModified:    15/Feb/2017
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
