---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# New-DelegateAdGpo

## SYNOPSIS
Creates and Links new GPO

## SYNTAX

### DelegatedAdGpo (Default)
```
New-DelegateAdGpo [-gpoDescription] <String> [-gpoScope] <String> [-gpoLinkPath] <String> [-GpoAdmin] <String>
 [[-gpoBackupID] <String>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### GpoBackup
```
New-DelegateAdGpo [-gpoDescription] <String> [-gpoScope] <String> [-gpoLinkPath] <String> [-GpoAdmin] <String>
 [[-gpoBackupID] <String>] [[-gpoBackupPath] <String>] [-ProgressAction <ActionPreference>] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
Create new custom delegated GPO, Delegate rights to an existing group and links it to
the given OU.
This function can import settings from an existing GPO backup.

## EXAMPLES

### EXAMPLE 1
```
New-DelegateAdGpo -gpoDescription MyNewGPO -gpoScope C -gpoLinkPath "OU=Servers,OU=eguibarit,OU=local" -GpoAdmin "SL_GpoRight"
```

### EXAMPLE 2
```
New-DelegateAdGpo -gpoDescription MyNewGPO -gpoScope C -gpoLinkPath "OU=Servers,OU=eguibarit,OU=local" -GpoAdmin "SL_GpoRight" -gpoBackupID '1D872D71-D961-4FCE-87E0-1CD368B5616F' -gpoBackupPath 'C:\PsScripts\Backups'
```

### EXAMPLE 3
```
$Splat = @{
    gpoDescription = 'MyNewGPO'
    gpoScope       = 'C'
    gpoLinkPath    = 'OU=Servers,OU=eguibarit,OU=local'
    GpoAdmin       = 'SL_GpoRight'
    gpoBackupID    = '1D872D71-D961-4FCE-87E0-1CD368B5616F'
    gpoBackupPath  = 'C:\PsScripts\Backups'
}
New-DelegateAdGpo @Splat
```

## PARAMETERS

### -gpoDescription
Description of the GPO.
Used to build the name.
Only Characters a-z A-Z

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

### -gpoScope
Scope of the GPO.
U for Users and C for Computers DEFAULT is U.
The non-used part of the GPO will get disabled

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

### -gpoLinkPath
DistinguishedName where to link the newly created GPO

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

### -GpoAdmin
Domain Local Group with GPO Rights to be assigned

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

### -gpoBackupID
Restore GPO settings from backup using the BackupID GUID

```yaml
Type: String
Parameter Sets: DelegatedAdGpo
Aliases: BackupID

Required: False
Position: 5
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

```yaml
Type: String
Parameter Sets: GpoBackup
Aliases: BackupID

Required: False
Position: 5
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -gpoBackupPath
Path where Backups are stored

```yaml
Type: String
Parameter Sets: GpoBackup
Aliases:

Required: False
Position: 6
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

### Microsoft.GroupPolicy.Gpo
## NOTES
Version:         1.2
DateModified:    21/Oct/2021
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
