---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# New-DelegateAdOU

## SYNOPSIS
Creates and Links new GPO

## SYNTAX

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
