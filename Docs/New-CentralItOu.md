---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# New-CentralItOu

## SYNOPSIS
Create Central OU and aditional Tier 0 infrastructure OUs

## SYNTAX

```
New-CentralItOu [-ConfigXMLFile] <String> [-CreateExchange] [-CreateDfs] [-CreateCa] [-CreateAGPM]
 [-CreateLAPS] [-CreateDHCP] [[-DMscripts] <String>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
Create Central OU including sub-OUs, secure them accordingly, move built-in objects
and secure them, create needed groups and secure them, make nesting and delegations
and finaly create PSO and delegate accordingly.
This function is mainly a wrapper used to create Tier0 objects

## EXAMPLES

### EXAMPLE 1
```
New-CentralItOu -ConfigXMLFile 'C:\PsScripts\Configuration.xml'
```

### EXAMPLE 2
```
# Get the Config.xml file
$param = @{
    ConfigXMLFile = Join-Path -Path $DMscripts -ChildPath Config.xml -Resolve
    verbose = $true
}
```

# Check if Exchange needs to be created
if($confXML.N.Domains.Prod.CreateExContainers) {
    $param.add("CreateExchange", $true)
}

# Check if DFS needs to be created
if($confXML.N.Domains.Prod.CreateDFS) {
    $param.add("CreateDFS", $true)
}

# Check if CA needs to be created
if($confXML.N.Domains.Prod.CreateCa) {
    $param.add("CreateCa", $true)
}

# Check if LAPS needs to be created
if($confXML.N.Domains.Prod.CreateLAPS) {
    $param.add("CreateLAPS", $true)
}

# Check if DHCP needs to be created
if($confXML.N.Domains.Prod.CreateDHCP) {
    $param.add("CreateDHCP", $true)
}

#Create Central OU Structure
New-CentralItOu @param

## PARAMETERS

### -ConfigXMLFile
\[STRING\] Full path to the configuration.xml file

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

### -CreateExchange
\[SWITCH\] If present It will create all needed Exchange objects, containers and delegations

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 2
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -CreateDfs
\[SWITCH\] If present It will create all needed DFS objects, containers and delegations

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 3
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -CreateCa
\[SWITCH\] If present It will create all needed Certificate Authority (PKI) objects, containers and delegations

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

### -CreateAGPM
\[SWITCH\] If present It will create all needed AGPM objects, containers and delegations

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 5
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -CreateLAPS
\[SWITCH\] If present It will create all needed LAPS objects, containers and delegations

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: 6
Default value: False
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -CreateDHCP
\[SWITCH\] If present It will create all needed DHCP objects, containers and delegations

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

### -DMscripts
\[String\] Full path to the Delegation Model Scripts Directory

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: False
Position: 8
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

### System.String
## NOTES
Version:         1.3
DateModified:    21/Oct/2021
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
