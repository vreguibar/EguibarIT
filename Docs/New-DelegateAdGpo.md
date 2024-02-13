---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# New-DelegateAdGpo

## SYNOPSIS
Create Central OU and aditional Tier 0 infrastructure OUs

## SYNTAX

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
