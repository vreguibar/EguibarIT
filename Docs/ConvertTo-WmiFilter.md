---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# ConvertTo-WmiFilter

## SYNOPSIS
Find network address based on IP Address and Subnet Mask (e.
g.
192.168.1.0 is the Network Address of 192.168.1.200/24)

## SYNTAX

## DESCRIPTION
Find network address based on IP Address and Subnet Mask (e.
g.
192.168.1.0 is the Network Address of 192.168.1.200/24)

## EXAMPLES

### EXAMPLE 1
```
ConvertTo-IPv4NetworkAddress -IPv4Address "192.168.1.200" -SubnetMask "255.255.255.0"
```

### EXAMPLE 2
```
ConvertTo-IPv4NetworkAddress -IPv4Address "192.168.1.200" -PrefixLength "24"
```

### EXAMPLE 3
```
ConvertTo-IPv4NetworkAddress "192.168.1.200" "255.255.255.0"
```

### EXAMPLE 4
```
ConvertTo-IPv4NetworkAddress "192.168.1.200" "24"
```

## PARAMETERS

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.Net.IPAddress
## NOTES
Version:         1.0
DateModified:    12/Apr/2022
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
