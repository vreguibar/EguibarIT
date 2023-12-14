---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# ConvertTo-IPv4NetworkAddress

## SYNOPSIS
Find network address based on IP Address and Subnet Mask (e.
g.
192.168.1.0 is the Network Address of 192.168.1.200/24)

## SYNTAX

### SubnetMask
```
ConvertTo-IPv4NetworkAddress [-IPv4Address] <String> [-SubnetMask] <String>
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### PrefixLength
```
ConvertTo-IPv4NetworkAddress [-IPv4Address] <String> [-PrefixLength] <String>
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

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

### -IPv4Address
Specifies the IPv4 Address as string (e.g., 192.168.1.200)

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

### -SubnetMask
Specifies the IPv4 network mask as string (e.g., 255.255.255.0)

```yaml
Type: String
Parameter Sets: SubnetMask
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -PrefixLength
Specifies the network prefix length, also known as CIDR  (e.g., 24)

```yaml
Type: String
Parameter Sets: PrefixLength
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

### System.Net.IPAddress
## NOTES
Version:         1.0
DateModified:    12/Apr/2022
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

## RELATED LINKS
