---
external help file: EguibarIT-help.xml
Module Name: EguibarIT
online version:
schema: 2.0.0
---

# Get-AdObjectType

## SYNOPSIS

Retrieves the type of an Active Directory object based on the provided identity.

## SYNTAX

```powershell
Get-AdObjectType [-Identity] <Object> [[-Server] <String>] [<CommonParameters>]
```

## DESCRIPTION

The Get-AdObjectType function determines the type of an Active Directory object based on the given identity.
It supports various object types, including AD users, computers, groups, organizational units, and group managed service accounts.
The function can handle different input formats such as AD objects, DistinguishedName, SamAccountName, SID, and GUID.
It also includes support for Well-Known SIDs.

The function is optimized for large AD environments and supports batch processing via pipeline input.

## EXAMPLES

### EXAMPLE 1

```powershell
Get-AdObjectType -Identity "davader"
```

Retrieves the type of the Active Directory object with the SamAccountName "davader".

### EXAMPLE 2

```powershell
Get-AdObjectType -Identity "CN=davade,OU=Users,OU=BAAD,OU=Sites,DC=EguibarIT,DC=local"
```

Retrieves the type of the Active Directory object with the DistinguishedName.

### EXAMPLE 3

```powershell
Get-AdObjectType -Identity "S-1-5-21-3484526001-1877030748-1169500100-1646"
```

Retrieves the type of the Active Directory object with the SID.

### EXAMPLE 4

```powershell
Get-AdObjectType -Identity "S-1-1-0"
```

Retrieves the Well-Known SID "Everyone" as a SecurityIdentifier object.

### EXAMPLE 5

```powershell
Get-AdObjectType -Identity "Everyone"
```

Retrieves the Well-Known SID "Everyone" by name.

### EXAMPLE 6

```powershell
Get-AdUser "testuser" | Get-AdObjectType
```

Pipes an ADUser object to Get-AdObjectType.

### EXAMPLE 7

```powershell
Get-AdObjectType -Identity "testcomputer" -Server "dc01.contoso.com"
```

Retrieves the type using a specific domain controller.

## PARAMETERS

### -Identity

Specifies the identity of the Active Directory object.
This parameter is mandatory.

Accepted values:

- ADAccount object
- ADComputer object
- ADGroup object
- ADOrganizationalUnit object
- ADServiceAccount object
- Security Identifier
- String representing DistinguishedName
- String representing SID (including Well-Known SIDs)
- String representing samAccountName (including Well-Known SID name)
- String representing GUID

```yaml
Type: Object
Parameter Sets: (All)
Aliases: ID, SamAccountName, DistinguishedName, DN, SID, GUID

Required: True
Position: 0
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Server

Specifies the Active Directory Domain Services instance to connect to.
If not specified, the default domain controller for the current domain is used.

```yaml
Type: String
Parameter Sets: (All)
Aliases: DomainController, DC

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### CommonParameters

This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

### System.String

String representing the identity of the Active Directory object.

### Microsoft.ActiveDirectory.Management.ADObject

An Active Directory object.

### System.Security.Principal.SecurityIdentifier

A security identifier object.

## OUTPUTS

### Microsoft.ActiveDirectory.Management.ADAccount

### Microsoft.ActiveDirectory.Management.ADComputer

### Microsoft.ActiveDirectory.Management.ADGroup

### Microsoft.ActiveDirectory.Management.ADOrganizationalUnit

### Microsoft.ActiveDirectory.Management.ADServiceAccount

### System.Security.Principal.SecurityIdentifier

### System.String

The function returns the appropriate AD object type based on the provided identity.

## NOTES

Version:         1.0
DateModified:    03/Jun/2025
LasModifiedBy:   Vicente Rodriguez Eguibar
    vicente@eguibar.com
    Eguibar Information Technology S.L.
    http://www.eguibarit.com

Used Functions:
    Name                                       ║ Module/Namespace
    ═══════════════════════════════════════════╬══════════════════════════════
    Write-Verbose                              ║ Microsoft.PowerShell.Utility
    Write-Warning                              ║ Microsoft.PowerShell.Utility
    Write-Error                                ║ Microsoft.PowerShell.Utility
    Write-Output                               ║ Microsoft.PowerShell.Utility
    Get-ADObject                               ║ ActiveDirectory
    Get-ADUser                                 ║ ActiveDirectory
    Get-ADGroup                                ║ ActiveDirectory
    Get-ADComputer                             ║ ActiveDirectory
    Get-ADOrganizationalUnit                   ║ ActiveDirectory
    Get-ADServiceAccount                       ║ ActiveDirectory
    Import-MyModule                            ║ EguibarIT
    Get-FunctionDisplay                        ║ EguibarIT

## RELATED LINKS

[Get-ADObject](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adobject)

[Get-ADUser](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-aduser)

[Get-ADGroup](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup)

[Get-ADComputer](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adcomputer)

[Get-ADOrganizationalUnit](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adorganizationalunit)

[Get-ADServiceAccount](https://docs.microsoft.com/en-us/powershell/module/activedirectory/get-adserviceaccount)

[GitHub Repository](https://github.com/vreguibar/EguibarIT/blob/main/Public/Get-AdObjectType.ps1)
