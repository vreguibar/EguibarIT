function Get-AllAdSubnet {
    <#
        .SYNOPSIS
            Retrieves all Active Directory subnets defined in the current forest.

        .DESCRIPTION
            This function retrieves all Active Directory subnets defined in the current forest
            using LDAP queries. It returns an array of subnet objects with all properties
            including site association, description, and location.

            Subnets are critical for client site awareness and proper domain controller
            selection in distributed Active Directory environments.

        .INPUTS
            None
            This function does not accept pipeline input.

        .OUTPUTS
            System.Array
            Returns an array of Microsoft.ActiveDirectory.Management.ADObject objects
            representing subnets, with all properties populated.

        .EXAMPLE
            Get-AllAdSubnet

            Returns all AD subnets defined in the current forest.

        .EXAMPLE
            Get-AllAdSubnet | Where-Object { $_.siteObject -eq $null }

            Returns all subnets that are not associated with any site.

        .EXAMPLE
            Get-AllAdSubnet | Select-Object Name, @{N='Site';E={($_.siteObject -split ',')[0] -replace 'CN=',''}}

            Returns all subnets with their names and associated site names in a readable format.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Import-MyModule                        ║ EguibarIT
                Get-ADObject                           ║ ActiveDirectory
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                ADSI                                   ║ System.DirectoryServices

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Get-AllAdSubnet.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Network Administration

        .FUNCTIONALITY
            Site and Subnet Management
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([array])]

    Param ()

    Begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToString('dd/MMM/yyyy'),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-MyModule -Name 'ServerManager' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition

    } #end Begin

    Process {
        #Get a reference to the RootDSE of the current domain
        $ADConfigurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext

        [array] $ADSubnets = Get-ADObject -Filter {
            objectclass -eq 'subnet'
        } -SearchBase $ADConfigurationNamingContext -Properties *
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'getting AD Subnets.'
        )
        Write-Verbose -Message $txt

        Return $ADSubnets
    } #end End
} #end Function
