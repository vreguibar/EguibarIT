function Get-AllAdSiteLink {
    <#
        .SYNOPSIS
            Retrieves all Active Directory site links from the current forest.

        .DESCRIPTION
            This function retrieves all Active Directory site links from the current forest
            using LDAP queries. It returns an array of site link objects with all properties,
            including replication schedules, cost, and connected sites.

            Site links are critical components of Active Directory replication topology
            and define how sites are interconnected for replication purposes.

        .INPUTS
            None
            This function does not accept pipeline input.

        .OUTPUTS
            System.Array
            Returns an array of Microsoft.ActiveDirectory.Management.ADObject objects
            representing site links, with all properties populated.

        .EXAMPLE
            Get-AllAdSiteLink

            Returns all AD site links in the current forest and displays the total count.

        .EXAMPLE
            Get-AllAdSiteLink | Select-Object Name, Cost, ReplicationInterval

            Returns all site links with their names, costs, and replication intervals.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Import-MyModule                        ║ EguibarIT
                Get-ADObject                           ║ ActiveDirectory
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Output                           ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Get-AllAdSiteLink.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Network Administration

        .FUNCTIONALITY
            Site Replication Management
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

        $ADSiteDN = 'CN=Sites,{0}' -f $Variables.configurationNamingContext
        #$SubnetsDN     = 'CN=Subnets,{0}' -f $ADSiteDN
        #$ADSiteLinksDN = 'CN=IP,CN=Inter-Site Transports,{0}' -f $ADSiteDN
    } #end Begin

    Process {
        Write-Verbose -Message "Get List of AD Site Links `r"

        [array] $ADSiteLinks = Get-ADObject -Filter { ObjectClass -eq 'sitelink' } -SearchBase $ADSiteDN -Properties *

        $ADSiteLinksCount = $ADSiteLinks.Count

        Write-Output -InputObject ("There are {0} AD Site Links in {1} `r" -f $ADSiteLinksCount, $env:USERDNSDOMAIN)
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'getting SiteLinks.'
        )
        Write-Verbose -Message $txt

        Return $ADSiteLinks
    } #end End
} #end Function
