function Get-AdSite {
    <#
        .SYNOPSIS
            Retrieves all Active Directory sites from the current forest.

        .DESCRIPTION
            This function retrieves all Active Directory sites from the current forest using
            the .NET DirectoryServices API. It returns an array of site objects containing
            information such as name, subnets, site links, and other site-related properties.

            This function is useful for inventory, documentation, and network topology analysis.

        .INPUTS
            None
            This function does not accept pipeline input.

        .OUTPUTS
            System.Array
            Returns an array of DirectoryServices.ActiveDirectory.ActiveDirectorySite objects.

        .EXAMPLE
            Get-AdSite

            Returns all AD sites in the current forest.

        .EXAMPLE
            Get-AdSite | Select-Object Name, Subnets

            Returns all AD sites with only their names and associated subnets.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Import-MyModule                        ║ EguibarIT
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Forest.GetCurrentForest                ║ System.DirectoryServices.ActiveDirectory

        .NOTES
            Version:         1.1
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/Get-AdSite.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Network Administration

        .FUNCTIONALITY
            Site Management
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Medium')]
    [OutputType([array])]

    param ()

    begin {
        Set-StrictMode -Version Latest

        # Initialize logging
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        Import-MyModule -Name 'ServerManager' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition
    } #end begin

    process {
        Write-Verbose -Message "Get AD Site List `r"
        [array] $ADSites = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
    } #end process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'getting AD Sites.'
        )
        Write-Verbose -Message $txt

        return $ADSites
    } #end end
} #end function
