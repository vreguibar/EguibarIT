function Get-AllAdSiteLink {
    <#
        .Synopsis
            Get AD Site Links from current Forest
        .DESCRIPTION
            Reads all Site Links from the current Forest and store those on an array.
        .EXAMPLE
            Get-AdSiteLinks
        .INPUTS
            No input needed.
        .NOTES
            Version:         1.0
            DateModified:    31/Mar/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
        #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([array])]

    Param ()

    Begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-Module -Name ServerManager -SkipEditionCheck -Force -Verbose:$false | Out-Null
        Import-Module -Name ActiveDirectory -SkipEditionCheck -Force -Verbose:$false | Out-Null

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
