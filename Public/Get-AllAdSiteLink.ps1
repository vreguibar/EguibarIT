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
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([array])]
    Param ()

    Begin {
        $txt = ($constants.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-Module -Name ServerManager -SkipEditionCheck -Force -Verbose:$false | Out-Null
        Import-Module -Name ActiveDirectory -SkipEditionCheck -Force -Verbose:$false | Out-Null

        ##############################
        # Variables Definition

        $ADSiteDN = 'CN=Sites,{0}' -f ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()
        #$SubnetsDN     = 'CN=Subnets,{0}' -f $ADSiteDN
        #$ADSiteLinksDN = 'CN=IP,CN=Inter-Site Transports,{0}' -f $ADSiteDN
    }

    Process {
        Write-Verbose -Message "Get List of AD Site Links `r"

        [array] $ADSiteLinks = Get-ADObject -Filter { ObjectClass -eq 'sitelink' } -SearchBase $ADSiteDN -Properties *

        $ADSiteLinksCount = $ADSiteLinks.Count

        Write-Output -InputObject ("There are {0} AD Site Links in {1} `r" -f $ADSiteLinksCount, $env:USERDNSDOMAIN)
    }

    End {

        Return $ADSiteLinks
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting SiteLinks."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
