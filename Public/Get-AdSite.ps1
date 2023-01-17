function Get-AdSite {
    <#
        .Synopsis
            Get AD Sites from current Forest
        .DESCRIPTION
            Reads all Sites from the current Forest and store those on an array.
        .EXAMPLE
            Get-AdSites
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
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition


        Import-Module -name ServerManager   -Verbose:$false
        Import-Module -name ActiveDirectory -Verbose:$false
    }
    Process {
        Write-Verbose -Message "Get AD Site List `r"
        [array] $ADSites = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
    }
    End  {

        Return $ADSites
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting AD Sites."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
