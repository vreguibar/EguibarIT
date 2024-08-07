function Get-AllAdSubnet {
    <#
        .Synopsis
            Get AD subnets from current Forest
        .DESCRIPTION
            Reads all Subnets from the current Forest and store those on an array.
        .EXAMPLE
            Get-AdSubnets
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

    }
    Process {
        #Get a reference to the RootDSE of the current domain
        $ADConfigurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext

        [array] $ADSubnets = Get-ADObject -Filter {
            objectclass -eq 'subnet'
        } -SearchBase $ADConfigurationNamingContext -Properties *
    }
    End {

        Return $ADSubnets
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished getting AD Subnets."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
