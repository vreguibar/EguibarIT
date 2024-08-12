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
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([array])]

    Param ()

    Begin {
        $txt = ($Variables.Header -f
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
    } #end Begin

    Process {
        Write-Verbose -Message "Get AD Site List `r"
        [array] $ADSites = [DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Sites
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'getting AD Sites.'
        )
        Write-Verbose -Message $txt

        Return $ADSites
    } #end End
} #end Function
