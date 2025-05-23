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
