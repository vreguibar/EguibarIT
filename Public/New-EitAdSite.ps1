function New-EitAdSite {
    <#
        .Synopsis
            Create new AD Site
        .DESCRIPTION
            Create new AD Site
        .EXAMPLE
            New-EitAdSite -NewSiteName $SiteName
        .INPUTS
            Param1 NewSiteName - Name for the new site.
        .NOTES
            Version:         1.0
            DateModified:    31/Mar/2015
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(ConfirmImpact = 'Medium')]
    [OutputType([string])]
    Param
    (
        # Param1 New Site name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Add help message for user',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $NewSiteName
    )

    Begin {
        $error.Clear()

        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition


        Import-Module -Name ServerManager -Verbose:$false
        Import-MyModule -name ActiveDirectory -Verbose:$false

        #Get a reference to the RootDSE of the current domain
        Write-Verbose -Message 'Get the Root DSE of the forest'
        $ADConfigurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()

        # Get the Sites container
        $ADSiteDN = "CN=Sites,$ADConfigurationNamingContext"

        Write-Verbose -Message "Set necessary site variables `r "
        $NewADSiteDN = 'CN={0},{1}' -f $PSBoundParameters['NewSiteName'], $ADSiteDN
    }
    Process {
        If (Test-Path -Path AD:$NewADSiteDN) {
            Write-Warning -Message ('The site {0} already exist. Please review the name and try again' -f $PSBoundParameters['NewSiteName'])
        } else {
            Write-Verbose -Message 'Create New Site Object `r '
            TRY {
                New-ADObject -Name $PSBoundParameters['NewSiteName'] -Path $ADSiteDN -Type Site
            } CATCH {
                Write-Warning -Message ('An error occured while attempting to create the new site {0} in the AD Site Path: {1} `r ' -f $PSBoundParameters['NewSiteName'], $ADSiteDN)
                ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                throw
            }

            $SiteCreationCheck = Test-Path -Path AD:$NewADSiteDN

            IF ($SiteCreationCheck -eq $false) {
                Write-Warning -Message ('Failed to create the new site {0} `r ' -f $PSBoundParameters['NewSiteName'])
            } ELSE {
                ## OPEN ELSE Site Object created successfully
                Write-Verbose -Message 'Create New Site Object Child Objects (NTDS Site Settings & Servers Container) `r '

                TRY {
                    ## OPEN TRY Create New Site Object Child Objects (NTDS Site Settings & Servers Container)
                    New-ADObject -Name 'NTDS Site Settings' -Path $NewADSiteDN -Type NTDSSiteSettings
                    New-ADObject -Name 'Servers' -Path $NewADSiteDN -Type serversContainer

                    Write-Verbose -Message 'Get New AD Site as variable `r '
                    $NewADSiteInfo = Get-ADObject $NewADSiteDN
                }  ## CLOSE TRY Create New Site Object Child Objects (NTDS Site Settings & Servers Container)
                CATCH {
                    Write-Warning -Message ('An error occured while attempting to create site {0} child objects in the AD Site Path: {1} `r ' -f $PSBoundParameters['NewSiteName'], $NewADSiteDN)
                    ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                    throw
                }
            }#end elseIf
        }#end elseIf
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished creating new AD Site."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
