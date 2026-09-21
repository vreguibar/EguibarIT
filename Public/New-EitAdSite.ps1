function New-EitAdSite {
    <#
        .SYNOPSIS
            Creates a new Active Directory site object.

        .DESCRIPTION
            Creates a new AD Site object in the Active Directory Sites and Services
            configuration partition. The function:
            - Verifies the site does not already exist before creation
            - Creates the site in the Sites container of the Configuration partition
            - Provides idempotent behavior (skips creation if site already exists)

        .PARAMETER NewSiteName
            [String] Name for the new Active Directory site.
            Must be a unique, valid AD site name.

        .EXAMPLE
            New-EitAdSite -NewSiteName 'GOOD'

            Creates a new AD site named GOOD in the Configuration partition.

        .EXAMPLE
            New-EitAdSite -NewSiteName 'Paris-Site1' -Verbose

            Creates a new AD site with verbose output.

        .EXAMPLE
            New-EitAdSite -NewSiteName 'London-HQ' -WhatIf

            Shows what would happen when creating the AD site without making changes.

        .INPUTS
            [System.String]
            You can pipe a site name string to this function.

        .OUTPUTS
            [void]
            This function does not return any output.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                New-ADObject                           ║ ActiveDirectory
                Get-FunctionDisplay                    ║ EguibarIT
                Import-MyModule                        ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Warning                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.1
            DateModified:    21/Sep/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/New-EitAdSite.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Infrastructure Administration

        .FUNCTIONALITY
            AD Site Management
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param
    (
        # Param1 New Site name
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Name for the new Active Directory site',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $NewSiteName
    )

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
        } #end If

        ##############################
        # Module imports

        Import-MyModule -Name 'ServerManager' -SkipEditionCheck -Verbose:$false
        Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

        ##############################
        # Variables Definition

        #Get a reference to the RootDSE of the current domain
        Write-Verbose -Message 'Get the Root DSE of the forest'
        $ADConfigurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()

        # Get the Sites container
        $ADSiteDN = 'CN=Sites,{0}' -f $variables.configurationNamingContext

        Write-Verbose -Message "Set necessary site variables `r "
        $NewADSiteDN = 'CN={0},{1}' -f $PSBoundParameters['NewSiteName'], $ADSiteDN
    } #end Begin

    process {
        if ($PSCmdlet.ShouldProcess($PSBoundParameters['NewSiteName'], 'Create AD Site')) {
            if (Test-Path -Path AD:$NewADSiteDN) {
                Write-Warning -Message ('The site {0} already exist. Please review the name and try again' -f $PSBoundParameters['NewSiteName'])
            } else {
                Write-Verbose -Message 'Create New Site Object `r '
                try {
                    New-ADObject -Name $PSBoundParameters['NewSiteName'] -Path $ADSiteDN -Type Site
                } catch {
                    Write-Error -Message ('An error occurred while attempting to create the new site {0} in the AD Site Path: {1} `r ' -f $PSBoundParameters['NewSiteName'], $ADSiteDN)
                    ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                    throw
                }

                $SiteCreationCheck = Test-Path -Path AD:$NewADSiteDN

                if ($SiteCreationCheck -eq $false) {
                    Write-Warning -Message ('Failed to create the new site {0} `r ' -f $PSBoundParameters['NewSiteName'])
                } else {
                    ## OPEN ELSE Site Object created successfully
                    Write-Verbose -Message 'Create New Site Object Child Objects (NTDS Site Settings & Servers Container) `r '

                    try {
                        ## OPEN TRY Create New Site Object Child Objects (NTDS Site Settings & Servers Container)
                        New-ADObject -Name 'NTDS Site Settings' -Path $NewADSiteDN -Type NTDSSiteSettings
                        New-ADObject -Name 'Servers' -Path $NewADSiteDN -Type serversContainer

                        Write-Verbose -Message 'Get New AD Site as variable `r '
                        $NewADSiteInfo = Get-ADObject $NewADSiteDN
                    }  ## CLOSE TRY Create New Site Object Child Objects (NTDS Site Settings & Servers Container)
                    catch {
                        Write-Warning -Message ('An error occurred while attempting to create site {0} child objects in the AD Site Path: {1} `r ' -f $PSBoundParameters['NewSiteName'], $NewADSiteDN)
                        ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                        throw
                    }
                }#end elseIf
            }#end elseIf
        } #end If ShouldProcess
    } #end Process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'creating new AD Site.'
        )
        Write-Verbose -Message $txt
    } #end End
} #end Function
