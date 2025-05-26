function ConvertTo-WmiFilter {
    <#
        .SYNOPSIS
            Converts an Active Directory object to a WMI filter object for Group Policy.

        .DESCRIPTION
            This function takes an Active Directory object, retrieves its corresponding WMI filter
            from the Group Policy domain, and returns it as an object of type
            "Microsoft.GroupPolicy.WmiFilter".

            The function includes error handling and retry logic to address Active Directory
            replication delays, making it robust for production environments.

        .PARAMETER ADObject
            An array of ADObject instances representing the Active Directory objects to convert
            to WMI filters. These must be valid AD objects that can be linked to WMI filters.

        .INPUTS
            Microsoft.ActiveDirectory.Management.ADObject[]
            You can pipe an array of Active Directory objects to this function.

        .OUTPUTS
            Microsoft.GroupPolicy.WmiFilter
            Returns the converted WMI filter object that can be used with Group Policy operations.

        .EXAMPLE
            $adObjects = Get-ADObject -Filter {objectClass -eq "msWMI-Som"} -SearchBase "CN=SOM,CN=WMIPolicy,CN=System,DC=contoso,DC=com"
            ConvertTo-WmiFilter -ADObject $adObjects

            Converts all WMI filter AD objects to Microsoft.GroupPolicy.WmiFilter objects.

        .EXAMPLE
            Get-ADObject -Identity "CN=WindowsServer2022,CN=SOM,CN=WMIPolicy,CN=System,DC=contoso,DC=com" | ConvertTo-WmiFilter

            Converts a specific WMI filter AD object using pipeline input.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Import-MyModule                        ║ EguibarIT
                Get-FunctionDisplay                    ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility
                Write-Warning                          ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.2
            DateModified:    22/May/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/ConvertTo-WmiFilter.ps1

        .COMPONENT
            Group Policy

        .ROLE
            System Administration

        .FUNCTIONALITY
            WMI Filter Management
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    Param (

        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Provide an ADObject instances representing the Active Directory objects to convert to WMI filter',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Microsoft.ActiveDirectory.Management.ADObject[]]
        $ADObject

    )

    Begin {
        $error.Clear()
        $txt = ($Variables.Header -f
            (Get-Date).ToString('dd/MMM/yyyy'),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        Import-MyModule -Name 'GroupPolicy' -SkipEditionCheck -Force -Verbose:$false


        ##############################
        # Variables Definition

        # The concept of this function has been taken directly from the GPWmiFilter.psm1 module
        # written by Bin Yi from Microsoft. I have modified it to allow for the challenges of
        # Active Directory replication. It will return the WMI filter as an object of type
        # "Microsoft.GroupPolicy.WmiFilter".
        #$gpDomain = New-Object -TypeName Microsoft.GroupPolicy.GPDomain
        $gpDomain = [Microsoft.GroupPolicy.GPDomain]::New()

    } #end Begin

    Process {

        # Iterate each ADObject
        foreach ($item in $ADObject) {
            if ($PSCmdlet.ShouldProcess($item.Name, 'Convert to WMI Filter')) {
                $path = 'MSFT_SomFilter.Domain="{0}",ID="{1}"' -f $gpDomain.DomainName, $item.Name
                $filter = $null
                $attempt = 0
                $maxAttempts = 4

                do {
                    try {
                        $filter = $gpDomain.GetWmiFilter($path)
                    } catch {
                        Write-Error -Message 'The WMI filter could not be found.'
                        ###Get-CurrentErrorToDisplay -CurrentError $error[0]
                        throw
                    } #end Try-Catch

                    if ($filter) {
                        [Guid]$Guid = $item.Name.Substring(1, $item.Name.Length - 2)

                        $filter | Add-Member -MemberType NoteProperty -Name Guid -Value $Guid -PassThru
                        $filter | Add-Member -MemberType NoteProperty -Name Content -Value $item.'msWMI-Parm2' -PassThru

                        break
                    } else {
                        $attempt++
                        if ($attempt -lt $maxAttempts) {
                            Write-Warning -Message 'Waiting 5 seconds for Active Directory replication to complete.'
                            Start-Sleep -Seconds 5
                            Write-Warning -Message 'Trying again to retrieve the WMI filter.'
                        } else {
                            Write-Error -Message 'Max attempts reached. Could not retrieve the WMI filter.'
                            break
                        } #end If-Else
                    } #end If-Else
                } while ($attempt -lt $maxAttempts)
            } #end ShouldProcess
        } #end Foreach
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'converting the WMI filter.'
        )
        Write-Verbose -Message $txt
    } #end Function
} #end Function
