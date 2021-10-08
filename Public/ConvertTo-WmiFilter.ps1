function ConvertTo-WmiFilter
{
    <#
        .Synopsis
        .DESCRIPTION
        .EXAMPLE
            ConvertTo-WmiFilter
        .INPUTS
        .NOTES
            Version:         1.0
            DateModified:    25/Mar/2014
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param (
        [Microsoft.ActiveDirectory.Management.ADObject[]] $ADObject
    )

    Begin  {
        $error.Clear()
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"

    }

    Process {
        # The concept of this function has been taken directly from the GPWmiFilter.psm1 module
        # written by Bin Yi from Microsoft. I have modified it to allow for the challenges of
        # Active Directory replication. It will return the WMI filter as an object of type
        # "Microsoft.GroupPolicy.WmiFilter".
        $gpDomain = New-Object -TypeName Microsoft.GroupPolicy.GPDomain

        $ADObject | ForEach-Object {
            $path = 'MSFT_SomFilter.Domain="' + $gpDomain.DomainName + '",ID="' + $_.Name + '"'
            $filter = $null
            try {
                $filter = $gpDomain.GetWmiFilter($path)
            }
            catch {
                Write-Error -Message 'The WMI filter could not be found.'
                Get-CurrentErrorToDisplay -CurrentError $error[0]
            }
            if ($filter) {
                [Guid]$Guid = $_.Name.Substring(1, $_.Name.Length - 2)
                $filter |
                    Add-Member -MemberType NoteProperty -Name Guid -Value $Guid -PassThru |
                    Add-Member -MemberType NoteProperty -Name Content -Value $_.'msWMI-Parm2' -PassThru
            } else {
                Write-Warning -Message 'Waiting 5 seconds for Active Directory replication to complete.'
                Start-Sleep -Seconds 5
                Write-Warning -Message 'Trying again to retrieve the WMI filter.'
                ConvertTo-WmiFilter $ADObject
            }
        }
    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished converting the WMI filter."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}