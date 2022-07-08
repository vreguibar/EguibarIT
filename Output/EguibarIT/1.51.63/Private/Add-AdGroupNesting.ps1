
# http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx
# http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/
function Add-AdGroupNesting
{
    <#
        .SYNOPSIS
            Same as Add-AdGroupMember but with error handling and loging
        .DESCRIPTION
            Same as Add-AdGroupMember but with error handling and loging
        .EXAMPLE
            Add-AdGroupNesting -Identity "Domain Admins" -Members TheUgly
        .NOTES
            Version:         1.0
            DateModified:    22/Jun/2016
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param
    (
        # Param1 Group which membership is to be changed
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'Group which membership is to be changed',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Identity,

        # Param2 ID of New Member of the group
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $False,
            HelpMessage = 'ID of New Member of the group. Can be a single string or array.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        $Members
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)

        #display PSBoundparameters formatted nicely for Verbose output
        $NL   = "`n"  # New Line
        $HTab = "`t"  # Horizontal Tab
        [string]$pb = ($PSBoundParameters | Format-Table -AutoSize | Out-String).TrimEnd()
        Write-Verbose -Message "Parameters used by the function... $NL$($pb.split($NL).Foreach({"$($HTab*4)$_"}) | Out-String) $NL"


        Import-Module -name ActiveDirectory -Verbose:$false

        # Active Directory Domain Distinguished Name
        If(-Not (Test-Path -Path variable:AdDn)) {
           $AdDn = ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()
        }

        # Define an empty array
        $CurrentMembers = @()
        $NewMembers     = @()
        $parameters     = $null

        If($identity.GetType() -eq [Microsoft.ActiveDirectory.Management.AdGroup]) {
            $Group = Get-AdGroup -Identity $Identity.ObjectGUID
        }

        If($identity.GetType() -eq [System.String]) {
            If($identity -contains $AdDn) {
                $Group = Get-AdGroup -Filter { distinguishedName -eq $Identity }
            } ELSE {
                $Group = Get-AdGroup -Filter { samAccountName -eq $Identity }
            }
        }
    }
    Process {
        # Get group members
        Get-AdGroupMember -Identity $Group.SID | Select-Object -ExpandProperty sAMAccountName | ForEach-Object { $CurrentMembers += $_ }

        try {
            Write-Verbose -Message ('Adding members to group..: {0}' -f $Group.SamAccountName)

            Foreach ($item in $Members) {
                If($CurrentMembers -notcontains $item) {
                    $NewMembers += $item
                } else {
                     Write-Verbose -Message ('{0} is already member of {1} group' -f $item.SamAccountName, $Group.SamAccountName)
                }
            }
            If($NewMembers.Count -gt 0) {
                $parameters = @{
                    Identity = $Group
                    Members  = $NewMembers
                }
                Add-AdGroupMember @parameters
            }
            #Add-AdGroupMember @parameters

            Write-Verbose -Message ('Member {0} was added correctly to group {1}' -f $Members, $Group.sAMAccountName)
        } catch { throw }
    }
    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
