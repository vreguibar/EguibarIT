
# http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx
# http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/
function Add-AdGroupNesting {
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
    Param (
        # Param1 Group which membership is to be changed
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'Group which membership is to be changed',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('GroupName')]
        $Identity,

        # Param2 ID of New Member of the group
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'ID of New Member of the group. Can be a single string or array.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('NewMembers')]
        $Members
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        if (-not (Get-Module -Name 'ActiveDirectory' -ListAvailable)) {
            Import-Module -Name 'ActiveDirectory' -Force -Verbose:$false
        } #end If

        ##############################
        # Variables Definition

        # Define variables and its type
        $CurrentMembers = [System.Collections.Generic.HashSet[String]]::New()
        $NewMembers = [System.Collections.Generic.HashSet[String]]::New()
        $Splat = [hashtable]::New()
    } #end Begin

    Process {

        # Ensure Identity is an AD Group
        If (-not ($Identity -is [Microsoft.ActiveDirectory.Management.AdGroup])) {
            $Identity = Get-AdObjectType -Identity $Identity
        }

        # Get current group members and store it on $CurrentMembers
        Get-AdGroupMember -Identity $Identity | Select-Object -ExpandProperty sAMAccountName | ForEach-Object { [void]$CurrentMembers.Add($_) }

        try {
            Write-Verbose -Message ('Adding members to group..: {0}' -f $Identity.SamAccountName)

            Foreach ($item in $Members) {
                If ($CurrentMembers -notcontains $item) {
                    [void]$NewMembers.Add($item)
                }
                else {
                    Write-Verbose -Message ('{0} is already member of {1} group' -f $item.SamAccountName, $Identity.SamAccountName)
                } #end If-Else
            } #end ForEach

            If ($NewMembers.Count -gt 0) {
                $Splat = @{
                    Identity = $Identity
                    Members  = $NewMembers -join ','
                }

                If ($PSCmdlet.ShouldProcess("Add members to Group $($Identity.SamAccountName)", 'Confirm?')) {
                    Add-AdGroupMember @Splat -WhatIf:$False
                }
                else {
                    Write-Verbose -Message 'Operation cancelled by User!'
                } #end If-Else
            }#end If
            #Add-AdGroupMember @Splat

            Write-Verbose -Message ('Member {0} was added correctly to group {1}' -f $Members, $Identity.sAMAccountName)
        }
        catch {
            throw
        } #end Try-Catch
    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) adding members to the group."
        Write-Verbose -Message ''
        Write-Verbose -Message '--------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
} #end Function
