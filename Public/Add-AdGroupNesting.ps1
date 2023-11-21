
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
        [Alias("GroupName")]
        $Identity,

        # Param2 ID of New Member of the group
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $False,
            HelpMessage = 'ID of New Member of the group. Can be a single string or array.',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias("NewMembers")]
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
        $NewMembers     = [System.Collections.Generic.HashSet[String]]::New()
        $Splat          = [hashtable]::New()
    } #end Begin

    Process {
        # Get group members
        Get-AdGroupMember -Identity $Group.SID | Select-Object -ExpandProperty sAMAccountName | ForEach-Object { $CurrentMembers.Add($_) }

        try {
            Write-Verbose -Message ('Adding members to group..: {0}' -f $Group.SamAccountName)

            Foreach ($item in $Members) {
                If($CurrentMembers -notcontains $item) {
                    $NewMembers.Add($item)
                } else {
                     Write-Verbose -Message ('{0} is already member of {1} group' -f $item.SamAccountName, $Group.SamAccountName)
                } #end If-Else
            } #end ForEach

            If($NewMembers.Count -gt 0) {
                $Splat = @{
                    Identity = $Group
                    Members  = $NewMembers
                }

                If($PSCmdlet.ShouldProcess("Add members to Group $(Group.SamAccountName)", "Confirm?")) {
                    Add-AdGroupMember @Splat -WhatIf:$False
                } else {
                    Write-Verbose -Message 'Operation cancelled by User!'
                } #end If-Else
            }#end If
            #Add-AdGroupMember @Splat

            Write-Verbose -Message ('Member {0} was added correctly to group {1}' -f $Members, $Group.sAMAccountName)
        } catch {
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
