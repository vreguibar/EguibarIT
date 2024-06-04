
# http://blogs.technet.com/b/lrobins/archive/2011/06/23/quot-admin-free-quot-active-directory-and-windows-part-1-understanding-privileged-groups-in-ad.aspx
# http://blogs.msmvps.com/acefekay/2012/01/06/using-group-nesting-strategy-ad-best-practices-for-group-strategy/
function Add-AdGroupNesting {
    <#
    .SYNOPSIS
        Same as Add-AdGroupMember but with error handling and logging
    .DESCRIPTION
        Same as Add-AdGroupMember but with error handling and logging
    .EXAMPLE
        Add-AdGroupNesting -Identity "Domain Admins" -Members TheUgly
    .NOTES
        Version:         1.3
        DateModified:    24/Jan/2024
        LastModifiedBy:   Vicente Rodriguez Eguibar
        vicente@eguibar.com
        Eguibar Information Technology S.L.
        http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    Param (
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
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Get-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        Import-MyModule -Name ActiveDirectory -Verbose:$false

        # Define array lists
        $CurrentMembers = [System.Collections.ArrayList]::new()
        $Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        # Check if Identity is a group. Retrieve the object if not Microsoft.ActiveDirectory.Management.AdGroup.
        $Identity = Get-AdObjectType -Identity $Identity

    } #end Begin

    Process {
        # Get group members
        Try {

            Write-Verbose -Message ('Getting members of group {0}' -f $Identity)
            $CurrentMembers = Get-ADGroupMember -Identity $Identity -Recursive -ErrorAction SilentlyContinue

        } Catch {
            ###Get-CurrentErrorToDisplay -CurrentError $error[0]
            Write-Error -Message ('Failed to retrieve members of the group "{0}". {1}' -f $Group.SamAccountName, $_)
            throw
        } #end Try-Catch


        try {
            Write-Verbose -Message ('Adding members to group..: {0}' -f $Identity.SamAccountName)

            Foreach ($item in $Members) {
                $item = Get-AdObjectType -Identity $item -ErrorAction Stop

                If ($CurrentMembers -notcontains $item) {

                    Write-Verbose -Message ('Adding: {0}' -f $Item)

                    If ($PSCmdlet.ShouldProcess($Identity.DistinguishedName, $confirmMessage)) {
                        $Splat = @{
                            Identity = $Identity
                            Members  = $item
                        }
                        Add-ADGroupMember @Splat
                    } #end If
                } else {
                    Write-Verbose -Message ('{0} is already a member of {1} group' -f $item.SamAccountName, $Identity.SamAccountName)
                } #end If-Else
            }

            Write-Verbose -Message ('Members were added correctly to group {0}' -f $Identity.sAMAccountName)
        } catch {
            ###Get-CurrentErrorToDisplay -CurrentError $error[0]
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
