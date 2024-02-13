function Get-CurrentErrorToDisplay {
    <#
        .Synopsis
            Process and displays all information from $Error variable
        .DESCRIPTION
            Process and displays all information from $Error variable
        .EXAMPLE
            Get-CurrentErrorToDisplay $error[0]
        .EXAMPLE
            Get-CurrentErrorToDisplay -CurrentError $error[0]
        .PARAMETER CurrentError
            Is the error to be processed
        .INPUTS
            System.Management.Automation.ErrorRecord
        .OUTPUTS
            System.String
        .LINKS
            http://www.eguibarit.com

        .NOTES
            Version:         1.0
            DateModified:    08/Oct/2021
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([System.String])]
    Param (
        [Parameter(Mandatory = $false, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Current error (usually from $Error variable) which is going to be proccessed. If no error is provided then $error[0] will be used instead.',
            Position = 0)]
        $CurrentError
    )

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition

        $Section = '----------------------------------------'
        $Header = '################################################################################'
        $OutputError = [System.Text.StringBuilder]::new()

        if (-not $PSBoundParameters['CurrentError']) {
            Write-Verbose -Message 'No error passed to the CurrentError variable. Using the last error stored on $error variable'
            $CurrentError = $error[0]
        }
    } # End BEGIN section

    Process {

        if ($PSCmdlet.ShouldProcess("Processing error: $($CurrentError.Exception.Message)", 'Continue?')) {
            try {
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine($Header)
                [void]$OutputError.AppendLine('#         Error: {0}' -f $CurrentError.ToString())
                [void]$OutputError.AppendLine($Header)
                [void]$OutputError.AppendLine()

                [void]$OutputError.AppendLine('   Category Info')
                [void]$OutputError.AppendLine($Section)
                [void]$OutputError.AppendLine($CurrentError.CategoryInfo)
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine()

                [void]$OutputError.AppendLine('   PowerSell Message Details')
                [void]$OutputError.AppendLine($Section)
                [void]$OutputError.AppendLine($CurrentError.PSMessageDetails)
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine()

                [void]$OutputError.AppendLine('   Exception')
                [void]$OutputError.AppendLine($Section)
                [void]$OutputError.AppendLine($CurrentError.Exception)
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine()

                [void]$OutputError.AppendLine('   Target Object')
                [void]$OutputError.AppendLine($Section)
                [void]$OutputError.AppendLine($CurrentError.TargetObject)
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine()

                [void]$OutputError.AppendLine('   Fully Qualifier Error ID')
                [void]$OutputError.AppendLine($Section)
                [void]$OutputError.AppendLine($CurrentError.FullyQualifiedErrorId)
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine()

                [void]$OutputError.AppendLine('   Error Details')
                [void]$OutputError.AppendLine($Section)
                [void]$OutputError.AppendLine($CurrentError.ErrorDetails)
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine()

                [void]$OutputError.AppendLine('   Script Trace')
                [void]$OutputError.AppendLine($Section)
                [void]$OutputError.AppendLine($CurrentError.ScriptStackTrace)
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine()

                [void]$OutputError.AppendLine('   Invocation Information')
                [void]$OutputError.AppendLine($Section)
                [void]$OutputError.AppendLine('MyCommand             : {0}' -f $CurrentError.InvocationInfo.MyCommand)
                [void]$OutputError.AppendLine('ScriptLineNumber      : {0}' -f $CurrentError.InvocationInfo.ScriptLineNumber)
                [void]$OutputError.AppendLine('OffsetInLine          : {0}' -f $CurrentError.InvocationInfo.OffsetInLine)
                [void]$OutputError.AppendLine('ScriptName            : {0}' -f $CurrentError.InvocationInfo.ScriptName)
                [void]$OutputError.AppendLine('Line                  : {0}' -f $CurrentError.InvocationInfo.Line)
                [void]$OutputError.AppendLine('PositionMessage       : {0}' -f $CurrentError.InvocationInfo.PositionMessage)
                [void]$OutputError.AppendLine('PSCommandPath         : {0}' -f $CurrentError.InvocationInfo.PSCommandPath)
                [void]$OutputError.AppendLine('InvocationName        : {0}' -f $CurrentError.InvocationInfo.InvocationName)
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine()

                [void]$OutputError.AppendLine($Header)
                [void]$OutputError.AppendLine('####      END Error')
                [void]$OutputError.AppendLine($Header)
                [void]$OutputError.AppendLine()
                [void]$OutputError.AppendLine()
            }
            catch {
                Write-Error "Error processing the error: $_"
            } #end Try-Catch
        } #end If
    } # End PROCESS section

    End {
        $result = $OutputError.ToString()
        Write-Verbose -Message 'Cleaning the $error variable'
        $error.Clear()
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
        return $result
    } # End END section
} # End Function
