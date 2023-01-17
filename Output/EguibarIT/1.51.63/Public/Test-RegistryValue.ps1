function Test-RegistryValue
{
    <#
        .Synopsis
            Function to Test Registry Values
        .DESCRIPTION
            Function to Test Registry Values
        .PARAMETER Path
            Registry path to be tested
        .PARAMETER Value
            Registry value to be tested
        .EXAMPLE
            Test-RegistryValue -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value "AutoAdminLogon"
        .EXAMPLE
            Test-RegistryValue "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "AutoAdminLogon"
        .NOTES
            Version:         1.0
            DateModified:    16/Ene/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
  #>
    [CmdletBinding(ConfirmImpact = 'Low')]
    [OutputType([Bool])]
    Param (
        [parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Registry path to be tested',
        Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [parameter(Mandatory=$true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ValueFromRemainingArguments = $false,
            HelpMessage = 'Registry value to be tested',
        Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Value
    )
    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message ('Parameters used by the function... {0}' -f (Set-FunctionDisplay $PsBoundParameters -Verbose:$False))

        ##############################
        # Variables Definition
    }
    Process {
        try {
            Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
            return $true
        }
        catch {
            return $false
        }
    }

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished testing registry."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    }
}
