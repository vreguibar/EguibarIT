function Test-RegistryValue {
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
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ItemProperty                       | Microsoft.PowerShell.Management
                Get-CurrentErrorToDisplay              | EguibarIT
                Get-FunctionDisplay                    | EguibarIT
        .NOTES
            Version:         1.0
            DateModified:    16/Ene/2018
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
  #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([Bool])]

    Param (
        [parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Registry path to be tested',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Path,

        [parameter(Mandatory = $true,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Registry value to be tested',
            Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Value
    )

    Begin {
        $txt = ($Variables.Header -f
            (Get-Date).ToShortDateString(),
            $MyInvocation.Mycommand,
            (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
        )
        Write-Verbose -Message $txt

        ##############################
        # Module imports

        ##############################
        # Variables Definition

    } #end Begin

    Process {
        try {
            Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
            return $true
        } catch {
            return $false
        }
    } #end Process

    End {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'testing registry.'
        )
        Write-Verbose -Message $txt
    } #end End

} #end Function
