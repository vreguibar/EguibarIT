#
param (
    [Parameter(Mandatory = $true)]
    $ModuleName,
    [Parameter(Mandatory = $true)]
    $ModuleVersion
)

Function CleanUp {
    <#
        .SYNOPSIS

        .DESCRIPTION

        .PARAMETER Length

        .EXAMPLE

        .NOTES
        Version:         0.0
            DateModified:    xx/Jun/2099
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $False)]

    param (

        [parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true,
            HelpMessage = 'Name of the module being processed.',
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName

    )

    Begin {

    } #end Begin

    Process {

        if (Test-Path '.\Output\temp') {
            Write-Verbose -Message 'Removing temp folders'
            Remove-Item '.\Output\temp' -Recurse -Force
        } #end If
        
    } #end Process

    End {

    } #end End
} #end Function


# Call the function with parameters
CleanUp
