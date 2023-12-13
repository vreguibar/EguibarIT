@{
    # Use Severity when you want to limit the generated diagnostic records to a
    # subset of: Error, Warning and Information.
    # Uncomment the following line if you only want Errors and Warnings but
    # not Information diagnostic records.
    Severity            = @(
        'Error',
        'Warning',
        'Information'
    )


    IncludeDefaultRules = $true

    # Use IncludeRules when you want to run only a subset of the default rule set.
    <#
    IncludeRules = @("Align assignment statement",
                    "Changing automtic variables might have undesired side effects",
                    "Avoid Default Value For Mandatory Parameter",
                    "Switch Parameters Should Not Default To True",
                    "Avoid global aliases.",
                    "Avoid global functiosn and aliases",
                    "No Global Variables",
                    "Avoid Invoking Empty Members",
                    "Avoid long lines",
                    "Avoid using null or empty HelpMessage parameter attribute.",
                    "Avoid overwriting built in cmdlets",
                    "Avoid Using ShouldContinue Without Boolean Force Parameter",
                    "Avoid trailing whitespace",
                    "Avoid Using Cmdlet Aliases or omitting the 'Get-' prefix.",
                    "Avoid Using ComputerName Hardcoded",
                    "Avoid Using SecureString With Plain Text",
                    "Avoid Using Deprecated Manifest Fields",
                    "Avoid using double quotes if the string is constant.",
                    "Avoid Using Empty Catch Block",
                    "Avoid Using Invoke-Expression",
                    "Avoid Using Plain Text For Password Parameter",
                    "Avoid Using Positional Parameters",
                    "Avoid Using Username and Password Parameters",
                    "Avoid Using Get-WMIObject, Remove-WMIObject, Invoke-WmiMethod, Register-WmiEvent, Set-WmiInstance",
                    "Avoid Using Write-Host",
                    "DSC examples are present",
                    "Dsc tests are present",
                    "Return Correct Types For DSC Functions",
                    "Use Standard Get/Set/Test TargetResource functions in DSC Resource",
                    "Use identical mandatory parameters for DSC Get/Test/Set TargetResource functions",
                    "Use Identical Parameters For DSC Test and Set Functions",
                    "Use verbose message in DSC resource",
                    "Misleading Backtick",
                    "Module Manifest Fields",
                    "Place close braces",
                    "Place open braces consistently",
                    "Null Comparison",
                    "'=' is not an assignment operator. Did you mean the equality operator '-eq'?",
                    "'>' is not a comparison operator. Use  '-gt' (greater than) or '-ge' (greater or equal).",
                    "Basic Comment Help",
                    "Reserved Cmdlet Chars",
                    "Reserved Parameters",
                    "ReviewUnusedParameter",
                    "Should Process",
                    "Cmdlet Verbs",
                    "Use BOM encoding for non-ASCII files",
                    "Use Cmdlet Correctly",
                    "Use compatible cmdlets",
                    "Use compatible commands",
                    "Use compatible syntax",
                    "Use compatible types",
                    "Use consistent indentation",
                    "Use whitespaces",
                    "Use exact casing of cmdlet/function/parameter name.",
                    "Extra Variables",
                    "Create hashtables with literal initializers",
                    "Use OutputType Correctly",
                    "Use process block for command that accepts input from pipeline.",
                    "Use PSCredential type.",
                    "Use ShouldProcess For State Changing Functions",
                    "Cmdlet Singular Noun",
                    "Use SupportsShouldProcess",
                    "Use the *ToExport module manifest fields.",
                    "Use 'Using:' scope modifier in RunSpace ScriptBlocks",
                    "Use UTF8 Encoding For Help File"
                )
    #>

    # Use ExcludeRules when you want to run most of the default set of rules except
    # for a few rules you wish to "exclude".  Note: if a rule is in both IncludeRules
    # and ExcludeRules, the rule will be excluded.
    #ExcludeRules = @('PSAvoidUsingWriteHost')

    # You can use the following entry to supply parameters to rules that take parameters.
    # For instance, the PSAvoidUsingCmdletAliases rule takes a whitelist for aliases you
    # want to allow.
    #Rules = @{
    #    Do not flag 'cd' alias.
    #    PSAvoidUsingCmdletAliases = @{Whitelist = @('cd')}

    #    Check if your script uses cmdlets that are compatible on PowerShell Core,
    #    version 6.0.0-alpha, on Linux.
    #    PSUseCompatibleCmdlets = @{Compatibility = @("core-6.0.0-alpha-linux")}
    #}

    Rules               = @{

        PSAlignAssignmentStatement                = @{
            Enable         = $true
            CheckHashtable = $true
        }

        PSAvoidLongLines                          = @{
            Enable            = $true
            MaximumLineLength = 120
        }

        PSAvoidUsingDoubleQuotesForConstantString = @{
            Enable = $true
        }

        PSPlaceOpenBrace                          = @{
            Enable             = $true
            OnSameLine         = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
        }

        PSPlaceCloseBrace                         = @{
            Enable             = $true
            NewLineAfter       = $true
            IgnoreOneLineBlock = $true
            NoEmptyLineBefore  = $false
        }

        PSProvideCommentHelp                      = @{
            Enable                  = $true
            ExportedOnly            = $false
            BlockComment            = $true
            VSCodeSnippetCorrection = $false
            Placement               = 'begin'
        }

        PSUseCompatibleSyntax                     = @{
            # This turns the rule on (setting it to false will turn it off)
            Enable         = $true

            # List the targeted versions of PowerShell here
            TargetVersions = @(
                '5.1',
                '7.0',
                '7.1',
                '7.2',
                '7.3',
                '7.4'
            )
        }

        PSUseConsistentIndentation                = @{
            Enable              = $true
            Kind                = 'space'
            PipelineIndentation = 'IncreaseIndentationForFirstPipeline'
            IndentationSize     = 4
        }

        PSUseConsistentWhitespace                 = @{
            Enable                                  = $true
            CheckInnerBrace                         = $true
            CheckOpenBrace                          = $true
            CheckOpenParen                          = $true
            CheckOperator                           = $true
            CheckPipe                               = $true
            CheckPipeForRedundantWhitespace         = $true
            CheckSeparator                          = $true
            CheckParameter                          = $true
            IgnoreAssignmentOperatorInsideHashTable = $true
        }

        PSUseCorrectCasing                        = @{
            Enable = $true
        }
    }
}
