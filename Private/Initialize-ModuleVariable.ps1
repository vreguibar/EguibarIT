Function Initialize-ModuleVariable {
    <#
        .SYNOPSIS
            Initializes module variables related to this module

        .DESCRIPTION
            This function initializes module variables required for CMDlets to delegate.

        .PARAMETER None
            This function does not accept any parameters.

        .NOTES
            Used Functions:
                Name                                   | Module
                ---------------------------------------|--------------------------
                Get-ExtendedRightHashTable             | ActiveDirectory
                Get-AttributeSchemaHashTable           | ActiveDirectory

        .NOTES
            Version:         1.0
            DateModified:    05/Apr/2024
            LasModifiedBy:   Vicente Rodriguez Eguibar
                vicente@eguibar.com
                Eguibar Information Technology S.L.
                http://www.eguibarit.com
    #>
    [CmdletBinding(SupportsShouldProcess = $false, ConfirmImpact = 'Low')]
    [OutputType([void])]

    Param ()

    Begin {
        Write-Verbose -Message '|=> ************************************************************************ <=|'
        Write-Verbose -Message (Get-Date).ToShortDateString()
        Write-Verbose -Message ('  Starting: {0}' -f $MyInvocation.Mycommand)
        Write-Verbose -Message 'This function does not uses any Parameter.'

        ##############################
        # Variables Definition

        Import-Module ActiveDirectory -Verbose:$false

    } #end Begin

    Process {

        # Active Directory DistinguishedName
        $Variables.AdDN = ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString()

        # Configuration Naming Context
        $Variables.configurationNamingContext = ([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString()

        # Active Directory DistinguishedName
        $Variables.defaultNamingContext = ([ADSI]'LDAP://RootDSE').DefaultNamingContext.ToString()

        # Get current DNS domain name
        $Variables.DnsFqdn = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name

        # Naming Contexts
        $Variables.namingContexts = ([ADSI]'LDAP://RootDSE').namingContexts

        # Partitions Container
        $Variables.PartitionsContainer = (([ADSI]'LDAP://RootDSE').configurationNamingContext.ToString())

        # Root Domain Naming Context
        $Variables.rootDomainNamingContext = ([ADSI]'LDAP://RootDSE').rootDomainNamingContext.ToString()

        # Schema Naming Context
        $Variables.SchemaNamingContext = ([ADSI]'LDAP://RootDSE').SchemaNamingContext.ToString()

        # Well-Known SIDs
        #. "$PSScriptRoot\Enum.WellKnownSids.ps1"
        #Get-AdWellKnownSID -SID 'S-1-5-18' | Out-Null  # Just to ensure it's loaded and callable

        # Following functions must be the last ones to be called, otherwise error is thrown.

        # Hashtable containing the mappings between ClassSchema/AttributeSchema and GUID's
        Try {
            [hashtable]$TmpMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
            [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

            Write-Verbose -Message 'The GUID map is null, empty, zero, or false.'
            Write-Verbose -Message 'Getting the GUID value of each schema class and attribute'
            #store the GUID value of each schema class and attribute
            $Splat = @{
                SearchBase = $Variables.SchemaNamingContext
                LDAPFilter = '(schemaidguid=*)'
                Properties = 'lDAPDisplayName', 'schemaIDGUID'
            }
            $AllSchema = Get-ADObject @Splat

            Write-Verbose -Message 'Processing all schema class and attribute'
            Foreach ($item in $AllSchema) {
                # add current Guid to $TempMap
                $TmpMap.Add($item.lDAPDisplayName, ([System.GUID]$item.schemaIDGUID).GUID)
            } #end ForEach

            # Include "ALL [nullGUID]"
            $TmpMap.Add('All', $Constants.guidNull)

            Write-Verbose -Message '$Variables.GuidMap was empty. Adding values to it!'
            $Variables.GuidMap = $TmpMap
        } catch {
            Write-Error -Message 'Something went wrong while trying to fill $Variables.GuidMap!'
            Throw
        }

        # Hashtable containing the mappings between SchemaExtendedRights and GUID's
        Try {
            [hashtable]$TmpMap = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)
            [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

            Write-Verbose -Message 'The Extended Rights map is null, empty, zero, or false.'
            Write-Verbose -Message 'Getting the GUID value of each Extended attribute'
            # store the GUID value of each extended right in the forest
            $Splat = @{
                SearchBase = ('CN=Extended-Rights,{0}' -f $Variables.configurationNamingContext)
                LDAPFilter = '(objectclass=controlAccessRight)'
                Properties = 'DisplayName', 'rightsGuid'
            }
            $AllExtended = Get-ADObject @Splat

            Write-Verbose -Message 'Processing all Extended attributes'
            ForEach ($Item in $AllExtended) {
                # add current Guid to $TempMap
                $TmpMap.Add($Item.displayName, ([system.guid]$Item.rightsGuid).GUID)
            } #end Foreach

            # Include "ALL [nullGUID]"
            $TmpMap.Add('All', $Constants.guidNull)

            Write-Verbose -Message '$Variables.ExtendedRightsMap was empty. Adding values to it!'
            $Variables.ExtendedRightsMap = $TmpMap
        } Catch {
            Write-Error -Message 'Something went wrong while trying to fill $Variables.ExtendedRightsMap!'
            Throw
        }


    } #end Process

    End {
        Write-Verbose -Message "Function $($MyInvocation.InvocationName) finished initializing Variables."
        Write-Verbose -Message ''
        Write-Verbose -Message '-------------------------------------------------------------------------------'
        Write-Verbose -Message ''
    } #end End
}
