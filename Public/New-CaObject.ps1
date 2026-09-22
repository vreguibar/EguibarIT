function New-CaObject {
    <#
        .SYNOPSIS
            Creates Certificate Authority (PKI) objects and delegations.

        .DESCRIPTION
            Creates the Certificate Authority objects used to manage this organisation by following
            the defined Delegation Model. Key features:
            - Creates PKI-specific security groups
            - Creates certificate-related organisational units
            - Delegates appropriate certificate management rights
            - Supports the three-tier administration model

        .PARAMETER ConfigXMLFile
            [System.IO.FileInfo] Full path to the configuration XML file.
            The XML file must contain required naming conventions, OU structure, and security settings.

        .EXAMPLE
            New-CaObject -ConfigXMLFile 'C:\PsScripts\Config.xml'

            Creates CA objects using the specified configuration file.

        .EXAMPLE
            $Splat = @{
                ConfigXMLFile = 'C:\PsScripts\Config.xml'
            }
            New-CaObject @Splat -Verbose

            Creates CA objects with verbose output.

        .EXAMPLE
            New-CaObject -ConfigXMLFile 'C:\PsScripts\Config.xml' -WhatIf

            Shows what would happen when creating CA objects without making changes.

        .INPUTS
            [System.String]
            You can pipe the path to the XML configuration file to this function.

        .OUTPUTS
            [void]
            This function does not return any output.

        .NOTES
            Used Functions:
                Name                                   ║ Module/Namespace
                ═══════════════════════════════════════╬══════════════════════════════
                Get-FunctionDisplay                    ║ EguibarIT
                New-AdDelegatedGroup                   ║ EguibarIT
                Import-MyModule                        ║ EguibarIT
                Write-Verbose                          ║ Microsoft.PowerShell.Utility
                Write-Error                            ║ Microsoft.PowerShell.Utility

        .NOTES
            Version:         1.4
            DateModified:    21/Sep/2025
            LastModifiedBy:  Vicente Rodriguez Eguibar
                            vicente@eguibar.com
                            Eguibar IT
                            http://www.eguibarit.com

        .LINK
            https://github.com/vreguibar/EguibarIT/blob/main/Public/New-CaObject.ps1

        .COMPONENT
            Active Directory

        .ROLE
            Infrastructure Administration

        .FUNCTIONALITY
            PKI Object Management
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([void])]

    param (
        # PARAM1 full path to the configuration.xml file
        [Parameter(Mandatory = $true,
            ValueFromPipeline = $True,
            ValueFromPipelineByPropertyName = $True,
            ValueFromRemainingArguments = $false,
            HelpMessage = 'Full path to the configuration.xml file',
            Position = 0)]
        [string]
        $ConfigXMLFile
    )

    begin {
        Set-StrictMode -Version Latest

        # Initialize logging
        if ($null -ne $Variables -and
            $null -ne $Variables.Header) {

            $txt = ($Variables.Header -f
                (Get-Date).ToString('dd/MMM/yyyy'),
                $MyInvocation.Mycommand,
                (Get-FunctionDisplay -HashTable $PsBoundParameters -Verbose:$False)
            )
            Write-Verbose -Message $txt
        } #end if

        ##############################
        # Module imports

        Import-MyModule -Name 'EguibarIT.DelegationPS' -Verbose:$false

        ##############################
        # Variables Definition

        #Get the OS Installation Type
        $RegKey = 'HKLM:Software\Microsoft\Windows NT\CurrentVersion'
        $OsInstalationType = Get-ItemProperty -Path $RegKey | Select-Object -ExpandProperty InstallationType

        try {
            # Check if Config.xml file is loaded. if not, proceed to load it.
            if (-not (Test-Path -Path variable:confXML)) {
                # Check if the Config.xml file exist on the given path
                if (Test-Path -Path $PSBoundParameters['ConfigXMLFile']) {
                    #Open the configuration XML file
                    $confXML = [xml](Get-Content $PSBoundParameters['ConfigXMLFile'])
                } #end if
            } #end if
        } catch {
            Write-Error -Message 'Error when reading XML file'
            throw
        }

        # Naming conventions hashtable
        $NC = @{'sl' = $confXML.n.NC.LocalDomainGroupPreffix
            'sg'     = $confXML.n.NC.GlobalGroupPreffix
            'su'     = $confXML.n.NC.UniversalGroupPreffix
            'Delim'  = $confXML.n.NC.Delimiter
            'T0'     = $confXML.n.NC.AdminAccSufix0
            'T1'     = $confXML.n.NC.AdminAccSufix1
            'T2'     = $confXML.n.NC.AdminAccSufix2
        }
        #('{0}{1}{2}{1}{3}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.lg.PAWM, $NC['T0'])
        # SG_PAWM_T0

        # Organizational Units Distinguished Names

        # IT Admin OU
        $ItAdminOu = $confXML.n.Admin.OUs.ItAdminOU.name
        # IT Admin OU Distinguished Name
        $ItAdminOuDn = 'OU={0},{1}' -f $ItAdminOu, $Variables.AdDn

        # It Admin Groups OU
        # $ItGroupsOu = $confXML.n.Admin.OUs.ItAdminGroupsOU.name
        # It Admin Groups OU Distinguished Name
        # $ItGroupsOuDn = 'OU={0},{1}' -f $ItGroupsOu, $ItAdminOuDn

        # It Privileged Groups OU
        $ItPGOu = $confXML.n.Admin.OUs.ItPrivGroupsOU.name
        # It Privileged Groups OU Distinguished Name
        $ItPGOuDn = 'OU={0},{1}' -f $ItPGOu, $ItAdminOuDn

        # It Admin Rights OU
        $ItRightsOu = $confXML.n.Admin.OUs.ItRightsOU.name
        # It Admin Rights OU Distinguished Name
        $ItRightsOuDn = 'OU={0},{1}' -f $ItRightsOu, $ItAdminOuDn

        [hashtable]$Splat = [hashtable]::New([StringComparer]::OrdinalIgnoreCase)

        #endregion Declarations
        ################################################################################
    } #end begin

    process {
        if ($PSCmdlet.ShouldProcess('Active Directory Certificate Services', 'Configure Certificate Authority')) {
            # Check if AD module is installed
            if (-not((Get-WindowsFeature -Name RSAT-AD-PowerShell).Installed)) {
                Install-WindowsFeature -Name RSAT-AD-PowerShell -IncludeAllSubFeature
            }
            Import-MyModule -Name 'ActiveDirectory' -Verbose:$false

            # AD CS Step by Step Guide: Two Tier PKI Hierarchy Deployment
            # https://social.technet.microsoft.com/wiki/contents/articles/15037.ad-cs-step-by-step-guide-two-tier-pki-hierarchy-deployment.aspx

            # Deploy a PKI on Windows Server 2016
            # https://timothygruber.com/pki/deploy-a-pki-on-windows-server-2016-part-2/


            try {
                # Check if feature is installed, if not then proceed to install it.
                if (-not((Get-WindowsFeature -Name ADCS-Cert-Authority).Installed)) {
                    Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeAllSubFeature

                    Install-WindowsFeature -Name ADCS-web-enrollment

                    Install-WindowsFeature -Name ADCS-Online-Cert

                    if ($OsInstalationType -ne 'Server Core') {
                        Install-WindowsFeature -Name RSAT-ADCS -IncludeAllSubFeature
                    }

                    # https://www.pkisolutions.com/tools/pspki/
                    # Install PSPKI module for managing Certification Authority
                    Install-PackageProvider -Name NuGet -Force
                    Install-Module -Name PSPKI -Force
                    Import-MyModule -Name 'PSPKI' -Verbose:$false

                    #Define PKI Cname
                    $PkiServer = ('pki.{0}' -f $env:USERDNSDOMAIN)

                    # Create CAPolicy.inf for Enterprise Root CA
                    $CaPolicy = @"
[Version]
Signature="$Windows NT$"
[PolicyStatementExtension]
Policies=AllIssuancePolicy
Critical=False
[AllIssuancePolicy]
OID=2.5.29.32.0
URL=http://$PkiServer/certdata/cps.txt
[Certsrv_Server]
RenewalKeyLength=$($confXML.n.CA.CAKeyLength)
RenewalValidityPeriod=Years
RenewalValidityPeriodUnits=$($confXML.n.CA.CACertValidity)
CRLPeriod=$($confXML.n.CA.CACRLPeriod)
CRLPeriodUnits=$($confXML.n.CA.CACRLPeriodUnits)
CRLDeltaPeriod=$($confXML.n.CA.CACRLDeltaPeriod)
CRLDeltaPeriodUnits=$($confXML.n.CA.CACRLDeltaPeriodUnits)
LoadDefaultTemplates=0
"@
                    # Set the content into the file
                    Set-Content -Path C:\Windows\CaPolicy.ini -Value $CaPolicy -Force

                    # Create Folder where to store CA Database
                    $CaConfig = ('{0}\CaConfig\' -f $env:SystemDrive)

                    if (-not(Test-Path $CaConfig)) {
                        New-Item -ItemType Directory -Force -Path $CaConfig
                    }

                    $Splat = @{
                        CAType                    = $confXML.n.CA.CAType
                        CryptoProviderName        = $confXML.n.CA.CACryptoProvider
                        KeyLength                 = $confXML.n.CA.CAKeyLength
                        HashAlgorithmName         = $confXML.n.CA.CAHashAlgorithm
                        ValidityPeriod            = 'Years'
                        ValidityPeriodUnits       = $confXML.n.CA.CACertValidity
                        CACommonName              = '{0}-CA' -f (($Variables.AdDn).Split(',')[0]).split('=')[1]
                        CADistinguishedNameSuffix = $Variables.AdDn
                        DatabaseDirectory         = $CaConfig
                        LogDirectory              = '{0}LOGs' -f $CaConfig
                        Force                     = $true
                        Confirm                   = $false
                    }
                    # Configure the new CA
                    Install-AdcsCertificationAuthority @Splat

                    # configure the web enrollment role service
                    Install-ADCSwebenrollment -Confirm
                } # end if
            } catch {
                Write-Error -Message 'Error when installing Certificate Authority'
                throw
            } # end try-catch
            finally {

                # Remove all distribution points
                foreach ($crl in Get-CACrlDistributionPoint) {
                    Remove-CACrlDistributionPoint $crl.uri -Force
                }

                # Add CDP local path
                Add-CACRLDistributionPoint -Uri C:\Windows\System32\CertSrv\CertEnroll\%3%8%9.crl -PublishToServer -PublishDeltaToServer -Force

                # Add CDP url
                Add-CACRLDistributionPoint -Uri http://$PkiServer/CertEnroll/%3%8%9.crl -AddToCertificateCDP -AddToFreshestCrl -Force

                Get-CAAuthorityInformationAccess | Where-Object { $_.Uri -like '*ldap*' -or $_.Uri -like '*http*' -or $_.Uri -like '*file*' } | Remove-CAAuthorityInformationAccess -Force

                # Add AIA url
                Add-CAAuthorityInformationAccess -AddToCertificateAia http://$PkiServer/CertEnroll/%1_%3%4.crt -Force


                # Configure CRL and DeltaCRL
                & certutil.exe -setreg 'CA\CRLPeriodUnits' $confXML.n.CA.CACRLPeriodUnits
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning -Message ('certutil CRLPeriodUnits returned exit code {0}' -f $LASTEXITCODE)
                }

                & certutil.exe -setreg 'CA\CRLPeriod' $confXML.n.CA.CACRLPeriod
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning -Message ('certutil CRLPeriod returned exit code {0}' -f $LASTEXITCODE)
                }

                & certutil.exe -setreg 'CA\CRLDeltaPeriodUnits' $confXML.n.CA.CACRLDeltaPeriodUnits
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning -Message ('certutil CRLDeltaPeriodUnits returned exit code {0}' -f $LASTEXITCODE)
                }

                & certutil.exe -setreg 'CA\CRLDeltaPeriod' $confXML.n.CA.CACRLDeltaPeriod
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning -Message ('certutil CRLDeltaPeriod returned exit code {0}' -f $LASTEXITCODE)
                }

                <##TODO
            Failing next 2
            #>

                & certutil.exe -setreg 'CA\CRLOverlapPeriodUnits' $confXML.n.CA.CACRLOverlapPeriodUnits
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning -Message ('certutil CRLOverlapPeriodUnits returned exit code {0}' -f $LASTEXITCODE)
                }

                & certutil.exe -setreg 'CA\CRLOverlapPeriod' $confXML.n.CA.CACRLOverlapPeriod
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning -Message ('certutil CRLOverlapPeriod returned exit code {0}' -f $LASTEXITCODE)
                }


                # Create A record for PKI
                Add-DnsServerResourceRecordCName -Name 'pki' -HostNameAlias ('{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN) -ZoneName $env:USERDNSDOMAIN


                # Configure CA auditing
                & certutil.exe -setreg 'CA\AuditFilter' 127
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning -Message ('certutil AuditFilter returned exit code {0}' -f $LASTEXITCODE)
                }

                # Configure the AIA
                [String]$AiaLocations = '1:C:\Windows\system32\CertSrv\CertEnroll\%1_%3%4.crt{0}2:ldap:///CN=%7,CN=AIA,CN=Public Key Services,CN=Services,%6%11{0}2:http://{1}/CertEnroll/%1_%3%4.crt' -f '\n', $PkiServer
                & certutil.exe -setreg 'CA\CACertPublicationURLs' $AiaLocations
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning -Message ('certutil CACertPublicationURLs returned exit code {0}' -f $LASTEXITCODE)
                }

                # Configure the CDP
                [String]$CdpLocations = '65:C:\Windows\system32\CertSrv\CertEnroll\%3%8%9.crl{0}79:ldap:///CN=%7%8,CN=%2,CN=CDP,CN=Public Key Services,CN=Services,%6%10{0}6:http://{1}/CertEnroll/%3%8%9.crl{0}65:\\{2}\CertEnroll\%3%8%9.crl' -f '\n', $PkiServer, ('{0}.{1}' -f $env:COMPUTERNAME, $env:USERDNSDOMAIN)
                & certutil.exe -setreg 'CA\CRLPublicationURLs' $CdpLocations
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning -Message ('certutil CRLPublicationURLs returned exit code {0}' -f $LASTEXITCODE)
                }

                # Configure Online Responder
                #Configure and Publish the OCSP Response Signing Certificate
                Get-CertificateTemplate -Name 'OCSPResponseSigning' | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -Identity ('{0}$' -f $env:computername) -AccessType Allow -AccessMask Read, Enroll | Set-CertificateTemplateAcl
                Get-CertificationAuthority | Get-CATemplate | Add-CATemplate -DisplayName 'OCSP Response Signing'

                Restart-Service certsvc

            } # end try-catch-Finally

            <#
        ###############################################################################
        #Install Edge
        $ProgressPreference='SilentlyContinue' #for faster download
        Invoke-WebRequest -Uri "http://dl.delivery.mp.microsoft.com/filestreamingservice/files/07367ab9-ceee-4409-a22f-c50d77a8ae06/MicrosoftEdgeEnterpriseX64.msi" -UseBasicParsing -OutFile "$env:USERPROFILE\Downloads\MicrosoftEdgeEnterpriseX64.msi"

        #start install
        Start-Process -Wait -Filepath msiexec.exe -Argumentlist "/i $env:UserProfile\Downloads\MicrosoftEdgeEnterpriseX64.msi /q"

        #start Edge
        start-sleep 5
        & "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
#>

            ###############################################################################
            # Create OU Admin groups
            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.PkiAdmins.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = $confXML.n.AdminXtra.GG.PkiAdmins.DisplayName
                Path                          = $ItPGOuDn
                Description                   = $confXML.n.AdminXtra.GG.PkiAdmins.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $SG_PkiAdmins = New-AdDelegatedGroup @Splat

            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.AdminXtra.GG.PkiTemplateAdmins.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'Global'
                DisplayName                   = $confXML.n.AdminXtra.GG.PkiTemplateAdmins.DisplayName
                Path                          = $ItPGOuDn
                Description                   = $confXML.n.AdminXtra.GG.PkiTemplateAdmins.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $SG_PkiTemplAdmins = New-AdDelegatedGroup @Splat

            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.PkiRight.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = $confXML.n.AdminXtra.LG.PkiRight.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = $confXML.n.AdminXtra.LG.PkiRight.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $SL_PkiRight = New-AdDelegatedGroup @Splat

            $Splat = @{
                Name                          = '{0}{1}{2}' -f $NC['sl'], $NC['Delim'], $confXML.n.AdminXtra.LG.PkiTemplateRight.Name
                GroupCategory                 = 'Security'
                GroupScope                    = 'DomainLocal'
                DisplayName                   = $confXML.n.AdminXtra.LG.PkiTemplateRight.DisplayName
                Path                          = $ItRightsOuDn
                Description                   = $confXML.n.AdminXtra.LG.PkiTemplateRight.Description
                ProtectFromAccidentalDeletion = $True
                RemoveAccountOperators        = $True
                RemoveEveryone                = $True
                RemovePreWin2000              = $True
            }
            $SL_PkiTemplRight = New-AdDelegatedGroup @Splat

            # Apply the PSO to the corresponding Groups
            $Splat = @{
                Identity = $confXML.n.Admin.PSOs.ItAdminsPSO.Name
                Subjects = $SG_PkiAdmins, $SG_PkiTemplAdmins, $SL_PkiRight, $SL_PkiTemplRight
            }
            Add-ADFineGrainedPasswordPolicySubject @Splat


            ###############################################################################
            # Nest Groups - Security for RODC
            # Avoid having privileged or semi-privileged groups copy to RODC

            $Splat = @{
                Identity = 'Denied RODC Password Replication Group'
                Members  = $SG_PkiAdmins, $SG_PkiTemplAdmins, $SL_PkiRight, $SL_PkiTemplRight
            }
            Add-ADGroupMember @Splat


            ###############################################################################
            # Nest Groups - Extend Rights through delegation model groups

            Add-AdGroupNesting -Identity $SG_PkiAdmins -Members ('{0}{1}{2}' -f $NC['sg'], $NC['Delim'], $confXML.n.Admin.GG.InfraAdmins.Name)

            Add-AdGroupNesting -Identity $SG_PkiTemplAdmins -Members $SG_PkiAdmins

            Add-AdGroupNesting -Identity $SL_PkiRight -Members $SG_PkiAdmins

            Add-AdGroupNesting -Identity $SL_PkiTemplRight -Members $SG_PkiTemplAdmins

            Add-AdGroupNesting -Identity 'Cryptographic Operators' -Members $SG_PkiAdmins

            ###############################################################################
            # START Delegation to SL_InfraRights group on ADMIN area

            #
            Set-AdAclPkiAdmin -Group $SL_PkiRight.SamAccountName -ItRightsOuDN $ItRightsOuDn

            #
            Set-AdAclPkiTemplateAdmin -Group $SL_PkiTemplRight.SamAccountName

            ###############################################################################
            # START Create new Templates

            #https://github.com/GoateePFE/ADCSTemplate
            # Install-Module -Name ADCSTemplate
            # Get-ADCSTemplate -DisplayName 'WinRM' -Server 'DC1.EguibarIT.local' | Select-Object *
            # Export-ADCSTemplate -Server DC1 -DisplayName WAC > .\WAC.json
            #
            # ldifde -m -v -d “CN=WinRM,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=EguibarIT,DC=local” -f sourcetemplate.ldf

            #
            #Windows Admin Center and Enterprise CA
            #https://github.com/microsoft/WSLab/tree/master/Scenarios/Windows%20Admin%20Center%20and%20Enterprise%20CA

            <#
        Get-ADCSTemplate -DisplayName 'RemoteDesktopAuthentication' -Server 'DC1.EguibarIT.local' | Select-Object *

CanonicalName                        : EguibarIT.local/Configuration/Services/Public Key Services/Certificate Templates/RemoteDesktopAuthentication
CN                                   : RemoteDesktopAuthentication
Created                              : 08/10/2021 17:19:50
createTimeStamp                      : 08/10/2021 17:19:50
Deleted                              :
Description                          :
DisplayName                          : RemoteDesktopAuthentication
DistinguishedName                    : CN=RemoteDesktopAuthentication,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=EguibarIT,DC=local
dSCorePropagationData                : {27/10/2021 17:00:33, 01/01/1601 1:00:00}
flags                                : 131680
instanceType                         : 4
isDeleted                            :
LastKnownParent                      :
Modified                             : 23/12/2021 17:16:43
modifyTimeStamp                      : 23/12/2021 17:16:43
msPKI-Cert-Template-OID              : 1.3.6.1.4.1.311.21.8.2144245.16492515.9915066.5498192.1427428.109.8434507.13944343
msPKI-Certificate-Application-Policy : {1.3.6.1.4.1.311.54.1.2, 1.3.6.1.5.5.7.3.1}
msPKI-Certificate-Name-Flag          : 1249902592
msPKI-Enrollment-Flag                : 40
msPKI-Minimal-Key-Size               : 2048
msPKI-Private-Key-Flag               : 101056512
msPKI-RA-Application-Policies        : {msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA256`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetr
                                       ic-Key-Length`DWORD`168`}
msPKI-RA-Signature                   : 0
msPKI-Template-Minor-Revision        : 1
msPKI-Template-Schema-Version        : 4
Name                                 : RemoteDesktopAuthentication
nTSecurityDescriptor                 : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                       : CN=PKI-Certificate-Template,CN=Schema,CN=Configuration,DC=EguibarIT,DC=local
ObjectClass                          : pKICertificateTemplate
ObjectGUID                           : 2f2dc922-669b-4917-a264-c5f1429788b1
pKICriticalExtensions                : {2.5.29.15}
pKIDefaultKeySpec                    : 1
pKIExpirationPeriod                  : {0, 128, 114, 14…}
pKIExtendedKeyUsage                  : {1.3.6.1.4.1.311.54.1.2, 1.3.6.1.5.5.7.3.1}
pKIKeyUsage                          : {160, 0}
pKIMaxIssuingDepth                   : 0
pKIOverlapPeriod                     : {0, 128, 166, 10…}
ProtectedFromAccidentalDeletion      : False
revision                             : 101
sDRightsEffective                    : 15
showInAdvancedViewOnly               : True
uSNChanged                           : 179020
uSNCreated                           : 21502
whenChanged                          : 23/12/2021 17:16:43
whenCreated                          : 08/10/2021 17:19:50
PropertyNames                        : {CanonicalName, CN, Created, createTimeStamp…}
AddedProperties                      : {}
RemovedProperties                    : {}
ModifiedProperties                   : {}
PropertyCount                        : 45
        #>
            $DisplayName = 'RemoteDesktopAuthentication'
            $TemplateOtherAttributes = @{
                'Name'                                 = [System.String]$DisplayName
                'description'                          = [System.String]'SSL Certificate used to secure RDP connections.'
                'ObjectClass'                          = [System.String]'pKICertificateTemplate'
                'flags'                                = [System.Int32]'131680'
                'revision'                             = [System.Int32]'100'
                'msPKI-Cert-Template-OID'              = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.4.1.311.21.8.13605061.7836627.5522072.972782.1389733.240.7712192.10755021')
                'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.4.1.311.54.1.2')
                'msPKI-Certificate-Name-Flag'          = [System.Int32]'1249902592'
                'msPKI-Enrollment-Flag'                = [System.Int32]'40'
                'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
                'msPKI-Private-Key-Flag'               = [System.Int32]'101056512'
                'msPKI-RA-Application-Policies'        = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA512`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168')
                'msPKI-RA-Signature'                   = [System.Int32]'0'
                'msPKI-Template-Minor-Revision'        = [System.Int32]'8'
                'msPKI-Template-Schema-Version'        = [System.Int32]'4'
                'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
                'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('3,Microsoft Smart Card Key Storage Provider, 2,Microsoft Platform Crypto Provider, 1,Microsoft Software Key Storage Provider')
                'pKIDefaultKeySpec'                    = [System.Int32]'1'
                'pKIExpirationPeriod'                  = [System.Byte[]]@('0', '128', '114', '14', '93', '194', '253', '255')
                'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.4.1.311.54.1.2')
                'pKIKeyUsage'                          = [System.Byte[]]@('160', '0')
                'pKIMaxIssuingDepth'                   = [System.Int32]'0'
                'pKIOverlapPeriod'                     = [System.Byte[]]@('0', '128', '166', '10', '255', '222', '255', '255')
            }
            New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

            #Publish  Template
            Publish-CertificateTemplate -CertDisplayName $DisplayName

            $DisplayName = 'WindowsAdminCenter'
            $TemplateOtherAttributes = @{
                'Name'                                 = [System.String]$DisplayName
                'ObjectClass'                          = [System.String]'pKICertificateTemplate'
                'flags'                                = [System.Int32]'131649'
                'revision'                             = [System.Int32]'101'
                'msPKI-Cert-Template-OID'              = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.4.1.311.21.8.2144245.16492515.9915066.5498192.1427428.109.11631727.2421588')
                'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.2', '1.3.6.1.5.5.7.3.1')
                'msPKI-Certificate-Name-Flag'          = [System.Int32]'1249902592'
                'msPKI-Enrollment-Flag'                = [System.Int32]'40'
                'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
                'msPKI-Private-Key-Flag'               = [System.Int32]'101056768'
                'msPKI-RA-Application-Policies'        = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA512`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168')
                'msPKI-RA-Signature'                   = [System.Int32]'0'
                'msPKI-Template-Minor-Revision'        = [System.Int32]'1'
                'msPKI-Template-Schema-Version'        = [System.Int32]'4'
                'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
                'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1,Microsoft RSA SChannel Cryptographic Provider', '2,Microsoft DH SChannel Cryptographic Provider')
                'pKIDefaultKeySpec'                    = [System.Int32]'1'
                'pKIExpirationPeriod'                  = [System.Byte[]]@('0', '128', '114', '14', '93', '194', '253', '255')
                'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2')
                'pKIKeyUsage'                          = [System.Byte[]]@('160', '0')
                'pKIMaxIssuingDepth'                   = [System.Int32]'0'
                'pKIOverlapPeriod'                     = [System.Byte[]]@('0', '128', '166', '10', '255', '222', '255', '255')
            }
            New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

            #Publish  Template
            Publish-CertificateTemplate -CertDisplayName $DisplayName

            $DisplayName = 'WinRM'
            $TemplateOtherAttributes = @{
                'Name'                                 = [System.String]$DisplayName
                'ObjectClass'                          = [System.String]'pKICertificateTemplate'
                'flags'                                = [System.Int32]'131649'
                'revision'                             = [System.Int32]'100'
                'msPKI-Cert-Template-OID'              = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.4.1.311.21.8.13605061.7836627.5522072.972782.1389733.240.12298286.5997517')
                'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1')
                'msPKI-Certificate-Name-Flag'          = [System.Int32]'1249902592'
                'msPKI-Enrollment-Flag'                = [System.Int32]'40'
                'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
                'msPKI-Private-Key-Flag'               = [System.Int32]'101056512'
                'msPKI-RA-Application-Policies'        = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA256`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168')
                'msPKI-RA-Signature'                   = [System.Int32]'0'
                'msPKI-Template-Minor-Revision'        = [System.Int32]'5'
                'msPKI-Template-Schema-Version'        = [System.Int32]'4'
                'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
                'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('3,Microsoft Smart Card Key Storage Provider, 2,Microsoft Platform Crypto Provider, 1,Microsoft Software Key Storage Provider')
                'pKIDefaultKeySpec'                    = [System.Int32]'1'
                'pKIExpirationPeriod'                  = [System.Byte[]]@('0', '128', '114', '14', '93', '194', '253', '255')
                'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1')
                'pKIKeyUsage'                          = [System.Byte[]]@('160', '0')
                'pKIMaxIssuingDepth'                   = [System.Int32]'0'
                'pKIOverlapPeriod'                     = [System.Byte[]]@('0', '128', '166', '10', '255', '222', '255', '255')
            }
            New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

            #Publish  Template
            Publish-CertificateTemplate -CertDisplayName $DisplayName

            $DisplayName = 'Web Server V2'
            $TemplateOtherAttributes = @{
                'Name'                                 = [System.String]$DisplayName
                'ObjectClass'                          = [System.String]'pKICertificateTemplate'
                'flags'                                = [System.Int32]'131649'
                'revision'                             = [System.Int32]'100'
                'msPKI-Cert-Template-OID'              = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.4.1.311.21.8.14549150.3855793.16599969.611048.427463.215.10855872.15895385')
                'msPKI-Certificate-Application-Policy' = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1')
                'msPKI-Certificate-Name-Flag'          = [System.Int32]'-1971322880'
                'msPKI-Enrollment-Flag'                = [System.Int32]'40'
                'msPKI-Minimal-Key-Size'               = [System.Int32]'2048'
                'msPKI-Private-Key-Flag'               = [System.Int32]'101056512'
                'msPKI-RA-Application-Policies'        = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('msPKI-Asymmetric-Algorithm`PZPWSTR`RSA`msPKI-Hash-Algorithm`PZPWSTR`SHA256`msPKI-Key-Usage`DWORD`16777215`msPKI-Symmetric-Algorithm`PZPWSTR`3DES`msPKI-Symmetric-Key-Length`DWORD`168`')
                'msPKI-RA-Signature'                   = [System.Int32]'0'
                'msPKI-Template-Minor-Revision'        = [System.Int32]'5'
                'msPKI-Template-Schema-Version'        = [System.Int32]'4'
                'pKICriticalExtensions'                = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('2.5.29.15')
                'pKIDefaultCSPs'                       = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('3,Microsoft Platform Crypto Provider, 2,Microsoft Smart Card Key Storage Provider, 1,Microsoft Software Key Storage Provider')
                'pKIDefaultKeySpec'                    = [System.Int32]'1'
                'pKIExpirationPeriod'                  = [System.Byte[]]@('0', '128', '114', '14', '93', '194', '253', '255')
                'pKIExtendedKeyUsage'                  = [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]@('1.3.6.1.5.5.7.3.1')
                'pKIKeyUsage'                          = [System.Byte[]]@('160')
                'pKIMaxIssuingDepth'                   = [System.Int32]'0'
                'pKIOverlapPeriod'                     = [System.Byte[]]@('0', '128', '166', '10', '255', '222', '255', '255')
            }
            New-Template -DisplayName $DisplayName -TemplateOtherAttributes $TemplateOtherAttributes

            #Publish  Template
            Publish-CertificateTemplate -CertDisplayName $DisplayName

            <#

$GatewayServerName="Wac1"
$TemplateName = "WindowsAdminCenter"

# Install PSPKI module for managing Certification Authority
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSPKI -Force
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope process -Force
Import-Module PSPKI

#Set Cert Template permission
Get-CertificateTemplate -Name $TemplateName | Get-CertificateTemplateAcl | Add-CertificateTemplateAcl -User "$GatewayServerName$" -AccessType Allow -AccessMask Read, Enroll,AutoEnroll | Set-CertificateTemplateAcl

#Configure AutoEnrollment policy and enroll cert on WACGW
Invoke-Command -ComputerName $GatewayServerName -ScriptBlock {
    Set-CertificateAutoEnrollmentPolicy -StoreName MY -PolicyState Enabled -ExpirationPercentage 10 -EnableTemplateCheck -EnableMyStoreManagement -context Machine
    certutil -pulse
}

#>

        } #end if ShouldProcess
    } #end process

    end {
        $txt = ($Variables.Footer -f $MyInvocation.InvocationName,
            'creating created Certificate Authority objects and Delegations.'
        )
        Write-Verbose -Message $txt
    } #end end

} #end function
